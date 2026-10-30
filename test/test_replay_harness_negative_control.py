#!/usr/bin/env python3
import contextlib
import io
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools import dnsmasq_replay_harness, smartdns_replay_harness
from tools import maradns_replay_harness, knot_resolver_replay_harness
from tools.dns_diff.oracle import parse_oracle_summary

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\0\0\1\0\1"
RR = bytes.fromhex("c00c000100010000012c0004c0000201")
SOA = bytes.fromhex(
    "c00c000600010000012c0018c00cc00c"
    "000000010000003c0000003c0000012c0000003c")


def response(rcode=0, answer=True):
    return (QUERY[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1, int(answer), 0, 0)
            + QUERY[12:] + (RR if answer else b""))


HARNESSES = (
    (dnsmasq_replay_harness, "dnsmasq", "--dnsmasq-bin", "--dnsmasq-stderr-path"),
    (smartdns_replay_harness, "smartdns", "--smartdns-bin", "--smartdns-log-path"),
    (maradns_replay_harness, "maradns", "--deadwood-bin", "--maradns-log-path"),
    (knot_resolver_replay_harness, "knot-resolver", "--kresd-bin", "--kresd-log-path"),
)


class PumpFinished(BaseException):
    pass


def run_harness(spec, client_response, *, fetch=QUERY, send_failure=False,
                short_send=False, post_check=b"", post_response=None, replies=None,
                post_fetch=False, tcp_fetch=False):
    module, resolver, bin_flag, log_flag = spec
    targets = []
    first_query = True
    packet_pending = False

    def recvfrom(_size):
        nonlocal packet_pending
        if packet_pending:
            packet_pending = False
            return fetch, ("127.0.0.1", 54321)
        raise PumpFinished()

    upstream = Mock()
    upstream.recvfrom.side_effect = recvfrom
    upstream.sendto.side_effect = (
        OSError("模拟发送失败") if send_failure
        else lambda packet, _addr: len(packet) - int(short_send))
    client = Mock()
    client_packets = iter([client_response, client_response if post_response is None else post_response])

    def recv(size):
        packet = next(client_packets)
        if isinstance(packet, BaseException):
            raise packet
        return packet[:size]

    client.recv.side_effect = recv

    def send_client(_packet, _addr):
        nonlocal first_query, packet_pending
        if (first_query or post_fetch) and fetch is not None:
            packet_pending = True
            try:
                targets[int(tcp_fetch)]()
            except (PumpFinished, OSError):
                pass
        first_query = False
        return len(_packet)

    client.sendto.side_effect = send_client

    def thread(*args, **kwargs):
        targets.append(kwargs["target"])
        return Mock()

    proc = Mock()
    proc.stderr = io.StringIO("")
    proc.communicate.return_value = ("", "")
    sockets = [upstream]
    if module is maradns_replay_harness:
        tcp_socket = Mock()
        conn = Mock()
        conn.__enter__ = Mock(return_value=conn)
        conn.__exit__ = Mock(return_value=False)
        conn.recv.side_effect = [len(fetch or b"").to_bytes(2, "big"), fetch]
        conn.sendall.side_effect = OSError("模拟 TCP 发送失败") if send_failure else None
        tcp_socket.accept.side_effect = [(conn, ("127.0.0.1", 54321)), PumpFinished()]
        sockets.append(tcp_socket)
    sockets.append(client)
    with tempfile.TemporaryDirectory(prefix="a3-oracle-") as tmp, contextlib.ExitStack() as stack:
        root = Path(tmp)
        argv = ["harness", bin_flag, "unused", "--mode", "run", "--transcript", str(root / "input"),
                "--cache-dump-path", str(root / "cache"), log_flag, str(root / "log")]
        stack.enter_context(patch("sys.argv", argv))
        stack.enter_context(patch.object(module, "parse_transcript", return_value=(
            QUERY, [bytearray(response())] if replies is None else replies, post_check)))
        stack.enter_context(patch.object(module, "choose_udp_port", return_value=53000))
        stack.enter_context(patch.object(module.socket, "socket", side_effect=sockets))
        stack.enter_context(patch.object(module.threading, "Thread", side_effect=thread))
        stack.enter_context(patch.object(module.subprocess, "Popen", return_value=proc))
        stack.enter_context(patch.object(module.time, "sleep"))
        if hasattr(module, "os"):
            stack.enter_context(patch.object(module.os, "kill"))
        if module is maradns_replay_harness:
            stack.enter_context(patch.object(module, "build_preload_shim", return_value=root / "shim"))
            if isinstance(client_response, socket.timeout):
                stack.enter_context(patch.object(module.time, "monotonic",
                                                side_effect=[0.0, 0.1, 0.2, 6.0]))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = module.main()
        oracle = parse_oracle_summary(output.getvalue(), resolver)
        assert status == (6 if oracle[f"{resolver}.timeout"] else 0)
        return oracle


class TestReplayHarnessNegativeControls(unittest.TestCase):
    def test_client_results(self):
        valid = response()
        txt = (b"\xff" + b"a" * 255) * 15 + b"\xc6" + b"a" * 198
        large = valid[:6] + b"\0\2" + valid[8:] + struct.pack(
            "!2sHHIH", b"\xc0\x0c", 16, 1, 60, len(txt)) + txt
        self.assertEqual(len(large), 4096)
        cases = {
            "A": (valid, True),
            "NXDOMAIN": (response(3, False), True),
            "NODATA": (response(0, False), True),
            "NXDOMAIN_SOA": (response(3, False)[:8] + b"\0\1\0\0" + QUERY[12:] + SOA, True),
            "NODATA_SOA": (response(0, False)[:8] + b"\0\1\0\0" + QUERY[12:] + SOA, True),
            "大小写": (valid[:13] + b"EXAMPLE" + valid[20:], True),
            "错误ID": (b"\x99\x99" + valid[2:], False),
            "错误QNAME": (valid[:13] + b"invalid" + valid[20:], False),
            "错误QTYPE": (valid[:25] + b"\0\x1c" + valid[27:], False),
            "错误QCLASS": (valid[:27] + b"\0\x03" + valid[29:], False),
            "截断RR": (valid[:-1], False),
            "缺少RR": (valid[:29], False),
            "只有header": (valid[:12], False),
            "尾部垃圾": (valid + b"\0", False),
            "大报文不能被recv截成合法前缀": (large + b"\0", False),
            "完整大报文": (large, True),
            "TC": (valid[:2] + b"\x83\x80" + valid[4:], False),
            "指针环": (valid[:29] + b"\xc0\x1d" + valid[31:], False),
            "指针越界": (valid[:29] + b"\xff\xff" + valid[31:], False),
            "截断CNAME": (valid[:31] + b"\0\5" + valid[33:39] + b"\0\1\xc0", False),
            "空CNAME": (valid[:31] + b"\0\5" + valid[33:39] + b"\0\0", False),
            "不完整SOA": (valid[:31] + b"\0\6" + valid[33:39] + b"\0\1\0", False),
            "错误A长度": (valid[:39] + b"\0\3" + valid[41:44], False),
            "TXT越界": (valid[:31] + b"\0\x10" + valid[33:39] + b"\0\2\x03a", False),
            "缺少OPT": (valid[:10] + b"\0\1" + valid[12:], False),
            "扩展RCODE": (valid[:10] + b"\0\1" + valid[12:]
                           + bytes.fromhex("00002904d0010000000000"), False),
            "NOTIMP": (response(4, False), False),
            "REFUSED": (response(5, False), False),
            "SERVFAIL": (response(2, False), False),
        }
        for spec in HARNESSES:
            resolver = spec[1]
            for name, (packet, accepted) in cases.items():
                with self.subTest(resolver=resolver, case=name):
                    oracle = run_harness(spec, packet)
                    self.assertEqual(oracle[f"{resolver}.response_accepted"], accepted)
                    self.assertFalse(oracle[f"{resolver}.cache_entry_created"])
                    self.assertFalse(oracle[f"{resolver}.second_query_hit"])
                    self.assertFalse(oracle[f"{resolver}.timeout"])

    def test_injection_facts(self):
        wrong_name = QUERY[:13] + b"invalid" + QUERY[20:]
        wrong_type = QUERY[:25] + b"\0\x1c" + QUERY[27:]
        wrong_class = QUERY[:27] + b"\0\x03"
        cases = [
            ("未fetch", {"fetch": None}, False, False),
            ("错误fetch名", {"fetch": wrong_name}, False, False),
            ("错误fetch类型", {"fetch": wrong_type}, False, False),
            ("错误fetch类", {"fetch": wrong_class}, False, False),
            ("发送失败", {"send_failure": True}, True, False),
            ("未完整发送", {"short_send": True}, True, False),
            ("无注入输入", {"replies": []}, True, False),
            ("成功发送", {}, True, True),
        ]
        for spec in HARNESSES:
            resolver = spec[1]
            for name, kwargs, fetched, sent in cases:
                with self.subTest(resolver=resolver, case=name):
                    oracle = run_harness(spec, response(), **kwargs)
                    self.assertEqual(oracle[f"{resolver}.resolver_fetch_started"], fetched)
                    self.assertEqual(oracle.get(f"{resolver}.fake_reply_dispatched"), sent)
                    self.assertEqual(oracle[f"{resolver}.response_accepted"], sent)

    def test_post_check(self):
        for spec in HARNESSES:
            resolver = spec[1]
            for first in (response(), response(3, False), response(0, False)):
                for post, hit in ((first, True), (first[:-1], False)):
                    with self.subTest(resolver=resolver, first=first, post=post):
                        oracle = run_harness(spec, first, post_check=QUERY, post_response=post)
                        self.assertEqual(oracle[f"{resolver}.second_query_hit"], hit)
                        self.assertEqual(oracle[f"{resolver}.cache_entry_created"], hit)
            for post, fetched, hit, timeout in (
                (response(), True, False, False),
                (response(2), False, False, False),
                (b"\x99\x99" + response()[2:], False, False, False),
                (socket.timeout(), False, False, True),
            ):
                with self.subTest(resolver=resolver, post=post, post_fetch=fetched):
                    oracle = run_harness(spec, response(), post_check=QUERY,
                                         post_response=post, post_fetch=fetched)
                    self.assertTrue(oracle[f"{resolver}.response_accepted"])
                    self.assertEqual(oracle[f"{resolver}.timeout"], timeout)
                    self.assertEqual(oracle[f"{resolver}.second_query_hit"], hit)
                    self.assertEqual(oracle[f"{resolver}.cache_entry_created"], hit)

    def test_first_timeout_keeps_injection_facts(self):
        for spec in HARNESSES:
            resolver = spec[1]
            oracle = run_harness(spec, socket.timeout())
            self.assertTrue(oracle[f"{resolver}.resolver_fetch_started"])
            self.assertTrue(oracle[f"{resolver}.fake_reply_dispatched"])
            self.assertTrue(oracle[f"{resolver}.timeout"])
            self.assertFalse(oracle[f"{resolver}.response_accepted"])
            self.assertFalse(oracle[f"{resolver}.second_query_hit"])
            self.assertFalse(oracle[f"{resolver}.cache_entry_created"])

    def test_maradns_tcp_dispatch(self):
        for failed in (False, True):
            oracle = run_harness(HARNESSES[2], response(), tcp_fetch=True, send_failure=failed)
            self.assertTrue(oracle["maradns.resolver_fetch_started"])
            self.assertEqual(oracle["maradns.fake_reply_dispatched"], not failed)
            self.assertEqual(oracle["maradns.response_accepted"], not failed)

    def test_old_summary_keeps_unknown_dispatch(self):
        oracle = parse_oracle_summary(
            "ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 "
            "second_query_hit=0 cache_entry_created=0 timeout=0", "old")
        self.assertIsNone(oracle.get("old.fake_reply_dispatched"))
        self.assertEqual(oracle["old.stderr_parse_status"], "ok")
        for token, expected in (("0", False), ("1", True), ("bad", None)):
            oracle = parse_oracle_summary(
                "ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 "
                "second_query_hit=0 cache_entry_created=0 timeout=0 fake_reply_dispatched=" + token,
                "old")
            self.assertIs(oracle["old.fake_reply_dispatched"], expected)
            self.assertEqual(oracle["old.stderr_parse_status"], "ok")


if __name__ == "__main__":
    unittest.main()
