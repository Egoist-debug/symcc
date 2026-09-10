#!/usr/bin/env python3
import argparse
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def parse_transcript(path: Path):
    data = path.read_bytes()
    if len(data) < 8 or data[:4] != b"DST1":
        raise ValueError("invalid DST1 transcript header")
    response_count = data[4]
    if response_count > 16:
        raise ValueError(f"unsupported response count: {response_count}")
    if len(data) >= 10 and data[5] == 0:
        query_len = int.from_bytes(data[6:8], "little")
        post_len = int.from_bytes(data[8:10], "little")
        offset = 10
    elif data[5] == 2:
        query_len = int.from_bytes(data[6:8], "little")
        post_len = len(data)
        offset = 8
    else:
        raise ValueError(f"unsupported transcript header flag: {data[5]}")
    lengths = []
    for _ in range(response_count):
        if offset + 2 > len(data):
            raise ValueError("truncated response length table")
        lengths.append(int.from_bytes(data[offset : offset + 2], "little"))
        offset += 2
    if offset + query_len > len(data):
        raise ValueError("truncated client query")
    client_query = data[offset : offset + query_len]
    offset += query_len
    responses = []
    for length in lengths:
        if offset + length > len(data):
            raise ValueError("truncated forged response")
        responses.append(bytearray(data[offset : offset + length]))
        offset += length
    if post_len == len(data):
        post_check = data[offset:]
    else:
        if offset + post_len != len(data):
            raise ValueError("truncated post-check query")
        post_check = data[offset : offset + post_len]
    return client_query, responses, post_check


def choose_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def is_acceptable_dns_response(packet: bytes, query: bytes = b"") -> bool:
    if not packet or len(packet) < 12:
        return False
    if query and len(query) >= 2 and packet[0:2] != query[0:2]:
        return False
    flags = int.from_bytes(packet[2:4], "big")
    qr = (flags >> 15) & 0x1
    rcode = flags & 0xF
    if qr != 1:
        return False
    if rcode not in (0, 3):
        return False
    return True


def build_preload_shim(work_dir: Path) -> Path:
    preferred_tmp = Path.home() / "tmp"
    shim_root = Path(
        tempfile.mkdtemp(
            prefix="deadwood_shim_",
            dir=str(preferred_tmp) if preferred_tmp.is_dir() else None,
        )
    )
    source = shim_root / "deadwood_sandbox_shim.c"
    output = shim_root / "deadwood_sandbox_shim.so"
    source.write_text(
        """
#define _GNU_SOURCE
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
int chroot(const char *path) { (void)path; return 0; }
int setgid(gid_t gid) { if (gid == 0) { errno = EPERM; return -1; } return 0; }
int setuid(uid_t uid) { if (uid == 0) { errno = EPERM; return -1; } return 0; }
int setgroups(size_t size, const gid_t *list) { (void)size; (void)list; return 0; }
""",
        encoding="utf-8",
    )
    subprocess.run(
        ["cc", "-shared", "-fPIC", str(source), "-o", str(output)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return output


def decode_deadwood_name(encoded: str) -> str:
    raw = encoded.encode("latin1", errors="ignore")
    out = bytearray()
    index = 0
    while index < len(raw):
        if raw[index] == 0x5C and index + 3 < len(raw):
            chunk = raw[index + 1 : index + 4]
            if all(48 <= b <= 57 for b in chunk):
                out.append(int(chunk.decode("ascii"), 10))
                index += 4
                continue
        out.append(raw[index])
        index += 1
    labels = []
    cursor = 0
    while cursor < len(out):
        length = out[cursor]
        if length == 0:
            break
        cursor += 1
        labels.append(out[cursor : cursor + length].decode("ascii", errors="replace"))
        cursor += length
    return ".".join(labels)


def decode_dns_wire_name(packet: bytes) -> str:
    if len(packet) < 13:
        return ""
    labels = []
    cursor = 12
    while cursor < len(packet):
        length = packet[cursor]
        if length == 0:
            break
        cursor += 1
        if cursor + length > len(packet):
            return ""
        labels.append(packet[cursor : cursor + length].decode("ascii", errors="replace"))
        cursor += length
    if not labels:
        return ""
    return ".".join(labels) + "."


def maradns_cache_dump(raw_log: str) -> str:
    lines = ["MARADNS_CACHE_DUMP"]
    for raw_line in raw_log.splitlines():
        line = raw_line.strip()
        if line.startswith("Fetching ") and " from cache" in line:
            encoded = line[len("Fetching ") : line.index(" from cache")]
            try:
                qname = decode_deadwood_name(encoded)
            except Exception:
                qname = encoded
            lines.append(f"CACHE_ENTRY\t{qname}\tA\t_")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadwood-bin", required=True)
    parser.add_argument("--mode", choices=("run", "dump"), required=True)
    parser.add_argument("--transcript")
    parser.add_argument("--cache-dump-path", required=True)
    parser.add_argument("--maradns-log-path", required=True)
    parser.add_argument("--timeout-sec", type=float, default=5.0)
    args = parser.parse_args()

    cache_dump_path = Path(args.cache_dump_path)
    maradns_log_path = Path(args.maradns_log_path)
    run_root = cache_dump_path.parent
    run_root.mkdir(parents=True, exist_ok=True)

    parse_ok = False
    resolver_fetch_started = False
    response_accepted = False
    second_query_hit = False
    cache_entry_created = False
    timeout_seen = False

    client_query = b""
    responses = []
    post_check_query = b""
    if args.mode == "run":
        if not args.transcript:
            raise SystemExit("run mode requires --transcript")
        client_query, responses, post_check_query = parse_transcript(Path(args.transcript))
        parse_ok = True

    listen_port = choose_udp_port()
    upstream_port = choose_udp_port()
    cache_file = run_root / "dw_cache"
    config_path = run_root / "dwood3rc"
    preload = build_preload_shim(run_root)

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind(("127.0.0.1", upstream_port))
    upstream_sock.settimeout(args.timeout_sec)
    upstream_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream_tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream_tcp_sock.bind(("127.0.0.1", upstream_port))
    upstream_tcp_sock.listen(4)
    upstream_tcp_sock.settimeout(0.5)
    stop_flag = {"stop": False}
    upstream_queries = []

    def build_reply(packet: bytes) -> bytes:
        if not responses:
            return packet
        index = min(len(upstream_queries) - 1, len(responses) - 1)
        reply = bytearray(responses[index])
        if len(reply) >= 2 and len(packet) >= 2:
            reply[0:2] = packet[0:2]
        return bytes(reply)

    def upstream_loop():
        while not stop_flag["stop"]:
            try:
                packet, addr = upstream_sock.recvfrom(4096)
            except Exception:
                continue
            upstream_queries.append(packet)
            upstream_sock.sendto(build_reply(packet), addr)

    threading.Thread(target=upstream_loop, daemon=True).start()

    def upstream_tcp_loop():
        while not stop_flag["stop"]:
            try:
                conn, _ = upstream_tcp_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(args.timeout_sec)
                try:
                    header = conn.recv(2)
                    if len(header) != 2:
                        continue
                    length = int.from_bytes(header, "big")
                    packet = bytearray()
                    while len(packet) < length:
                        chunk = conn.recv(length - len(packet))
                        if not chunk:
                            break
                        packet.extend(chunk)
                    if len(packet) != length:
                        continue
                    upstream_queries.append(bytes(packet))
                    reply = build_reply(bytes(packet))
                    conn.sendall(len(reply).to_bytes(2, "big") + reply)
                except socket.timeout:
                    continue

    threading.Thread(target=upstream_tcp_loop, daemon=True).start()

    uid = os.getuid()
    gid = os.getgid()
    config_path.write_text(
        (
            'bind_address="127.0.0.1"\n'
            f'chroot_dir="{run_root}"\n'
            f"dns_port = {listen_port}\n"
            "root_servers = {}\n"
            "upstream_servers = {}\n"
            f"upstream_port = {upstream_port}\n"
            'recursive_acl = "127.0.0.1/16"\n'
            "num_retries = 1\n"
            "filter_rfc1918 = 0\n"
            'cache_file = "dw_cache"\n'
            "verbose_level = 1000\n"
            f"maradns_uid = {uid}\n"
            f"maradns_gid = {gid}\n"
            + (
                f'upstream_servers["{decode_dns_wire_name(client_query)}"] = "127.0.0.1"\n'
                if client_query and decode_dns_wire_name(client_query) != "."
                else ""
            )
            + 'root_servers["."] = "127.0.0.1"\n'
        ),
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["LD_PRELOAD"] = str(preload)
    proc = subprocess.Popen(
        [args.deadwood_bin, "-f", str(config_path)],
        cwd=run_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    time.sleep(1.0)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(args.timeout_sec)
    stdout_text = ""
    try:
        if args.mode == "run":
            deadline = time.monotonic() + args.timeout_sec
            response = b""
            while time.monotonic() < deadline:
                cli.sendto(client_query, ("127.0.0.1", listen_port))
                remaining = max(0.05, deadline - time.monotonic())
                cli.settimeout(min(0.25, remaining))
                try:
                    response = cli.recv(4096)
                    break
                except socket.timeout:
                    continue
            resolver_fetch_started = len(upstream_queries) > 0
            fake_reply_dispatched = resolver_fetch_started and len(responses) > 0
            response_accepted = bool(
                resolver_fetch_started
                and fake_reply_dispatched
                and is_acceptable_dns_response(response, client_query)
            )
            upstream_after_first = len(upstream_queries)
            if post_check_query:
                cli.sendto(post_check_query, ("127.0.0.1", listen_port))
                post_response = cli.recv(4096)
                second_query_hit = bool(
                    response_accepted
                    and is_acceptable_dns_response(post_response, post_check_query)
                    and len(upstream_queries) == upstream_after_first
                )
                cache_entry_created = second_query_hit
            if not response_accepted:
                timeout_seen = True
        os.kill(proc.pid, signal.SIGUSR1)
        time.sleep(0.3)
    except socket.timeout:
        timeout_seen = True
    finally:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        stdout_text, _ = proc.communicate(timeout=5)
        stop_flag["stop"] = True
        upstream_sock.close()
        upstream_tcp_sock.close()
        cli.close()

    write_text(maradns_log_path, stdout_text)
    write_text(cache_dump_path, maradns_cache_dump(stdout_text))

    if args.mode == "dump":
        parse_ok = True

    print(
        "ORACLE_SUMMARY "
        f"parse_ok={1 if parse_ok else 0} "
        f"resolver_fetch_started={1 if resolver_fetch_started else 0} "
        f"response_accepted={1 if response_accepted else 0} "
        f"second_query_hit={1 if second_query_hit else 0} "
        f"cache_entry_created={1 if cache_entry_created else 0} "
        f"timeout={1 if timeout_seen else 0}"
    )
    print(f"maradns_native_log={maradns_log_path}")
    print(f"maradns_cache_file={cache_file}")
    print(f"maradns_upstream_queries={len(upstream_queries)}")
    return 0 if not timeout_seen else 6


if __name__ == "__main__":
    raise SystemExit(main())
