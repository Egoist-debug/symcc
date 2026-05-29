#!/usr/bin/env python3
import argparse
import shutil
import signal
import socket
import subprocess
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


def qtype_name(qtype: int):
    mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        65: "HTTPS",
    }
    return mapping.get(qtype, f"TYPE{qtype}")


def parse_question(packet: bytes):
    if len(packet) < 12:
        return "_", "_"
    qdcount = int.from_bytes(packet[4:6], "big")
    if qdcount == 0:
        return "_", "_"
    offset = 12
    labels = []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if offset + length > len(packet):
            return "_", "_"
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    if offset + 4 > len(packet):
        return ".".join(labels) if labels else "_", "_"
    qtype = int.from_bytes(packet[offset : offset + 2], "big")
    qname = ".".join(labels) if labels else "_"
    return qname, qtype_name(qtype)


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_cache_dump(path: Path, entries):
    lines = ["KNOT_RESOLVER_CACHE_DUMP"]
    for qname, qtype in entries:
        lines.append(f"CACHE_ENTRY\t{qname}\t{qtype}\t_")
    write_text(path, "\n".join(lines) + "\n")


def acceptable_response(packet: bytes):
    if len(packet) < 12:
        return False
    flags = int.from_bytes(packet[2:4], "big")
    qr = (flags >> 15) & 0x1
    rcode = flags & 0xF
    ancount = int.from_bytes(packet[6:8], "big")
    return qr == 1 and rcode == 0 and ancount > 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kresd-bin", required=True)
    parser.add_argument("--mode", choices=("run", "dump"), required=True)
    parser.add_argument("--transcript")
    parser.add_argument("--cache-dump-path", required=True)
    parser.add_argument("--kresd-log-path", required=True)
    parser.add_argument("--timeout-sec", type=float, default=3.0)
    args = parser.parse_args()

    cache_dump_path = Path(args.cache_dump_path)
    kresd_log_path = Path(args.kresd_log_path)
    run_root = cache_dump_path.parent
    run_root.mkdir(parents=True, exist_ok=True)

    if args.mode == "dump":
        write_cache_dump(cache_dump_path, [])
        write_text(kresd_log_path, "")
        print(
            "ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=0 "
            "response_accepted=0 second_query_hit=0 cache_entry_created=0 timeout=0"
        )
        print(f"knot_resolver_native_log={kresd_log_path}")
        return 0

    if not args.transcript:
        raise SystemExit("run mode requires --transcript")

    client_query, responses, post_check_query = parse_transcript(Path(args.transcript))
    qname, qtype = parse_question(client_query)
    target_signature = (qname, qtype)
    parse_ok = True
    resolver_fetch_started = False
    response_accepted = False
    second_query_hit = False
    cache_entry_created = False
    timeout_seen = False

    listen_port = choose_udp_port()
    upstream_port = choose_udp_port()
    config_path = run_root / "kresd.config.lua"
    config_path.write_text(
        (
            "modules = { 'policy' }\n"
            "cache.open(20 * MB)\n"
            "trust_anchors.remove('.')\n"
            "mode('permissive')\n"
            f"policy.add(policy.all(policy.STUB('127.0.0.1@{upstream_port}')))\n"
        ),
        encoding="utf-8",
    )

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind(("127.0.0.1", upstream_port))
    upstream_sock.settimeout(args.timeout_sec)
    upstream_queries = []
    matching_queries = []
    stop_flag = {"stop": False}

    def upstream_loop():
        while not stop_flag["stop"]:
            try:
                packet, addr = upstream_sock.recvfrom(4096)
            except Exception:
                continue
            upstream_queries.append(packet)
            if parse_question(packet) == target_signature:
                matching_queries.append(packet)
            if not responses:
                continue
            reply = bytearray(responses[min(len(upstream_queries) - 1, len(responses) - 1)])
            if len(reply) >= 2 and len(packet) >= 2:
                reply[0:2] = packet[0:2]
            upstream_sock.sendto(reply, addr)

    threading.Thread(target=upstream_loop, daemon=True).start()

    proc = subprocess.Popen(
        [
            args.kresd_bin,
            "-n",
            "-q",
            "-a",
            f"127.0.0.1@{listen_port}",
            "-c",
            str(config_path),
            str(run_root),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1.0)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(args.timeout_sec)
    raw_log = ""
    try:
        cli.sendto(client_query, ("127.0.0.1", listen_port))
        response = cli.recv(4096)
        resolver_fetch_started = len(matching_queries) > 0
        response_accepted = acceptable_response(response)
        upstream_after_first = len(matching_queries)
        if post_check_query:
            cli.sendto(post_check_query, ("127.0.0.1", listen_port))
            post_response = cli.recv(4096)
            second_query_hit = (
                acceptable_response(post_response)
                and len(matching_queries) == upstream_after_first
            )
        cache_entry_created = second_query_hit or (response_accepted and not post_check_query)
    except socket.timeout:
        timeout_seen = True
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            raw_log, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            raw_log, _ = proc.communicate(timeout=5)
        stop_flag["stop"] = True
        upstream_sock.close()
        cli.close()

    entries = [(qname, qtype)] if cache_entry_created else []
    write_cache_dump(cache_dump_path, entries)
    write_text(kresd_log_path, raw_log)

    for pattern in ("data.mdb", "lock.mdb", "top"):
        for stale in run_root.rglob(pattern):
            try:
                stale.unlink()
            except (FileNotFoundError, IsADirectoryError):
                pass
    for ruledb_dir in run_root.rglob("ruledb"):
        if ruledb_dir.is_dir():
            shutil.rmtree(ruledb_dir, ignore_errors=True)

    print(
        "ORACLE_SUMMARY "
        f"parse_ok={1 if parse_ok else 0} "
        f"resolver_fetch_started={1 if resolver_fetch_started else 0} "
        f"response_accepted={1 if response_accepted else 0} "
        f"second_query_hit={1 if second_query_hit else 0} "
        f"cache_entry_created={1 if cache_entry_created else 0} "
        f"timeout={1 if timeout_seen else 0}"
    )
    print(f"knot_resolver_native_log={kresd_log_path}")
    print(f"knot_resolver_upstream_queries={len(upstream_queries)}")
    print(f"knot_resolver_matching_queries={len(matching_queries)}")
    return 0 if not timeout_seen else 6


if __name__ == "__main__":
    raise SystemExit(main())
