#!/usr/bin/env python3
import argparse
import shutil
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


def write_empty_cache(path: Path):
    import struct

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = struct.pack("<Q32sI4x", 0x6548634163536E44, b"cache ver 1.3\0", 0)
    path.write_bytes(payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smartdns-bin", required=True)
    parser.add_argument("--mode", choices=("run", "dump"), required=True)
    parser.add_argument("--transcript")
    parser.add_argument("--cache-dump-path", required=True)
    parser.add_argument("--smartdns-log-path", required=True)
    parser.add_argument("--timeout-sec", type=float, default=3.0)
    args = parser.parse_args()

    cache_dump_path = Path(args.cache_dump_path)
    smartdns_log_path = Path(args.smartdns_log_path)

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
    cache_file = cache_dump_path.parent / "smartdns.cache"
    config_path = cache_dump_path.parent / "smartdns.conf"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        (
            f"bind :{listen_port}\n"
            f"server 127.0.0.1:{upstream_port}\n"
            "speed-check-mode none\n"
            "response-mode fastest-response\n"
            "dualstack-ip-selection no\n"
            "log-console yes\n"
            "cache-persist yes\n"
            f"cache-file {cache_file}\n"
        ),
        encoding="utf-8",
    )

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind(("127.0.0.1", upstream_port))
    upstream_sock.settimeout(args.timeout_sec)
    stop_flag = {"stop": False}
    upstream_queries = []

    def upstream_loop():
        while not stop_flag["stop"]:
            try:
                packet, addr = upstream_sock.recvfrom(4096)
            except Exception:
                continue
            upstream_queries.append(packet)
            if responses:
                index = min(len(upstream_queries) - 1, len(responses) - 1)
                reply = bytearray(responses[index])
                if len(reply) >= 2 and len(packet) >= 2:
                    reply[0:2] = packet[0:2]
                upstream_sock.sendto(reply, addr)

    upstream_thr = threading.Thread(target=upstream_loop, daemon=True)
    upstream_thr.start()

    proc = subprocess.Popen(
        [args.smartdns_bin, "-f", "-c", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.8)
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(args.timeout_sec)
    stdout_text = ""
    stderr_text = ""
    try:
        if args.mode == "run":
            cli.sendto(client_query, ("127.0.0.1", listen_port))
            response = cli.recv(4096)
            resolver_fetch_started = len(upstream_queries) > 0
            response_accepted = bool(response)
            upstream_after_first = len(upstream_queries)
            if post_check_query:
                cli.sendto(post_check_query, ("127.0.0.1", listen_port))
                post_response = cli.recv(4096)
                second_query_hit = (
                    bool(post_response) and len(upstream_queries) == upstream_after_first
                )
                cache_entry_created = second_query_hit
        proc.terminate()
        stdout_text, stderr_text = proc.communicate(timeout=5)
    except socket.timeout:
        timeout_seen = True
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        stdout_text, stderr_text = proc.communicate(timeout=5)
    finally:
        stop_flag["stop"] = True
        upstream_sock.close()
        cli.close()

    raw_log = stdout_text + stderr_text
    write_text(smartdns_log_path, raw_log)

    if cache_file.exists() and cache_file.stat().st_size >= 48:
        shutil.copyfile(cache_file, cache_dump_path)
    else:
        write_empty_cache(cache_dump_path)

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
    print(f"smartdns_native_log={smartdns_log_path}")
    print(f"smartdns_cache_file={cache_file}")
    print(f"smartdns_upstream_queries={len(upstream_queries)}")
    return 0 if not timeout_seen else 6


if __name__ == "__main__":
    raise SystemExit(main())
