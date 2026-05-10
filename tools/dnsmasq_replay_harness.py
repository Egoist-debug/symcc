#!/usr/bin/env python3
import argparse
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path


def parse_transcript(path: Path):
    data = path.read_bytes()
    if len(data) < 8 or data[:4] != b"DST1":
        raise ValueError("invalid DST1 transcript header")
    response_count = data[4]
    version = data[5]
    if version != 2:
        raise ValueError(f"unsupported transcript version: {version}")
    query_len = int.from_bytes(data[6:8], "little")
    offset = 8
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
    post_check = data[offset:]
    return client_query, responses, post_check


def choose_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def reader_thread(stream, bucket):
    try:
        for line in stream:
            bucket.append(line)
    finally:
        stream.close()


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dnsmasq-bin", required=True)
    parser.add_argument("--mode", choices=("run", "dump"), required=True)
    parser.add_argument("--transcript")
    parser.add_argument("--cache-dump-path", required=True)
    parser.add_argument("--dnsmasq-stderr-path", required=True)
    parser.add_argument("--timeout-sec", type=float, default=3.0)
    args = parser.parse_args()

    cache_dump_path = Path(args.cache_dump_path)
    dnsmasq_stderr_path = Path(args.dnsmasq_stderr_path)

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

    upstream_port = choose_udp_port()
    listen_port = choose_udp_port()
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

    cmd = [
        args.dnsmasq_bin,
        "--no-daemon",
        "--log-queries",
        "--log-facility=-",
        "--port",
        str(listen_port),
        "--listen-address=127.0.0.1",
        "--bind-interfaces",
        "--no-hosts",
        "--no-resolv",
        "--server=127.0.0.1#" + str(upstream_port),
        "--cache-size=1000",
        "--conf-file=/dev/null",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    stderr_lines = []
    stderr_thr = threading.Thread(
        target=reader_thread, args=(proc.stderr, stderr_lines), daemon=True
    )
    stderr_thr.start()

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(args.timeout_sec)
    time.sleep(0.4)
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
        os.kill(proc.pid, signal.SIGUSR1)
        time.sleep(0.3)
    except socket.timeout:
        timeout_seen = True
    finally:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        stop_flag["stop"] = True
        upstream_sock.close()
        cli.close()
        stderr_thr.join(timeout=1)

    raw_stderr = "".join(stderr_lines)
    write_text(dnsmasq_stderr_path, raw_stderr)
    write_text(cache_dump_path, raw_stderr)

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
    print(f"dnsmasq_native_stderr={dnsmasq_stderr_path}")
    print(f"dnsmasq_cache_dump={cache_dump_path}")
    print(f"dnsmasq_upstream_queries={len(upstream_queries)}")
    return 0 if not timeout_seen else 6


if __name__ == "__main__":
    sys.exit(main())
