#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-dnsmasq-replay.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

assert_file_exists() {
	local path="$1"
	if [ ! -f "$path" ]; then
		printf 'ASSERT FAIL: 缺少文件 %s\n' "$path" >&2
		exit 1
	fi
}

python3 - "$WORKDIR/sample.bin" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
response = (
    b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    b'\x07example\x03com\x00\x00\x01\x00\x01'
    b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04'
)
post = b'\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
wire = bytearray(b'DST1')
wire += bytes([1, 2])
wire += len(query).to_bytes(2, "little")
wire += len(response).to_bytes(2, "little")
wire += query + response + post
path.write_bytes(wire)
PY

"$DNSLABCTL_BIN" adapter-build \
	--resolver dnsmasq \
	--build-root "$ROOT_DIR/experiments/subjects/dnsmasq/v2.92-build" \
	>"$WORKDIR/adapter-build.json"

"$DNSLABCTL_BIN" adapter-replay \
	--resolver dnsmasq \
	--sample "$WORKDIR/sample.bin" \
	--build-root "$ROOT_DIR/experiments/subjects/dnsmasq/v2.92-build" \
	--run-root "$WORKDIR/run" \
	>"$WORKDIR/adapter-replay.json"

assert_file_exists "$WORKDIR/run/dnsmasq.stderr"
assert_file_exists "$WORKDIR/run/dnsmasq.native.stderr"
assert_file_exists "$WORKDIR/run/dnsmasq.after.cache.txt"

python3 - "$WORKDIR/adapter-replay.json" "$WORKDIR/run/dnsmasq.after.cache.txt" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
cache_dump = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if payload.get("resolver") != "dnsmasq":
    raise SystemExit(f"ASSERT FAIL: resolver={payload.get('resolver')!r} != 'dnsmasq'")
if payload.get("dump_cache_exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: dump_cache_exit_code={payload.get('dump_cache_exit_code')!r} != 0")
if payload.get("run_sample_exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: run_sample_exit_code={payload.get('run_sample_exit_code')!r} != 0")
oracle = payload.get("oracle")
if not isinstance(oracle, dict):
    raise SystemExit("ASSERT FAIL: oracle 应为对象")
for field in (
    "dnsmasq.parse_ok",
    "dnsmasq.resolver_fetch_started",
    "dnsmasq.response_accepted",
    "dnsmasq.second_query_hit",
    "dnsmasq.cache_entry_created",
):
    if oracle.get(field) is not True:
        raise SystemExit(f"ASSERT FAIL: {field}={oracle.get(field)!r} != True")
if "cached example.com is 1.2.3.4" not in cache_dump:
    raise SystemExit("ASSERT FAIL: cache dump 缺少缓存命中证据")
PY

printf 'PASS: dnslabctl dnsmasq replay smoke test passed\n'
