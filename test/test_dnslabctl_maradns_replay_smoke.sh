#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-maradns-replay.XXXXXX")"
PARSED_TSV="$WORKDIR/maradns.norm.tsv"

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

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

python3 - "$WORKDIR/sample.bin" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
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
	--resolver maradns \
	--build-root "$ROOT_DIR/experiments/subjects/maradns/deadwood-3.3.02-build" \
	>"$WORKDIR/adapter-build.json"

"$DNSLABCTL_BIN" adapter-replay \
	--resolver maradns \
	--sample "$WORKDIR/sample.bin" \
	--build-root "$ROOT_DIR/experiments/subjects/maradns/deadwood-3.3.02-build" \
	--run-root "$WORKDIR/run" \
	>"$WORKDIR/adapter-replay.json"

assert_file_exists "$WORKDIR/run/maradns.stderr"
assert_file_exists "$WORKDIR/run/maradns.native.log"
assert_file_exists "$WORKDIR/run/maradns.after.cache.txt"

PYTHONPATH="$ROOT_DIR" python3 -m tools.dns_diff.cli parse-cache maradns \
	"$WORKDIR/run/maradns.after.cache.txt" "$PARSED_TSV" >/dev/null

assert_file_exists "$PARSED_TSV"
assert_file_contains "$PARSED_TSV" $'maradns\t_\texample.com\tA\tA\tCACHE\trrset\t_\t_\tsource=deadwood-log'
assert_file_contains "$WORKDIR/run/maradns.stderr" "ORACLE_SUMMARY parse_ok=1"
assert_file_contains "$WORKDIR/run/maradns.stderr" "second_query_hit=1"
assert_file_contains "$WORKDIR/run/maradns.stderr" "cache_entry_created=1"

printf 'PASS: dnslabctl maradns replay smoke test passed\n'
