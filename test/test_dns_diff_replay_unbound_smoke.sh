#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-replay-unbound-real.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/real_experiment_paths.sh"

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

SAMPLE_FILE="$WORKDIR/rootns.dst1"
OUTPUT_DIR="$WORKDIR/out"

python3 - "$SAMPLE_FILE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
qname = b'\x00'
query = bytes.fromhex('123401000001000000000000') + qname + bytes.fromhex('00020001')
rdata = b'\x01a\x0croot-servers\x03net\x00'
response = (
    bytes.fromhex('567881800001000100000000')
    + qname
    + bytes.fromhex('00020001')
    + bytes.fromhex('c00c000200010000003c')
    + len(rdata).to_bytes(2, 'big')
    + rdata
)
post = bytes.fromhex('9abc01000001000000000000') + qname + bytes.fromhex('00020001')
wire = bytearray(b'DST1')
wire += bytes([1, 0])
wire += len(query).to_bytes(2, 'little')
wire += len(post).to_bytes(2, 'little')
wire += len(response).to_bytes(2, 'little')
wire += query + response + post
path.write_bytes(wire)
PY

env \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORKDIR/work" \
	BIND9_AFL_TREE="$(bind9_afl_tree)" \
	BIND9_SRC_TREE="$(resolver_src_root bind9)" \
	AFL_TREE="$(unbound_afl_tree)" \
	UNBOUND_SRC_TREE="$(resolver_src_root unbound)" \
	RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
	BIND9_NAMED_CONF_TEMPLATE="$ROOT_DIR/named_experiment/runtime/named.conf" \
	python3 -m tools.dns_diff.cli replay-diff-cache "$SAMPLE_FILE" "$OUTPUT_DIR" >/dev/null

assert_file_exists "$OUTPUT_DIR/oracle.json"
assert_file_exists "$OUTPUT_DIR/sample.meta.json"
assert_file_exists "$OUTPUT_DIR/bind9.before.cache.txt"
assert_file_exists "$OUTPUT_DIR/bind9.after.cache.txt"
assert_file_exists "$OUTPUT_DIR/unbound.before.cache.txt"
assert_file_exists "$OUTPUT_DIR/unbound.after.cache.txt"

python3 - "$OUTPUT_DIR/oracle.json" "$OUTPUT_DIR/unbound.stderr" <<'PY'
import json
import pathlib
import sys

oracle = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stderr_text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

for field in (
    "bind9.parse_ok",
    "bind9.resolver_fetch_started",
    "bind9.response_accepted",
    "bind9.second_query_hit",
    "bind9.cache_entry_created",
    "unbound.parse_ok",
    "unbound.resolver_fetch_started",
    "unbound.response_accepted",
    "unbound.second_query_hit",
    "unbound.cache_entry_created",
):
    if oracle.get(field) is not True:
        raise SystemExit(f"ASSERT FAIL: {field}={oracle.get(field)!r} != True")
if "ORACLE_SUMMARY parse_ok=1" not in stderr_text:
    raise SystemExit("ASSERT FAIL: unbound.stderr 缺少 ORACLE_SUMMARY parse_ok=1")
PY

printf 'PASS: real bind9+unbound replay smoke test passed\n'
