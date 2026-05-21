#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMED_WRAPPER="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-transcript-current.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

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

SCENARIO_WORK="$WORKDIR/work"
SOURCE_DIR="$SCENARIO_WORK/transcript_corpus"
TARGET_DIR="$SCENARIO_WORK/stable_transcript_corpus"
RESPONSE_DIR="$SCENARIO_WORK/response_corpus"
LOG_FILE="$WORKDIR/filter-seeds.log"

mkdir -p "$SOURCE_DIR" "$TARGET_DIR" "$RESPONSE_DIR"
printf '\x00' >"$RESPONSE_DIR/id_000000_dummy"

python3 - "$TARGET_DIR/id:000001,orig:current-dst1" <<'PY'
from pathlib import Path
import struct
import sys

output = Path(sys.argv[1])
qname = b'\x07example\x03com\x00'
query = bytes.fromhex('123401000001000000000000') + qname + bytes.fromhex('00010001')
response = bytes.fromhex('567881800001000100000000') + qname + bytes.fromhex('00010001c00c000100010000003c000401020304')
post_check = bytes.fromhex('9abc01000001000000000000') + qname + bytes.fromhex('00010001')

payload = bytearray()
payload += b"DST1"
payload += bytes([1])
payload += bytes([0])
payload += struct.pack("<H", len(query))
payload += struct.pack("<H", len(post_check))
payload += struct.pack("<H", len(response))
payload += query
payload += response
payload += post_check
output.write_bytes(payload)
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$SCENARIO_WORK" \
	FUZZ_PROFILE=poison-stateful \
	REGEN_SEEDS=0 \
	REFILTER_QUERIES=0 \
	bash "$NAMED_WRAPPER" filter-seeds >"$LOG_FILE" 2>&1

assert_file_contains "$LOG_FILE" "复用已有稳定输入语料"
assert_file_contains "$LOG_FILE" "$TARGET_DIR"

printf 'PASS: named current DST1 transcript acceptance test passed\n'
