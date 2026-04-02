#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMED_WRAPPER="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-transcript-migration.XXXXXX")"
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
RESPONSE_DIR="$SCENARIO_WORK/response_corpus"
LOG_FILE="$WORKDIR/filter-seeds.log"

mkdir -p "$SOURCE_DIR" "$RESPONSE_DIR"
printf '\x00' >"$RESPONSE_DIR/id_000000_dummy"

python3 - "$SOURCE_DIR/legacy-v0-three-part" <<'PY'
from pathlib import Path
import struct
import sys

output = Path(sys.argv[1])
magic = b"DST1"
response_count = 1
version = 0
client_query = b"\x12\x34\x00\x01"
response = b"\xaa\xbb\xcc"
post_check = b"\xde\xad"

payload = bytearray()
payload += magic
payload += bytes([response_count])
payload += bytes([version])
payload += struct.pack("<H", len(client_query))
payload += struct.pack("<H", len(response))
payload += client_query
payload += response
payload += post_check

output.write_bytes(bytes(payload))
PY

set +e
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$SCENARIO_WORK" \
	FUZZ_PROFILE=poison-stateful \
	REGEN_SEEDS=0 \
	REFILTER_QUERIES=1 \
	bash "$NAMED_WRAPPER" filter-seeds >"$LOG_FILE" 2>&1
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
	printf 'ASSERT FAIL: 期望旧三段式 transcript seed 被 fail-fast 拒绝，但 filter-seeds 成功返回\n' >&2
	cat "$LOG_FILE" >&2
	exit 1
fi

assert_file_contains "$LOG_FILE" "version=0"
assert_file_contains "$LOG_FILE" "请删除旧语料后重新生成 transcript corpus"

printf 'PASS: named transcript seed migration regression test passed\n'
