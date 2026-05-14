#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-knot-replay.XXXXXX")"
PARSED_TSV="$WORKDIR/knot.norm.tsv"

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

write_fake_knot_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_knot_harness() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--kresd-bin', required=True)
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--kresd-log-path', required=True)
parser.add_argument('--transcript')
args = parser.parse_args()
if args.mode == 'run':
    Path(args.cache_dump_path).write_text('KNOT_RESOLVER_CACHE_DUMP\\nCACHE_ENTRY\\texample.com\\tA\\t_\\n', encoding='utf-8')
    print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
else:
    Path(args.cache_dump_path).write_text('KNOT_RESOLVER_CACHE_DUMP\\n', encoding='utf-8')
    print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=0 response_accepted=0 second_query_hit=0 cache_entry_created=0 timeout=0')
Path(args.kresd_log_path).write_text('knot-native\\n', encoding='utf-8')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
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

KNOT_BUILD="$WORKDIR/knot-build"
KNOT_BIN="$KNOT_BUILD/knot-build/daemon/kresd"
KNOT_HARNESS="$WORKDIR/knot-harness.py"
write_fake_knot_binary "$KNOT_BIN"
write_fake_knot_harness "$KNOT_HARNESS"

env KNOT_RESOLVER_HARNESS_SCRIPT="$KNOT_HARNESS" \
	"$DNSLABCTL_BIN" adapter-replay \
		--resolver knot-resolver \
		--sample "$WORKDIR/sample.bin" \
		--build-root "$KNOT_BUILD" \
		--run-root "$WORKDIR/run" \
		>"$WORKDIR/adapter-replay.json"

assert_file_exists "$WORKDIR/run/knot-resolver.stderr"
assert_file_exists "$WORKDIR/run/knot-resolver.native.log"
assert_file_exists "$WORKDIR/run/knot-resolver.after.cache.txt"

PYTHONPATH="$ROOT_DIR" python3 -m tools.dns_diff.cli parse-cache knot-resolver \
	"$WORKDIR/run/knot-resolver.after.cache.txt" "$PARSED_TSV" >/dev/null

assert_file_exists "$PARSED_TSV"
assert_file_contains "$PARSED_TSV" $'knot-resolver\t_\texample.com\tA\tA\tCACHE\trrset\t_\t_\tsource=kresd-harness'
assert_file_contains "$WORKDIR/run/knot-resolver.stderr" "ORACLE_SUMMARY parse_ok=1"
assert_file_contains "$WORKDIR/run/knot-resolver.stderr" "second_query_hit=1"
assert_file_contains "$WORKDIR/run/knot-resolver.stderr" "cache_entry_created=1"

printf 'PASS: dnslabctl knot-resolver replay smoke test passed\n'
