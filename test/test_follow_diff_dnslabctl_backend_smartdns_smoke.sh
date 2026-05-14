#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-follow-diff-dnslabctl-smartdns.XXXXXX")"
QUEUE_DIR="$WORKDIR/bind9-work/afl_out/master/queue"
WORK_STATEFUL="$WORKDIR/work"
export PYTHONDONTWRITEBYTECODE=1

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

assert_dir_exists() {
	local path="$1"
	if [ ! -d "$path" ]; then
		printf 'ASSERT FAIL: 缺少目录 %s\n' "$path" >&2
		exit 1
	fi
}

write_fake_bind9_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
script = """#!/usr/bin/env python3
import os
import pathlib
import sys
dump_path = os.environ.get("NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH")
has_input = any("input=" in arg for arg in sys.argv[1:])
ttl = "299" if has_input else "300"
pathlib.Path(dump_path).write_text(
    "\\n".join([
        ";",
        "; Cache dump of view '_default' (cache _default)",
        ";",
        f"example.com. {ttl} IN A 1.2.3.4",
    ]) + "\\n",
    encoding="utf-8",
)
sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
sys.exit(0)
"""
path.write_text(script, encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_smartdns_binary() {
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

write_fake_smartdns_harness() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import struct
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--smartdns-log-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--smartdns-bin')
args = parser.parse_args()
packet = (
    b'\\x56\\x78\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00'
    b'\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'
    b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x02\\x58\\x00\\x04\\x01\\x02\\x03\\x04'
)
info = bytearray(344)
info[0:len(b'example.com')] = b'example.com'
struct.pack_into('<i', info, 256, 1)
struct.pack_into('<I', info, 292, 0)
struct.pack_into('<i', info, 296, 600)
struct.pack_into('<i', info, 300, 0)
struct.pack_into('<i', info, 304, 6)
struct.pack_into('<i', info, 308, -1)
struct.pack_into('<q', info, 328, 111)
struct.pack_into('<q', info, 336, 222)
payload = struct.pack('<Q32sI4x', 0x6548634163536E44, b'cache ver 1.3\\0', 1)
payload += struct.pack('<I4x', 0x64526352)
payload += bytes(info)
payload += struct.pack('<i4xqI4x', 1, len(packet), 0x61546144)
payload += packet
Path(args.cache_dump_path).write_bytes(payload)
Path(args.smartdns_log_path).write_text('smartdns-native\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
BIND9_SRC="$WORKDIR/bind9-src"
SMARTDNS_BUILD="$WORKDIR/smartdns-build"
SMARTDNS_BIN="$SMARTDNS_BUILD/smartdns-build/src/smartdns"
SMARTDNS_SRC="$WORKDIR/smartdns-src"
SMARTDNS_HARNESS="$WORKDIR/smartdns-harness.py"
SAMPLE_FILE="$QUEUE_DIR/id:000001,orig:seed"

mkdir -p "$QUEUE_DIR" "$BIND9_SRC" "$SMARTDNS_SRC"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_smartdns_binary "$SMARTDNS_BIN"
write_fake_smartdns_harness "$SMARTDNS_HARNESS"
printf '\x01\x02\x03\x04' >"$SAMPLE_FILE"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=smartdns \
	DNS_DIFF_REPLAY_BACKEND=dnslabctl \
	BIND9_AFL_TREE="$BIND9_TREE" \
	BIND9_SRC_TREE="$BIND9_SRC" \
	SMARTDNS_BUILD_TREE="$SMARTDNS_BUILD" \
	SMARTDNS_SRC_TREE="$SMARTDNS_SRC" \
	SMARTDNS_HARNESS_SCRIPT="$SMARTDNS_HARNESS" \
	python3 -m tools.dns_diff.cli follow-diff-once >/dev/null

SAMPLE_DIR="$(find "$WORK_STATEFUL/follow_diff" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
assert_file_exists "$SAMPLE_DIR/sample.meta.json"
assert_file_exists "$SAMPLE_DIR/oracle.json"
assert_file_exists "$SAMPLE_DIR/cache_diff.json"
assert_file_exists "$SAMPLE_DIR/triage.json"
assert_file_exists "$SAMPLE_DIR/bind9.before.cache.txt"
assert_file_exists "$SAMPLE_DIR/bind9.after.cache.txt"
assert_file_exists "$SAMPLE_DIR/smartdns.before.cache.txt"
assert_file_exists "$SAMPLE_DIR/smartdns.after.cache.txt"
assert_dir_exists "$SAMPLE_DIR/bind9"
assert_dir_exists "$SAMPLE_DIR/smartdns"

python3 - "$SAMPLE_DIR" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
meta = json.loads((sample_dir / "sample.meta.json").read_text(encoding="utf-8"))
triage = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))
artifacts = meta.get("artifacts", {})
if artifacts.get("smartdns_stderr") != "smartdns.stderr":
    raise SystemExit(f"ASSERT FAIL: artifacts 未保留 smartdns_stderr: {artifacts!r}")
if meta.get("status") != "completed":
    raise SystemExit(f"ASSERT FAIL: sample.meta.status={meta.get('status')!r}")
if triage.get("status") != "completed_oracle_diff":
    raise SystemExit(f"ASSERT FAIL: triage.status={triage.get('status')!r}")
PY

printf 'PASS: follow diff dnslabctl backend smartdns smoke test passed\n'
