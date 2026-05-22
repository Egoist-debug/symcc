#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-follow-diff-secondary-smartdns.XXXXXX")"
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
SMARTDNS_BUILD_ROOT="$WORKDIR/smartdns-build"
SMARTDNS_BUILD="$SMARTDNS_BUILD_ROOT/smartdns-build"
SMARTDNS_BIN="$SMARTDNS_BUILD/src/smartdns"
SMARTDNS_HARNESS="$WORKDIR/smartdns-harness.py"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"
RESPONSE_CORPUS_DIR="$WORKDIR/response_corpus"
SAMPLE_FILE="$QUEUE_DIR/id:000001,orig:seed"

mkdir -p "$QUEUE_DIR"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_smartdns_binary "$SMARTDNS_BIN"
write_fake_smartdns_harness "$SMARTDNS_HARNESS"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
mkdir -p "$RESPONSE_CORPUS_DIR"
printf 'seed\n' >"$RESPONSE_CORPUS_DIR/seed.txt"
python3 - "$SAMPLE_FILE" <<'PY'
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
wire += len(query).to_bytes(2, 'little')
wire += len(response).to_bytes(2, 'little')
wire += query + response + post
path.write_bytes(wire)
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=smartdns \
	BIND9_AFL_TREE="$BIND9_TREE" \
	SMARTDNS_BUILD_TREE="$SMARTDNS_BUILD_ROOT" \
	SMARTDNS_HARNESS_SCRIPT="$SMARTDNS_HARNESS" \
	BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
	RESPONSE_CORPUS_DIR="$RESPONSE_CORPUS_DIR" \
	python3 -m tools.dns_diff.cli follow-diff-once >/dev/null

SAMPLE_META="$(find "$WORK_STATEFUL/follow_diff" -maxdepth 2 -mindepth 2 -type f -name sample.meta.json | sort | head -n 1)"
assert_file_exists "$SAMPLE_META"
SAMPLE_DIR="$(dirname "$SAMPLE_META")"
assert_file_exists "$SAMPLE_DIR/sample.meta.json"
assert_file_exists "$SAMPLE_DIR/oracle.json"
assert_file_exists "$SAMPLE_DIR/cache_diff.json"
assert_file_exists "$SAMPLE_DIR/triage.json"
assert_file_exists "$SAMPLE_DIR/smartdns/smartdns.native.log"

python3 - "$SAMPLE_DIR" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
meta = json.loads((sample_dir / "sample.meta.json").read_text(encoding="utf-8"))
oracle = json.loads((sample_dir / "oracle.json").read_text(encoding="utf-8"))
triage = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))
cache_diff = json.loads((sample_dir / "cache_diff.json").read_text(encoding="utf-8"))

artifacts = meta.get("artifacts", {})
if artifacts.get("smartdns_stderr") != "smartdns/smartdns.stderr":
    raise SystemExit(f"ASSERT FAIL: sample.meta.artifacts 未保留 smartdns stderr: {artifacts!r}")
if oracle.get("smartdns.parse_ok") is not True:
    raise SystemExit(f"ASSERT FAIL: oracle 缺少 smartdns.parse_ok: {oracle!r}")
if triage.get("status") != "completed_oracle_diff":
    raise SystemExit(f"ASSERT FAIL: triage.status={triage.get('status')!r}")
if "unbound" not in cache_diff:
    raise SystemExit(f"ASSERT FAIL: cache_diff 缺少 unbound 兼容槽位: {cache_diff!r}")
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=smartdns \
	python3 - <<'PY'
from tools.dns_diff.follow_diff import _build_follow_diff_comparability_keys, _collect_config

config = _collect_config()
aggregation_key, baseline_compare_key = _build_follow_diff_comparability_keys(config, budget_sec=5)
if aggregation_key.get("resolver_pair") != "bind9_vs_smartdns":
    raise SystemExit(f"ASSERT FAIL: aggregation_key.resolver_pair={aggregation_key.get('resolver_pair')!r}")
if baseline_compare_key.get("resolver_pair") != "bind9_vs_smartdns":
    raise SystemExit(f"ASSERT FAIL: baseline_compare_key.resolver_pair={baseline_compare_key.get('resolver_pair')!r}")
PY

printf 'PASS: follow diff secondary smartdns smoke test passed\n'
