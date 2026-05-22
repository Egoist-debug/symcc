#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-replay-secondary.XXXXXX")"
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
if not dump_path:
    sys.stderr.write("missing dump path\\n")
    sys.exit(9)
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

write_fake_dnsmasq_binary() {
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

write_fake_dnsmasq_harness() {
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
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--dnsmasq-stderr-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--dnsmasq-bin')
args = parser.parse_args()
Path(args.cache_dump_path).write_text(
    'May 10 05:49:01 dnsmasq[250875]: Host                           Address                                  Flags      Expires                  Source\\n'
    'May 10 05:49:01 dnsmasq[250875]: ------------------------------ ---------------------------------------- ---------- ------------------------ ------------\\n'
    'May 10 05:49:01 dnsmasq[250875]: example.com                    1.2.3.4                                  4F         Sun May 10 05:50:01 2026\\n',
    encoding='utf-8',
)
Path(args.dnsmasq_stderr_path).write_text('dnsmasq-native\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
DNSMASQ_BUILD="$WORKDIR/dnsmasq-build"
DNSMASQ_BIN="$DNSMASQ_BUILD/dnsmasq"
DNSMASQ_HARNESS="$WORKDIR/dnsmasq-harness.py"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"
OUTPUT_DIR="$WORKDIR/replay-out"
SAMPLE_FILE="$WORKDIR/sample.bin"

write_fake_bind9_binary "$BIND9_BIN"
write_fake_dnsmasq_binary "$DNSMASQ_BIN"
write_fake_dnsmasq_harness "$DNSMASQ_HARNESS"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"

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
	DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
	BIND9_AFL_TREE="$BIND9_TREE" \
	DNSMASQ_BUILD_TREE="$DNSMASQ_BUILD" \
	DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
	BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
	python3 -m tools.dns_diff.cli replay-diff-cache "$SAMPLE_FILE" "$OUTPUT_DIR" >/dev/null

assert_file_exists "$OUTPUT_DIR/bind9.stderr"
assert_file_exists "$OUTPUT_DIR/dnsmasq.stderr"
assert_file_exists "$OUTPUT_DIR/bind9.before.cache.txt"
assert_file_exists "$OUTPUT_DIR/bind9.after.cache.txt"
assert_file_exists "$OUTPUT_DIR/dnsmasq.before.cache.txt"
assert_file_exists "$OUTPUT_DIR/dnsmasq.after.cache.txt"
assert_file_exists "$OUTPUT_DIR/sample.meta.json"
assert_file_exists "$OUTPUT_DIR/oracle.json"

python3 - "$OUTPUT_DIR" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
meta = json.loads((output_dir / "sample.meta.json").read_text(encoding="utf-8"))
oracle = json.loads((output_dir / "oracle.json").read_text(encoding="utf-8"))

artifacts = meta.get("artifacts")
expected = {
    "sample_bin": "sample.bin",
    "bind9_stderr": "bind9.stderr",
    "dnsmasq_stderr": "dnsmasq.stderr",
    "bind9_before_cache": "bind9.before.cache.txt",
    "bind9_after_cache": "bind9.after.cache.txt",
    "dnsmasq_before_cache": "dnsmasq.before.cache.txt",
    "dnsmasq_after_cache": "dnsmasq.after.cache.txt",
    "oracle": "oracle.json",
}
if artifacts != expected:
    raise SystemExit(f"ASSERT FAIL: sample.meta.json.artifacts 不匹配: {artifacts!r}")
for field in (
    "bind9.parse_ok",
    "dnsmasq.parse_ok",
    "bind9.response_accepted",
    "dnsmasq.response_accepted",
    "dnsmasq.second_query_hit",
    "dnsmasq.cache_entry_created",
):
    if oracle.get(field) is not True:
        raise SystemExit(f"ASSERT FAIL: {field}={oracle.get(field)!r} != True")
PY

printf 'PASS: dns diff replay secondary smoke test passed\n'

SMARTDNS_BUILD_ROOT="$WORKDIR/smartdns-build"
SMARTDNS_BUILD="$SMARTDNS_BUILD_ROOT/smartdns-build"
SMARTDNS_BIN="$SMARTDNS_BUILD/src/smartdns"
SMARTDNS_HARNESS="$WORKDIR/smartdns-harness.py"
SMARTDNS_OUTPUT_DIR="$WORKDIR/replay-out-smartdns"

python3 - "$SMARTDNS_BIN" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY

python3 - "$SMARTDNS_HARNESS" <<'PY'
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

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	DNS_DIFF_SECONDARY_RESOLVER=smartdns \
	BIND9_AFL_TREE="$BIND9_TREE" \
	SMARTDNS_BUILD_TREE="$SMARTDNS_BUILD_ROOT" \
	SMARTDNS_HARNESS_SCRIPT="$SMARTDNS_HARNESS" \
	BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
	python3 -m tools.dns_diff.cli replay-diff-cache "$SAMPLE_FILE" "$SMARTDNS_OUTPUT_DIR" >/dev/null

assert_file_exists "$SMARTDNS_OUTPUT_DIR/bind9.stderr"
assert_file_exists "$SMARTDNS_OUTPUT_DIR/smartdns.stderr"
assert_file_exists "$SMARTDNS_OUTPUT_DIR/smartdns.native.log"
assert_file_exists "$SMARTDNS_OUTPUT_DIR/smartdns.after.cache.txt"

python3 - "$SMARTDNS_OUTPUT_DIR" <<'PY'
import json
import pathlib
import sys

output_dir = pathlib.Path(sys.argv[1])
meta = json.loads((output_dir / "sample.meta.json").read_text(encoding="utf-8"))
oracle = json.loads((output_dir / "oracle.json").read_text(encoding="utf-8"))
expected = {
    "sample_bin": "sample.bin",
    "bind9_stderr": "bind9.stderr",
    "smartdns_stderr": "smartdns.stderr",
    "bind9_before_cache": "bind9.before.cache.txt",
    "bind9_after_cache": "bind9.after.cache.txt",
    "smartdns_before_cache": "smartdns.before.cache.txt",
    "smartdns_after_cache": "smartdns.after.cache.txt",
    "oracle": "oracle.json",
}
if meta.get("artifacts") != expected:
    raise SystemExit(f"ASSERT FAIL: smartdns artifacts 不匹配: {meta.get('artifacts')!r}")
for field in (
    "smartdns.parse_ok",
    "smartdns.response_accepted",
    "smartdns.second_query_hit",
    "smartdns.cache_entry_created",
):
    if oracle.get(field) is not True:
        raise SystemExit(f"ASSERT FAIL: {field}={oracle.get(field)!r} != True")
PY

printf 'PASS: dns diff replay secondary smoke test passed\n'
