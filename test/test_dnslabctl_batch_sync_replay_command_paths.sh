#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-batch-sync-replay.XXXXXX")"

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
import argparse
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
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
DNSMASQ_BUILD="$WORKDIR/dnsmasq-build"
DNSMASQ_BIN="$DNSMASQ_BUILD/dnsmasq"
DNSMASQ_HARNESS="$WORKDIR/dnsmasq-harness.py"
SMARTDNS_BUILD_ROOT="$WORKDIR/smartdns-build"
SMARTDNS_BUILD="$SMARTDNS_BUILD_ROOT/smartdns-build"
SMARTDNS_BIN="$SMARTDNS_BUILD/src/smartdns"
SMARTDNS_HARNESS="$WORKDIR/smartdns-harness.py"
SAMPLE_DIR="$WORKDIR/samples"
RUN_ROOT="$WORKDIR/run"
SAMPLE_FILE="$SAMPLE_DIR/id:000001,orig:seed"
RESPONSE_CORPUS_DIR="$WORKDIR/response-corpus"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"

mkdir -p "$WORKDIR/bind9-source" "$WORKDIR/dnsmasq-source" "$WORKDIR/smartdns-source" "$SAMPLE_DIR" "$RESPONSE_CORPUS_DIR"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_dnsmasq_binary "$DNSMASQ_BIN"
write_fake_dnsmasq_harness "$DNSMASQ_HARNESS"
write_fake_smartdns_binary "$SMARTDNS_BIN"
write_fake_smartdns_harness "$SMARTDNS_HARNESS"
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

(
	cd /tmp
	env \
		DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
		SMARTDNS_HARNESS_SCRIPT="$SMARTDNS_HARNESS" \
		SMARTDNS_BUILD_TREE="$(python3 - "$SMARTDNS_BUILD_ROOT" <<'PY'
import os
import pathlib
import sys
print(os.path.relpath(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path('/tmp')))
PY
)" \
		SMARTDNS_SRC_TREE="$(python3 - "$WORKDIR/smartdns-source" <<'PY'
import os
import pathlib
import sys
print(os.path.relpath(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path('/tmp')))
PY
)" \
		RESPONSE_CORPUS_DIR="$RESPONSE_CORPUS_DIR" \
		BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
		"$DNSLABCTL_BIN" batch-sync-replay \
			--sample-dir "$SAMPLE_DIR" \
			--run-root "$RUN_ROOT" \
			--bind9-build-root "$BIND9_TREE" \
			--secondary-resolver dnsmasq \
			--secondary-build-root "$DNSMASQ_BUILD" \
			--bind9-source-root "$WORKDIR/bind9-source" \
			--secondary-source-root "$WORKDIR/dnsmasq-source" \
			--unbound-build-root "$DNSMASQ_BUILD" \
			--resolvers bind9,dnsmasq,smartdns \
			>"$WORKDIR/batch-sync-replay.json"
)

assert_file_exists "$WORKDIR/batch-sync-replay.json"
assert_file_exists "$RUN_ROOT/evidence_bundle.json"
assert_file_exists "$RUN_ROOT/case_studies/index.tsv"

python3 - "$RUN_ROOT/evidence_bundle.json" "$RUN_ROOT/case_studies/index.tsv" "$DNSLABCTL_BIN" "$SMARTDNS_BUILD_ROOT" "$WORKDIR/smartdns-source" <<'PY'
import csv
import json
import pathlib
import sys

bundle = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
index_path = pathlib.Path(sys.argv[2]).resolve()
dnslabctl_bin = pathlib.Path(sys.argv[3]).resolve()
smartdns_build_root = pathlib.Path(sys.argv[4]).resolve()
smartdns_source_root = pathlib.Path(sys.argv[5]).resolve()
expected_command = f"{dnslabctl_bin} batch-sync-replay"

artifacts = bundle.get("artifacts")
if not isinstance(artifacts, list) or not artifacts:
    raise SystemExit("ASSERT FAIL: evidence_bundle.artifacts 应为非空数组")

for item in artifacts:
    if not isinstance(item, dict):
        raise SystemExit(f"ASSERT FAIL: artifact={item!r} 应为对象")
    if item.get("regenerate_command") != expected_command:
        raise SystemExit(
            f"ASSERT FAIL: artifact.regenerate_command={item.get('regenerate_command')!r} "
            f"!= {expected_command!r}"
        )

with index_path.open(encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    expected_columns = [
        "sample_id",
        "semantic_outcome",
        "selection_reason",
        "case_study_path",
        "replay_command",
        "executed_resolvers",
        "diff_detected",
        "resolver_diffs_json",
    ]
    if reader.fieldnames != expected_columns:
        raise SystemExit(
            "ASSERT FAIL: case_studies/index.tsv 列顺序不符合预期:\n"
            f"actual={reader.fieldnames!r}\nexpected={expected_columns!r}"
        )
    rows = list(reader)

if not rows:
    raise SystemExit("ASSERT FAIL: case_studies/index.tsv 期望至少 1 条样本")

replay_command = rows[0].get("replay_command", "")
if f"{dnslabctl_bin} sync-replay " not in replay_command:
    raise SystemExit(
        f"ASSERT FAIL: replay_command={replay_command!r} 未引用真实 dnslabctl 路径 {dnslabctl_bin!s}"
    )
if f"SMARTDNS_BUILD_TREE={smartdns_build_root}" not in replay_command:
    raise SystemExit(
        f"ASSERT FAIL: replay_command 未写入 SMARTDNS_BUILD_TREE: {replay_command!r}"
    )
if f"SMARTDNS_SRC_TREE={smartdns_source_root}" not in replay_command:
    raise SystemExit(
        f"ASSERT FAIL: replay_command 未写入 SMARTDNS_SRC_TREE: {replay_command!r}"
    )
if "--resolvers bind9,dnsmasq,smartdns" not in replay_command:
    raise SystemExit(
        f"ASSERT FAIL: replay_command 未保留完整 resolver 列表: {replay_command!r}"
    )
PY

printf 'PASS: dnslabctl batch-sync-replay command path regression test passed\n'
