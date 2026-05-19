#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-sync-replay-secondary.XXXXXX")"

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

write_fake_unbound_binary() {
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

payload = sys.stdin.buffer.read()
dump_path = os.environ.get("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH")
if not dump_path:
    sys.stderr.write("missing unbound dump path\\n")
    sys.exit(9)
ttl = "299" if payload else "300"
pathlib.Path(dump_path).write_text(
    "\\n".join([
        "START_RRSET_CACHE",
        f"example.com. {ttl} IN A 1.2.3.4",
        "END_RRSET_CACHE",
        "START_MSG_CACHE",
        "msg example.com. IN A NOERROR 1 300 0 1 0 0 0 ok",
        "EOF",
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

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
UNBOUND_BUILD="$WORKDIR/unbound-afl"
UNBOUND_BIN="$UNBOUND_BUILD/.libs/unbound-fuzzme"
DNSMASQ_BUILD="$WORKDIR/dnsmasq-build"
DNSMASQ_BIN="$DNSMASQ_BUILD/dnsmasq"
DNSMASQ_HARNESS="$WORKDIR/dnsmasq-harness.py"
RESPONSE_CORPUS_DIR="$WORKDIR/response-corpus"
mkdir -p "$WORKDIR/bind9-source" "$WORKDIR/dnsmasq-source"
mkdir -p "$WORKDIR/unbound-source"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"
RUN_ROOT="$WORKDIR/run"
SAMPLE_FILE="$WORKDIR/sample.bin"

write_fake_bind9_binary "$BIND9_BIN"
write_fake_unbound_binary "$UNBOUND_BIN"
write_fake_dnsmasq_binary "$DNSMASQ_BIN"
write_fake_dnsmasq_harness "$DNSMASQ_HARNESS"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
mkdir -p "$RESPONSE_CORPUS_DIR"

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
	AFL_TREE="$UNBOUND_BUILD" \
	DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
	RESPONSE_CORPUS_DIR="$RESPONSE_CORPUS_DIR" \
	UNBOUND_SRC_TREE="$WORKDIR/unbound-source" \
	"$DNSLABCTL_BIN" sync-replay \
		--sample "$SAMPLE_FILE" \
		--run-root "$RUN_ROOT" \
		--bind9-build-root "$BIND9_TREE" \
		--secondary-resolver dnsmasq \
		--secondary-build-root "$DNSMASQ_BUILD" \
		--bind9-source-root "$WORKDIR/bind9-source" \
		--secondary-source-root "$WORKDIR/dnsmasq-source" \
		--unbound-build-root "$DNSMASQ_BUILD" \
		--resolvers bind9,unbound,dnsmasq \
		>"$WORKDIR/sync-replay.json"

assert_file_exists "$WORKDIR/sync-replay.json"
assert_file_exists "$RUN_ROOT/sample.meta.json"
assert_file_exists "$RUN_ROOT/oracle.json"
assert_file_exists "$RUN_ROOT/bind9/bind9.stderr"
assert_file_exists "$RUN_ROOT/unbound/unbound.stderr"
assert_file_exists "$RUN_ROOT/dnsmasq/dnsmasq.stderr"
assert_file_exists "$RUN_ROOT/dnsmasq/dnsmasq.after.cache.txt"

python3 - "$WORKDIR/sync-replay.json" "$RUN_ROOT/sample.meta.json" "$RUN_ROOT/oracle.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
sample_meta = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
oracle_doc = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
if payload.get("secondary_resolver") != "dnsmasq":
    raise SystemExit(f"ASSERT FAIL: secondary_resolver={payload.get('secondary_resolver')!r} != 'dnsmasq'")
if "dnsmasq" not in payload:
    raise SystemExit("ASSERT FAIL: sync-replay 输出缺少 dnsmasq 键")
resolvers = payload.get("resolvers")
if not isinstance(resolvers, dict):
    raise SystemExit(f"ASSERT FAIL: resolvers={resolvers!r} 应为对象")
for resolver in ("bind9", "unbound", "dnsmasq"):
    if resolver not in resolvers:
        raise SystemExit(f"ASSERT FAIL: resolvers 缺少 {resolver}: {resolvers!r}")
executed = payload.get("executed_resolvers")
if executed != ["bind9", "dnsmasq", "unbound"] and executed != ["bind9", "unbound", "dnsmasq"]:
    raise SystemExit(f"ASSERT FAIL: executed_resolvers={executed!r}")
if payload.get("diff_detected") is not True:
    raise SystemExit(f"ASSERT FAIL: diff_detected={payload.get('diff_detected')!r} != True")
resolver_diffs = payload.get("resolver_diffs")
if not isinstance(resolver_diffs, list) or not resolver_diffs:
    raise SystemExit(f"ASSERT FAIL: resolver_diffs={resolver_diffs!r}")
if sample_meta.get("executed_resolvers") != executed:
    raise SystemExit(f"ASSERT FAIL: sample.meta.executed_resolvers={sample_meta.get('executed_resolvers')!r}")
if sample_meta.get("diff_detected") is not True:
    raise SystemExit(f"ASSERT FAIL: sample.meta.diff_detected={sample_meta.get('diff_detected')!r}")
meta_diffs = sample_meta.get("resolver_diffs")
if not isinstance(meta_diffs, list) or not meta_diffs:
    raise SystemExit(f"ASSERT FAIL: sample.meta.resolver_diffs={meta_diffs!r}")
artifacts = sample_meta.get("artifacts", {})
for key, expected in {
    "bind9_stderr": "bind9/bind9.stderr",
    "unbound_stderr": "unbound/unbound.stderr",
    "dnsmasq_stderr": "dnsmasq/dnsmasq.stderr",
}.items():
    if artifacts.get(key) != expected:
        raise SystemExit(f"ASSERT FAIL: sample.meta.artifacts[{key!r}]={artifacts.get(key)!r} != {expected!r}")
if oracle_doc.get("executed_resolvers") != executed:
    raise SystemExit(f"ASSERT FAIL: oracle.executed_resolvers={oracle_doc.get('executed_resolvers')!r}")
if oracle_doc.get("diff_detected") is not True:
    raise SystemExit(f"ASSERT FAIL: oracle.diff_detected={oracle_doc.get('diff_detected')!r}")
oracle_resolvers = oracle_doc.get("resolvers")
if not isinstance(oracle_resolvers, dict) or "unbound" not in oracle_resolvers:
    raise SystemExit(f"ASSERT FAIL: oracle.resolvers={oracle_resolvers!r}")
resolver_payload = payload["dnsmasq"]
if resolver_payload.get("run_sample_exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: dnsmasq.run_sample_exit_code={resolver_payload.get('run_sample_exit_code')!r} != 0")
oracle = resolver_payload.get("oracle")
if not isinstance(oracle, dict):
    raise SystemExit("ASSERT FAIL: dnsmasq.oracle 应为对象")
for field in (
    "dnsmasq.parse_ok",
    "dnsmasq.response_accepted",
    "dnsmasq.second_query_hit",
    "dnsmasq.cache_entry_created",
):
    if oracle.get(field) is not True:
        raise SystemExit(f"ASSERT FAIL: {field}={oracle.get(field)!r} != True")
PY

printf 'PASS: dnslabctl sync-replay secondary regression test passed\n'
