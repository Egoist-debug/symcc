#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-sync-replay-knot.XXXXXX")"

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

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
KNOT_BUILD="$WORKDIR/knot-build"
KNOT_BIN="$KNOT_BUILD/knot-build/daemon/kresd"
KNOT_HARNESS="$WORKDIR/knot-harness.py"
mkdir -p "$WORKDIR/bind9-source" "$WORKDIR/knot-source"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"
RUN_ROOT="$WORKDIR/run"
SAMPLE_FILE="$WORKDIR/sample.bin"

write_fake_bind9_binary "$BIND9_BIN"
write_fake_knot_binary "$KNOT_BIN"
write_fake_knot_harness "$KNOT_HARNESS"
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
	KNOT_RESOLVER_HARNESS_SCRIPT="$KNOT_HARNESS" \
	"$DNSLABCTL_BIN" sync-replay \
		--sample "$SAMPLE_FILE" \
		--run-root "$RUN_ROOT" \
		--bind9-build-root "$BIND9_TREE" \
		--secondary-resolver knot-resolver \
		--secondary-build-root "$KNOT_BUILD" \
		--bind9-source-root "$WORKDIR/bind9-source" \
		--secondary-source-root "$WORKDIR/knot-source" \
		--unbound-build-root "$KNOT_BUILD" \
		>"$WORKDIR/sync-replay.json"

assert_file_exists "$WORKDIR/sync-replay.json"
assert_file_exists "$RUN_ROOT/bind9/bind9.stderr"
assert_file_exists "$RUN_ROOT/knot-resolver/knot-resolver.stderr"
assert_file_exists "$RUN_ROOT/knot-resolver/knot-resolver.after.cache.txt"

python3 - "$WORKDIR/sync-replay.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("secondary_resolver") != "knot-resolver":
    raise SystemExit(f"ASSERT FAIL: secondary_resolver={payload.get('secondary_resolver')!r} != 'knot-resolver'")
if "knot-resolver" not in payload:
    raise SystemExit("ASSERT FAIL: sync-replay 输出缺少 knot-resolver 键")
resolver_payload = payload["knot-resolver"]
if resolver_payload.get("run_sample_exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: knot-resolver.run_sample_exit_code={resolver_payload.get('run_sample_exit_code')!r} != 0")
oracle = resolver_payload.get("oracle")
if not isinstance(oracle, dict):
    raise SystemExit("ASSERT FAIL: knot-resolver.oracle 应为对象")
for field in (
    "knot-resolver.parse_ok",
    "knot-resolver.response_accepted",
    "knot-resolver.second_query_hit",
    "knot-resolver.cache_entry_created",
):
    if oracle.get(field) is not True:
        raise SystemExit(f"ASSERT FAIL: {field}={oracle.get(field)!r} != True")
PY

printf 'PASS: dnslabctl sync-replay secondary knot regression test passed\n'
