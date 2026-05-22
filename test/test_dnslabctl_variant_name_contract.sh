#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-variant-name.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

write_fake_bind9_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("""#!/usr/bin/env python3
import os
import pathlib
import sys
dump_path = os.environ["NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"]
pathlib.Path(dump_path).write_text(";\\n; Cache dump\\n;\\nexample.com. 299 IN A 1.2.3.4\\n", encoding="utf-8")
sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
sys.exit(0)
""", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_dnsmasq_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_dnsmasq_harness() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("""#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--dnsmasq-stderr-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--dnsmasq-bin')
args = parser.parse_args()
Path(args.cache_dump_path).write_text('example.com. 1.2.3.4\\n', encoding='utf-8')
Path(args.dnsmasq_stderr_path).write_text('dnsmasq\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

assert_variant() {
	local variant_name="$1"
	local mutator="$2"
	local cache_delta="$3"
	local symcc="$4"
	local run_root="$WORKDIR/$variant_name"
	local bind9_tree="$WORKDIR/bind9-afl"
	local bind9_src="$WORKDIR/bind9-src"
	local dnsmasq_build="$WORKDIR/dnsmasq-build"
	local dnsmasq_src="$WORKDIR/dnsmasq-src"
	local dnsmasq_harness="$WORKDIR/dnsmasq-harness.py"
	local queue_dir="$run_root/bind9-work/afl_out/master/queue"
	local sample_file="$queue_dir/id:000001,orig:seed"
	mkdir -p "$queue_dir" "$WORKDIR/named_experiment/runtime" "$WORKDIR/named_experiment/work/response_corpus"
	printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$WORKDIR/named_experiment/runtime/named.conf"
	printf 'seed\n' >"$WORKDIR/named_experiment/work/response_corpus/seed.txt"
	write_fake_bind9_binary "$bind9_tree/bin/named/.libs/named"
	write_fake_dnsmasq_binary "$dnsmasq_build/dnsmasq"
	write_fake_dnsmasq_harness "$dnsmasq_harness"
	python3 - "$sample_file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
response = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04'
post = query
wire = bytearray(b'DST1')
wire += bytes([1, 2])
wire += len(query).to_bytes(2, 'little')
wire += len(response).to_bytes(2, 'little')
wire += query + response + post
path.write_bytes(wire)
PY
	env \
		DNSMASQ_HARNESS_SCRIPT="$dnsmasq_harness" \
		ROOT_DIR="$ROOT_DIR" \
		WORK_DIR="$run_root/work" \
		BIND9_WORK_DIR="$run_root/bind9-work" \
		DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
		DNSLABCTL_BIN="$DNSLABCTL_BIN" \
		BIND9_AFL_TREE="$bind9_tree" \
		BIND9_SRC_TREE="$bind9_src" \
		BIND9_NAMED_CONF_TEMPLATE="$WORKDIR/named_experiment/runtime/named.conf" \
		RESPONSE_CORPUS_DIR="$WORKDIR/named_experiment/work/response_corpus" \
		DNSMASQ_BUILD_TREE="$dnsmasq_build" \
		DNSMASQ_SRC_TREE="$dnsmasq_src" \
		ENABLE_DST1_MUTATOR="$mutator" \
		ENABLE_CACHE_DELTA="$cache_delta" \
		ENABLE_TRIAGE=1 \
		ENABLE_SYMCC="$symcc" \
		FOLLOW_DIFF_INTERVAL_SEC=0.1 \
		FOLLOW_DIFF_WINDOW_IDLE_ROUNDS=1 \
		"$DNSLABCTL_BIN" campaign-close --budget-sec 2 >/dev/null || true
	local sample_dir
	sample_dir="$(find "$run_root/work/follow_diff" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
	python3 - "$sample_dir/sample.meta.json" "$variant_name" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
variant_name = sys.argv[2]
value = payload.get('aggregation_key', {}).get('variant_name')
if value != variant_name:
    raise SystemExit(f"ASSERT FAIL: variant_name={value!r} != {variant_name!r}")
PY
}

assert_variant full_stack 1 1 1
assert_variant afl_only 1 1 0
assert_variant no_mutator 0 1 1
assert_variant no_cache_delta 1 0 1

printf 'PASS: dnslabctl variant_name contract test passed\n'
