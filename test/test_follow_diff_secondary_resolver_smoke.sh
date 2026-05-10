#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-follow-diff-secondary.XXXXXX")"
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
SAMPLE_FILE="$QUEUE_DIR/id:000001,orig:seed"

mkdir -p "$QUEUE_DIR"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_dnsmasq_binary "$DNSMASQ_BIN"
write_fake_dnsmasq_harness "$DNSMASQ_HARNESS"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
printf '\x01\x02\x03\x04' >"$SAMPLE_FILE"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
	BIND9_AFL_TREE="$BIND9_TREE" \
	DNSMASQ_BUILD_TREE="$DNSMASQ_BUILD" \
	DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
	BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
	python3 -m tools.dns_diff.cli follow-diff-once >/dev/null

SAMPLE_DIR="$(find "$WORK_STATEFUL/follow_diff" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
assert_file_exists "$SAMPLE_DIR/sample.meta.json"
assert_file_exists "$SAMPLE_DIR/oracle.json"
assert_file_exists "$SAMPLE_DIR/cache_diff.json"
assert_file_exists "$SAMPLE_DIR/triage.json"

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
if artifacts.get("dnsmasq_stderr") != "dnsmasq.stderr":
    raise SystemExit(f"ASSERT FAIL: sample.meta.artifacts 未保留 dnsmasq stderr: {artifacts!r}")
if oracle.get("dnsmasq.parse_ok") is not True:
    raise SystemExit(f"ASSERT FAIL: oracle 缺少 dnsmasq.parse_ok: {oracle!r}")
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
	DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
	python3 - <<'PY'
from tools.dns_diff.follow_diff import _build_follow_diff_comparability_keys, _collect_config

config = _collect_config()
aggregation_key, baseline_compare_key = _build_follow_diff_comparability_keys(config, budget_sec=5)
if aggregation_key.get("resolver_pair") != "bind9_vs_dnsmasq":
    raise SystemExit(f"ASSERT FAIL: aggregation_key.resolver_pair={aggregation_key.get('resolver_pair')!r}")
if baseline_compare_key.get("resolver_pair") != "bind9_vs_dnsmasq":
    raise SystemExit(f"ASSERT FAIL: baseline_compare_key.resolver_pair={baseline_compare_key.get('resolver_pair')!r}")
PY

printf 'PASS: follow diff secondary resolver smoke test passed\n'
