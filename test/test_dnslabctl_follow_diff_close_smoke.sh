#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-follow-diff-close.XXXXXX")"
ROOT_ENV="$WORKDIR/root"
QUEUE_DIR="$WORKDIR/bind9-work/afl_out/master/queue"
WORK_STATEFUL="$WORKDIR/work"

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
BIND9_SRC="$WORKDIR/bind9-src"
DNSMASQ_BUILD="$WORKDIR/dnsmasq-build"
DNSMASQ_BIN="$DNSMASQ_BUILD/dnsmasq"
DNSMASQ_SRC="$WORKDIR/dnsmasq-src"
DNSMASQ_HARNESS="$WORKDIR/dnsmasq-harness.py"
NAMED_CONF_TEMPLATE="$ROOT_ENV/named_experiment/runtime/named.conf"
RESPONSE_CORPUS_DIR="$ROOT_ENV/named_experiment/work/response_corpus"
SAMPLE_FILE="$QUEUE_DIR/id:000001,orig:seed"
WINDOW_STDOUT="$WORKDIR/follow-diff-window.stdout.json"
CAMPAIGN_STDOUT="$WORKDIR/campaign-close.stdout.json"
STATE_FILE="$WORK_STATEFUL/follow_diff.state.json"
WINDOW_SUMMARY="$WORK_STATEFUL/follow_diff.window.summary.json"
CAMPAIGN_SUMMARY="$WORK_STATEFUL/campaign_close.summary.json"
FOLLOW_ROOT="$WORK_STATEFUL/follow_diff"

mkdir -p \
	"$QUEUE_DIR" \
	"$BIND9_SRC" \
	"$DNSMASQ_SRC" \
	"$RESPONSE_CORPUS_DIR" \
	"$ROOT_ENV/named_experiment/runtime"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
printf 'seed\n' >"$RESPONSE_CORPUS_DIR/seed.txt"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_dnsmasq_binary "$DNSMASQ_BIN"
write_fake_dnsmasq_harness "$DNSMASQ_HARNESS"

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
	DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
	ROOT_DIR="$ROOT_ENV" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
	BIND9_AFL_TREE="$BIND9_TREE" \
	BIND9_SRC_TREE="$BIND9_SRC" \
	DNSMASQ_BUILD_TREE="$DNSMASQ_BUILD" \
	DNSMASQ_SRC_TREE="$DNSMASQ_SRC" \
	FOLLOW_DIFF_INTERVAL_SEC=0.1 \
	FOLLOW_DIFF_WINDOW_IDLE_ROUNDS=1 \
	"$DNSLABCTL_BIN" follow-diff-window --budget-sec 2 >"$WINDOW_STDOUT"

assert_file_exists "$WINDOW_STDOUT"
assert_file_exists "$STATE_FILE"
assert_file_exists "$WINDOW_SUMMARY"
assert_dir_exists "$FOLLOW_ROOT"

SAMPLE_DIR="$(find "$FOLLOW_ROOT" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
assert_file_exists "$SAMPLE_DIR/sample.meta.json"
assert_file_exists "$SAMPLE_DIR/oracle.json"
assert_file_exists "$SAMPLE_DIR/cache_diff.json"
assert_file_exists "$SAMPLE_DIR/triage.json"

python3 - "$WINDOW_STDOUT" "$WINDOW_SUMMARY" "$STATE_FILE" "$SAMPLE_FILE" <<'PY'
import json
import pathlib
import sys

stdout_path, summary_path, state_path, sample_path = map(pathlib.Path, sys.argv[1:5])
stdout_payload = json.loads(stdout_path.read_text(encoding="utf-8"))
summary = json.loads(summary_path.read_text(encoding="utf-8"))
state = json.loads(state_path.read_text(encoding="utf-8"))
queue_tail_id = sample_path.name

if stdout_payload.get("exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: follow-diff-window stdout exit_code={stdout_payload.get('exit_code')!r}")
if stdout_payload.get("exit_reason") != "quiescent":
    raise SystemExit(f"ASSERT FAIL: follow-diff-window stdout exit_reason={stdout_payload.get('exit_reason')!r}")
if summary.get("exit_reason") != "quiescent":
    raise SystemExit(f"ASSERT FAIL: window summary exit_reason={summary.get('exit_reason')!r}")
if summary.get("exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: window summary exit_code={summary.get('exit_code')!r}")
if summary.get("queue_tail_id") != queue_tail_id:
    raise SystemExit(f"ASSERT FAIL: queue_tail_id={summary.get('queue_tail_id')!r} != {queue_tail_id!r}")
if summary.get("completed_count", 0) < 1:
    raise SystemExit(f"ASSERT FAIL: completed_count={summary.get('completed_count')!r}")
if not summary.get("run_id"):
    raise SystemExit("ASSERT FAIL: run_id 应为非空字符串")
if state.get("last_exit_reason") != "quiescent":
    raise SystemExit(f"ASSERT FAIL: state.last_exit_reason={state.get('last_exit_reason')!r}")
if state.get("last_queue_event_id") != queue_tail_id:
    raise SystemExit(f"ASSERT FAIL: state.last_queue_event_id={state.get('last_queue_event_id')!r}")
PY

env \
	DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
	ROOT_DIR="$ROOT_ENV" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
	BIND9_AFL_TREE="$BIND9_TREE" \
	BIND9_SRC_TREE="$BIND9_SRC" \
	DNSMASQ_BUILD_TREE="$DNSMASQ_BUILD" \
	DNSMASQ_SRC_TREE="$DNSMASQ_SRC" \
	FOLLOW_DIFF_INTERVAL_SEC=0.1 \
	FOLLOW_DIFF_WINDOW_IDLE_ROUNDS=1 \
	"$DNSLABCTL_BIN" campaign-close --budget-sec 2 >"$CAMPAIGN_STDOUT"

assert_file_exists "$CAMPAIGN_STDOUT"
assert_file_exists "$CAMPAIGN_SUMMARY"
assert_file_exists "$FOLLOW_ROOT/cluster_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/status_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/high_value_samples.txt"
assert_file_exists "$FOLLOW_ROOT/semantic_frontier_manifest.json"
assert_file_exists "$FOLLOW_ROOT/triage_report.md"

python3 - "$CAMPAIGN_STDOUT" "$CAMPAIGN_SUMMARY" <<'PY'
import json
import pathlib
import sys

stdout_path, summary_path = map(pathlib.Path, sys.argv[1:3])
stdout_payload = json.loads(stdout_path.read_text(encoding="utf-8"))
summary = json.loads(summary_path.read_text(encoding="utf-8"))

if stdout_payload.get("exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: campaign-close stdout exit_code={stdout_payload.get('exit_code')!r}")
if summary.get("status") != "completed":
    raise SystemExit(f"ASSERT FAIL: campaign_close.status={summary.get('status')!r}")
if summary.get("exit_reason") != "completed":
    raise SystemExit(f"ASSERT FAIL: campaign_close.exit_reason={summary.get('exit_reason')!r}")
for phase in ("follow-diff-window", "triage-report", "campaign-report"):
    phase_payload = (summary.get("phases") or {}).get(phase) or {}
    if phase_payload.get("status") != "completed":
        raise SystemExit(f"ASSERT FAIL: phase {phase} status={phase_payload.get('status')!r}")
metric_denominators = summary.get("metric_denominators") or {}
if metric_denominators.get("sample_count", 0) < 1:
    raise SystemExit(f"ASSERT FAIL: sample_count={metric_denominators.get('sample_count')!r}")
triage_report = ((summary.get("phase_context") or {}).get("triage_report")) or {}
if not triage_report.get("root"):
    raise SystemExit("ASSERT FAIL: phase_context.triage_report.root 缺失")
PY

printf 'PASS: dnslabctl follow-diff/campaign-close smoke test passed\n'
