#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-campaign-secondary-maradns.XXXXXX")"
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

write_fake_maradns_binary() {
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

write_fake_maradns_harness() {
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
parser.add_argument('--maradns-log-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--deadwood-bin')
args = parser.parse_args()
Path(args.cache_dump_path).write_text('MARADNS_CACHE_DUMP\\nCACHE_ENTRY\\texample.com\\tA\\t_\\n', encoding='utf-8')
Path(args.maradns_log_path).write_text('maradns-native\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
MARADNS_BUILD="$WORKDIR/maradns-build"
MARADNS_BIN="$MARADNS_BUILD/deadwood-build/deadwood-github/src/Deadwood"
MARADNS_HARNESS="$WORKDIR/maradns-harness.py"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"
SAMPLE_FILE="$QUEUE_DIR/id:000001,orig:seed"

mkdir -p "$QUEUE_DIR"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_maradns_binary "$MARADNS_BIN"
write_fake_maradns_harness "$MARADNS_HARNESS"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
printf '\x01\x02\x03\x04' >"$SAMPLE_FILE"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORK_STATEFUL" \
	BIND9_WORK_DIR="$WORKDIR/bind9-work" \
	DNS_DIFF_SECONDARY_RESOLVER=maradns \
	FOLLOW_DIFF_INTERVAL_SEC=0.1 \
	BIND9_AFL_TREE="$BIND9_TREE" \
	MARADNS_BUILD_TREE="$MARADNS_BUILD" \
	MARADNS_HARNESS_SCRIPT="$MARADNS_HARNESS" \
	BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
	python3 -m tools.dns_diff.cli follow-diff-window --budget-sec 5 >/dev/null

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	WORK_DIR="$WORK_STATEFUL" \
	DNS_DIFF_SECONDARY_RESOLVER=maradns \
	python3 -m tools.dns_diff.cli campaign-report --root "$WORK_STATEFUL/follow_diff" >/dev/null

REPORT_DIR="$(python3 - "$WORK_STATEFUL/follow_diff/campaign_reports" <<'PY'
from pathlib import Path
import sys
dirs = sorted(path for path in Path(sys.argv[1]).iterdir() if path.is_dir())
print(dirs[-1])
PY
)"

assert_file_exists "$REPORT_DIR/summary.json"
assert_file_exists "$REPORT_DIR/oracle_audit.tsv"
assert_file_exists "$REPORT_DIR/evidence_bundle.json"

python3 - "$REPORT_DIR/summary.json" "$REPORT_DIR/oracle_audit.tsv" "$REPORT_DIR/evidence_bundle.json" <<'PY'
import csv
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
audit_rows = list(csv.DictReader(pathlib.Path(sys.argv[2]).open(encoding="utf-8"), delimiter="\t"))
bundle = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))

comparability = summary.get("comparability") or {}
if comparability.get("aggregation_key", {}).get("resolver_pair") != "bind9_vs_maradns":
    raise SystemExit(f"ASSERT FAIL: summary.comparability.aggregation_key.resolver_pair={comparability.get('aggregation_key', {}).get('resolver_pair')!r}")
if comparability.get("baseline_compare_key", {}).get("resolver_pair") != "bind9_vs_maradns":
    raise SystemExit(f"ASSERT FAIL: summary.comparability.baseline_compare_key.resolver_pair={comparability.get('baseline_compare_key', {}).get('resolver_pair')!r}")
if len(audit_rows) != 1:
    raise SystemExit(f"ASSERT FAIL: 期望 1 条 oracle_audit 记录，实际 {len(audit_rows)}")
row = audit_rows[0]
if row["unbound.parse_ok"] != "true":
    raise SystemExit(f"ASSERT FAIL: secondary parse_ok 未映射到 audit 列: {row['unbound.parse_ok']!r}")
artifacts = bundle["raw_sample_root"]["claim_review_artifacts"]
if "maradns.stderr" not in artifacts:
    raise SystemExit(f"ASSERT FAIL: evidence bundle 缺少 maradns.stderr: {artifacts!r}")
PY

printf 'PASS: campaign secondary maradns smoke test passed\n'
