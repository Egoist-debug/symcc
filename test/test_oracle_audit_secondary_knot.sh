#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-oracle-audit-knot.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sample_dir = root / "sample-knot"
sample_dir.mkdir(parents=True, exist_ok=True)

def write_json(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")

write_json(
    sample_dir / "sample.meta.json",
    {
        "schema_version": 1,
        "generated_at": "2026-05-10T00:00:00Z",
        "sample_id": "sample-knot",
        "artifacts": {
            "sample_bin": "sample.bin",
            "bind9_stderr": "bind9.stderr",
            "knot-resolver_stderr": "knot-resolver.stderr",
            "bind9_before_cache": "bind9.before.cache.txt",
            "bind9_after_cache": "bind9.after.cache.txt",
            "knot-resolver_before_cache": "knot-resolver.before.cache.txt",
            "knot-resolver_after_cache": "knot-resolver.after.cache.txt",
            "oracle": "oracle.json",
        },
    },
)
write_json(
    sample_dir / "triage.json",
    {
        "schema_version": 1,
        "generated_at": "2026-05-10T00:00:00Z",
        "sample_id": "sample-knot",
        "status": "completed_oracle_diff",
        "analysis_state": "included",
        "semantic_outcome": "oracle_diff",
        "oracle_audit_candidate": True,
        "manual_truth_status": "not_started",
    },
)
write_json(
    sample_dir / "oracle.json",
    {
        "bind9.parse_ok": True,
        "knot-resolver.parse_ok": False,
        "bind9.response_accepted": True,
        "knot-resolver.response_accepted": True,
        "bind9.second_query_hit": False,
        "knot-resolver.second_query_hit": True,
        "bind9.cache_entry_created": False,
        "knot-resolver.cache_entry_created": True,
        "bind9.resolver_fetch_started": True,
        "knot-resolver.resolver_fetch_started": True,
        "bind9.timeout": False,
        "knot-resolver.timeout": False,
        "bind9.stderr_parse_status": "ok",
        "knot-resolver.stderr_parse_status": "ok",
    },
)
write_json(
    sample_dir / "cache_diff.json",
    {
        "bind9": {"has_cache_diff": False},
        "knot-resolver": {"has_cache_diff": True},
    },
)
PY

PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	python3 -m tools.dns_diff.cli campaign-report --root "$FOLLOW_ROOT" >/dev/null

REPORT_DIR="$(python3 - "$FOLLOW_ROOT/campaign_reports" <<'PY'
from pathlib import Path
import sys
dirs = sorted(path for path in Path(sys.argv[1]).iterdir() if path.is_dir())
print(dirs[-1])
PY
)"

python3 - "$REPORT_DIR/oracle_audit.tsv" "$REPORT_DIR/oracle_reliability.json" <<'PY'
import csv
import json
import pathlib
import sys

audit_path = pathlib.Path(sys.argv[1])
rows = list(csv.DictReader(audit_path.open(encoding="utf-8"), delimiter="\t"))
if len(rows) != 1:
    raise SystemExit(f"ASSERT FAIL: 期望 1 条 audit 记录，实际 {len(rows)}")
row = rows[0]
if row["sample_id"] != "sample-knot":
    raise SystemExit(f"ASSERT FAIL: sample_id={row['sample_id']!r}")
if row["unbound.parse_ok"] != "false":
    raise SystemExit(f"ASSERT FAIL: secondary parse_ok 未映射到列: {row['unbound.parse_ok']!r}")
if row["unbound.second_query_hit"] != "true":
    raise SystemExit(f"ASSERT FAIL: secondary second_query_hit 未映射到列: {row['unbound.second_query_hit']!r}")
if row["oracle_diff_fields"] != "parse_ok,second_query_hit,cache_entry_created":
    raise SystemExit(f"ASSERT FAIL: oracle_diff_fields={row['oracle_diff_fields']!r}")

payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
signals = payload["signals"]
if signals["oracle_diff_any"]["eligible_count"] != 1:
    raise SystemExit("ASSERT FAIL: oracle_diff_any.eligible_count 应为 1")
PY

printf 'PASS: oracle audit secondary knot regression test passed\n'
