#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-oracle-audit-report.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow"
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

run_cli() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		ENABLE_DST1_MUTATOR=0 \
		ENABLE_CACHE_DELTA=1 \
		ENABLE_TRIAGE=1 \
		ENABLE_SYMCC=1 \
		python3 -m tools.dns_diff.cli "$@"
}

get_latest_report_dir() {
	local report_base="$1"
	python3 - "$report_base" <<'PY'
from pathlib import Path
import sys

report_base = Path(sys.argv[1])
dirs = sorted(path for path in report_base.iterdir() if path.is_dir())
if not dirs:
    raise SystemExit(
        f"ASSERT FAIL: 期望 {report_base} 下至少有 1 个报告目录，实际为空"
    )
print(dirs[-1])
PY
}

python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


def triage(
    sample_id: str,
    *,
    status: str,
    analysis_state: str,
    semantic_outcome: str,
    oracle_audit_candidate: bool,
    manual_truth_status: str,
) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-03-24T00:00:00Z",
        "sample_id": sample_id,
        "status": status,
        "analysis_state": analysis_state,
        "semantic_outcome": semantic_outcome,
        "oracle_audit_candidate": oracle_audit_candidate,
        "manual_truth_status": manual_truth_status,
    }


def oracle(
    *,
    bind9_parse_ok: bool,
    unbound_parse_ok: bool,
    bind9_response_accepted: bool,
    unbound_response_accepted: bool,
    bind9_second_query_hit: bool,
    unbound_second_query_hit: bool,
    bind9_cache_entry_created: bool,
    unbound_cache_entry_created: bool,
) -> dict:
    return {
        "bind9.parse_ok": bind9_parse_ok,
        "unbound.parse_ok": unbound_parse_ok,
        "bind9.response_accepted": bind9_response_accepted,
        "unbound.response_accepted": unbound_response_accepted,
        "bind9.second_query_hit": bind9_second_query_hit,
        "unbound.second_query_hit": unbound_second_query_hit,
        "bind9.cache_entry_created": bind9_cache_entry_created,
        "unbound.cache_entry_created": unbound_cache_entry_created,
        "bind9.resolver_fetch_started": True,
        "unbound.resolver_fetch_started": True,
        "bind9.timeout": False,
        "unbound.timeout": False,
        "bind9.stderr_parse_status": "ok",
        "unbound.stderr_parse_status": "ok",
    }


def cache_diff(*, has_diff_bind9: bool, has_diff_unbound: bool) -> dict:
    return {
        "cache_delta_triggered": has_diff_bind9 or has_diff_unbound,
        "bind9": {"has_cache_diff": has_diff_bind9},
        "unbound": {"has_cache_diff": has_diff_unbound},
    }


fixtures = {
    "sample-a": {
        "triage.json": triage(
            "sample-a",
            status="completed_oracle_diff",
            analysis_state="included",
            semantic_outcome="oracle_and_cache_diff",
            oracle_audit_candidate=True,
            manual_truth_status="not_started",
        ),
        "oracle.json": oracle(
            bind9_parse_ok=True,
            unbound_parse_ok=False,
            bind9_response_accepted=True,
            unbound_response_accepted=True,
            bind9_second_query_hit=False,
            unbound_second_query_hit=False,
            bind9_cache_entry_created=False,
            unbound_cache_entry_created=False,
        ),
        "cache_diff.json": cache_diff(has_diff_bind9=True, has_diff_unbound=False),
    },
    "sample-b": {
        "triage.json": triage(
            "sample-b",
            status="completed_cache_changed_needs_review",
            analysis_state="included",
            semantic_outcome="cache_diff_interesting",
            oracle_audit_candidate=True,
            manual_truth_status="not_started",
        ),
        "oracle.json": oracle(
            bind9_parse_ok=True,
            unbound_parse_ok=True,
            bind9_response_accepted=False,
            unbound_response_accepted=False,
            bind9_second_query_hit=True,
            unbound_second_query_hit=False,
            bind9_cache_entry_created=False,
            unbound_cache_entry_created=False,
        ),
        "cache_diff.json": cache_diff(has_diff_bind9=True, has_diff_unbound=False),
    },
    "sample-c": {
        "triage.json": triage(
            "sample-c",
            status="completed_no_diff",
            analysis_state="included",
            semantic_outcome="no_diff",
            oracle_audit_candidate=False,
            manual_truth_status="not_applicable",
        ),
        "oracle.json": oracle(
            bind9_parse_ok=True,
            unbound_parse_ok=True,
            bind9_response_accepted=False,
            unbound_response_accepted=False,
            bind9_second_query_hit=False,
            unbound_second_query_hit=False,
            bind9_cache_entry_created=False,
            unbound_cache_entry_created=True,
        ),
        "cache_diff.json": cache_diff(has_diff_bind9=False, has_diff_unbound=False),
    },
    "sample-d": {
        "triage.json": triage(
            "sample-d",
            status="failed_parse",
            analysis_state="unknown",
            semantic_outcome="runtime_or_parse_failure",
            oracle_audit_candidate=False,
            manual_truth_status="not_applicable",
        ),
        "oracle.json": oracle(
            bind9_parse_ok=True,
            unbound_parse_ok=True,
            bind9_response_accepted=True,
            unbound_response_accepted=False,
            bind9_second_query_hit=False,
            unbound_second_query_hit=False,
            bind9_cache_entry_created=False,
            unbound_cache_entry_created=False,
        ),
        "cache_diff.json": cache_diff(has_diff_bind9=False, has_diff_unbound=False),
    },
}

for sample_id, artifacts in fixtures.items():
    sample_dir = root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        sample_dir / "sample.meta.json",
        {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": sample_id,
            "contract_version": 1,
        },
    )
    for filename, payload in artifacts.items():
        write_json(sample_dir / filename, payload)
PY

run_cli campaign-report --root "$FOLLOW_ROOT" >/dev/null
REPORT_DIR="$(get_latest_report_dir "$FOLLOW_ROOT/campaign_reports")"

assert_file_exists "$REPORT_DIR/oracle_audit.tsv"
assert_file_exists "$REPORT_DIR/oracle_reliability.json"

python3 - "$REPORT_DIR/oracle_audit.tsv" "$FOLLOW_ROOT" <<'PY'
import csv
import pathlib
import sys

audit_path = pathlib.Path(sys.argv[1])
follow_root = pathlib.Path(sys.argv[2]).resolve()

expected_columns = [
    "sample_id",
    "triage_status",
    "analysis_state",
    "semantic_outcome",
    "oracle_audit_candidate",
    "manual_truth_status",
    "bind9.parse_ok",
    "unbound.parse_ok",
    "bind9.response_accepted",
    "unbound.response_accepted",
    "bind9.second_query_hit",
    "unbound.second_query_hit",
    "bind9.cache_entry_created",
    "unbound.cache_entry_created",
    "oracle_diff_fields",
    "sample_meta_path",
    "oracle_path",
    "cache_diff_path",
    "triage_path",
]

with audit_path.open(encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    if reader.fieldnames != expected_columns:
        raise SystemExit(
            "ASSERT FAIL: oracle_audit.tsv 列顺序不符合预期:\n"
            f"actual={reader.fieldnames!r}\nexpected={expected_columns!r}"
        )
    rows = list(reader)

if len(rows) != 4:
    raise SystemExit(f"ASSERT FAIL: oracle_audit.tsv 期望 4 行样本，实际 {len(rows)}")

rows_by_id = {row["sample_id"]: row for row in rows}
if set(rows_by_id.keys()) != {"sample-a", "sample-b", "sample-c", "sample-d"}:
    raise SystemExit(f"ASSERT FAIL: sample_id 集合异常: {set(rows_by_id.keys())!r}")

sample_a = rows_by_id["sample-a"]
if sample_a["oracle_diff_fields"] != "parse_ok":
    raise SystemExit(
        f"ASSERT FAIL: sample-a oracle_diff_fields={sample_a['oracle_diff_fields']!r} != 'parse_ok'"
    )
if sample_a["oracle_audit_candidate"] != "true":
    raise SystemExit(
        f"ASSERT FAIL: sample-a oracle_audit_candidate={sample_a['oracle_audit_candidate']!r}"
    )
if sample_a["manual_truth_status"] != "not_started":
    raise SystemExit(
        f"ASSERT FAIL: sample-a manual_truth_status={sample_a['manual_truth_status']!r}"
    )

sample_c = rows_by_id["sample-c"]
if sample_c["oracle_diff_fields"] != "cache_entry_created":
    raise SystemExit(
        "ASSERT FAIL: sample-c oracle_diff_fields="
        f"{sample_c['oracle_diff_fields']!r} != 'cache_entry_created'"
    )

for sample_id, row in rows_by_id.items():
    expected_files = {
        "sample_meta_path": "sample.meta.json",
        "oracle_path": "oracle.json",
        "cache_diff_path": "cache_diff.json",
        "triage_path": "triage.json",
    }
    for key, filename in expected_files.items():
        actual = pathlib.Path(row[key]).resolve()
        expected = (follow_root / sample_id / filename).resolve()
        if actual != expected:
            raise SystemExit(
                f"ASSERT FAIL: {sample_id}.{key}={actual!s} != {expected!s}"
            )
PY

python3 - "$REPORT_DIR/oracle_reliability.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

expected = {
    "signals": {
        "response_accepted_any": {
            "eligible_count": 1,
            "pending_manual_count": 1,
            "judged_count": 0,
            "confirmed_relevant_count": 0,
            "false_positive_count": 0,
            "inconclusive_count": 0,
        },
        "second_query_hit_any": {
            "eligible_count": 1,
            "pending_manual_count": 1,
            "judged_count": 0,
            "confirmed_relevant_count": 0,
            "false_positive_count": 0,
            "inconclusive_count": 0,
        },
        "cache_entry_created_any": {
            "eligible_count": 0,
            "pending_manual_count": 0,
            "judged_count": 0,
            "confirmed_relevant_count": 0,
            "false_positive_count": 0,
            "inconclusive_count": 0,
        },
        "oracle_diff_any": {
            "eligible_count": 2,
            "pending_manual_count": 2,
            "judged_count": 0,
            "confirmed_relevant_count": 0,
            "false_positive_count": 0,
            "inconclusive_count": 0,
        },
    },
    "signal_combos": {
        "oracle_diff_plus_cache_diff": {
            "eligible_count": 2,
            "pending_manual_count": 2,
            "judged_count": 0,
            "confirmed_relevant_count": 0,
            "false_positive_count": 0,
            "inconclusive_count": 0,
        }
    },
}

if payload != expected:
    raise SystemExit(
        "ASSERT FAIL: oracle_reliability.json 与预期不一致:\n"
        f"actual={payload!r}\nexpected={expected!r}"
    )
PY

printf 'PASS: oracle audit campaign report regression test passed\n'
