#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-failure-taxonomy.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

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

write_fixtures() {
	python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1])
follow_root.mkdir(parents=True, exist_ok=True)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


def shared_meta(sample_id: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-03-24T00:00:00Z",
        "sample_id": sample_id,
    }


def fingerprint(sample_id: str) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "bind9.forwarding_path": "iterative",
            "bind9.retry_seen": False,
            "bind9.msg_cache_seen": False,
            "bind9.rrset_cache_seen": False,
            "bind9.negative_cache_seen": False,
            "unbound.forwarding_path": "iterative",
            "unbound.retry_seen": False,
            "unbound.msg_cache_seen": False,
            "unbound.rrset_cache_seen": False,
            "unbound.negative_cache_seen": False,
        }
    )
    return payload


def cache_empty(sample_id: str) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "cache_delta_triggered": False,
            "bind9": {
                "entries_before": 0,
                "entries_after": 0,
                "has_cache_diff": False,
                "interesting_delta_count": 0,
                "delta_items": [],
            },
            "unbound": {
                "entries_before": 0,
                "entries_after": 0,
                "has_cache_diff": False,
                "interesting_delta_count": 0,
                "delta_items": [],
            },
        }
    )
    return payload


def cache_benign(sample_id: str) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "cache_delta_triggered": False,
            "bind9": {
                "entries_before": 0,
                "entries_after": 1,
                "has_cache_diff": True,
                "interesting_delta_count": 0,
                "delta_items": [],
            },
            "unbound": {
                "entries_before": 0,
                "entries_after": 0,
                "has_cache_diff": False,
                "interesting_delta_count": 0,
                "delta_items": [],
            },
        }
    )
    return payload


fixtures = {
    "completed_no_diff": {
        "sample.meta.json": {**shared_meta("completed_no_diff"), "status": "completed"},
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": True,
            "bind9.response_accepted": True,
            "unbound.response_accepted": True,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
            "bind9.timeout": False,
            "unbound.timeout": False,
        },
        "cache_diff.json": cache_empty("completed_no_diff"),
        "state_fingerprint.json": fingerprint("completed_no_diff"),
    },
    "completed_cache_changed_but_benign": {
        "sample.meta.json": {
            **shared_meta("completed_cache_changed_but_benign"),
            "status": "completed",
        },
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": True,
            "bind9.response_accepted": True,
            "unbound.response_accepted": True,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
            "bind9.timeout": False,
            "unbound.timeout": False,
        },
        "cache_diff.json": cache_benign("completed_cache_changed_but_benign"),
        "state_fingerprint.json": fingerprint("completed_cache_changed_but_benign"),
    },
    "failed_parse": {
        "sample.meta.json": {**shared_meta("failed_parse"), "status": "completed"},
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "missing_summary",
        },
        "cache_diff.json": cache_empty("failed_parse"),
        "state_fingerprint.json": fingerprint("failed_parse"),
    },
    "failed_replay_missing_artifact": {
        "sample.meta.json": {
            **shared_meta("failed_replay_missing_artifact"),
            "status": "failed",
            "failure": {
                "kind": "replay_error",
                "reason": "missing_artifact",
                "message": "unbound.before 未生成有效文件: unbound.before.cache.txt",
                "stage": "unbound.before",
                "resolver": "unbound",
                "artifact_path": "unbound.before.cache.txt",
                "exit_code": 5,
            },
        },
        "oracle.json": {
            "bind9.stderr_parse_status": None,
            "unbound.stderr_parse_status": None,
        },
        "cache_diff.json": cache_empty("failed_replay_missing_artifact"),
        "state_fingerprint.json": fingerprint("failed_replay_missing_artifact"),
    },
    "failed_replay_subprocess_launch_error": {
        "sample.meta.json": {
            **shared_meta("failed_replay_subprocess_launch_error"),
            "status": "failed",
            "failure": {
                "kind": "replay_error",
                "reason": "subprocess_launch_error",
                "message": "子进程执行失败: [Errno 8] Exec format error",
                "stage": "unbound.before",
                "resolver": "unbound",
                "exit_code": 4,
            },
        },
        "oracle.json": {
            "bind9.stderr_parse_status": None,
            "unbound.stderr_parse_status": None,
        },
        "cache_diff.json": cache_empty("failed_replay_subprocess_launch_error"),
        "state_fingerprint.json": fingerprint("failed_replay_subprocess_launch_error"),
    },
    "failed_replay_timeout": {
        "sample.meta.json": {
            **shared_meta("failed_replay_timeout"),
            "status": "failed",
            "failure": {
                "kind": "replay_error",
                "reason": "timeout",
                "message": "unbound.before 超时，退出码=124",
                "stage": "unbound.before",
                "resolver": "unbound",
                "returncode": 124,
                "exit_code": 4,
            },
        },
        "oracle.json": {
            "bind9.stderr_parse_status": None,
            "unbound.stderr_parse_status": None,
        },
        "cache_diff.json": cache_empty("failed_replay_timeout"),
        "state_fingerprint.json": fingerprint("failed_replay_timeout"),
    },
    "oracle_diff": {
        "sample.meta.json": {**shared_meta("oracle_diff"), "status": "completed"},
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": False,
            "bind9.response_accepted": True,
            "unbound.response_accepted": True,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
            "bind9.timeout": False,
            "unbound.timeout": False,
        },
        "cache_diff.json": cache_empty("oracle_diff"),
        "state_fingerprint.json": fingerprint("oracle_diff"),
    },
}

for sample_id, files in fixtures.items():
    sample_dir = follow_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        write_json(sample_dir / name, payload)
PY
}

get_latest_report_dir() {
	local report_base="$1"
	python3 - "$report_base" <<'PY'
from pathlib import Path
import sys

report_base = Path(sys.argv[1])
dirs = sorted(path for path in report_base.iterdir() if path.is_dir())
if not dirs:
    raise SystemExit(f"ASSERT FAIL: 期望 {report_base} 下存在 campaign 报告目录")
print(dirs[-1])
PY
}

assert_taxonomy_contract() {
	python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

expected = {
    "completed_no_diff": ("included", "no_diff", "valid_negative", "no_diff", None),
    "completed_cache_changed_but_benign": (
        "included",
        "cache_diff_benign",
        "valid_negative",
        "cache_diff_benign",
        None,
    ),
    "failed_parse": (
        "unknown",
        "runtime_or_parse_failure",
        "input_parse_failure",
        "oracle_parse_incomplete",
        None,
    ),
    "failed_replay_missing_artifact": (
        "excluded",
        "infra_failure",
        "infra_artifact_failure",
        "replay_missing_artifact",
        "infra_failure",
    ),
    "failed_replay_subprocess_launch_error": (
        "excluded",
        "infra_failure",
        "orchestrator_compat_failure",
        "replay_subprocess_launch_error",
        "infra_failure",
    ),
    "failed_replay_timeout": (
        "unknown",
        "runtime_or_parse_failure",
        "target_runtime_failure",
        "replay_timeout",
        None,
    ),
    "oracle_diff": ("included", "oracle_diff", "semantic_diff", "oracle_diff", None),
}

for sample_id, (analysis_state, semantic_outcome, primary, detail, exclude_reason) in expected.items():
    triage = json.loads((root / sample_id / "triage.json").read_text(encoding="utf-8"))
    actual = (
        triage.get("analysis_state"),
        triage.get("semantic_outcome"),
        triage.get("failure_bucket_primary"),
        triage.get("failure_bucket_detail"),
        triage.get("exclude_reason"),
    )
    if actual != (analysis_state, semantic_outcome, primary, detail, exclude_reason):
        raise SystemExit(
            f"ASSERT FAIL: {sample_id} taxonomy 不符合预期: actual={actual!r} expected={(analysis_state, semantic_outcome, primary, detail, exclude_reason)!r}"
        )
    if triage.get("failure_taxonomy_version") != 1:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.failure_taxonomy_version={triage.get('failure_taxonomy_version')!r} != 1"
        )
PY
}

assert_campaign_outputs() {
	local report_dir="$1"
	python3 - "$report_dir" <<'PY'
import csv
import json
import pathlib
import sys

report_dir = pathlib.Path(sys.argv[1])
summary = json.loads((report_dir / "summary.json").read_text(encoding="utf-8"))
denominators = summary.get("metric_denominators", {})
analysis_state = denominators.get("analysis_state", {})

included = int(analysis_state.get("included", 0))
excluded = int(analysis_state.get("excluded", 0))
unknown = int(analysis_state.get("unknown", 0))
total = int(denominators.get("total_samples", -1))
if included + excluded + unknown != total:
    raise SystemExit(
        "ASSERT FAIL: metric_denominators 不守恒: "
        f"included({included})+excluded({excluded})+unknown({unknown}) != total({total})"
    )

if (included, excluded, unknown, total) != (3, 2, 2, 7):
    raise SystemExit(
        "ASSERT FAIL: metric_denominators.analysis_state 计数不符合 fixture 预期: "
        f"actual={(included, excluded, unknown, total)!r}"
    )

taxonomy_path = report_dir / "failure_taxonomy.tsv"
rows = list(csv.DictReader(taxonomy_path.open(encoding="utf-8", newline=""), delimiter="\t"))
counts = {
    (row["failure_bucket_primary"], row["failure_bucket_detail"]): int(row["count"])
    for row in rows
    if row["failure_bucket_primary"] != "__total__"
}
expected_counts = {
    ("valid_negative", "no_diff"): 1,
    ("valid_negative", "cache_diff_benign"): 1,
    ("input_parse_failure", "oracle_parse_incomplete"): 1,
    ("infra_artifact_failure", "replay_missing_artifact"): 1,
    ("orchestrator_compat_failure", "replay_subprocess_launch_error"): 1,
    ("target_runtime_failure", "replay_timeout"): 1,
    ("semantic_diff", "oracle_diff"): 1,
}
if counts != expected_counts:
    raise SystemExit(
        f"ASSERT FAIL: failure_taxonomy.tsv 计数不符合预期: actual={counts!r} expected={expected_counts!r}"
    )

taxonomy_total_rows = [row for row in rows if row["failure_bucket_primary"] == "__total__"]
if len(taxonomy_total_rows) != 1 or int(taxonomy_total_rows[0]["count"]) != 7:
    raise SystemExit("ASSERT FAIL: failure_taxonomy.tsv __total__ 应为 7")

exclusion_rows = list(
    csv.DictReader(
        (report_dir / "exclusion_summary.tsv").open(encoding="utf-8", newline=""),
        delimiter="\t",
    )
)
exclusion_counts = {
    row["failure_bucket_primary"]: (
        row["analysis_state"],
        int(row["count"]),
    )
    for row in exclusion_rows
    if row["failure_bucket_primary"] != "__total__"
}
expected_exclusion = {
    "semantic_diff": ("included", 1),
    "valid_negative": ("included", 2),
    "input_parse_failure": ("unknown", 1),
    "infra_artifact_failure": ("excluded", 1),
    "orchestrator_compat_failure": ("excluded", 1),
    "target_runtime_failure": ("unknown", 1),
}
if exclusion_counts != expected_exclusion:
    raise SystemExit(
        f"ASSERT FAIL: exclusion_summary.tsv 不符合预期: actual={exclusion_counts!r} expected={expected_exclusion!r}"
    )
PY
}

write_fixtures
run_cli triage --root "$FOLLOW_ROOT" --rewrite >/dev/null
assert_taxonomy_contract

run_cli campaign-report --root "$FOLLOW_ROOT" >/dev/null
REPORT_DIR="$(get_latest_report_dir "$FOLLOW_ROOT/campaign_reports")"

if [ ! -f "$REPORT_DIR/failure_taxonomy.tsv" ]; then
	printf 'ASSERT FAIL: 缺少文件 %s\n' "$REPORT_DIR/failure_taxonomy.tsv" >&2
	exit 1
fi
if [ ! -f "$REPORT_DIR/exclusion_summary.tsv" ]; then
	printf 'ASSERT FAIL: 缺少文件 %s\n' "$REPORT_DIR/exclusion_summary.tsv" >&2
	exit 1
fi

assert_campaign_outputs "$REPORT_DIR"

echo "PASS: failure taxonomy campaign report test passed"
