#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-sample-analysis-state.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

write_fixture_root() {
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


def fingerprint_payload(sample_id: str) -> dict:
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


def stale_triage_payload(sample_id: str) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "status": "completed_no_diff",
            "diff_class": "no_diff",
            "analysis_state": "unknown",
            "exclude_reason": None,
            "semantic_outcome": "legacy",
            "filter_labels": ["legacy_label"],
            "cluster_key": "legacy|no_diff|legacy_label",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": False,
            "oracle_audit_candidate": False,
            "case_study_candidate": False,
            "manual_truth_status": "not_applicable",
            "notes": ["legacy triage should be rewritten"],
        }
    )
    return payload


def cache_diff_empty(sample_id: str) -> dict:
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


def cache_diff_present(sample_id: str, *, interesting: bool, has_diff: bool = True) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "cache_delta_triggered": bool(interesting),
            "bind9": {
                "entries_before": 0,
                "entries_after": 1 if has_diff else 0,
                "has_cache_diff": bool(has_diff),
                "interesting_delta_count": 1 if interesting else 0,
                "delta_items": [{"kind": "added"}] if interesting else [],
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


def oracle_ok_same() -> dict:
    return {
        "bind9.stderr_parse_status": "ok",
        "unbound.stderr_parse_status": "ok",
        "bind9.parse_ok": True,
        "unbound.parse_ok": True,
        "bind9.resolver_fetch_started": True,
        "unbound.resolver_fetch_started": True,
        "bind9.response_accepted": True,
        "unbound.response_accepted": True,
        "bind9.second_query_hit": False,
        "unbound.second_query_hit": False,
        "bind9.cache_entry_created": False,
        "unbound.cache_entry_created": False,
        "bind9.timeout": False,
        "unbound.timeout": False,
    }


def oracle_with_diff() -> dict:
    payload = oracle_ok_same()
    payload["unbound.parse_ok"] = False
    return payload


fixtures = {
    "oracle_diff": {
        "sample.meta.json": {**shared_meta("oracle_diff"), "status": "completed"},
        "oracle.json": oracle_with_diff(),
        "cache_diff.json": cache_diff_empty("oracle_diff"),
        "state_fingerprint.json": fingerprint_payload("oracle_diff"),
        "triage.json": stale_triage_payload("oracle_diff"),
    },
    "oracle_and_cache_diff": {
        "sample.meta.json": {**shared_meta("oracle_and_cache_diff"), "status": "completed"},
        "oracle.json": oracle_with_diff(),
        "cache_diff.json": cache_diff_present("oracle_and_cache_diff", interesting=False),
        "state_fingerprint.json": fingerprint_payload("oracle_and_cache_diff"),
        "triage.json": stale_triage_payload("oracle_and_cache_diff"),
    },
    "cache_diff_interesting": {
        "sample.meta.json": {**shared_meta("cache_diff_interesting"), "status": "completed"},
        "oracle.json": oracle_ok_same(),
        "cache_diff.json": cache_diff_present("cache_diff_interesting", interesting=True),
        "state_fingerprint.json": fingerprint_payload("cache_diff_interesting"),
        "triage.json": stale_triage_payload("cache_diff_interesting"),
    },
    "cache_diff_benign": {
        "sample.meta.json": {**shared_meta("cache_diff_benign"), "status": "completed"},
        "oracle.json": oracle_ok_same(),
        "cache_diff.json": cache_diff_present("cache_diff_benign", interesting=False),
        "state_fingerprint.json": fingerprint_payload("cache_diff_benign"),
        "triage.json": stale_triage_payload("cache_diff_benign"),
    },
    "completed_no_diff": {
        "sample.meta.json": {**shared_meta("completed_no_diff"), "status": "completed"},
        "oracle.json": oracle_ok_same(),
        "cache_diff.json": cache_diff_empty("completed_no_diff"),
        "state_fingerprint.json": fingerprint_payload("completed_no_diff"),
        "triage.json": stale_triage_payload("completed_no_diff"),
    },
    "failed_parse": {
        "sample.meta.json": {**shared_meta("failed_parse"), "status": "completed"},
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "missing_summary",
        },
        "cache_diff.json": cache_diff_empty("failed_parse"),
        "state_fingerprint.json": fingerprint_payload("failed_parse"),
        "triage.json": stale_triage_payload("failed_parse"),
    },
    "failed_replay_timeout": {
        "sample.meta.json": {
            **shared_meta("failed_replay_timeout"),
            "status": "failed",
            "failure": {
                "kind": "replay_error",
                "message": "unbound.before 超时，退出码=124",
                "exit_code": 4,
                "reason": "timeout",
                "stage": "unbound.before",
                "resolver": "unbound",
                "returncode": 124,
            },
        },
        "oracle.json": {
            "bind9.stderr_parse_status": None,
            "unbound.stderr_parse_status": None,
        },
        "cache_diff.json": cache_diff_empty("failed_replay_timeout"),
        "state_fingerprint.json": fingerprint_payload("failed_replay_timeout"),
        "triage.json": stale_triage_payload("failed_replay_timeout"),
    },
    "failed_replay_missing_artifact": {
        "sample.meta.json": {
            **shared_meta("failed_replay_missing_artifact"),
            "status": "failed",
            "failure": {
                "kind": "replay_error",
                "message": "unbound.before 未生成有效文件: unbound.before.cache.txt",
                "exit_code": 5,
                "reason": "missing_artifact",
                "stage": "unbound.before",
                "resolver": "unbound",
                "artifact_path": "unbound.before.cache.txt",
            },
        },
        "oracle.json": {
            "bind9.stderr_parse_status": None,
            "unbound.stderr_parse_status": None,
        },
        "cache_diff.json": cache_diff_empty("failed_replay_missing_artifact"),
        "state_fingerprint.json": fingerprint_payload("failed_replay_missing_artifact"),
        "triage.json": stale_triage_payload("failed_replay_missing_artifact"),
    },
}

for sample_id, files in fixtures.items():
    sample_dir = follow_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    for filename, payload in files.items():
        write_json(sample_dir / filename, payload)
PY
}

run_triage_rewrite() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		python3 -m tools.dns_diff.cli triage --root "$FOLLOW_ROOT" --rewrite >/dev/null
}

assert_sample_analysis_state() {
	python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1])

expected = {
    "oracle_diff": {
        "status": "completed_oracle_diff",
        "diff_class": "oracle_diff",
        "analysis_state": "included",
        "exclude_reason": None,
        "semantic_outcome": "oracle_diff",
        "failure_bucket_primary": "semantic_diff",
        "failure_bucket_detail": "oracle_diff",
        "oracle_audit_candidate": True,
        "case_study_candidate": True,
        "manual_truth_status": "not_started",
        "needs_manual_review": True,
    },
    "oracle_and_cache_diff": {
        "status": "completed_oracle_diff",
        "diff_class": "oracle_and_cache_diff",
        "analysis_state": "included",
        "exclude_reason": None,
        "semantic_outcome": "oracle_and_cache_diff",
        "failure_bucket_primary": "semantic_diff",
        "failure_bucket_detail": "oracle_and_cache_diff",
        "oracle_audit_candidate": True,
        "case_study_candidate": True,
        "manual_truth_status": "not_started",
        "needs_manual_review": True,
    },
    "cache_diff_interesting": {
        "status": "completed_cache_changed_needs_review",
        "diff_class": "cache_diff_interesting",
        "analysis_state": "included",
        "exclude_reason": None,
        "semantic_outcome": "cache_diff_interesting",
        "failure_bucket_primary": "semantic_diff",
        "failure_bucket_detail": "cache_diff_interesting",
        "oracle_audit_candidate": True,
        "case_study_candidate": True,
        "manual_truth_status": "not_started",
        "needs_manual_review": True,
    },
    "cache_diff_benign": {
        "status": "completed_cache_changed_but_benign",
        "diff_class": "cache_diff_benign",
        "analysis_state": "included",
        "exclude_reason": None,
        "semantic_outcome": "cache_diff_benign",
        "failure_bucket_primary": "valid_negative",
        "failure_bucket_detail": "cache_diff_benign",
        "oracle_audit_candidate": False,
        "case_study_candidate": False,
        "manual_truth_status": "not_applicable",
        "needs_manual_review": False,
    },
    "completed_no_diff": {
        "status": "completed_no_diff",
        "diff_class": "no_diff",
        "analysis_state": "included",
        "exclude_reason": None,
        "semantic_outcome": "no_diff",
        "failure_bucket_primary": "valid_negative",
        "failure_bucket_detail": "no_diff",
        "oracle_audit_candidate": False,
        "case_study_candidate": False,
        "manual_truth_status": "not_applicable",
        "needs_manual_review": False,
    },
    "failed_parse": {
        "status": "failed_parse",
        "diff_class": "oracle_parse_incomplete",
        "analysis_state": "unknown",
        "exclude_reason": None,
        "semantic_outcome": "runtime_or_parse_failure",
        "failure_bucket_primary": "input_parse_failure",
        "failure_bucket_detail": "oracle_parse_incomplete",
        "oracle_audit_candidate": False,
        "case_study_candidate": False,
        "manual_truth_status": "not_applicable",
        "needs_manual_review": True,
    },
    "failed_replay_timeout": {
        "status": "failed_replay",
        "diff_class": "replay_incomplete",
        "analysis_state": "unknown",
        "exclude_reason": None,
        "semantic_outcome": "runtime_or_parse_failure",
        "failure_bucket_primary": "target_runtime_failure",
        "failure_bucket_detail": "replay_timeout",
        "oracle_audit_candidate": False,
        "case_study_candidate": False,
        "manual_truth_status": "not_applicable",
        "needs_manual_review": True,
    },
    "failed_replay_missing_artifact": {
        "status": "failed_replay",
        "diff_class": "replay_incomplete",
        "analysis_state": "excluded",
        "exclude_reason": "infra_failure",
        "semantic_outcome": "infra_failure",
        "failure_bucket_primary": "infra_artifact_failure",
        "failure_bucket_detail": "replay_missing_artifact",
        "oracle_audit_candidate": False,
        "case_study_candidate": False,
        "manual_truth_status": "not_applicable",
        "needs_manual_review": True,
    },
}

for sample_id, rules in expected.items():
    triage = json.loads((follow_root / sample_id / "triage.json").read_text(encoding="utf-8"))
    for field, expected_value in rules.items():
        actual = triage.get(field)
        if actual != expected_value:
            raise SystemExit(
                f"ASSERT FAIL: {sample_id}.triage[{field!r}]={actual!r} != {expected_value!r}"
            )

    if triage.get("analysis_state") != "excluded" and triage.get("exclude_reason") is not None:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.exclude_reason 仅允许 excluded 场景非空: {triage.get('exclude_reason')!r}"
        )

    if triage.get("manual_truth_status") not in {"not_started", "not_applicable"}:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.manual_truth_status 非法: {triage.get('manual_truth_status')!r}"
        )

    expected_case_study = bool(
        triage.get("oracle_audit_candidate") and triage.get("needs_manual_review")
    )
    if triage.get("case_study_candidate") is not expected_case_study:
        raise SystemExit(
            "ASSERT FAIL: "
            f"{sample_id}.triage.case_study_candidate={triage.get('case_study_candidate')!r} "
            f"!= oracle_audit_candidate&&needs_manual_review ({expected_case_study!r})"
        )
PY
}

write_fixture_root
run_triage_rewrite
assert_sample_analysis_state

echo "PASS: sample analysis_state mapping regression test passed"
