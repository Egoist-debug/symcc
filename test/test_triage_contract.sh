#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-triage-contract.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
SNAPSHOT_FILE="$WORKDIR/triage-snapshot.json"
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
        "generated_at": "2026-03-23T00:00:00Z",
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
            "filter_labels": ["legacy_label"],
            "cluster_key": "legacy|no_diff|legacy_label",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": False,
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


def cache_diff_interesting(sample_id: str) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "cache_delta_triggered": True,
            "bind9": {
                "entries_before": 0,
                "entries_after": 1,
                "has_cache_diff": True,
                "interesting_delta_count": 1,
                "delta_items": [
                    {
                        "kind": "added",
                        "count_before": 0,
                        "count_after": 1,
                        "delta": 1,
                        "fields": {
                            "resolver": "bind9",
                            "view": "_default",
                            "qname": "www.example.",
                            "qtype": "A",
                            "rrtype": "A",
                            "section": "answer",
                            "cache_type": "rrset",
                            "rdata_norm": "192.0.2.1",
                            "flags": "-",
                        },
                    }
                ],
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
    "failed_replay": {
        "sample.meta.json": {
            **shared_meta("failed_replay"),
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
        "cache_diff.json": cache_diff_empty("failed_replay"),
        "state_fingerprint.json": fingerprint_payload("failed_replay"),
        "triage.json": stale_triage_payload("failed_replay"),
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
    "failed_parse": {
        "sample.meta.json": {
            **shared_meta("failed_parse"),
            "status": "completed",
        },
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "missing_summary",
        },
        "cache_diff.json": cache_diff_empty("failed_parse"),
        "state_fingerprint.json": fingerprint_payload("failed_parse"),
        "triage.json": stale_triage_payload("failed_parse"),
    },
    "oracle_diff": {
        "sample.meta.json": {
            **shared_meta("oracle_diff"),
            "status": "completed",
        },
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": False,
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
        },
        "cache_diff.json": cache_diff_empty("oracle_diff"),
        "state_fingerprint.json": fingerprint_payload("oracle_diff"),
        "triage.json": stale_triage_payload("oracle_diff"),
    },
    "cache_diff": {
        "sample.meta.json": {
            **shared_meta("cache_diff"),
            "status": "completed",
        },
        "oracle.json": {
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
        },
        "cache_diff.json": cache_diff_interesting("cache_diff"),
        "state_fingerprint.json": fingerprint_payload("cache_diff"),
        "triage.json": stale_triage_payload("cache_diff"),
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

assert_triage_contract() {
	python3 - "$FOLLOW_ROOT" "$SNAPSHOT_FILE" <<'PY'
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1])
snapshot_path = pathlib.Path(sys.argv[2])

expected = {
    "failed_replay": {
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
        "required_labels": {"oracle_missing", "replay_missing_artifact"},
        "cluster_tokens": {"oracle_missing", "replay_missing_artifact", "fp:iterative->iterative"},
        "cache_delta_triggered": False,
        "interesting_delta_count": 0,
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
        "required_labels": {"oracle_missing", "replay_timeout"},
        "cluster_tokens": {"oracle_missing", "replay_timeout", "fp:iterative->iterative"},
        "cache_delta_triggered": False,
        "interesting_delta_count": 0,
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
        "required_labels": {"oracle_parse_incomplete"},
        "cluster_tokens": {"oracle_parse_incomplete", "fp:iterative->iterative"},
        "cache_delta_triggered": False,
        "interesting_delta_count": 0,
    },
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
        "required_labels": {"oracle_diff"},
        "cluster_tokens": {"oracle_diff", "fp:iterative->iterative"},
        "cache_delta_triggered": False,
        "interesting_delta_count": 0,
    },
    "cache_diff": {
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
        "required_labels": {
            "cache_diff_present",
            "cache_delta_review",
            "cache_delta_triggered",
            "cache_delta_items_present",
        },
        "cluster_tokens": {"cache_delta_review", "cache_delta_triggered", "fp:iterative->iterative"},
        "cache_delta_triggered": True,
        "interesting_delta_count": 1,
    },
}

snapshot = {}
for sample_id, rules in expected.items():
    triage_path = follow_root / sample_id / "triage.json"
    triage = json.loads(triage_path.read_text(encoding="utf-8"))

    for field in (
        "status",
        "diff_class",
        "analysis_state",
        "exclude_reason",
        "semantic_outcome",
        "failure_bucket_primary",
        "failure_bucket_detail",
        "oracle_audit_candidate",
        "case_study_candidate",
        "manual_truth_status",
        "needs_manual_review",
    ):
        if triage.get(field) != rules[field]:
            raise SystemExit(
                f"ASSERT FAIL: {sample_id}.triage[{field!r}]={triage.get(field)!r} != {rules[field]!r}"
            )

    if triage.get("analysis_state") != "excluded" and triage.get("exclude_reason") is not None:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.exclude_reason 仅允许 excluded 场景非空: {triage.get('exclude_reason')!r}"
        )
    if triage.get("failure_taxonomy_version") != 1:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.failure_taxonomy_version={triage.get('failure_taxonomy_version')!r} != 1"
        )

    if triage.get("cache_delta_triggered") is not rules["cache_delta_triggered"]:
        raise SystemExit(
            "ASSERT FAIL: "
            f"{sample_id}.triage['cache_delta_triggered']={triage.get('cache_delta_triggered')!r} "
            f"!= {rules['cache_delta_triggered']!r}"
        )
    if triage.get("interesting_delta_count") != rules["interesting_delta_count"]:
        raise SystemExit(
            "ASSERT FAIL: "
            f"{sample_id}.triage['interesting_delta_count']={triage.get('interesting_delta_count')!r} "
            f"!= {rules['interesting_delta_count']!r}"
        )

    labels = triage.get("filter_labels")
    if not isinstance(labels, list):
        raise SystemExit(f"ASSERT FAIL: {sample_id}.triage.filter_labels 应为数组")
    missing_labels = sorted(label for label in rules["required_labels"] if label not in labels)
    if missing_labels:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.filter_labels 缺少 {missing_labels!r}: {labels!r}"
        )

    cluster_key = triage.get("cluster_key")
    prefix = f"{rules['status']}|{rules['diff_class']}|"
    if not isinstance(cluster_key, str) or not cluster_key.startswith(prefix):
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.cluster_key 前缀不符合预期: {cluster_key!r} !^ {prefix!r}"
        )
    missing_tokens = sorted(
        token for token in rules["cluster_tokens"] if token not in cluster_key
    )
    if missing_tokens:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.cluster_key 缺少关键 token {missing_tokens!r}: {cluster_key!r}"
        )

    snapshot[sample_id] = {
        "status": triage["status"],
        "diff_class": triage["diff_class"],
        "analysis_state": triage["analysis_state"],
        "exclude_reason": triage["exclude_reason"],
        "semantic_outcome": triage["semantic_outcome"],
        "failure_bucket_primary": triage["failure_bucket_primary"],
        "failure_bucket_detail": triage["failure_bucket_detail"],
        "oracle_audit_candidate": triage["oracle_audit_candidate"],
        "case_study_candidate": triage["case_study_candidate"],
        "manual_truth_status": triage["manual_truth_status"],
        "filter_labels": labels,
        "cluster_key": cluster_key,
        "cache_delta_triggered": triage["cache_delta_triggered"],
        "interesting_delta_count": triage["interesting_delta_count"],
        "needs_manual_review": triage["needs_manual_review"],
    }

if snapshot_path.exists():
    previous = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if previous != snapshot:
        raise SystemExit(
            "ASSERT FAIL: 第二次 triage --rewrite 结果发生漂移: "
            f"previous={previous!r} current={snapshot!r}"
        )
else:
    snapshot_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
PY
}

write_fixture_root

for sample_id in failed_replay failed_replay_timeout failed_parse oracle_diff cache_diff; do
	assert_file_exists "$FOLLOW_ROOT/$sample_id/triage.json"
done

run_triage_rewrite
assert_triage_contract

run_triage_rewrite
assert_triage_contract

echo "PASS: triage contract regression test passed"
