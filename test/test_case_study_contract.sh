#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-case-study.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
EMPTY_ROOT="$WORKDIR/follow_diff_empty"
CAMPAIGN_REPORT_DIR="$WORKDIR/campaign_report"
EMPTY_REPORT_DIR="$WORKDIR/campaign_report_empty"
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

assert_file_not_exists() {
	local path="$1"
	if [ -e "$path" ]; then
		printf 'ASSERT FAIL: 不期望存在文件 %s\n' "$path" >&2
		exit 1
	fi
}

run_cli() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		python3 -m tools.dns_diff.cli "$@"
}

write_main_fixture_root() {
	python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1])
follow_root.mkdir(parents=True, exist_ok=True)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def shared_meta(sample_id: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-03-24T00:00:00Z",
        "sample_id": sample_id,
    }


def sample_meta(sample_id: str, *, status: str = "completed", failure=None) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "status": status,
            "sample_sha1": f"sha1-{sample_id}",
            "sample_size": 4,
            "sample_path": f"/fixtures/{sample_id}.bin",
        }
    )
    if failure is not None:
        payload["failure"] = failure
    return payload


def oracle_payload(sample_id: str, *, oracle_diff: bool) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": False if oracle_diff else True,
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
    )
    return payload


def oracle_parse_incomplete_payload(sample_id: str) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "missing_summary",
        }
    )
    return payload


def cache_diff_payload(sample_id: str, *, interesting: bool) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "cache_delta_triggered": interesting,
            "bind9": {
                "has_cache_diff": interesting,
                "interesting_delta_count": 1 if interesting else 0,
                "delta_items": [
                    {
                        "kind": "added",
                        "fields": {
                            "resolver": "bind9",
                            "qname": f"{sample_id}.example.",
                            "qtype": "A",
                        },
                    }
                ]
                if interesting
                else [],
            },
            "unbound": {
                "has_cache_diff": False,
                "interesting_delta_count": 0,
                "delta_items": [],
            },
        }
    )
    return payload


def triage_payload(
    sample_id: str,
    *,
    status: str,
    diff_class: str,
    analysis_state: str,
    semantic_outcome: str,
    failure_bucket_primary: str,
    failure_bucket_detail: str,
    needs_manual_review: bool,
    filter_labels,
    notes,
    cache_delta_triggered: bool,
    interesting_delta_count: int,
    oracle_audit_candidate: bool,
    case_study_candidate: bool,
    manual_truth_status: str,
) -> dict:
    payload = shared_meta(sample_id)
    payload.update(
        {
            "status": status,
            "diff_class": diff_class,
            "analysis_state": analysis_state,
            "exclude_reason": failure_bucket_primary if analysis_state == "excluded" else None,
            "semantic_outcome": semantic_outcome,
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": failure_bucket_primary,
            "failure_bucket_detail": failure_bucket_detail,
            "oracle_audit_candidate": oracle_audit_candidate,
            "case_study_candidate": case_study_candidate,
            "manual_truth_status": manual_truth_status,
            "filter_labels": filter_labels,
            "cluster_key": f"{status}|{diff_class}|{','.join(filter_labels) or '_'}|fp:iterative->iterative",
            "cache_delta_triggered": cache_delta_triggered,
            "interesting_delta_count": interesting_delta_count,
            "needs_manual_review": needs_manual_review,
            "notes": notes,
        }
    )
    return payload


def write_sample(
    sample_id: str,
    *,
    triage: dict,
    sample_meta_payload: dict,
    oracle: dict,
    cache_diff: dict,
) -> None:
    sample_dir = follow_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    write_json(sample_dir / "sample.meta.json", sample_meta_payload)
    write_json(sample_dir / "oracle.json", oracle)
    write_json(sample_dir / "cache_diff.json", cache_diff)
    write_json(sample_dir / "triage.json", triage)
    (sample_dir / "sample.bin").write_bytes(bytes((1, 2, 3, 4)))
    write_text(
        sample_dir / "bind9.stderr",
        f"===== bind9.after =====\nORACLE_SUMMARY sample={sample_id} parse_ok=1\n",
    )
    write_text(
        sample_dir / "unbound.stderr",
        f"===== unbound.after =====\nORACLE_SUMMARY sample={sample_id} parse_ok=1\n",
    )


write_sample(
    "sample-001",
    triage=triage_payload(
        "sample-001",
        status="completed_oracle_diff",
        diff_class="oracle_and_cache_diff",
        analysis_state="included",
        semantic_outcome="oracle_and_cache_diff",
        failure_bucket_primary="semantic_diff",
        failure_bucket_detail="oracle_and_cache_diff",
        needs_manual_review=True,
        filter_labels=["oracle_diff", "cache_diff_present", "cache_delta_review"],
        notes=["oracle 与 cache 差异同时命中"],
        cache_delta_triggered=True,
        interesting_delta_count=1,
        oracle_audit_candidate=True,
        case_study_candidate=True,
        manual_truth_status="not_started",
    ),
    sample_meta_payload=sample_meta("sample-001"),
    oracle=oracle_payload("sample-001", oracle_diff=True),
    cache_diff=cache_diff_payload("sample-001", interesting=True),
)
write_sample(
    "sample-002",
    triage=triage_payload(
        "sample-002",
        status="completed_oracle_diff",
        diff_class="oracle_diff",
        analysis_state="included",
        semantic_outcome="oracle_diff",
        failure_bucket_primary="semantic_diff",
        failure_bucket_detail="oracle_diff",
        needs_manual_review=True,
        filter_labels=["oracle_diff"],
        notes=["oracle parse_ok 字段不一致"],
        cache_delta_triggered=False,
        interesting_delta_count=0,
        oracle_audit_candidate=True,
        case_study_candidate=True,
        manual_truth_status="not_started",
    ),
    sample_meta_payload=sample_meta("sample-002"),
    oracle=oracle_payload("sample-002", oracle_diff=True),
    cache_diff=cache_diff_payload("sample-002", interesting=False),
)
write_sample(
    "sample-003",
    triage=triage_payload(
        "sample-003",
        status="completed_oracle_diff",
        diff_class="oracle_diff",
        analysis_state="included",
        semantic_outcome="oracle_diff",
        failure_bucket_primary="semantic_diff",
        failure_bucket_detail="oracle_diff",
        needs_manual_review=True,
        filter_labels=["oracle_diff"],
        notes=["oracle parse_ok 字段不一致"],
        cache_delta_triggered=False,
        interesting_delta_count=0,
        oracle_audit_candidate=True,
        case_study_candidate=True,
        manual_truth_status="not_started",
    ),
    sample_meta_payload=sample_meta("sample-003"),
    oracle=oracle_payload("sample-003", oracle_diff=True),
    cache_diff=cache_diff_payload("sample-003", interesting=False),
)
write_sample(
    "sample-004",
    triage=triage_payload(
        "sample-004",
        status="completed_oracle_diff",
        diff_class="oracle_and_cache_diff",
        analysis_state="included",
        semantic_outcome="oracle_and_cache_diff",
        failure_bucket_primary="semantic_diff",
        failure_bucket_detail="oracle_and_cache_diff",
        needs_manual_review=True,
        filter_labels=["oracle_diff", "cache_diff_present", "cache_delta_review"],
        notes=["oracle 与 cache 差异同时命中"],
        cache_delta_triggered=True,
        interesting_delta_count=1,
        oracle_audit_candidate=True,
        case_study_candidate=True,
        manual_truth_status="not_started",
    ),
    sample_meta_payload=sample_meta("sample-004"),
    oracle=oracle_payload("sample-004", oracle_diff=True),
    cache_diff=cache_diff_payload("sample-004", interesting=True),
)
write_sample(
    "sample-005",
    triage=triage_payload(
        "sample-005",
        status="completed_cache_changed_needs_review",
        diff_class="cache_diff_interesting",
        analysis_state="included",
        semantic_outcome="cache_diff_interesting",
        failure_bucket_primary="semantic_diff",
        failure_bucket_detail="cache_diff_interesting",
        needs_manual_review=True,
        filter_labels=["cache_diff_present", "cache_delta_review"],
        notes=["cache interesting delta 命中"],
        cache_delta_triggered=True,
        interesting_delta_count=1,
        oracle_audit_candidate=True,
        case_study_candidate=True,
        manual_truth_status="not_started",
    ),
    sample_meta_payload=sample_meta("sample-005"),
    oracle=oracle_payload("sample-005", oracle_diff=False),
    cache_diff=cache_diff_payload("sample-005", interesting=True),
)
write_sample(
    "sample-006",
    triage=triage_payload(
        "sample-006",
        status="completed_cache_changed_needs_review",
        diff_class="cache_diff_interesting",
        analysis_state="included",
        semantic_outcome="cache_diff_interesting",
        failure_bucket_primary="semantic_diff",
        failure_bucket_detail="cache_diff_interesting",
        needs_manual_review=True,
        filter_labels=["cache_diff_present", "cache_delta_review"],
        notes=["cache interesting delta 命中"],
        cache_delta_triggered=True,
        interesting_delta_count=1,
        oracle_audit_candidate=True,
        case_study_candidate=True,
        manual_truth_status="not_started",
    ),
    sample_meta_payload=sample_meta("sample-006"),
    oracle=oracle_payload("sample-006", oracle_diff=False),
    cache_diff=cache_diff_payload("sample-006", interesting=True),
)
write_sample(
    "sample-007",
    triage=triage_payload(
        "sample-007",
        status="completed_no_diff",
        diff_class="no_diff",
        analysis_state="included",
        semantic_outcome="no_diff",
        failure_bucket_primary="valid_negative",
        failure_bucket_detail="no_diff",
        needs_manual_review=False,
        filter_labels=[],
        notes=["无结构化差异"],
        cache_delta_triggered=False,
        interesting_delta_count=0,
        oracle_audit_candidate=False,
        case_study_candidate=False,
        manual_truth_status="not_applicable",
    ),
    sample_meta_payload=sample_meta("sample-007"),
    oracle=oracle_payload("sample-007", oracle_diff=False),
    cache_diff=cache_diff_payload("sample-007", interesting=False),
)
write_sample(
    "failed_replay",
    triage=triage_payload(
        "failed_replay",
        status="failed_replay",
        diff_class="replay_incomplete",
        analysis_state="excluded",
        semantic_outcome="replay_missing_artifact",
        failure_bucket_primary="infra_artifact_failure",
        failure_bucket_detail="replay_missing_artifact",
        needs_manual_review=True,
        filter_labels=["oracle_missing", "replay_missing_artifact"],
        notes=["oracle.json 缺失，作为 replay 缺件失败"],
        cache_delta_triggered=False,
        interesting_delta_count=0,
        oracle_audit_candidate=False,
        case_study_candidate=False,
        manual_truth_status="not_applicable",
    ),
    sample_meta_payload=sample_meta(
        "failed_replay",
        status="failed",
        failure={
            "kind": "replay_error",
            "reason": "missing_artifact",
            "message": "oracle 缺失",
            "artifact_path": "oracle.json",
        },
    ),
    oracle=shared_meta("failed_replay"),
    cache_diff=cache_diff_payload("failed_replay", interesting=False),
)
write_sample(
    "failed_parse",
    triage=triage_payload(
        "failed_parse",
        status="failed_parse",
        diff_class="oracle_parse_incomplete",
        analysis_state="unknown",
        semantic_outcome="oracle_parse_incomplete",
        failure_bucket_primary="input_parse_failure",
        failure_bucket_detail="oracle_parse_incomplete",
        needs_manual_review=True,
        filter_labels=["oracle_parse_incomplete"],
        notes=["oracle parse 不完整"],
        cache_delta_triggered=False,
        interesting_delta_count=0,
        oracle_audit_candidate=False,
        case_study_candidate=False,
        manual_truth_status="not_applicable",
    ),
    sample_meta_payload=sample_meta("failed_parse"),
    oracle=oracle_parse_incomplete_payload("failed_parse"),
    cache_diff=cache_diff_payload("failed_parse", interesting=False),
)
PY
}

write_empty_fixture_root() {
	python3 - "$EMPTY_ROOT" <<'PY'
import json
import pathlib
import sys

empty_root = pathlib.Path(sys.argv[1])
empty_root.mkdir(parents=True, exist_ok=True)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


samples = {
    "failed_only": {
        "sample.meta.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "failed_only",
            "status": "failed",
        },
        "oracle.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "failed_only",
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "missing_summary",
        },
        "cache_diff.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "failed_only",
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0, "delta_items": []},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0, "delta_items": []},
        },
        "triage.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "failed_only",
            "status": "failed_parse",
            "diff_class": "oracle_parse_incomplete",
            "analysis_state": "unknown",
            "exclude_reason": None,
            "semantic_outcome": "oracle_parse_incomplete",
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "input_parse_failure",
            "failure_bucket_detail": "oracle_parse_incomplete",
            "oracle_audit_candidate": False,
            "case_study_candidate": False,
            "manual_truth_status": "not_applicable",
            "filter_labels": ["oracle_parse_incomplete"],
            "cluster_key": "failed_parse|oracle_parse_incomplete|oracle_parse_incomplete|fp:iterative->iterative",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": True,
            "notes": ["oracle parse 不完整"],
        },
        "bind9.stderr": "bind9 fail\n",
        "unbound.stderr": "unbound fail\n",
    },
    "no_diff_only": {
        "sample.meta.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "no_diff_only",
            "status": "completed",
        },
        "oracle.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "no_diff_only",
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": True,
        },
        "cache_diff.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "no_diff_only",
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0, "delta_items": []},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0, "delta_items": []},
        },
        "triage.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "no_diff_only",
            "status": "completed_no_diff",
            "diff_class": "no_diff",
            "analysis_state": "included",
            "exclude_reason": None,
            "semantic_outcome": "no_diff",
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "valid_negative",
            "failure_bucket_detail": "no_diff",
            "oracle_audit_candidate": False,
            "case_study_candidate": False,
            "manual_truth_status": "not_applicable",
            "filter_labels": [],
            "cluster_key": "completed_no_diff|no_diff|_|fp:iterative->iterative",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": False,
            "notes": ["无结构化差异"],
        },
        "bind9.stderr": "bind9 ok\n",
        "unbound.stderr": "unbound ok\n",
    },
}

for sample_id, files in samples.items():
    sample_dir = empty_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "sample.bin").write_bytes(b"\x00\x01")
    for filename, payload in files.items():
        path = sample_dir / filename
        if filename.endswith(".json"):
            write_json(path, payload)
        else:
            write_text(path, payload)
PY
}

assert_case_study_contract() {
	python3 - "$FOLLOW_ROOT" "$CAMPAIGN_REPORT_DIR" <<'PY'
import csv
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1]).resolve()
campaign_report_dir = pathlib.Path(sys.argv[2]).resolve()
case_dir = campaign_report_dir / "case_studies"
index_path = case_dir / "index.tsv"

expected_columns = [
    "sample_id",
    "semantic_outcome",
    "selection_reason",
    "case_study_path",
]
expected_order = [
    "sample-001",
    "sample-002",
    "sample-003",
    "sample-004",
    "sample-005",
]

with index_path.open(encoding="utf-8", newline="") as handle:
    reader = csv.DictReader(handle, delimiter="\t")
    if reader.fieldnames != expected_columns:
        raise SystemExit(
            "ASSERT FAIL: case_studies/index.tsv 列顺序不符合预期:\n"
            f"actual={reader.fieldnames!r}\nexpected={expected_columns!r}"
        )
    rows = list(reader)

actual_order = [row["sample_id"] for row in rows]
if actual_order != expected_order:
    raise SystemExit(
        f"ASSERT FAIL: case_studies/index.tsv 顺序异常: actual={actual_order!r} expected={expected_order!r}"
    )

if len(rows) != 5:
    raise SystemExit(f"ASSERT FAIL: case_studies/index.tsv 应仅导出 5 行，实际 {len(rows)}")

disallowed = {"failed_replay", "failed_parse", "sample-006", "sample-007"}
if disallowed & set(actual_order):
    raise SystemExit(
        f"ASSERT FAIL: 不应导出的样本进入 index.tsv: {sorted(disallowed & set(actual_order))!r}"
    )

expected_manual_truth = {
    "status": "not_started",
    "reviewer_primary": "",
    "reviewer_secondary": "",
    "adjudicator": "",
    "judgment": "",
    "notes": "",
    "decided_at": "",
}
expected_path_suffix = {
    "sample_meta_path": "sample.meta.json",
    "oracle_path": "oracle.json",
    "cache_diff_path": "cache_diff.json",
    "triage_path": "triage.json",
    "sample_bin_path": "sample.bin",
    "bind9_stderr_path": "bind9.stderr",
    "unbound_stderr_path": "unbound.stderr",
}

for row in rows:
    sample_id = row["sample_id"]
    sample_dir = (follow_root / sample_id).resolve()
    case_path = pathlib.Path(row["case_study_path"]).resolve()
    expected_case_path = (case_dir / f"{sample_id}.json").resolve()
    if case_path != expected_case_path:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.case_study_path={case_path!s} != {expected_case_path!s}"
        )

    payload = json.loads(expected_case_path.read_text(encoding="utf-8"))
    required_keys = {
        "sample_id",
        "selection_reason",
        "raw_evidence",
        "automated_summary",
        "manual_truth",
        "claim_scope",
        "limitations",
    }
    if not required_keys.issubset(payload.keys()):
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.json 缺少必需字段: {sorted(required_keys - set(payload.keys()))!r}"
        )

    if payload["sample_id"] != sample_id:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.json sample_id={payload['sample_id']!r}"
        )
    if payload["selection_reason"] != row["selection_reason"]:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.selection_reason 与 index.tsv 不一致"
        )
    if sample_id == "sample-005":
        if "次优先级" not in payload["selection_reason"]:
            raise SystemExit(f"ASSERT FAIL: {sample_id} 应为次优先级选择理由")
    else:
        if "高优先级" not in payload["selection_reason"]:
            raise SystemExit(f"ASSERT FAIL: {sample_id} 应为高优先级选择理由")

    raw_evidence = payload["raw_evidence"]
    paths = raw_evidence.get("paths")
    if not isinstance(paths, dict):
        raise SystemExit(f"ASSERT FAIL: {sample_id}.raw_evidence.paths 应为对象")
    if set(paths.keys()) != set(expected_path_suffix.keys()):
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.raw_evidence.paths keys={set(paths.keys())!r}"
        )

    for field, filename in expected_path_suffix.items():
        actual = pathlib.Path(paths[field]).resolve()
        expected = (sample_dir / filename).resolve()
        if actual != expected:
            raise SystemExit(
                f"ASSERT FAIL: {sample_id}.{field}={actual!s} != {expected!s}"
            )
        try:
            actual.relative_to(sample_dir)
        except ValueError as exc:
            raise SystemExit(
                f"ASSERT FAIL: {sample_id}.{field} 越出 sample_dir 边界: {actual!s}"
            ) from exc

    if raw_evidence["triage"].get("analysis_state") != "included":
        raise SystemExit(f"ASSERT FAIL: {sample_id}.raw_evidence.triage.analysis_state 应为 included")
    if raw_evidence["triage"].get("semantic_outcome") != row["semantic_outcome"]:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.raw_evidence.triage.semantic_outcome 不匹配"
        )
    if raw_evidence["sample_bin"].get("exists") is not True:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.raw_evidence.sample_bin.exists 应为 true")
    if raw_evidence["sample_bin"].get("size") != 4:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.raw_evidence.sample_bin.size 应为 4")
    if raw_evidence["stderr"]["bind9"].get("exists") is not True:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.bind9 stderr 应存在")
    if raw_evidence["stderr"]["unbound"].get("exists") is not True:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.unbound stderr 应存在")

    automated_summary = payload["automated_summary"]
    if automated_summary.get("semantic_outcome") != row["semantic_outcome"]:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.automated_summary.semantic_outcome 不匹配"
        )
    if not isinstance(automated_summary.get("summary_text"), str) or not automated_summary.get("summary_text"):
        raise SystemExit(f"ASSERT FAIL: {sample_id}.automated_summary.summary_text 应为非空字符串")
    if not isinstance(automated_summary.get("filter_labels"), list):
        raise SystemExit(f"ASSERT FAIL: {sample_id}.automated_summary.filter_labels 应为数组")
    if not isinstance(automated_summary.get("notes"), list):
        raise SystemExit(f"ASSERT FAIL: {sample_id}.automated_summary.notes 应为数组")

    if payload["manual_truth"] != expected_manual_truth:
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.manual_truth={payload['manual_truth']!r} != {expected_manual_truth!r}"
        )

    if not isinstance(payload["claim_scope"], list) or not payload["claim_scope"]:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.claim_scope 应为非空数组")
    if not isinstance(payload["limitations"], list) or not payload["limitations"]:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.limitations 应为非空数组")

    triage_after = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))
    if "manual_truth" in triage_after:
        raise SystemExit(f"ASSERT FAIL: {sample_id}.triage.json 不应被回写 manual_truth scaffold")
    if triage_after.get("manual_truth_status") != "not_started":
        raise SystemExit(
            f"ASSERT FAIL: {sample_id}.triage.manual_truth_status 被错误改写: {triage_after.get('manual_truth_status')!r}"
        )

for sample_id in ("failed_replay", "failed_parse", "sample-006", "sample-007"):
    case_path = case_dir / f"{sample_id}.json"
    if case_path.exists():
        raise SystemExit(f"ASSERT FAIL: 不应生成 {case_path}")
PY
}

assert_empty_export_contract() {
	python3 - "$EMPTY_REPORT_DIR" <<'PY'
import pathlib
import sys

empty_report_dir = pathlib.Path(sys.argv[1]).resolve()
case_dir = empty_report_dir / "case_studies"
index_path = case_dir / "index.tsv"

lines = index_path.read_text(encoding="utf-8").splitlines()
expected_header = "sample_id\tsemantic_outcome\tselection_reason\tcase_study_path"
if lines != [expected_header]:
    raise SystemExit(
        f"ASSERT FAIL: 空 case_study index 只能包含表头: actual={lines!r} expected={[expected_header]!r}"
    )

json_files = sorted(path.name for path in case_dir.glob("*.json"))
if json_files:
    raise SystemExit(
        f"ASSERT FAIL: 空 case-study-export 不应生成 JSON 产物，实际 {json_files!r}"
    )
PY
}

write_main_fixture_root
write_empty_fixture_root

run_cli case-study-export --root "$FOLLOW_ROOT" --campaign-report-dir "$CAMPAIGN_REPORT_DIR" --top-n 5 >/dev/null
assert_file_exists "$CAMPAIGN_REPORT_DIR/case_studies/index.tsv"
assert_file_exists "$CAMPAIGN_REPORT_DIR/case_studies/sample-001.json"
assert_file_exists "$CAMPAIGN_REPORT_DIR/case_studies/sample-005.json"
assert_file_not_exists "$CAMPAIGN_REPORT_DIR/case_studies/sample-006.json"
assert_case_study_contract

run_cli case-study-export --root "$EMPTY_ROOT" --campaign-report-dir "$EMPTY_REPORT_DIR" >/dev/null
assert_file_exists "$EMPTY_REPORT_DIR/case_studies/index.tsv"
assert_empty_export_contract

printf 'PASS: case study export contract test passed\n'
