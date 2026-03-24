#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-evidence-bundle.XXXXXX")"
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

write_fixtures() {
	python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sample_meta(sample_id: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-03-24T00:00:00Z",
        "sample_id": sample_id,
        "contract_version": 1,
        "aggregation_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": "poison-stateful",
            "input_model": "DST1 transcript",
            "source_queue_dir": "/tmp/follow/queue",
            "budget_sec": 5,
            "seed_timeout_sec": 1,
            "variant_name": "control",
            "ablation_status": {
                "mutator": "off",
                "cache-delta": "on",
                "triage": "on",
                "symcc": "on",
            },
            "contract_version": 1,
        },
        "baseline_compare_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": "poison-stateful",
            "input_model": "DST1 transcript",
            "source_queue_dir": "/tmp/follow/queue",
            "budget_sec": 5,
            "seed_timeout_sec": 1,
            "repeat_count": 3,
            "contract_version": 1,
        },
    }


fixtures = {
    "sample-001": {
        "triage.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "sample-001",
            "status": "completed_oracle_diff",
            "diff_class": "oracle_diff",
            "analysis_state": "included",
            "exclude_reason": None,
            "semantic_outcome": "oracle_diff",
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "semantic_diff",
            "failure_bucket_detail": "oracle_diff",
            "oracle_audit_candidate": True,
            "case_study_candidate": True,
            "manual_truth_status": "not_started",
            "filter_labels": ["oracle_diff"],
            "cluster_key": "cluster-a",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": True,
            "notes": ["oracle 字段存在差异"],
        },
        "oracle.json": {
            "bind9.parse_ok": True,
            "unbound.parse_ok": False,
            "bind9.response_accepted": True,
            "unbound.response_accepted": False,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
        },
        "cache_diff.json": {
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
        },
    },
    "sample-002": {
        "triage.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "sample-002",
            "status": "failed_replay",
            "diff_class": "replay_incomplete",
            "analysis_state": "excluded",
            "exclude_reason": "infra_artifact_failure",
            "semantic_outcome": "replay_missing_artifact",
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "infra_artifact_failure",
            "failure_bucket_detail": "replay_missing_artifact",
            "oracle_audit_candidate": False,
            "case_study_candidate": False,
            "manual_truth_status": "not_applicable",
            "filter_labels": ["replay_missing_artifact"],
            "cluster_key": "cluster-b",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": True,
            "notes": ["缺少 replay 工件"],
        },
        "oracle.json": {
            "bind9.parse_ok": None,
            "unbound.parse_ok": None,
            "bind9.response_accepted": None,
            "unbound.response_accepted": None,
            "bind9.second_query_hit": None,
            "unbound.second_query_hit": None,
            "bind9.cache_entry_created": None,
            "unbound.cache_entry_created": None,
        },
        "cache_diff.json": {
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
        },
    },
    "sample-003": {
        "triage.json": {
            "schema_version": 1,
            "generated_at": "2026-03-24T00:00:00Z",
            "sample_id": "sample-003",
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
            "cluster_key": "cluster-c",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": True,
            "notes": ["oracle 解析不完整"],
        },
        "oracle.json": {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "missing_summary",
        },
        "cache_diff.json": {
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
        },
    },
}

for sample_id, files in fixtures.items():
    sample_dir = root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    write_json(sample_dir / "sample.meta.json", sample_meta(sample_id))
    for filename, payload in files.items():
        write_json(sample_dir / filename, payload)
    (sample_dir / "sample.bin").write_bytes(b"\x00\x01\x02\x03")
    (sample_dir / "bind9.stderr").write_text("bind9 stderr\n", encoding="utf-8")
    (sample_dir / "unbound.stderr").write_text("unbound stderr\n", encoding="utf-8")

(root / "high_value_samples.txt").write_text(
    str((root / "sample-001" / "sample.bin").resolve()) + "\n",
    encoding="utf-8",
)
PY
}

assert_evidence_bundle_contract() {
	local report_dir="$1"
	python3 - "$report_dir" "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

report_dir = pathlib.Path(sys.argv[1]).resolve()
follow_root = pathlib.Path(sys.argv[2]).resolve()
bundle = json.loads((report_dir / "evidence_bundle.json").read_text(encoding="utf-8"))

required_keys = {
    "contract_name",
    "contract_version",
    "campaign_summary",
    "oracle_audit",
    "oracle_reliability",
    "failure_taxonomy",
    "exclusion_summary",
    "case_study_index",
    "raw_sample_root",
    "regeneration_commands",
    "claims",
}
missing = required_keys - set(bundle.keys())
if missing:
    raise SystemExit(f"ASSERT FAIL: evidence_bundle.json 缺少字段 {sorted(missing)!r}")

if bundle["contract_name"] != "publication_evidence_bundle":
    raise SystemExit(
        f"ASSERT FAIL: contract_name={bundle['contract_name']!r} != 'publication_evidence_bundle'"
    )
if bundle["contract_version"] != 1:
    raise SystemExit(
        f"ASSERT FAIL: contract_version={bundle['contract_version']!r} != 1"
    )

expected_paths = {
    "campaign_summary": report_dir / "summary.json",
    "oracle_audit": report_dir / "oracle_audit.tsv",
    "oracle_reliability": report_dir / "oracle_reliability.json",
    "failure_taxonomy": report_dir / "failure_taxonomy.tsv",
    "exclusion_summary": report_dir / "exclusion_summary.tsv",
    "case_study_index": report_dir / "case_studies" / "index.tsv",
}
for key, expected_path in expected_paths.items():
    actual_path = pathlib.Path(bundle[key]["path"]).resolve()
    if actual_path != expected_path.resolve():
        raise SystemExit(
            f"ASSERT FAIL: {key}.path={actual_path!s} != {expected_path!s}"
        )

if bundle["case_study_index"].get("exists") is not False:
    raise SystemExit("ASSERT FAIL: 未执行 case-study-export 时 case_study_index.exists 应为 false")
if bundle["case_study_index"].get("optional") is not True:
    raise SystemExit("ASSERT FAIL: case_study_index.optional 应为 true")

raw_sample_root = bundle["raw_sample_root"]
if pathlib.Path(raw_sample_root["path"]).resolve() != follow_root:
    raise SystemExit("ASSERT FAIL: raw_sample_root.path 不符合 follow_root")
if raw_sample_root.get("exists") is not True:
    raise SystemExit("ASSERT FAIL: raw_sample_root.exists 应为 true")

commands = bundle["regeneration_commands"]
for key in ("triage_rewrite", "triage_report", "campaign_report", "case_study_export"):
    value = commands.get(key)
    if not isinstance(value, str) or not value:
        raise SystemExit(f"ASSERT FAIL: regeneration_commands.{key} 应为非空字符串")
    if str(follow_root) not in value:
        raise SystemExit(f"ASSERT FAIL: regeneration_commands.{key} 未引用 root 路径")

summary = json.loads((report_dir / "summary.json").read_text(encoding="utf-8"))
if summary.get("semantic_diff_count") != 1:
    raise SystemExit(
        f"ASSERT FAIL: summary.semantic_diff_count={summary.get('semantic_diff_count')!r} != 1"
    )

claims = bundle["claims"]
if not isinstance(claims, list) or not claims:
    raise SystemExit("ASSERT FAIL: claims 应为非空数组")

claim_map = {item.get("claim"): item for item in claims}
required_claims = {
    "semantic_diff_count": (1, "semantic_diff_count"),
    "included_samples": (1, "metric_denominators.analysis_state.included"),
    "excluded_samples": (1, "metric_denominators.analysis_state.excluded"),
    "unknown_samples": (1, "metric_denominators.analysis_state.unknown"),
    "repro_rate": (1.0, "repro_rate"),
    "cluster_count": (3, "cluster_count"),
}
if set(required_claims) - set(claim_map):
    raise SystemExit(
        f"ASSERT FAIL: 缺少 claim {sorted(set(required_claims) - set(claim_map))!r}"
    )

summary_path = (report_dir / "summary.json").resolve()
for claim_name, (expected_value, expected_field_path) in required_claims.items():
    payload = claim_map[claim_name]
    if pathlib.Path(payload.get("source_file_path", "")).resolve() != summary_path:
        raise SystemExit(f"ASSERT FAIL: {claim_name}.source_file_path 应指向 summary.json")
    if payload.get("field_path") != expected_field_path:
        raise SystemExit(
            f"ASSERT FAIL: {claim_name}.field_path={payload.get('field_path')!r} != {expected_field_path!r}"
        )
    if payload.get("regeneration_command") != commands["campaign_report"]:
        raise SystemExit(f"ASSERT FAIL: {claim_name}.regeneration_command 应复用 campaign_report 命令")
    if payload.get("artifact") != "campaign_summary":
        raise SystemExit(f"ASSERT FAIL: {claim_name}.artifact 应为 campaign_summary")
    actual_value = payload.get("value")
    if isinstance(expected_value, float):
        if not isinstance(actual_value, (int, float)) or abs(float(actual_value) - expected_value) > 1e-9:
            raise SystemExit(
                f"ASSERT FAIL: {claim_name}.value={actual_value!r} != {expected_value!r}"
            )
    elif actual_value != expected_value:
        raise SystemExit(
            f"ASSERT FAIL: {claim_name}.value={actual_value!r} != {expected_value!r}"
        )
    guardrail = payload.get("guardrail")
    if not isinstance(guardrail, str) or not guardrail:
        raise SystemExit(f"ASSERT FAIL: {claim_name}.guardrail 应为非空字符串")

semantic_support = claim_map["semantic_diff_count"].get("supporting_sources")
if not isinstance(semantic_support, list) or len(semantic_support) != 1:
    raise SystemExit("ASSERT FAIL: semantic_diff_count.supporting_sources 应包含 1 条 failure_taxonomy 来源")
support = semantic_support[0]
if pathlib.Path(support.get("source_file_path", "")).resolve() != (report_dir / "failure_taxonomy.tsv").resolve():
    raise SystemExit("ASSERT FAIL: semantic_diff_count 的辅助来源应指向 failure_taxonomy.tsv")
if support.get("field_path") != "rows[failure_bucket_primary=semantic_diff].count(sum)":
    raise SystemExit("ASSERT FAIL: semantic_diff_count 的辅助 field_path 不符合预期")
PY
}

write_fixtures
run_cli campaign-report --root "$FOLLOW_ROOT" >/dev/null
REPORT_DIR="$(get_latest_report_dir "$FOLLOW_ROOT/campaign_reports")"

if [ ! -f "$REPORT_DIR/evidence_bundle.json" ]; then
	printf 'ASSERT FAIL: 缺少文件 %s\n' "$REPORT_DIR/evidence_bundle.json" >&2
	exit 1
fi

assert_evidence_bundle_contract "$REPORT_DIR"

printf 'PASS: publication evidence bundle regression test passed\n'
