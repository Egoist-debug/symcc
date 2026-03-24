#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

python3 - <<'PY'
from copy import deepcopy

from tools.dns_diff.schema import build_run_comparability_payload


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ASSERT FAIL: {message}")


def build_sample(
    sample_id: str,
    *,
    variant_name: str = "control",
    ablation_status: dict | None = None,
    budget_sec: int = 5,
    repeat_count: int = 3,
) -> dict:
    if ablation_status is None:
        ablation_status = {
            "mutator": "off",
            "cache-delta": "on",
            "triage": "on",
            "symcc": "on",
        }

    return {
        "sample_id": sample_id,
        "aggregation_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": "poison-stateful",
            "input_model": "DST1 transcript",
            "source_queue_dir": "/tmp/follow/queue",
            "budget_sec": budget_sec,
            "seed_timeout_sec": 1,
            "variant_name": variant_name,
            "ablation_status": deepcopy(ablation_status),
            "contract_version": 1,
        },
        "baseline_compare_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": "poison-stateful",
            "input_model": "DST1 transcript",
            "source_queue_dir": "/tmp/follow/queue",
            "budget_sec": budget_sec,
            "seed_timeout_sec": 1,
            "repeat_count": repeat_count,
            "contract_version": 1,
        },
    }


# 1) 缺失 comparability 字段必须拒绝，不能默认可比。
missing = build_sample("missing")
del missing["aggregation_key"]
missing_result = build_run_comparability_payload([missing])
assert_true(
    missing_result.get("status") == "non_comparable",
    f"缺字段场景 status 非法: {missing_result!r}",
)
assert_true(
    missing_result.get("reason") == "missing_comparability_fields",
    f"缺字段场景 reason 非法: {missing_result!r}",
)
assert_true(
    missing_result.get("non_comparable_sample_ids") == ["missing"],
    f"缺字段场景 non_comparable_sample_ids 非法: {missing_result!r}",
)
issue = missing_result.get("issues", [{}])[0]
assert_true(
    isinstance(issue, dict)
    and "missing_aggregation_key_fields" in issue
    and "resolver_pair" in issue["missing_aggregation_key_fields"],
    f"缺字段场景 issue 未给出 aggregation_key 缺失详情: {missing_result!r}",
)


# 2) aggregation_key 真冲突必须拒绝。
left = build_sample("left")
right = build_sample("right", budget_sec=30)
conflict_result = build_run_comparability_payload([left, right])
assert_true(
    conflict_result.get("status") == "non_comparable",
    f"aggregation_key 冲突场景 status 非法: {conflict_result!r}",
)
assert_true(
    conflict_result.get("reason") == "aggregation_key_conflict",
    f"aggregation_key 冲突场景 reason 非法: {conflict_result!r}",
)
assert_true(
    not conflict_result.get("baseline_comparable"),
    f"budget_sec 冲突时 baseline_comparable 不应为 true: {conflict_result!r}",
)
assert_true(
    "budget_sec" in conflict_result.get("aggregation_key_conflict_fields", []),
    f"aggregation_key 冲突场景未标记 budget_sec: {conflict_result!r}",
)
assert_true(
    "budget_sec" in conflict_result.get("baseline_compare_key_conflict_fields", []),
    f"baseline_compare_key 冲突场景未标记 budget_sec: {conflict_result!r}",
)


# 3) 仅 variant_name / ablation_status 差异时，整体聚合仍 non-comparable，
#    但 baseline_compare_key 一致，必须允许后续 baseline comparator 语义。
control = build_sample("control")
ablation = build_sample(
    "ablation",
    variant_name="cache-delta-off",
    ablation_status={
        "mutator": "off",
        "cache-delta": "off",
        "triage": "on",
        "symcc": "on",
    },
)
baseline_result = build_run_comparability_payload([control, ablation])
assert_true(
    baseline_result.get("status") == "non_comparable",
    f"variant/ablation 差异场景 status 非法: {baseline_result!r}",
)
assert_true(
    baseline_result.get("reason") == "aggregation_key_conflict",
    f"variant/ablation 差异场景 reason 非法: {baseline_result!r}",
)
assert_true(
    not baseline_result.get("aggregation_comparable"),
    f"variant/ablation 差异场景 aggregation_comparable 不应为 true: {baseline_result!r}",
)
assert_true(
    baseline_result.get("baseline_comparable"),
    f"variant/ablation 差异场景应保留 baseline_comparable=true: {baseline_result!r}",
)
assert_true(
    set(baseline_result.get("aggregation_key_conflict_fields", []))
    == {"variant_name", "ablation_status"},
    f"variant/ablation 差异应仅标记这两个冲突字段: {baseline_result!r}",
)
assert_true(
    baseline_result.get("aggregation_key") is None,
    f"variant/ablation 差异场景 aggregation_key 应为 null: {baseline_result!r}",
)
assert_true(
    baseline_result.get("baseline_compare_key") == control["baseline_compare_key"]
    == ablation["baseline_compare_key"],
    f"variant/ablation 差异场景 baseline_compare_key 应保持一致: {baseline_result!r}",
)

print("PASS: run comparability contract test passed")
PY
