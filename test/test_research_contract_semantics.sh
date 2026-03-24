#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

python3 - <<'PY'
from tools.dns_diff.schema import (
    AGGREGATION_KEY_FIELDS,
    BASELINE_COMPARE_KEY_FIELDS,
    CONTRACT_VERSION,
    apply_sample_meta_contract_defaults,
    build_sample_meta_payload,
    validate_sample_meta_fields,
)


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ASSERT FAIL: {message}")


FROZEN_PRODUCER_PROFILE = "poison-stateful"
FROZEN_INPUT_MODEL = "DST1 transcript"


def legacy_fixture(status: str = "completed"):
    return {
        "schema_version": 1,
        "generated_at": "2026-03-24T00:00:00Z",
        "sample_id": "id:000001,orig:seed__deadbeef",
        "queue_event_id": "id:000001,orig:seed",
        "source_queue_file": "/tmp/queue/id:000001,orig:seed",
        "source_resolver": "bind9",
        "sample_sha1": "a" * 40,
        "sample_size": 4,
        "is_stateful": True,
        "afl_tags": ["+cov"],
        "first_seen_ts": "2026-03-24T00:00:00Z",
        "status": status,
    }


# 1) 旧 artifact 缺字段时，必须回落 unknown/null，且不能默认 included。
legacy = legacy_fixture()
normalized_legacy = apply_sample_meta_contract_defaults(legacy)
assert_true(
    normalized_legacy.get("analysis_state") == "unknown",
    "legacy analysis_state 必须默认 unknown",
)
assert_true(
    normalized_legacy.get("exclude_reason") is None,
    "legacy exclude_reason 必须默认 null",
)
assert_true(
    normalized_legacy.get("contract_version") == 1,
    "legacy contract_version 必须从 schema_version 回填",
)
assert_true(
    normalized_legacy.get("analysis_state") != "included",
    "legacy 缺字段不得静默计入 included",
)

legacy_errors = validate_sample_meta_fields(legacy)
assert_true(not legacy_errors, f"legacy 载入后不应校验失败: {legacy_errors!r}")


# 2) 冻结 aggregation_key / baseline_compare_key 组成差异。
expected_aggregation_fields = (
    "resolver_pair",
    "producer_profile",
    "input_model",
    "source_queue_dir",
    "budget_sec",
    "seed_timeout_sec",
    "variant_name",
    "ablation_status",
    "contract_version",
)
expected_baseline_fields = (
    "resolver_pair",
    "producer_profile",
    "input_model",
    "source_queue_dir",
    "budget_sec",
    "seed_timeout_sec",
    "repeat_count",
    "contract_version",
)
assert_true(
    tuple(AGGREGATION_KEY_FIELDS) == expected_aggregation_fields,
    "aggregation_key 字段集合与冻结契约不一致",
)
assert_true(
    tuple(BASELINE_COMPARE_KEY_FIELDS) == expected_baseline_fields,
    "baseline_compare_key 字段集合与冻结契约不一致",
)
assert_true(
    "variant_name" not in BASELINE_COMPARE_KEY_FIELDS
    and "ablation_status" not in BASELINE_COMPARE_KEY_FIELDS,
    "baseline_compare_key 不得包含 variant_name/ablation_status",
)


# 3) 构造新 payload，校验 contract_version 透传与 key 默认补齐。
payload = build_sample_meta_payload(
    sample_id="id:000002,orig:seed__facefeed",
    queue_event_id="id:000002,orig:seed",
    source_queue_file="/tmp/queue/id:000002,orig:seed",
    sample_sha1="b" * 40,
    sample_size=8,
    status="completed",
    source_resolver="unbound",
    is_stateful=False,
    afl_tags=[],
    generated_at="2026-03-24T00:00:00Z",
    first_seen_ts="2026-03-24T00:00:00Z",
    base_payload={
        "contract_version": 7,
        "analysis_state": "excluded",
        "exclude_reason": "manual_review",
        "aggregation_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": FROZEN_PRODUCER_PROFILE,
            "input_model": FROZEN_INPUT_MODEL,
        },
        "baseline_compare_key": {
            "producer_profile": FROZEN_PRODUCER_PROFILE,
            "input_model": FROZEN_INPUT_MODEL,
            "repeat_count": 3,
        },
    },
)
assert_true(payload.get("contract_version") == 7, "payload.contract_version 必须保持显式值")
assert_true(payload.get("analysis_state") == "excluded", "analysis_state 必须保持显式值")
assert_true(payload.get("exclude_reason") == "manual_review", "exclude_reason 必须保持显式值")

aggregation_key = payload.get("aggregation_key")
baseline_compare_key = payload.get("baseline_compare_key")
assert_true(isinstance(aggregation_key, dict), "aggregation_key 必须是对象")
assert_true(isinstance(baseline_compare_key, dict), "baseline_compare_key 必须是对象")
assert_true(
    set(aggregation_key.keys()) == set(expected_aggregation_fields),
    "aggregation_key 必须完整包含冻结字段",
)
assert_true(
    set(baseline_compare_key.keys()) == set(expected_baseline_fields),
    "baseline_compare_key 必须完整包含冻结字段",
)
assert_true(
    aggregation_key.get("contract_version") == 7
    and baseline_compare_key.get("contract_version") == 7,
    "两类 key 的 contract_version 必须与 payload 对齐",
)
assert_true(
    aggregation_key.get("producer_profile") == FROZEN_PRODUCER_PROFILE
    and baseline_compare_key.get("producer_profile") == FROZEN_PRODUCER_PROFILE,
    "两类 key 的 producer_profile 必须冻结为 poison-stateful",
)
assert_true(
    aggregation_key.get("input_model") == FROZEN_INPUT_MODEL
    and baseline_compare_key.get("input_model") == FROZEN_INPUT_MODEL,
    "两类 key 的 input_model 必须冻结为 DST1 transcript",
)
assert_true(
    "variant_name" not in baseline_compare_key
    and "ablation_status" not in baseline_compare_key,
    "baseline_compare_key 不应含 variant_name/ablation_status 字段",
)

payload_errors = validate_sample_meta_fields(payload)
assert_true(not payload_errors, f"新 payload 不应校验失败: {payload_errors!r}")


# 4) 排除态必须给出 exclude_reason。
invalid_excluded = legacy_fixture()
invalid_excluded["analysis_state"] = "excluded"
invalid_errors = validate_sample_meta_fields(invalid_excluded)
assert_true(
    any("analysis_state=excluded 时必须提供 exclude_reason" in msg for msg in invalid_errors),
    f"缺少排除理由时应明确报错，实际: {invalid_errors!r}",
)


# 5) sample.meta.json.failure 必须是嵌套字段（JSON 路径），不是独立文件名键。
failed_payload = build_sample_meta_payload(
    sample_id="id:000003,orig:seed__cafebabe",
    queue_event_id="id:000003,orig:seed",
    source_queue_file="/tmp/queue/id:000003,orig:seed",
    sample_sha1="c" * 40,
    sample_size=16,
    status="failed",
    source_resolver="bind9",
    is_stateful=True,
    afl_tags=["+cov"],
    generated_at="2026-03-24T00:00:00Z",
    first_seen_ts="2026-03-24T00:00:00Z",
    base_payload={
        "failure": {
            "kind": "replay_error",
            "reason": "timeout",
            "exit_code": 4,
        }
    },
)
assert_true(isinstance(failed_payload.get("failure"), dict), "failure 必须是 sample.meta.json 内嵌对象")
assert_true(
    "sample.meta.json.failure" not in failed_payload,
    "不得把 sample.meta.json.failure 当作独立字段名",
)
assert_true(CONTRACT_VERSION >= 1, "contract_version 常量必须为正整数")

print("PASS: research contract semantics test passed")
PY
