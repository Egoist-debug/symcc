#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-multi-run-aggregate.XXXXXX")"
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

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

run_cli() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		python3 -m tools.dns_diff.cli "$@"
}

get_latest_aggregate_dir() {
	local aggregate_base="$1"
	python3 - "$aggregate_base" <<'PY'
from pathlib import Path
import sys

base = Path(sys.argv[1])
if not base.exists() or not base.is_dir():
    raise SystemExit(f"ASSERT FAIL: 聚合目录不存在 {base}")

dirs = sorted(path for path in base.iterdir() if path.is_dir())
if not dirs:
    raise SystemExit(f"ASSERT FAIL: 期望 {base} 下至少有 1 个聚合目录")
print(dirs[-1])
PY
}

write_summary() {
	local run_dir="$1"
	local payload_json="$2"
	python3 - "$run_dir" "$payload_json" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
payload = json.loads(sys.argv[2])
run_dir.mkdir(parents=True, exist_ok=True)
(run_dir / "summary.json").write_text(
    json.dumps(payload, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
PY
}

assert_summary_status() {
	local summary_path="$1"
	local expected_run_count="$2"
	local expected_status="$3"
	python3 - "$summary_path" "$expected_run_count" "$expected_status" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_run_count = int(sys.argv[2])
expected_status = sys.argv[3]

if summary.get("run_count") != expected_run_count:
    raise SystemExit(
        f"ASSERT FAIL: run_count={summary.get('run_count')!r} != {expected_run_count!r}"
    )

if summary.get("variance_status") != expected_status:
    raise SystemExit(
        "ASSERT FAIL: variance_status="
        f"{summary.get('variance_status')!r} != {expected_status!r}"
    )

metrics = summary.get("aggregate_metrics")
expected_metrics = [
    "total_samples",
    "included_samples",
    "excluded_samples",
    "unknown_samples",
    "needs_review_count",
    "cluster_count",
    "repro_rate",
    "oracle_audit_candidate_count",
    "semantic_diff_count",
]
if metrics != expected_metrics:
    raise SystemExit(
        f"ASSERT FAIL: aggregate_metrics={metrics!r} != {expected_metrics!r}"
    )
PY
}

assert_variance_ok_payload() {
	local summary_path="$1"
	python3 - "$summary_path" <<'PY'
import json
import math
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
aggregates = summary.get("aggregates")
if not isinstance(aggregates, dict):
    raise SystemExit("ASSERT FAIL: summary.aggregates 应为对象")

required_metrics = {
    "total_samples",
    "included_samples",
    "excluded_samples",
    "unknown_samples",
    "needs_review_count",
    "cluster_count",
    "repro_rate",
    "oracle_audit_candidate_count",
    "semantic_diff_count",
}
if set(aggregates.keys()) != required_metrics:
    raise SystemExit(
        f"ASSERT FAIL: aggregates keys={set(aggregates.keys())!r} != {required_metrics!r}"
    )

total = aggregates["total_samples"]
if abs(float(total.get("mean", -1)) - 15.0) > 1e-9:
    raise SystemExit(f"ASSERT FAIL: total_samples.mean 非预期: {total!r}")
if abs(float(total.get("min", -1)) - 10.0) > 1e-9:
    raise SystemExit(f"ASSERT FAIL: total_samples.min 非预期: {total!r}")
if abs(float(total.get("max", -1)) - 20.0) > 1e-9:
    raise SystemExit(f"ASSERT FAIL: total_samples.max 非预期: {total!r}")
if abs(float(total.get("stddev", -1)) - 5.0) > 1e-9:
    raise SystemExit(f"ASSERT FAIL: total_samples.stddev 非预期: {total!r}")

repro = aggregates["repro_rate"]
if abs(float(repro.get("mean", -1)) - 0.5) > 1e-9:
    raise SystemExit(f"ASSERT FAIL: repro_rate.mean 非预期: {repro!r}")
if abs(float(repro.get("stddev", -1)) - 0.3) > 1e-9:
    raise SystemExit(f"ASSERT FAIL: repro_rate.stddev 非预期: {repro!r}")
PY
}

COMMON_KEY='{"resolver_pair":"bind9_vs_unbound","producer_profile":"poison-stateful","input_model":"DST1 transcript","source_queue_dir":"/tmp/follow/queue","budget_sec":5,"seed_timeout_sec":1,"variant_name":"control","ablation_status":{"mutator":"off","cache-delta":"on","triage":"on","symcc":"on"},"contract_version":1}'
BASELINE_KEY='{"resolver_pair":"bind9_vs_unbound","producer_profile":"poison-stateful","input_model":"DST1 transcript","source_queue_dir":"/tmp/follow/queue","budget_sec":5,"seed_timeout_sec":1,"repeat_count":3,"contract_version":1}'
ALT_KEY='{"resolver_pair":"bind9_vs_unbound","producer_profile":"poison-stateful","input_model":"DST1 transcript","source_queue_dir":"/tmp/follow/queue","budget_sec":30,"seed_timeout_sec":1,"variant_name":"control","ablation_status":{"mutator":"off","cache-delta":"on","triage":"on","symcc":"on"},"contract_version":1}'

MIX_ROOT="$WORKDIR/mixed/campaign_reports"
mkdir -p "$MIX_ROOT"
write_summary "$MIX_ROOT/run-a" "{\"total_samples\":10,\"needs_review_count\":1,\"cluster_count\":2,\"repro_rate\":0.2,\"oracle_audit_candidate_count\":4,\"semantic_diff_count\":3,\"semantic_counts\":{\"no_diff\":7,\"cache_diff_interesting\":3},\"metric_denominators\":{\"analysis_state\":{\"included\":8,\"excluded\":1,\"unknown\":1}},\"comparability\":{\"status\":\"comparable\",\"reason\":\"ok\",\"aggregation_key\":$COMMON_KEY,\"baseline_compare_key\":$BASELINE_KEY}}"
write_summary "$MIX_ROOT/run-b" "{\"total_samples\":20,\"needs_review_count\":3,\"cluster_count\":5,\"repro_rate\":0.8,\"oracle_audit_candidate_count\":6,\"semantic_diff_count\":10,\"semantic_counts\":{\"no_diff\":10,\"cache_diff_interesting\":10},\"metric_denominators\":{\"analysis_state\":{\"included\":15,\"excluded\":3,\"unknown\":2}},\"comparability\":{\"status\":\"non_comparable\",\"reason\":\"aggregation_key_conflict\",\"aggregation_key\":$ALT_KEY,\"baseline_compare_key\":$BASELINE_KEY,\"aggregation_key_conflict_fields\":[\"budget_sec\"]}}"

MIX_STDERR="$WORKDIR/mixed.stderr"
if run_cli campaign-aggregate --reports-root "$MIX_ROOT" --output-dir "$WORKDIR/mixed/out" >/dev/null 2>"$MIX_STDERR"; then
	printf 'ASSERT FAIL: mixed aggregation_key 场景应返回非零\n' >&2
	exit 1
fi
assert_file_contains "$MIX_STDERR" "campaign-aggregate 失败"
assert_file_contains "$MIX_STDERR" "comparability.aggregation_key"

MIX_LATEST="$(get_latest_aggregate_dir "$WORKDIR/mixed/out/campaign_aggregates")"
assert_file_exists "$MIX_LATEST/summary.json"
assert_file_exists "$MIX_LATEST/run_matrix.tsv"
assert_file_exists "$MIX_LATEST/variance.tsv"
assert_file_exists "$MIX_LATEST/comparability.tsv"
assert_summary_status "$MIX_LATEST/summary.json" 2 "incompatible_aggregation_key"
assert_file_contains "$MIX_LATEST/comparability.tsv" "run-a"
assert_file_contains "$MIX_LATEST/comparability.tsv" "run-b"
assert_file_contains "$MIX_LATEST/comparability.tsv" "budget_sec"
assert_file_contains "$MIX_LATEST/variance.tsv" $'__status__\tincompatible_aggregation_key'

MISSING_ROOT="$WORKDIR/missing/campaign_reports"
mkdir -p "$MISSING_ROOT"
write_summary "$MISSING_ROOT/run-a" "{\"total_samples\":9,\"needs_review_count\":1,\"cluster_count\":2,\"repro_rate\":0.1,\"oracle_audit_candidate_count\":2,\"semantic_diff_count\":1,\"semantic_counts\":{\"no_diff\":8,\"cache_diff_interesting\":1},\"metric_denominators\":{\"analysis_state\":{\"included\":7,\"excluded\":1,\"unknown\":1}}}"
write_summary "$MISSING_ROOT/run-b" "{\"total_samples\":11,\"needs_review_count\":2,\"cluster_count\":3,\"repro_rate\":0.2,\"oracle_audit_candidate_count\":3,\"semantic_diff_count\":2,\"semantic_counts\":{\"no_diff\":9,\"cache_diff_interesting\":2},\"metric_denominators\":{\"analysis_state\":{\"included\":9,\"excluded\":1,\"unknown\":1}}}"

MISSING_STDERR="$WORKDIR/missing.stderr"
if run_cli campaign-aggregate --reports-root "$MISSING_ROOT" --output-dir "$WORKDIR/missing/out" >/dev/null 2>"$MISSING_STDERR"; then
	printf 'ASSERT FAIL: 缺失 comparability 元数据场景应返回非零\n' >&2
	exit 1
fi
assert_file_contains "$MISSING_STDERR" "campaign-aggregate 失败"
assert_file_contains "$MISSING_STDERR" "缺失 comparability 元数据"

MISSING_LATEST="$(get_latest_aggregate_dir "$WORKDIR/missing/out/campaign_aggregates")"
assert_file_exists "$MISSING_LATEST/summary.json"
assert_file_exists "$MISSING_LATEST/run_matrix.tsv"
assert_file_exists "$MISSING_LATEST/variance.tsv"
assert_file_exists "$MISSING_LATEST/comparability.tsv"
assert_summary_status "$MISSING_LATEST/summary.json" 2 "missing_comparability_metadata"
assert_file_contains "$MISSING_LATEST/comparability.tsv" "run-a"
assert_file_contains "$MISSING_LATEST/comparability.tsv" "run-b"
assert_file_contains "$MISSING_LATEST/comparability.tsv" "<null>"
assert_file_contains "$MISSING_LATEST/variance.tsv" $'__status__\tmissing_comparability_metadata'

DRIFT_ROOT="$WORKDIR/drift/campaign_reports"
mkdir -p "$DRIFT_ROOT"
write_summary "$DRIFT_ROOT/run-a" "{\"total_samples\":12,\"needs_review_count\":2,\"cluster_count\":3,\"repro_rate\":0.4,\"oracle_audit_candidate_count\":5,\"semantic_counts\":{\"no_diff\":11,\"cache_diff_interesting\":1},\"metric_denominators\":{\"analysis_state\":{\"included\":9,\"excluded\":2,\"unknown\":1}},\"comparability\":{\"status\":\"comparable\",\"reason\":\"ok\",\"aggregation_key\":$COMMON_KEY,\"baseline_compare_key\":$BASELINE_KEY}}"
write_summary "$DRIFT_ROOT/run-b" "{\"total_samples\":13,\"needs_review_count\":2,\"cluster_count\":4,\"repro_rate\":0.5,\"semantic_diff_count\":1,\"semantic_counts\":{\"no_diff\":12,\"cache_diff_interesting\":1},\"metric_denominators\":{\"analysis_state\":{\"included\":10,\"excluded\":2,\"unknown\":1}},\"comparability\":{\"status\":\"comparable\",\"reason\":\"ok\",\"aggregation_key\":$COMMON_KEY,\"baseline_compare_key\":$BASELINE_KEY}}"

DRIFT_STDERR="$WORKDIR/drift.stderr"
if run_cli campaign-aggregate --reports-root "$DRIFT_ROOT" --output-dir "$WORKDIR/drift/out" >/dev/null 2>"$DRIFT_STDERR"; then
	printf 'ASSERT FAIL: 缺失 canonical 指标字段场景应返回非零\n' >&2
	exit 1
fi
assert_file_contains "$DRIFT_STDERR" "campaign-aggregate 失败"
assert_file_contains "$DRIFT_STDERR" "缺失 canonical 指标字段"

DRIFT_LATEST="$(get_latest_aggregate_dir "$WORKDIR/drift/out/campaign_aggregates")"
assert_file_exists "$DRIFT_LATEST/summary.json"
assert_file_exists "$DRIFT_LATEST/run_matrix.tsv"
assert_file_exists "$DRIFT_LATEST/variance.tsv"
assert_file_exists "$DRIFT_LATEST/comparability.tsv"
assert_summary_status "$DRIFT_LATEST/summary.json" 2 "missing_canonical_metrics"
assert_file_contains "$DRIFT_LATEST/run_matrix.tsv" $'run-a\t'
assert_file_contains "$DRIFT_LATEST/run_matrix.tsv" $'run-b\t'
assert_file_contains "$DRIFT_LATEST/run_matrix.tsv" $'\tNA'
assert_file_contains "$DRIFT_LATEST/variance.tsv" $'__status__\tmissing_canonical_metrics'

OK_ROOT="$WORKDIR/ok/campaign_reports"
mkdir -p "$OK_ROOT"
write_summary "$OK_ROOT/run-1" "{\"total_samples\":10,\"needs_review_count\":1,\"cluster_count\":2,\"repro_rate\":0.2,\"oracle_audit_candidate_count\":4,\"semantic_diff_count\":3,\"semantic_counts\":{\"no_diff\":7,\"cache_diff_interesting\":3},\"metric_denominators\":{\"analysis_state\":{\"included\":8,\"excluded\":1,\"unknown\":1}},\"comparability\":{\"status\":\"comparable\",\"reason\":\"ok\",\"aggregation_key\":$COMMON_KEY,\"baseline_compare_key\":$BASELINE_KEY}}"
write_summary "$OK_ROOT/run-2" "{\"total_samples\":20,\"needs_review_count\":3,\"cluster_count\":5,\"repro_rate\":0.8,\"oracle_audit_candidate_count\":6,\"semantic_diff_count\":10,\"semantic_counts\":{\"no_diff\":10,\"cache_diff_interesting\":10},\"metric_denominators\":{\"analysis_state\":{\"included\":15,\"excluded\":3,\"unknown\":2}},\"comparability\":{\"status\":\"comparable\",\"reason\":\"ok\",\"aggregation_key\":$COMMON_KEY,\"baseline_compare_key\":$BASELINE_KEY}}"

run_cli campaign-aggregate --reports-root "$OK_ROOT" --output-dir "$WORKDIR/ok/out" >/dev/null
OK_LATEST="$(get_latest_aggregate_dir "$WORKDIR/ok/out/campaign_aggregates")"
assert_file_exists "$OK_LATEST/summary.json"
assert_file_exists "$OK_LATEST/run_matrix.tsv"
assert_file_exists "$OK_LATEST/variance.tsv"
assert_file_exists "$OK_LATEST/comparability.tsv"
assert_summary_status "$OK_LATEST/summary.json" 2 "ok"
assert_variance_ok_payload "$OK_LATEST/summary.json"
assert_file_contains "$OK_LATEST/run_matrix.tsv" $'run_id\tsummary_path\ttotal_samples'
assert_file_contains "$OK_LATEST/variance.tsv" $'metric\tmean\tmin\tmax\tstddev'
assert_file_contains "$OK_LATEST/variance.tsv" "oracle_audit_candidate_count"
assert_file_contains "$OK_LATEST/variance.tsv" "semantic_diff_count"

ONE_ROOT="$WORKDIR/one/campaign_reports"
mkdir -p "$ONE_ROOT"
write_summary "$ONE_ROOT/run-only" "{\"total_samples\":12,\"needs_review_count\":2,\"cluster_count\":3,\"repro_rate\":0.4,\"oracle_audit_candidate_count\":5,\"semantic_diff_count\":1,\"semantic_counts\":{\"no_diff\":11,\"cache_diff_interesting\":1},\"metric_denominators\":{\"analysis_state\":{\"included\":9,\"excluded\":2,\"unknown\":1}},\"comparability\":{\"status\":\"comparable\",\"reason\":\"ok\",\"aggregation_key\":$COMMON_KEY,\"baseline_compare_key\":$BASELINE_KEY}}"

run_cli campaign-aggregate --reports-root "$ONE_ROOT" --output-dir "$WORKDIR/one/out" >/dev/null
ONE_LATEST="$(get_latest_aggregate_dir "$WORKDIR/one/out/campaign_aggregates")"
assert_file_exists "$ONE_LATEST/summary.json"
assert_file_exists "$ONE_LATEST/run_matrix.tsv"
assert_file_exists "$ONE_LATEST/variance.tsv"
assert_file_exists "$ONE_LATEST/comparability.tsv"
assert_summary_status "$ONE_LATEST/summary.json" 1 "insufficient_runs"
assert_file_contains "$ONE_LATEST/variance.tsv" $'__status__\tinsufficient_runs'

printf 'PASS: multi-run aggregate regression test passed\n'
