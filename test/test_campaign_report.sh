#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-campaign-report.XXXXXX")"
EMPTY_ROOT="$WORKDIR/empty-follow"
NONEMPTY_ROOT="$WORKDIR/nonempty-follow"
META_ONLY_ROOT="$WORKDIR/meta-only-follow"
FAIL_ROOT="$WORKDIR/fail-follow"
BAD_TRUTH_ROOT="$WORKDIR/bad-truth-follow"
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

assert_file_not_contains() {
	local path="$1"
	local unexpected="$2"
	if grep -Fq -- "$unexpected" "$path"; then
		printf 'ASSERT FAIL: 不期望 %s 包含: %s\n' "$path" "$unexpected" >&2
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

assert_summary_contract() {
	local summary_path="$1"
	local total_samples="$2"
	local needs_review_count="$3"
	local cluster_count="$4"
	local manifest_size="$5"
	local reproduced_count="$6"
	local repro_rate="$7"
	local oracle_audit_candidate_count="$8"
	local semantic_diff_count="$9"
	python3 - "$summary_path" "$total_samples" "$needs_review_count" "$cluster_count" "$manifest_size" "$reproduced_count" "$repro_rate" "$oracle_audit_candidate_count" "$semantic_diff_count" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "total_samples": int(sys.argv[2]),
    "needs_review_count": int(sys.argv[3]),
    "cluster_count": int(sys.argv[4]),
    "manifest_size": int(sys.argv[5]),
    "reproduced_count": int(sys.argv[6]),
    "repro_rate": float(sys.argv[7]),
    "oracle_audit_candidate_count": int(sys.argv[8]),
    "semantic_diff_count": int(sys.argv[9]),
}

for key, value in expected.items():
    actual = summary.get(key)
    if key == "repro_rate":
        if not isinstance(actual, (int, float)) or abs(float(actual) - value) > 1e-9:
            raise SystemExit(
                f"ASSERT FAIL: summary[{key!r}] 期望 {value!r}，实际 {actual!r}"
            )
        continue
    if actual != value:
        raise SystemExit(
            f"ASSERT FAIL: summary[{key!r}] 期望 {value!r}，实际 {actual!r}"
        )

campaign_id = summary.get("campaign_id")
if not isinstance(campaign_id, str) or not campaign_id:
    raise SystemExit("ASSERT FAIL: summary.campaign_id 应为非空字符串")

ablation = summary.get("ablation_status")
expected_ablation = {
    "mutator": "off",
    "cache-delta": "on",
    "triage": "on",
    "symcc": "on",
}
if ablation != expected_ablation:
    raise SystemExit(
        f"ASSERT FAIL: summary.ablation_status 期望 {expected_ablation!r}，实际 {ablation!r}"
    )
PY
}

assert_summary_metadata_contract() {
	local summary_path="$1"
	local scenario="$2"
	python3 - "$summary_path" "$scenario" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
scenario = sys.argv[2]

if summary.get("contract_version") != 1:
    raise SystemExit(
        f"ASSERT FAIL: summary.contract_version={summary.get('contract_version')!r} != 1"
    )

metric_denominators = summary.get("metric_denominators")
if not isinstance(metric_denominators, dict):
    raise SystemExit("ASSERT FAIL: summary.metric_denominators 应为对象")

comparability = summary.get("comparability")
if not isinstance(comparability, dict):
    raise SystemExit("ASSERT FAIL: summary.comparability 应为对象")

if scenario == "empty":
    expected_denominators = {
        "total_samples": 0,
        "analysis_state": {"included": 0, "excluded": 0, "unknown": 0},
        "comparable_samples": 0,
        "non_comparable_samples": 0,
    }
    if metric_denominators != expected_denominators:
        raise SystemExit(
            f"ASSERT FAIL: 空 root metric_denominators={metric_denominators!r} != {expected_denominators!r}"
        )
    if summary.get("semantic_counts") != {}:
        raise SystemExit(
            f"ASSERT FAIL: 空 root semantic_counts={summary.get('semantic_counts')!r} != {{}}"
        )
    if summary.get("run_id") is not None:
        raise SystemExit(
            f"ASSERT FAIL: 空 root run_id={summary.get('run_id')!r} 应为 null"
        )
    if comparability.get("status") != "non_comparable":
        raise SystemExit("ASSERT FAIL: 空 root comparability.status 应为 non_comparable")
    if comparability.get("reason") != "no_samples":
        raise SystemExit(
            f"ASSERT FAIL: 空 root comparability.reason={comparability.get('reason')!r} != 'no_samples'"
        )
    if comparability.get("aggregation_key") is not None:
        raise SystemExit("ASSERT FAIL: 空 root comparability.aggregation_key 应为 null")
    if comparability.get("baseline_compare_key") is not None:
        raise SystemExit(
            "ASSERT FAIL: 空 root comparability.baseline_compare_key 应为 null"
        )
elif scenario == "comparable":
    expected_denominators = {
        "total_samples": 2,
        "analysis_state": {"included": 2, "excluded": 0, "unknown": 0},
        "comparable_samples": 2,
        "non_comparable_samples": 0,
    }
    if metric_denominators != expected_denominators:
        raise SystemExit(
            f"ASSERT FAIL: 可比 root metric_denominators={metric_denominators!r} != {expected_denominators!r}"
        )
    expected_semantic_counts = {
        "cache_diff_interesting": 1,
        "no_diff": 1,
    }
    if summary.get("semantic_counts") != expected_semantic_counts:
        raise SystemExit(
            f"ASSERT FAIL: 可比 root semantic_counts={summary.get('semantic_counts')!r} != {expected_semantic_counts!r}"
        )
    if summary.get("run_id") is not None:
        raise SystemExit(
            f"ASSERT FAIL: 自定义 root run_id={summary.get('run_id')!r} 应为 null"
        )

    expected_aggregation_key = {
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
    }
    expected_baseline_compare_key = {
        "resolver_pair": "bind9_vs_unbound",
        "producer_profile": "poison-stateful",
        "input_model": "DST1 transcript",
        "source_queue_dir": "/tmp/follow/queue",
        "budget_sec": 5,
        "seed_timeout_sec": 1,
        "repeat_count": 3,
        "contract_version": 1,
    }
    if comparability.get("status") != "comparable":
        raise SystemExit("ASSERT FAIL: 可比 root comparability.status 应为 comparable")
    if comparability.get("reason") != "ok":
        raise SystemExit(
            f"ASSERT FAIL: 可比 root comparability.reason={comparability.get('reason')!r} != 'ok'"
        )
    if comparability.get("aggregation_key") != expected_aggregation_key:
        raise SystemExit(
            "ASSERT FAIL: comparability.aggregation_key 不符合预期: "
            f"{comparability.get('aggregation_key')!r}"
        )
    if comparability.get("baseline_compare_key") != expected_baseline_compare_key:
        raise SystemExit(
            "ASSERT FAIL: comparability.baseline_compare_key 不符合预期: "
            f"{comparability.get('baseline_compare_key')!r}"
        )
else:
    raise SystemExit(f"ASSERT FAIL: 未知 scenario {scenario!r}")
PY
}

assert_oracle_reliability_scaffold() {
	local reliability_path="$1"
	python3 - "$reliability_path" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
signals = payload.get("signals")
signal_combos = payload.get("signal_combos")
if not isinstance(signals, dict):
    raise SystemExit("ASSERT FAIL: oracle_reliability.signals 应为对象")
if not isinstance(signal_combos, dict):
    raise SystemExit("ASSERT FAIL: oracle_reliability.signal_combos 应为对象")

required_signal_names = {
    "response_accepted_any",
    "second_query_hit_any",
    "cache_entry_created_any",
    "oracle_diff_any",
}
if set(signals.keys()) != required_signal_names:
    raise SystemExit(
        f"ASSERT FAIL: signals keys={set(signals.keys())!r} != {required_signal_names!r}"
    )

required_combo_names = {"oracle_diff_plus_cache_diff"}
if set(signal_combos.keys()) != required_combo_names:
    raise SystemExit(
        "ASSERT FAIL: signal_combos keys="
        f"{set(signal_combos.keys())!r} != {required_combo_names!r}"
    )

required_fields = {
    "eligible_count",
    "pending_manual_count",
    "judged_count",
    "confirmed_relevant_count",
    "false_positive_count",
    "inconclusive_count",
}

for scope_name, scope_payload in (
    ("signals", signals),
    ("signal_combos", signal_combos),
):
    for signal_name, stats in scope_payload.items():
        if not isinstance(stats, dict):
            raise SystemExit(
                f"ASSERT FAIL: {scope_name}.{signal_name} 应为对象: {stats!r}"
            )
        if set(stats.keys()) != required_fields:
            raise SystemExit(
                f"ASSERT FAIL: {scope_name}.{signal_name} fields={set(stats.keys())!r} != {required_fields!r}"
            )
        for field, value in stats.items():
            if not isinstance(value, int) or value < 0:
                raise SystemExit(
                    f"ASSERT FAIL: {scope_name}.{signal_name}.{field} 应为非负整数，实际 {value!r}"
                )
        if (
            stats["judged_count"] != 0
            or stats["confirmed_relevant_count"] != 0
            or stats["false_positive_count"] != 0
            or stats["inconclusive_count"] != 0
        ):
            raise SystemExit(
                f"ASSERT FAIL: {scope_name}.{signal_name} 在无 manual truth 输入时 judged 相关字段必须为 0，实际 {stats!r}"
            )
PY
}

assert_oracle_audit_header() {
	local audit_tsv="$1"
	python3 - "$audit_tsv" <<'PY'
import pathlib
import sys

header = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()[0]
expected = "\t".join(
    [
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
)
if header != expected:
    raise SystemExit(f"ASSERT FAIL: oracle_audit.tsv 表头不符合预期:\nactual={header!r}\nexpected={expected!r}")
PY
}

assert_oracle_reliability_gate_with_noneligible_signal_hits() {
	local reliability_path="$1"
	local audit_tsv_path="$2"
	python3 - "$reliability_path" "$audit_tsv_path" <<'PY'
import csv
import json
import pathlib
import sys

reliability = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
audit_path = pathlib.Path(sys.argv[2])

signal_hit_count = 0
with audit_path.open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))

for row in rows:
    if row.get("oracle_audit_candidate") != "false":
        continue
    signal_hit = (
        row.get("bind9.response_accepted") == "true"
        or row.get("unbound.response_accepted") == "true"
        or row.get("bind9.second_query_hit") == "true"
        or row.get("unbound.second_query_hit") == "true"
        or row.get("bind9.cache_entry_created") == "true"
        or row.get("unbound.cache_entry_created") == "true"
        or row.get("oracle_diff_fields") != "-"
    )
    if signal_hit:
        signal_hit_count += 1

if signal_hit_count <= 0:
    raise SystemExit(
        "ASSERT FAIL: 期望至少存在 1 个非 audit candidate 且命中 signal 的样本，用于验证 denominator gate"
    )

for scope_name in ("signals", "signal_combos"):
    scope = reliability.get(scope_name)
    if not isinstance(scope, dict):
        raise SystemExit(f"ASSERT FAIL: {scope_name} 应为对象")
    for name, stats in scope.items():
        if not isinstance(stats, dict):
            raise SystemExit(f"ASSERT FAIL: {scope_name}.{name} 应为对象")
        for field in (
            "eligible_count",
            "pending_manual_count",
            "judged_count",
            "confirmed_relevant_count",
            "false_positive_count",
            "inconclusive_count",
        ):
            if stats.get(field) != 0:
                raise SystemExit(
                    f"ASSERT FAIL: {scope_name}.{name}.{field} 期望为 0（非eligible样本不应抬高 denominator），实际 {stats.get(field)!r}"
                )
PY
}

mkdir -p "$EMPTY_ROOT" "$NONEMPTY_ROOT" "$META_ONLY_ROOT" "$FAIL_ROOT"
touch "$EMPTY_ROOT/high_value_samples.txt"

run_cli campaign-report --root "$EMPTY_ROOT" >/dev/null
EMPTY_REPORT_DIR="$(get_latest_report_dir "$EMPTY_ROOT/campaign_reports")"

assert_file_exists "$EMPTY_REPORT_DIR/summary.json"
assert_file_exists "$EMPTY_REPORT_DIR/ablation_matrix.tsv"
assert_file_exists "$EMPTY_REPORT_DIR/cluster_counts.tsv"
assert_file_exists "$EMPTY_REPORT_DIR/repro_rate.tsv"
assert_file_exists "$EMPTY_REPORT_DIR/oracle_audit.tsv"
assert_file_exists "$EMPTY_REPORT_DIR/oracle_reliability.json"
assert_summary_contract "$EMPTY_REPORT_DIR/summary.json" 0 0 0 0 0 0.0 0 0
assert_summary_metadata_contract "$EMPTY_REPORT_DIR/summary.json" empty
assert_oracle_audit_header "$EMPTY_REPORT_DIR/oracle_audit.tsv"
assert_oracle_reliability_scaffold "$EMPTY_REPORT_DIR/oracle_reliability.json"
assert_file_contains "$EMPTY_REPORT_DIR/repro_rate.tsv" $'metric\tvalue'
assert_file_contains "$EMPTY_REPORT_DIR/repro_rate.tsv" $'manifest_size\t0'
assert_file_contains "$EMPTY_REPORT_DIR/repro_rate.tsv" $'reproduced_count\t0'
assert_file_contains "$EMPTY_REPORT_DIR/repro_rate.tsv" $'repro_rate\t0.0000'
assert_file_contains "$EMPTY_REPORT_DIR/cluster_counts.tsv" $'cluster_key\tcount'
assert_file_contains "$EMPTY_REPORT_DIR/cluster_counts.tsv" $'_\t0'
assert_file_contains "$EMPTY_REPORT_DIR/ablation_matrix.tsv" $'module\tstatus'
assert_file_contains "$EMPTY_REPORT_DIR/ablation_matrix.tsv" $'cache-delta\ton'
assert_file_contains "$EMPTY_REPORT_DIR/ablation_matrix.tsv" $'mutator\toff'
assert_file_contains "$EMPTY_REPORT_DIR/ablation_matrix.tsv" $'symcc\ton'
assert_file_contains "$EMPTY_REPORT_DIR/ablation_matrix.tsv" $'triage\ton'

python3 - "$NONEMPTY_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])


def sample_meta(sample_id: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-03-23T00:00:00Z",
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

sample_dir = root / "sample"
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "sample.bin").write_bytes(b"\x00\x00\x00\x00")
(sample_dir / "sample.meta.json").write_text(
    json.dumps(sample_meta("sample"), ensure_ascii=False) + "\n",
    encoding="utf-8",
)
(sample_dir / "triage.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": "sample",
            "status": "completed_no_diff",
            "diff_class": "no_diff",
            "analysis_state": "included",
            "exclude_reason": None,
            "semantic_outcome": "no_diff",
            "filter_labels": [],
            "cluster_key": "non-manifest-cluster",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": False,
            "notes": [],
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(sample_dir / "oracle.json").write_text(
    json.dumps(
        {
            "bind9.parse_ok": True,
            "unbound.parse_ok": True,
            "bind9.response_accepted": True,
            "unbound.response_accepted": False,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(sample_dir / "cache_diff.json").write_text(
    json.dumps(
        {
            "bind9": {"has_cache_diff": False},
            "unbound": {"has_cache_diff": False},
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

sample_one_dir = root / "sample-1"
sample_one_dir.mkdir(parents=True, exist_ok=True)
(sample_one_dir / "sample.bin").write_bytes(b"\x01\x02\x03\x04")
(sample_one_dir / "sample.meta.json").write_text(
    json.dumps(sample_meta("sample-1"), ensure_ascii=False) + "\n",
    encoding="utf-8",
)
(sample_one_dir / "triage.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": "sample-1",
            "status": "completed_cache_changed_needs_review",
            "diff_class": "cache_diff_interesting",
            "analysis_state": "included",
            "exclude_reason": None,
            "semantic_outcome": "cache_diff_interesting",
            "filter_labels": ["cache_delta_review"],
            "cluster_key": "review-cluster",
            "cache_delta_triggered": True,
            "interesting_delta_count": 1,
            "needs_manual_review": True,
            "notes": [],
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(sample_one_dir / "oracle.json").write_text(
    json.dumps(
        {
            "bind9.parse_ok": True,
            "unbound.parse_ok": False,
            "bind9.response_accepted": False,
            "unbound.response_accepted": False,
            "bind9.second_query_hit": True,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": True,
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(sample_one_dir / "cache_diff.json").write_text(
    json.dumps(
        {
            "bind9": {"has_cache_diff": True},
            "unbound": {"has_cache_diff": False},
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

(root / "high_value_samples.txt").write_text(
    str((sample_one_dir / "sample.bin").resolve()) + "\n",
    encoding="utf-8",
)
PY

run_cli campaign-report --root "$NONEMPTY_ROOT" >/dev/null
NONEMPTY_REPORT_DIR="$(get_latest_report_dir "$NONEMPTY_ROOT/campaign_reports")"

assert_file_exists "$NONEMPTY_REPORT_DIR/summary.json"
assert_file_exists "$NONEMPTY_REPORT_DIR/ablation_matrix.tsv"
assert_file_exists "$NONEMPTY_REPORT_DIR/cluster_counts.tsv"
assert_file_exists "$NONEMPTY_REPORT_DIR/repro_rate.tsv"
assert_file_exists "$NONEMPTY_REPORT_DIR/oracle_audit.tsv"
assert_file_exists "$NONEMPTY_REPORT_DIR/oracle_reliability.json"
assert_summary_contract "$NONEMPTY_REPORT_DIR/summary.json" 2 1 2 1 1 1.0 0 0
assert_summary_metadata_contract "$NONEMPTY_REPORT_DIR/summary.json" comparable
assert_oracle_audit_header "$NONEMPTY_REPORT_DIR/oracle_audit.tsv"
assert_oracle_reliability_scaffold "$NONEMPTY_REPORT_DIR/oracle_reliability.json"
assert_oracle_reliability_gate_with_noneligible_signal_hits "$NONEMPTY_REPORT_DIR/oracle_reliability.json" "$NONEMPTY_REPORT_DIR/oracle_audit.tsv"
assert_file_contains "$NONEMPTY_REPORT_DIR/repro_rate.tsv" $'metric\tvalue'
assert_file_contains "$NONEMPTY_REPORT_DIR/repro_rate.tsv" $'manifest_size\t1'
assert_file_contains "$NONEMPTY_REPORT_DIR/repro_rate.tsv" $'reproduced_count\t1'
assert_file_contains "$NONEMPTY_REPORT_DIR/repro_rate.tsv" $'repro_rate\t1.0000'
assert_file_contains "$NONEMPTY_REPORT_DIR/cluster_counts.tsv" $'cluster_key\tcount'
assert_file_contains "$NONEMPTY_REPORT_DIR/cluster_counts.tsv" $'non-manifest-cluster\t1'
assert_file_contains "$NONEMPTY_REPORT_DIR/cluster_counts.tsv" $'review-cluster\t1'
assert_file_contains "$NONEMPTY_REPORT_DIR/ablation_matrix.tsv" $'module\tstatus'
assert_file_contains "$NONEMPTY_REPORT_DIR/ablation_matrix.tsv" $'cache-delta\ton'
assert_file_contains "$NONEMPTY_REPORT_DIR/ablation_matrix.tsv" $'mutator\toff'
assert_file_contains "$NONEMPTY_REPORT_DIR/ablation_matrix.tsv" $'symcc\ton'
assert_file_contains "$NONEMPTY_REPORT_DIR/ablation_matrix.tsv" $'triage\ton'

run_cli campaign-report --root "$NONEMPTY_ROOT" >/dev/null
NONEMPTY_REPORT_DIR_SECOND="$(get_latest_report_dir "$NONEMPTY_ROOT/campaign_reports")"
assert_summary_contract "$NONEMPTY_REPORT_DIR_SECOND/summary.json" 2 1 2 1 1 1.0 0 0
assert_summary_metadata_contract "$NONEMPTY_REPORT_DIR_SECOND/summary.json" comparable

run_cli report --root "$NONEMPTY_ROOT" >/dev/null
assert_file_exists "$NONEMPTY_ROOT/status_summary.tsv"
assert_file_exists "$NONEMPTY_ROOT/semantic_frontier_manifest.json"
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'status\tcount'
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'completed_cache_changed_needs_review\t1'
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'completed_no_diff\t1'
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'__total__\t2'
assert_file_not_contains "$NONEMPTY_ROOT/status_summary.tsv" $'unknown\t'

python3 - "$NONEMPTY_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
payload = json.loads((root / "semantic_frontier_manifest.json").read_text(encoding="utf-8"))
expected_top_level_fields = {
    "contract_name",
    "contract_version",
    "generated_at",
    "root",
    "entries",
}
if set(payload.keys()) != expected_top_level_fields:
    raise SystemExit(
        "ASSERT FAIL: semantic_frontier_manifest 顶层字段不符合预期: "
        f"{set(payload.keys())!r} != {expected_top_level_fields!r}"
    )
if payload.get("contract_name") != "semantic_frontier_manifest":
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest.contract_name={payload.get('contract_name')!r} != 'semantic_frontier_manifest'"
    )
if payload.get("contract_version") != 1:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest.contract_version={payload.get('contract_version')!r} != 1"
    )
generated_at = payload.get("generated_at")
if not isinstance(generated_at, str) or not generated_at:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest.generated_at 应为非空字符串，实际 {generated_at!r}"
    )
if payload.get("root") != str(root.resolve()):
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest.root={payload.get('root')!r} != {str(root.resolve())!r}"
    )
entries = payload.get("entries")
if not isinstance(entries, list):
    raise SystemExit("ASSERT FAIL: semantic_frontier_manifest.entries 应为数组")

expected_fields = {
    "sample_path",
    "sample_id",
    "analysis_state",
    "semantic_outcome",
    "oracle_audit_candidate",
    "needs_manual_review",
    "priority_tier",
}
for entry in entries:
    if set(entry.keys()) != expected_fields:
        raise SystemExit(
            f"ASSERT FAIL: semantic_frontier_manifest entry 字段不符合预期: {entry!r}"
        )

expected_paths = [
    str((root / "sample-1" / "sample.bin").resolve()),
    str((root / "sample" / "sample.bin").resolve()),
]
actual_paths = [entry.get("sample_path") for entry in entries]
if actual_paths != expected_paths:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest sample_path 顺序不符合预期: {actual_paths!r} != {expected_paths!r}"
    )

actual_tiers = [entry.get("priority_tier") for entry in entries]
if actual_tiers != [3, 0]:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest priority_tier 顺序不符合预期: {actual_tiers!r} != [3, 0]"
    )

entries_by_id = {entry["sample_id"]: entry for entry in entries}
if entries_by_id["sample-1"] != {
    "sample_path": expected_paths[0],
    "sample_id": "sample-1",
    "analysis_state": "included",
    "semantic_outcome": "cache_diff_interesting",
    "oracle_audit_candidate": False,
    "needs_manual_review": True,
    "priority_tier": 3,
}:
    raise SystemExit(
        f"ASSERT FAIL: sample-1 frontier entry 不符合预期: {entries_by_id['sample-1']!r}"
    )

if entries_by_id["sample"] != {
    "sample_path": expected_paths[1],
    "sample_id": "sample",
    "analysis_state": "included",
    "semantic_outcome": "no_diff",
    "oracle_audit_candidate": False,
    "needs_manual_review": False,
    "priority_tier": 0,
}:
    raise SystemExit(
        f"ASSERT FAIL: sample frontier entry 不符合预期: {entries_by_id['sample']!r}"
    )

high_value_lines = (root / "high_value_samples.txt").read_text(encoding="utf-8").splitlines()
json_subset = [
    entry["sample_path"]
    for entry in entries
    if entry.get("priority_tier") in {1, 2, 3}
]
if high_value_lines != json_subset:
    raise SystemExit(
        f"ASSERT FAIL: high_value_samples.txt 与 semantic_frontier_manifest Tier1-3 子集不一致: {high_value_lines!r} != {json_subset!r}"
    )
PY

python3 - "$META_ONLY_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sample_dir = root / "sample-meta-only"
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "sample.bin").write_bytes(b"\x09\x08\x07\x06")
(sample_dir / "sample.meta.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-26T00:00:00Z",
            "sample_id": "sample-meta-only",
            "status": "completed",
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
            "seed_provenance": {
                "cold_start": False,
                "seed_source_dir": "/tmp/follow/stable_transcript_corpus",
                "seed_materialization_method": "reused_filtered_corpus",
                "seed_snapshot_id": "1111111111111111111111111111111111111111",
                "regen_seeds": False,
                "refilter_queries": False,
                "stable_input_dir": "/tmp/follow/stable_transcript_corpus",
                "recorded_at": "2026-03-26T00:00:00Z",
            },
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(root / "high_value_samples.txt").write_text(
    str((sample_dir / "sample.bin").resolve()) + "\n",
    encoding="utf-8",
)
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	python3 - "$META_ONLY_ROOT" <<'PY'
import pathlib
import sys

from tools.dns_diff.report import collect_report_snapshot

root = pathlib.Path(sys.argv[1])
snapshot = collect_report_snapshot(root, require_root=False)

expected_seed_provenance = {
    "cold_start": False,
    "seed_source_dir": "/tmp/follow/stable_transcript_corpus",
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": "/tmp/follow/stable_transcript_corpus",
    "recorded_at": "2026-03-26T00:00:00Z",
}
expected_aggregation_key = {
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
}
expected_baseline_compare_key = {
    "resolver_pair": "bind9_vs_unbound",
    "producer_profile": "poison-stateful",
    "input_model": "DST1 transcript",
    "source_queue_dir": "/tmp/follow/queue",
    "budget_sec": 5,
    "seed_timeout_sec": 1,
    "repeat_count": 3,
    "contract_version": 1,
}

if snapshot.get("total_samples") != 1:
    raise SystemExit(f"ASSERT FAIL: meta-only snapshot.total_samples={snapshot.get('total_samples')!r} != 1")
if snapshot.get("run_id") is not None:
    raise SystemExit(f"ASSERT FAIL: meta-only snapshot.run_id={snapshot.get('run_id')!r} 应为 null")
if snapshot.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: meta-only snapshot.seed_provenance 不符合预期: "
        f"{snapshot.get('seed_provenance')!r}"
    )
if dict(snapshot.get("status_counter", {})) != {"completed": 1}:
    raise SystemExit(
        f"ASSERT FAIL: meta-only status_counter={dict(snapshot.get('status_counter', {}))!r} != {{'completed': 1}}"
    )
if dict(snapshot.get("cluster_counter", {})) != {"_": 1}:
    raise SystemExit(
        f"ASSERT FAIL: meta-only cluster_counter={dict(snapshot.get('cluster_counter', {}))!r} != {{'_': 1}}"
    )
if dict(snapshot.get("analysis_state_counter", {})) != {"unknown": 1}:
    raise SystemExit(
        "ASSERT FAIL: meta-only analysis_state_counter 应把缺失 triage 的样本记为 unknown"
    )

comparability = snapshot.get("comparability")
if comparability.get("status") != "comparable" or comparability.get("reason") != "ok":
    raise SystemExit(
        f"ASSERT FAIL: meta-only comparability={comparability!r} 期望 status=comparable, reason=ok"
    )
if comparability.get("aggregation_key") != expected_aggregation_key:
    raise SystemExit(
        "ASSERT FAIL: meta-only comparability.aggregation_key 不符合预期: "
        f"{comparability.get('aggregation_key')!r}"
    )
if comparability.get("baseline_compare_key") != expected_baseline_compare_key:
    raise SystemExit(
        "ASSERT FAIL: meta-only comparability.baseline_compare_key 不符合预期: "
        f"{comparability.get('baseline_compare_key')!r}"
    )

metric_denominators = snapshot.get("metric_denominators")
expected_denominators = {
    "total_samples": 1,
    "analysis_state": {"included": 0, "excluded": 0, "unknown": 1},
    "comparable_samples": 1,
    "non_comparable_samples": 0,
}
if metric_denominators != expected_denominators:
    raise SystemExit(
        f"ASSERT FAIL: meta-only metric_denominators={metric_denominators!r} != {expected_denominators!r}"
    )

frontier_entries = snapshot.get("semantic_frontier_entries")
if not isinstance(frontier_entries, list) or len(frontier_entries) != 1:
    raise SystemExit(
        f"ASSERT FAIL: meta-only semantic_frontier_entries={frontier_entries!r} 应为长度 1 的数组"
    )
entry = frontier_entries[0]
expected_sample_path = str((root / "sample-meta-only" / "sample.bin").resolve())
if entry != {
    "sample_path": expected_sample_path,
    "sample_id": "sample-meta-only",
    "analysis_state": "unknown",
    "semantic_outcome": "unknown",
    "oracle_audit_candidate": False,
    "needs_manual_review": False,
    "priority_tier": 0,
}:
    raise SystemExit(f"ASSERT FAIL: meta-only frontier entry 不符合预期: {entry!r}")
PY

run_cli report --root "$META_ONLY_ROOT" >/dev/null
assert_file_exists "$META_ONLY_ROOT/status_summary.tsv"
assert_file_exists "$META_ONLY_ROOT/semantic_frontier_manifest.json"
assert_file_contains "$META_ONLY_ROOT/status_summary.tsv" $'status\tcount'
assert_file_contains "$META_ONLY_ROOT/status_summary.tsv" $'completed\t1'
assert_file_contains "$META_ONLY_ROOT/status_summary.tsv" $'__total__\t1'

python3 - "$FAIL_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sample_dir = root / "sample-1"
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "sample.bin").write_bytes(b"\x01")
(sample_dir / "sample.meta.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "contract_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": "sample-1",
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(sample_dir / "triage.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": "sample-1",
            "status": "completed_cache_changed_needs_review",
            "diff_class": "cache_diff_interesting",
            "filter_labels": ["cache_delta_review"],
            "cluster_key": "review-cluster",
            "cache_delta_triggered": True,
            "interesting_delta_count": 1,
            "needs_manual_review": True,
            "notes": [],
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
PY

python3 - "$BAD_TRUTH_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sample_dir = root / "sample-bad-truth"
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "sample.bin").write_bytes(b"\x02")
(sample_dir / "sample.meta.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "contract_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": "sample-bad-truth",
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
(sample_dir / "triage.json").write_text('{"broken":', encoding="utf-8")
PY

FAIL_MANIFEST_TARGET="$FAIL_ROOT/manifest-target-dir"
mkdir -p "$FAIL_MANIFEST_TARGET"
REPORT_FAIL_STDERR="$WORKDIR/report-fail.stderr"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	ENABLE_DST1_MUTATOR=0 \
	ENABLE_CACHE_DELTA=1 \
	ENABLE_TRIAGE=1 \
	ENABLE_SYMCC=1 \
	SYMCC_HIGH_VALUE_MANIFEST="$FAIL_MANIFEST_TARGET" \
	python3 -m tools.dns_diff.cli report --root "$FAIL_ROOT" >/dev/null 2>"$REPORT_FAIL_STDERR"; then
	printf 'ASSERT FAIL: manifest 目标不可写时 report 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$REPORT_FAIL_STDERR" "dns-diff: report 失败: 写入 high_value_samples.txt 失败:"

CAMPAIGN_BAD_TRUTH_STDERR="$WORKDIR/campaign-bad-truth.stderr"
if run_cli campaign-report --root "$BAD_TRUTH_ROOT" >/dev/null 2>"$CAMPAIGN_BAD_TRUTH_STDERR"; then
	printf 'ASSERT FAIL: campaign-report 对坏 truth-source 输入不应成功\n' >&2
	exit 1
fi
assert_file_contains "$CAMPAIGN_BAD_TRUTH_STDERR" 'dns-diff: campaign-report 失败: 样本 semantic truth-source 无效:'
assert_file_contains "$CAMPAIGN_BAD_TRUTH_STDERR" 'file=triage.json'
assert_file_not_contains "$CAMPAIGN_BAD_TRUTH_STDERR" 'Traceback'
if [ -e "$BAD_TRUTH_ROOT/campaign_reports" ]; then
	printf 'ASSERT FAIL: bad truth-source 时不应生成 campaign_reports 目录\n' >&2
	exit 1
fi

printf 'PASS: campaign report regression test passed\n'
