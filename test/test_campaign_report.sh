#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-campaign-report.XXXXXX")"
EMPTY_ROOT="$WORKDIR/empty-follow"
NONEMPTY_ROOT="$WORKDIR/nonempty-follow"
FAIL_ROOT="$WORKDIR/fail-follow"
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
	python3 - "$summary_path" "$total_samples" "$needs_review_count" "$cluster_count" "$manifest_size" "$reproduced_count" "$repro_rate" <<'PY'
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

mkdir -p "$EMPTY_ROOT" "$NONEMPTY_ROOT" "$FAIL_ROOT"
touch "$EMPTY_ROOT/high_value_samples.txt"

run_cli campaign-report --root "$EMPTY_ROOT" >/dev/null
EMPTY_REPORT_DIR="$(get_latest_report_dir "$EMPTY_ROOT/campaign_reports")"

assert_file_exists "$EMPTY_REPORT_DIR/summary.json"
assert_file_exists "$EMPTY_REPORT_DIR/ablation_matrix.tsv"
assert_file_exists "$EMPTY_REPORT_DIR/cluster_counts.tsv"
assert_file_exists "$EMPTY_REPORT_DIR/repro_rate.tsv"
assert_summary_contract "$EMPTY_REPORT_DIR/summary.json" 0 0 0 0 0 0.0
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

sample_dir = root / "sample"
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "triage.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": "sample",
            "status": "completed_no_diff",
            "diff_class": "no_diff",
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

sample_one_dir = root / "sample-1"
sample_one_dir.mkdir(parents=True, exist_ok=True)
(sample_one_dir / "sample.bin").write_bytes(b"\x01\x02\x03\x04")
(sample_one_dir / "triage.json").write_text(
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
assert_summary_contract "$NONEMPTY_REPORT_DIR/summary.json" 2 1 2 1 1 1.0
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
assert_summary_contract "$NONEMPTY_REPORT_DIR_SECOND/summary.json" 2 1 2 1 1 1.0

run_cli report --root "$NONEMPTY_ROOT" >/dev/null
assert_file_exists "$NONEMPTY_ROOT/status_summary.tsv"
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'status\tcount'
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'completed_cache_changed_needs_review\t1'
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'completed_no_diff\t1'
assert_file_contains "$NONEMPTY_ROOT/status_summary.tsv" $'__total__\t2'
assert_file_not_contains "$NONEMPTY_ROOT/status_summary.tsv" $'unknown\t'

python3 - "$FAIL_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sample_dir = root / "sample-1"
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "sample.bin").write_bytes(b"\x01")
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

printf 'PASS: campaign report regression test passed\n'
