#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_helper_bin() {
	python3 - "$ROOT_DIR" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
candidates = [
    root / "build/linux/x86_64/release/symcc_fuzzing_helper",
    root / "util/symcc_fuzzing_cpp/build/linux/x86_64/release/symcc_fuzzing_helper",
]
existing = [path for path in candidates if path.is_file() and path.stat().st_mode & 0o111]
if not existing:
    raise SystemExit(1)
print(max(existing, key=lambda path: path.stat().st_mtime))
PY
}

ensure_helper_bin() {
	xmake f -P "$ROOT_DIR/util/symcc_fuzzing_cpp" -m release >/dev/null
	xmake b -P "$ROOT_DIR/util/symcc_fuzzing_cpp" symcc_fuzzing_helper >/dev/null
	local helper_bin=""
	helper_bin="$(resolve_helper_bin || true)"
	if [[ -z "$helper_bin" ]]; then
		printf 'ASSERT FAIL: 未找到 symcc_fuzzing_helper，可执行文件构建失败\n' >&2
		exit 1
	fi
	printf '%s\n' "$helper_bin"
}

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

assert_running_sequence() {
	local log_file="$1"
	shift
	python3 - "$log_file" "$@" <<'PY'
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
expected = sys.argv[2:]
lines = []
for line in log_path.read_text(encoding="utf-8").splitlines():
    marker = "Running SymCC on request sample "
    if marker in line:
        lines.append(line.split(marker, 1)[1])

actual = lines[: len(expected)]
if actual != expected:
    full_log = log_path.read_text(encoding="utf-8") if log_path.exists() else "<missing log>"
    raise SystemExit(
        "ASSERT FAIL: helper 处理顺序不符合预期:\n"
        f"actual={actual!r}\nexpected={expected!r}\nlog=\n{full_log}"
    )
PY
}

assert_all_copy_counts_zero() {
	local log_file="$1"
	python3 - "$log_file" <<'PY'
import pathlib
import re
import sys

log_path = pathlib.Path(sys.argv[1])
pattern = re.compile(r"Generated (\d+) test cases, copied (\d+) to AFL queue")
matches = []
for line in log_path.read_text(encoding="utf-8").splitlines():
	match = pattern.search(line)
	if match:
		matches.append((line, int(match.group(2))))

if not matches:
	full_log = log_path.read_text(encoding="utf-8") if log_path.exists() else "<missing log>"
	raise SystemExit(
		"ASSERT FAIL: 未找到 AFL queue copy summary:\n"
		f"log=\n{full_log}"
	)

non_zero = [line for line, copied in matches if copied != 0]
if non_zero:
	full_log = log_path.read_text(encoding="utf-8") if log_path.exists() else "<missing log>"
	raise SystemExit(
		"ASSERT FAIL: semantic-only 调度不应向 AFL queue 复制新样本:\n"
		f"offending_lines={non_zero!r}\nlog=\n{full_log}"
	)
PY
}

assert_no_symcc_queue_samples() {
	local queue_dir="$1"
	python3 - "$queue_dir" <<'PY'
import pathlib
import sys

queue_dir = pathlib.Path(sys.argv[1])
symcc_samples = sorted(
	path.name for path in queue_dir.iterdir() if path.is_file() and path.name.endswith(",symcc")
)
if symcc_samples:
	raise SystemExit(
		"ASSERT FAIL: semantic-only 选择不应生成新的 AFL ',symcc' 队列样本:\n"
		f"queue_dir={queue_dir}\nactual={symcc_samples!r}"
	)
PY
}

wait_for_log_line() {
	local log_file="$1"
	local expected="$2"
	local timeout_sec="$3"
	local deadline=$((SECONDS + timeout_sec))

	while (( SECONDS < deadline )); do
		if [[ -f "$log_file" ]] && grep -Fq -- "$expected" "$log_file"; then
			return 0
		fi
		sleep 0.1
	done

	printf 'ASSERT FAIL: 等待日志超时，未看到: %s\n' "$expected" >&2
	if [[ -f "$log_file" ]]; then
		cat "$log_file" >&2
	fi
	exit 1
}

advance_manifest_mtime() {
	sleep 1.1
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

prepare_fixture() {
	local work_root="$1"
	local out_dir="$work_root/afl_out"
	local run_name="exp"
	local fuzzer_name="master"
	local fuzzer_dir="$out_dir/$run_name/$fuzzer_name"
	local queue_dir="$fuzzer_dir/queue"

	mkdir -p "$queue_dir"
	printf '%s\n' 'command_line : /usr/bin/afl-fuzz -i in -o out -- /bin/true @@' > "$fuzzer_dir/fuzzer_stats"
	printf '%s\n' "$queue_dir"
}

write_sleep_target() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    "#!/usr/bin/env python3\n"
    "import time\n"
    "time.sleep(2.0)\n",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_follow_sample() {
	local follow_root="$1"
	local sample_id="$2"
	local queue_file="$3"
	local analysis_state="$4"
	local semantic_outcome="$5"
	local oracle_audit_candidate="$6"
	local needs_manual_review="$7"

	python3 - "$follow_root" "$sample_id" "$queue_file" "$analysis_state" "$semantic_outcome" "$oracle_audit_candidate" "$needs_manual_review" <<'PY'
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1])
sample_id = sys.argv[2]
queue_file = pathlib.Path(sys.argv[3]).resolve()
analysis_state = sys.argv[4]
semantic_outcome = sys.argv[5]
oracle_audit_candidate = sys.argv[6] == "true"
needs_manual_review = sys.argv[7] == "true"

sample_dir = follow_root / sample_id
sample_dir.mkdir(parents=True, exist_ok=True)
(sample_dir / "sample.bin").write_bytes(sample_id.encode("utf-8"))
(sample_dir / "sample.meta.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "contract_version": 1,
            "generated_at": "2026-03-25T00:00:00Z",
            "sample_id": sample_id,
            "queue_event_id": queue_file.name,
            "source_queue_file": str(queue_file),
            "source_resolver": "bind9",
            "sample_sha1": None,
            "sample_size": queue_file.stat().st_size,
            "is_stateful": True,
            "afl_tags": [],
            "first_seen_ts": "2026-03-25T00:00:00Z",
            "status": "completed",
            "analysis_state": analysis_state,
            "exclude_reason": None,
            "aggregation_key": None,
            "baseline_compare_key": None,
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
(sample_dir / "triage.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-25T00:00:00Z",
            "sample_id": sample_id,
            "status": "completed",
            "diff_class": semantic_outcome,
            "analysis_state": analysis_state,
            "exclude_reason": None,
            "semantic_outcome": semantic_outcome,
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "semantic_diff"
            if semantic_outcome != "no_diff"
            else "no_failure",
            "failure_bucket_detail": semantic_outcome,
            "oracle_audit_candidate": oracle_audit_candidate,
            "case_study_candidate": oracle_audit_candidate and needs_manual_review,
            "manual_truth_status": "not_started"
            if oracle_audit_candidate
            else "not_applicable",
            "filter_labels": [],
            "cluster_key": sample_id,
            "cache_delta_triggered": semantic_outcome == "cache_diff_interesting",
            "interesting_delta_count": 1 if semantic_outcome == "cache_diff_interesting" else 0,
            "needs_manual_review": needs_manual_review,
            "notes": [],
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY
}

assert_report_wiring() {
	local text_manifest="$1"
	local json_manifest="$2"
	local low_sample="$3"
	local mid_sample="$4"
	local high_sample="$5"
	python3 - "$text_manifest" "$json_manifest" "$low_sample" "$mid_sample" "$high_sample" <<'PY'
import json
import pathlib
import sys

text_manifest = pathlib.Path(sys.argv[1]).resolve()
json_manifest = pathlib.Path(sys.argv[2]).resolve()
low_sample = str(pathlib.Path(sys.argv[3]).resolve())
mid_sample = str(pathlib.Path(sys.argv[4]).resolve())
high_sample = str(pathlib.Path(sys.argv[5]).resolve())

payload = json.loads(json_manifest.read_text(encoding="utf-8"))
entries = payload.get("entries")
if not isinstance(entries, list):
    raise SystemExit("ASSERT FAIL: semantic_frontier_manifest.entries 应为数组")

expected_paths = [high_sample, mid_sample, low_sample]
actual_paths = [entry.get("sample_path") for entry in entries]
if actual_paths != expected_paths:
    raise SystemExit(
        "ASSERT FAIL: semantic_frontier_manifest sample_path 顺序不符合预期:\n"
        f"actual={actual_paths!r}\nexpected={expected_paths!r}"
    )

generated_at = payload.get("generated_at")
if not isinstance(generated_at, str) or not generated_at:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier_manifest.generated_at 应为非空字符串，实际 {generated_at!r}"
    )

manifest_lines = text_manifest.read_text(encoding="utf-8").splitlines()
if manifest_lines != expected_paths:
    raise SystemExit(
        "ASSERT FAIL: high_value manifest 未与 semantic frontier queue 路径对齐:\n"
        f"actual={manifest_lines!r}\nexpected={expected_paths!r}"
    )

tiers = [entry.get("priority_tier") for entry in entries]
if tiers != [3, 2, 1]:
    raise SystemExit(
        f"ASSERT FAIL: priority_tier 顺序不符合预期: {tiers!r} != [3, 2, 1]"
    )
PY
}

assert_close_summary_semantic_context() {
	local work_dir="$1"
	local follow_root="$2"
	local text_manifest="$3"
	local json_manifest="$4"
	SYMCC_HIGH_VALUE_MANIFEST="$text_manifest" \
	python3 - "$ROOT_DIR" "$work_dir" "$follow_root" "$text_manifest" "$json_manifest" <<'PY'
import json
import pathlib
import sys

root_dir = pathlib.Path(sys.argv[1])
work_dir = pathlib.Path(sys.argv[2])
follow_root = pathlib.Path(sys.argv[3])
text_manifest = str(pathlib.Path(sys.argv[4]).resolve())
json_manifest = str(pathlib.Path(sys.argv[5]).resolve())

sys.path.insert(0, str(root_dir))
from tools.dns_diff.close_loop import _write_close_summary_with_context

summary_path = _write_close_summary_with_context(
    work_dir,
    follow_root,
    {
        "status": "success",
        "exit_reason": "success",
        "exit_code": 0,
        "phases": {},
    },
)
payload = json.loads(pathlib.Path(summary_path).read_text(encoding="utf-8"))
phase_context = payload.get("phase_context")
if not isinstance(phase_context, dict):
    raise SystemExit("ASSERT FAIL: close summary.phase_context 应为对象")

manifest = phase_context.get("semantic_frontier_manifest")
if not isinstance(manifest, dict):
    raise SystemExit("ASSERT FAIL: close summary 缺少 semantic_frontier_manifest 上下文")

if manifest.get("text_manifest_path") != text_manifest:
    raise SystemExit(
        f"ASSERT FAIL: text_manifest_path={manifest.get('text_manifest_path')!r} != {text_manifest!r}"
    )
if manifest.get("sidecar_path") != json_manifest:
    raise SystemExit(
        f"ASSERT FAIL: sidecar_path={manifest.get('sidecar_path')!r} != {json_manifest!r}"
    )
if manifest.get("sidecar_status") != "ok":
    raise SystemExit(
        f"ASSERT FAIL: sidecar_status={manifest.get('sidecar_status')!r} != 'ok'"
    )
if manifest.get("entry_count") != 3:
    raise SystemExit(
        f"ASSERT FAIL: entry_count={manifest.get('entry_count')!r} != 3"
    )
generated_at = manifest.get("generated_at")
if not isinstance(generated_at, str) or not generated_at:
    raise SystemExit(
        f"ASSERT FAIL: generated_at 应为非空字符串，实际 {generated_at!r}"
    )
PY
}

main() {
	local helper_bin=""
	local work_root=""
	local queue_dir=""
	local follow_root=""
	local frontier_dir=""
	local low_sample=""
	local high_sample=""
	local mid_sample=""
	local text_manifest=""
	local json_manifest=""
	local log_file=""
	local report_stdout=""
	local report_stderr=""
	local close_summary_dir=""
	local sleep_target=""
	local timeout_pid=""

	helper_bin="$(ensure_helper_bin)"
	work_root="$(mktemp -d "${TMPDIR:-/tmp}/symcc-semantic-feedback.XXXXXX")"
	trap 'rm -rf "${work_root:-}"' EXIT

	queue_dir="$(prepare_fixture "$work_root")"
	follow_root="$work_root/follow_diff"
	frontier_dir="$work_root/frontier"
	text_manifest="$frontier_dir/high_value_samples.txt"
	json_manifest="$frontier_dir/semantic_frontier_manifest.json"
	log_file="$work_root/helper.log"
	report_stdout="$work_root/report.stdout"
	report_stderr="$work_root/report.stderr"
	close_summary_dir="$work_root/close-summary"
	sleep_target="$work_root/fake_target.py"

	mkdir -p "$follow_root" "$frontier_dir" "$close_summary_dir"
	write_sleep_target "$sleep_target"

	low_sample="$queue_dir/id:000001,src:000000,text-tier1"
	high_sample="$queue_dir/id:000002,src:000000,json-tier3"
	mid_sample="$queue_dir/id:000003,src:000000,json-tier2"

	printf 'low\n' > "$low_sample"
	printf 'high\n' > "$high_sample"
	printf 'mid\n' > "$mid_sample"
	printf '%s\n' "$low_sample" > "$text_manifest"

	write_follow_sample "$follow_root" "sample-low" "$low_sample" "excluded" "no_diff" "false" "true"
	write_follow_sample "$follow_root" "sample-high" "$high_sample" "included" "oracle_diff" "true" "true"
	write_follow_sample "$follow_root" "sample-mid" "$mid_sample" "excluded" "no_diff" "true" "false"

	env \
		SYMCC_HIGH_VALUE_MANIFEST="$text_manifest" \
		SYMCC_SEMANTIC_FRONTIER_MANIFEST="$json_manifest" \
		SYMCC_FRONTIER_RELOAD_SEC=1 \
		timeout -k 1 12 "$helper_bin" \
			-a master -o "$work_root/afl_out" -n exp -- "$sleep_target" @@ >"$log_file" 2>&1 &
	timeout_pid=$!

	wait_for_log_line "$log_file" "Running SymCC on request sample $low_sample" 5
	assert_file_contains "$log_file" 'Loaded semantic frontier snapshot from text manifest'
	assert_file_contains "$log_file" 'Semantic frontier snapshot state: source=text manifest, applied_at='
	assert_file_contains "$log_file" "Picked high-value request sample from text manifest (tier=1): $low_sample"

	advance_manifest_mtime
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		ENABLE_DST1_MUTATOR=0 \
		ENABLE_CACHE_DELTA=1 \
		ENABLE_TRIAGE=1 \
		ENABLE_SYMCC=1 \
		SYMCC_HIGH_VALUE_MANIFEST="$text_manifest" \
		python3 -m tools.dns_diff.cli report --root "$follow_root" >"$report_stdout" 2>"$report_stderr"

	assert_file_exists "$text_manifest"
	assert_file_exists "$json_manifest"
	assert_file_contains "$report_stdout" 'dns-diff: semantic frontier sidecar 已写入 '
	assert_file_contains "$report_stdout" "path=$json_manifest"
	assert_file_contains "$report_stdout" 'generated_at='
	assert_file_contains "$report_stdout" 'entries=3'
	assert_file_contains "$report_stdout" 'dns-diff: report 生成完成 '
	assert_file_not_contains "$report_stderr" 'dns-diff: report 失败:'
	assert_report_wiring "$text_manifest" "$json_manifest" "$low_sample" "$mid_sample" "$high_sample"
	assert_close_summary_semantic_context "$close_summary_dir" "$follow_root" "$text_manifest" "$json_manifest"

	wait_for_log_line "$log_file" 'Reloaded semantic frontier snapshot from semantic JSON manifest' 5
	wait_for_log_line "$log_file" "Running SymCC on request sample $high_sample" 6
	assert_file_contains "$log_file" 'Semantic frontier snapshot state: source=semantic JSON manifest, applied_at='
	assert_file_contains "$log_file" 'manifest_generated_at='
	assert_file_contains "$log_file" "Picked high-value request sample from semantic JSON manifest (tier=3): $high_sample"

	advance_manifest_mtime
	printf '%s\n' '{"contract_name": "semantic_frontier_manifest", "entries": [' > "$json_manifest"
	wait_for_log_line "$log_file" 'Kept last-known-good semantic frontier snapshot from semantic JSON manifest' 5

	wait "$timeout_pid" || true

	assert_running_sequence "$log_file" "$low_sample" "$high_sample" "$mid_sample"
	assert_file_contains "$log_file" 'semantic frontier JSON parse error'
	assert_file_contains "$log_file" 'Semantic frontier snapshot state preserved: source=semantic JSON manifest, applied_at='
	assert_file_contains "$log_file" "Picked high-value request sample from semantic JSON manifest (tier=2): $mid_sample"
	assert_file_not_contains "$log_file" "Picked high-value request sample from text manifest (tier=1): $mid_sample"
	assert_file_not_contains "$log_file" 'Reloaded semantic frontier snapshot from text manifest'
	assert_all_copy_counts_zero "$log_file"
	assert_no_symcc_queue_samples "$queue_dir"
	assert_file_not_contains "$log_file" 'Fatal:'

	printf 'PASS: semantic feedback smoke test passed\n'
}

main "$@"
