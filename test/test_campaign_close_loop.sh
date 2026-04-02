#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-campaign-close-loop.XXXXXX")"
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

write_text_file() {
	local path="$1"
	local content="$2"
	python3 - "$path" "$content" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(sys.argv[2], encoding="utf-8")
PY
}

write_fake_binary() {
	local path="$1"
	local mode="$2"
	python3 - "$path" "$mode" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
path.parent.mkdir(parents=True, exist_ok=True)

scripts = {
    "dump_success": f"""#!/usr/bin/env python3
import os
import pathlib
import sys

def log_invocation() -> None:
    log_path = os.environ.get(\"FAKE_BINARY_LOG_PATH\")
    if not log_path:
        return
    path = pathlib.Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(\"a\", encoding=\"utf-8\") as handle:
        handle.write(f\"{{pathlib.Path(__file__).name}}\\tdump_success\\n\")

log_invocation()
dump_path = os.environ.get(\"UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\") or os.environ.get(\"NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\")
if dump_path:
    dump_file = pathlib.Path(dump_path)
    dump_file.parent.mkdir(parents=True, exist_ok=True)
    dump_file.write_text(\"cache-entry\\n\", encoding=\"utf-8\")
sys.stderr.write(\"ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n\")
sys.exit(0)
""",
    "timeout": f"""#!/usr/bin/env python3
import os
import pathlib
import sys
import time

def log_invocation() -> None:
    log_path = os.environ.get(\"FAKE_BINARY_LOG_PATH\")
    if not log_path:
        return
    path = pathlib.Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(\"a\", encoding=\"utf-8\") as handle:
        handle.write(f\"{{pathlib.Path(__file__).name}}\\ttimeout\\n\")

log_invocation()
sys.stderr.write(\"fake timeout stage\\n\")
sys.stderr.flush()
time.sleep(5)
sys.exit(0)
""",
    "missing_artifact": f"""#!/usr/bin/env python3
import os
import pathlib
import sys

def log_invocation() -> None:
    log_path = os.environ.get(\"FAKE_BINARY_LOG_PATH\")
    if not log_path:
        return
    path = pathlib.Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(\"a\", encoding=\"utf-8\") as handle:
        handle.write(f\"{{pathlib.Path(__file__).name}}\\tmissing_artifact\\n\")

log_invocation()
sys.stderr.write(\"fake missing artifact\\n\")
sys.stderr.flush()
sys.exit(0)
""",
}

script = scripts.get(mode)
if script is None:
    raise SystemExit(f"unknown fake binary mode: {mode}")

path.write_text(script, encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

compute_sample_id() {
	local queue_file="$1"
	python3 - "$queue_file" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
sha1 = hashlib.sha1(path.read_bytes()).hexdigest()
print(f"{path.name}__{sha1[:8]}")
PY
}

write_seed_provenance_fixture() {
	local work_dir="$1"
	python3 - "$work_dir" <<'PY'
import json
import pathlib
import sys

work_dir = pathlib.Path(sys.argv[1]).resolve()
seed_dir = (work_dir / "stable_transcript_corpus").resolve()
seed_dir.mkdir(parents=True, exist_ok=True)
payload = {
    "cold_start": False,
    "seed_source_dir": str(seed_dir),
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": str(seed_dir),
    "transcript_format_version": 2,
    "transcript_max_responses": 3,
    "response_preserve": 20,
    "recorded_at": "2026-03-26T00:00:00Z",
}
path = work_dir / "producer_seed_provenance.json"
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

get_latest_report_dir() {
	local report_base="$1"
	python3 - "$report_base" <<'PY'
from pathlib import Path
import sys

report_base = Path(sys.argv[1])
if not report_base.is_dir():
    raise SystemExit(f"ASSERT FAIL: campaign report 目录不存在 {report_base}")
dirs = sorted(path for path in report_base.iterdir() if path.is_dir())
if not dirs:
    raise SystemExit(f"ASSERT FAIL: 期望 {report_base} 下至少有 1 个报告目录，实际为空")
print(dirs[-1])
PY
}

init_scenario() {
	local scenario_name="$1"
	local unbound_mode="$2"
	local bind9_mode="${3:-dump_success}"

	SCENARIO_ROOT="$WORKDIR/$scenario_name"
	SCENARIO_WORK="$SCENARIO_ROOT/work"
	QUEUE_DIR="$SCENARIO_WORK/afl_out/master/queue"
	FOLLOW_ROOT="$SCENARIO_WORK/follow_diff"
	RESPONSE_DIR="$SCENARIO_WORK/response_corpus"
	BIND9_TREE="$SCENARIO_ROOT/bind9-afl"
	UNBOUND_TREE="$SCENARIO_ROOT/unbound-afl"
	BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
	UNBOUND_BIN="$UNBOUND_TREE/.libs/unbound-fuzzme"
	NAMED_CONF_TEMPLATE="$SCENARIO_ROOT/named.conf.template"
	QUEUE_FILE="$QUEUE_DIR/id:000001,orig:seed"
	QUEUE_EVENT_ID="${QUEUE_FILE##*/}"
	SAMPLE_ID=''
	CAMPAIGN_STDOUT="$SCENARIO_ROOT/campaign-close.stdout"
	CAMPAIGN_STDERR="$SCENARIO_ROOT/campaign-close.stderr"
	CAMPAIGN_SUMMARY="$SCENARIO_WORK/campaign_close.summary.json"
	WINDOW_SUMMARY="$SCENARIO_WORK/follow_diff.window.summary.json"
	CAMPAIGN_REPORT_BASE="$SCENARIO_WORK/campaign_reports"
	HIGH_VALUE_MANIFEST="$SCENARIO_WORK/high_value_samples.txt"
	INVOCATION_LOG="$SCENARIO_ROOT/fake-binary.log"
	SEED_TIMEOUT_SEC_OVERRIDE=1
	SYMCC_HIGH_VALUE_MANIFEST_OVERRIDE=''

	mkdir -p "$QUEUE_DIR" "$FOLLOW_ROOT" "$RESPONSE_DIR"
	write_seed_provenance_fixture "$SCENARIO_WORK"
	write_text_file "$NAMED_CONF_TEMPLATE" $'options { directory "__RUNTIME_STATE_DIR__"; };\n'
	write_fake_binary "$BIND9_BIN" "$bind9_mode"
	write_fake_binary "$UNBOUND_BIN" "$unbound_mode"
	python3 - "$QUEUE_FILE" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(b"\x09\x08\x07\x06")
PY
	SAMPLE_ID="$(compute_sample_id "$QUEUE_FILE")"
}

assert_command_ready() {
	local stderr_path="$1"
	local command_name="$2"
	if grep -Fq -- "invalid choice: '$command_name'" "$stderr_path"; then
		printf 'ASSERT FAIL: 缺少 %s 子命令；该脚本用于锁定 close-loop 红灯契约\n' "$command_name" >&2
		cat "$stderr_path" >&2
		exit 1
	fi
	if grep -Fq -- '尚未实现' "$stderr_path"; then
		printf 'ASSERT FAIL: %s 子命令已接线但仍未实现 close-loop 契约\n' "$command_name" >&2
		cat "$stderr_path" >&2
		exit 1
	fi
	if grep -Fq -- 'unrecognized arguments: --budget-sec' "$stderr_path"; then
		printf 'ASSERT FAIL: %s 缺少 --budget-sec 全局 deadline 契约\n' "$command_name" >&2
		cat "$stderr_path" >&2
		exit 1
	fi
}

run_campaign_close_capture() {
	local budget_sec="$1"
	set +e
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		WORK_DIR="$SCENARIO_WORK" \
		BIND9_AFL_TREE="$BIND9_TREE" \
		AFL_TREE="$UNBOUND_TREE" \
		RESPONSE_CORPUS_DIR="$RESPONSE_DIR" \
		BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
		FOLLOW_DIFF_INTERVAL_SEC=0.01 \
		SEED_TIMEOUT_SEC="$SEED_TIMEOUT_SEC_OVERRIDE" \
		SYMCC_HIGH_VALUE_MANIFEST="$SYMCC_HIGH_VALUE_MANIFEST_OVERRIDE" \
		FAKE_BINARY_LOG_PATH="$INVOCATION_LOG" \
		python3 -m tools.dns_diff.cli campaign-close --budget-sec "$budget_sec" >"$CAMPAIGN_STDOUT" 2>"$CAMPAIGN_STDERR"
	CAMPAIGN_EXIT_CODE=$?
	set -e
	assert_command_ready "$CAMPAIGN_STDERR" "campaign-close"
}

assert_follow_window_phase_summary() {
	local summary_path="$1"
	local expected_queue_tail_id="$2"
	local expected_exit_reason="$3"
	local expected_exit_code="$4"
	python3 - "$summary_path" "$expected_queue_tail_id" "$expected_exit_reason" "$expected_exit_code" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_queue_tail_id = sys.argv[2]
expected_exit_reason = sys.argv[3]
expected_exit_code = int(sys.argv[4])

for key in (
    "budget_sec",
    "deadline_ts",
    "queue_tail_id",
    "run_id",
    "exit_reason",
    "exit_code",
    "completed_count",
    "failed_count",
    "last_queue_event_id",
    "seed_provenance",
):
    if key not in summary:
        raise SystemExit(f"ASSERT FAIL: follow_diff.window.summary.json 缺少字段 {key}")

if summary.get("queue_tail_id") != expected_queue_tail_id:
    raise SystemExit(
        f"ASSERT FAIL: follow_diff.window.summary.queue_tail_id={summary.get('queue_tail_id')!r} != {expected_queue_tail_id!r}"
    )
if not isinstance(summary.get("run_id"), str) or not summary["run_id"]:
    raise SystemExit("ASSERT FAIL: follow_diff.window.summary.run_id 应为非空字符串")
if summary.get("exit_reason") != expected_exit_reason:
    raise SystemExit(
        f"ASSERT FAIL: follow_diff.window.summary.exit_reason={summary.get('exit_reason')!r} != {expected_exit_reason!r}"
    )
if summary.get("exit_code") != expected_exit_code:
    raise SystemExit(
        f"ASSERT FAIL: follow_diff.window.summary.exit_code={summary.get('exit_code')!r} != {expected_exit_code!r}"
    )

expected_seed_dir = str((pathlib.Path(sys.argv[1]).resolve().parent / "stable_transcript_corpus").resolve())
expected_seed_provenance = {
    "cold_start": False,
    "seed_source_dir": expected_seed_dir,
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": expected_seed_dir,
    "transcript_format_version": 2,
    "transcript_max_responses": 3,
    "response_preserve": 20,
    "recorded_at": "2026-03-26T00:00:00Z",
}
if summary.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: follow_diff.window.summary.seed_provenance 不符合预期: "
        f"{summary.get('seed_provenance')!r}"
    )
PY
}

assert_campaign_close_success_summary() {
	local summary_path="$1"
	local expected_queue_tail_id="$2"
	python3 - "$summary_path" "$expected_queue_tail_id" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_queue_tail_id = sys.argv[2]

for key in (
    "budget_sec",
    "deadline_ts",
    "queue_tail_id",
    "status",
    "exit_reason",
    "exit_code",
    "phases",
):
    if key not in summary:
        raise SystemExit(f"ASSERT FAIL: campaign_close.summary.json 缺少字段 {key}")

if summary.get("queue_tail_id") != expected_queue_tail_id:
    raise SystemExit(
        f"ASSERT FAIL: summary.queue_tail_id={summary.get('queue_tail_id')!r} != {expected_queue_tail_id!r}"
    )
if summary.get("status") != "success":
    raise SystemExit(f"ASSERT FAIL: summary.status={summary.get('status')!r} != 'success'")
if summary.get("exit_reason") != "success":
    raise SystemExit(
        f"ASSERT FAIL: summary.exit_reason={summary.get('exit_reason')!r} != 'success'"
    )
if summary.get("exit_code") != 0:
    raise SystemExit(f"ASSERT FAIL: summary.exit_code={summary.get('exit_code')!r} != 0")

phases = summary.get("phases")
if not isinstance(phases, dict):
    raise SystemExit("ASSERT FAIL: summary.phases 应为对象")

for phase in ("follow-diff-window", "triage-report", "campaign-report"):
    payload = phases.get(phase)
    if not isinstance(payload, dict):
        raise SystemExit(f"ASSERT FAIL: summary.phases 缺少阶段 {phase!r}")
    for key in ("status", "started_at", "finished_at", "duration_sec", "exit_reason", "exit_code"):
        if key not in payload:
            raise SystemExit(f"ASSERT FAIL: summary.phases[{phase!r}] 缺少字段 {key}")
    if payload.get("status") != "success":
        raise SystemExit(
            f"ASSERT FAIL: summary.phases[{phase!r}].status={payload.get('status')!r} != 'success'"
        )
    if payload.get("exit_code") != 0:
        raise SystemExit(
            f"ASSERT FAIL: summary.phases[{phase!r}].exit_code={payload.get('exit_code')!r} != 0"
        )
    if not isinstance(payload.get("started_at"), str) or not payload["started_at"]:
        raise SystemExit(f"ASSERT FAIL: summary.phases[{phase!r}].started_at 应为非空字符串")
    if not isinstance(payload.get("finished_at"), str) or not payload["finished_at"]:
        raise SystemExit(f"ASSERT FAIL: summary.phases[{phase!r}].finished_at 应为非空字符串")
    if not isinstance(payload.get("duration_sec"), (int, float)) or float(payload["duration_sec"]) < 0:
        raise SystemExit(f"ASSERT FAIL: summary.phases[{phase!r}].duration_sec 应为非负数")
    if not isinstance(payload.get("exit_reason"), str) or not payload["exit_reason"]:
        raise SystemExit(f"ASSERT FAIL: summary.phases[{phase!r}].exit_reason 应为非空字符串")
PY
}

assert_campaign_close_failure_summary() {
	local summary_path="$1"
	local expected_queue_tail_id="$2"
	local expected_exit_code="$3"
	local expected_exit_reason="$4"
	local expected_failed_phase="$5"
	local expected_phase_exit_reason="$6"
	local expected_message_keyword="$7"
	python3 - \
		"$summary_path" \
		"$expected_queue_tail_id" \
		"$expected_exit_code" \
		"$expected_exit_reason" \
		"$expected_failed_phase" \
		"$expected_phase_exit_reason" \
		"$expected_message_keyword" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_queue_tail_id = sys.argv[2]
expected_exit_code = int(sys.argv[3])
expected_exit_reason = sys.argv[4]
expected_failed_phase = sys.argv[5]
expected_phase_exit_reason = sys.argv[6]
expected_message_keyword = sys.argv[7]

for key in (
    "budget_sec",
    "deadline_ts",
    "queue_tail_id",
    "status",
    "exit_reason",
    "exit_code",
    "failed_phase",
    "phases",
):
    if key not in summary:
        raise SystemExit(f"ASSERT FAIL: campaign_close.summary.json 缺少字段 {key}")

if summary.get("queue_tail_id") != expected_queue_tail_id:
    raise SystemExit(
        f"ASSERT FAIL: summary.queue_tail_id={summary.get('queue_tail_id')!r} != {expected_queue_tail_id!r}"
    )
if summary.get("status") != "failed":
    raise SystemExit(f"ASSERT FAIL: summary.status={summary.get('status')!r} != 'failed'")
if summary.get("exit_reason") != expected_exit_reason:
    raise SystemExit(
        f"ASSERT FAIL: summary.exit_reason={summary.get('exit_reason')!r} != {expected_exit_reason!r}"
    )
if summary.get("exit_code") != expected_exit_code:
    raise SystemExit(
        f"ASSERT FAIL: summary.exit_code={summary.get('exit_code')!r} != {expected_exit_code!r}"
    )
if summary.get("failed_phase") != expected_failed_phase:
    raise SystemExit(
        f"ASSERT FAIL: summary.failed_phase={summary.get('failed_phase')!r} != {expected_failed_phase!r}"
    )

phases = summary.get("phases")
if not isinstance(phases, dict):
    raise SystemExit("ASSERT FAIL: summary.phases 应为对象")

payload = phases.get(expected_failed_phase)
if not isinstance(payload, dict):
    raise SystemExit(f"ASSERT FAIL: summary.phases 缺少失败阶段 {expected_failed_phase!r}")
for key in ("status", "started_at", "finished_at", "duration_sec", "exit_reason", "exit_code"):
    if key not in payload:
        raise SystemExit(f"ASSERT FAIL: summary.phases[{expected_failed_phase!r}] 缺少字段 {key}")
if payload.get("status") == "success":
    raise SystemExit(f"ASSERT FAIL: 失败阶段 {expected_failed_phase!r} 不应标记为 success")
if payload.get("exit_code") != expected_exit_code:
    raise SystemExit(
        "ASSERT FAIL: summary.phases[failed].exit_code="
        f"{payload.get('exit_code')!r} != {expected_exit_code!r}"
    )
if expected_phase_exit_reason != "__nonempty__" and payload.get("exit_reason") != expected_phase_exit_reason:
    raise SystemExit(
        "ASSERT FAIL: summary.phases[failed].exit_reason="
        f"{payload.get('exit_reason')!r} != {expected_phase_exit_reason!r}"
    )
if expected_phase_exit_reason == "__nonempty__" and (
    not isinstance(payload.get("exit_reason"), str) or not payload["exit_reason"]
):
    raise SystemExit("ASSERT FAIL: summary.phases[failed].exit_reason 应为非空字符串")
if expected_message_keyword != "-":
    message = payload.get("message")
    if not isinstance(message, str) or expected_message_keyword not in message:
        raise SystemExit(
            "ASSERT FAIL: summary.phases[failed].message 未包含关键字 "
            f"{expected_message_keyword!r}: {message!r}"
        )
PY
}

assert_campaign_close_metadata_contract() {
	local summary_path="$1"
	local scenario="$2"
	python3 - "$summary_path" "$scenario" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
scenario = sys.argv[2]
work_dir = pathlib.Path(sys.argv[1]).resolve().parent
expected_seed_dir = str((work_dir / "stable_transcript_corpus").resolve())
expected_seed_provenance = {
    "cold_start": False,
    "seed_source_dir": expected_seed_dir,
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": expected_seed_dir,
    "transcript_format_version": 2,
    "transcript_max_responses": 3,
    "response_preserve": 20,
    "recorded_at": "2026-03-26T00:00:00Z",
}

run_id = summary.get("run_id")
if not isinstance(run_id, str) or not run_id:
    raise SystemExit("ASSERT FAIL: close summary.run_id 应为非空字符串")

metric_denominators = summary.get("metric_denominators")
if not isinstance(metric_denominators, dict):
    raise SystemExit("ASSERT FAIL: close summary.metric_denominators 应为对象")
analysis_state = metric_denominators.get("analysis_state")
if not isinstance(analysis_state, dict):
    raise SystemExit("ASSERT FAIL: metric_denominators.analysis_state 应为对象")
for key in ("included", "excluded", "unknown"):
    value = analysis_state.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(
            f"ASSERT FAIL: metric_denominators.analysis_state[{key!r}]={value!r} 非法"
        )

total_samples = metric_denominators.get("total_samples")
if isinstance(total_samples, bool) or not isinstance(total_samples, int) or total_samples < 0:
    raise SystemExit(
        f"ASSERT FAIL: metric_denominators.total_samples={total_samples!r} 非法"
    )
if sum(analysis_state.values()) != total_samples:
    raise SystemExit(
        "ASSERT FAIL: analysis_state 分母求和与 total_samples 不一致: "
        f"{analysis_state!r} vs {total_samples!r}"
    )

comparability = summary.get("comparability")
if not isinstance(comparability, dict):
    raise SystemExit("ASSERT FAIL: close summary.comparability 应为对象")
if scenario in {"success", "report-missing"}:
    if comparability.get("status") != "comparable":
        raise SystemExit(
            f"ASSERT FAIL: close summary.comparability.status={comparability.get('status')!r} != 'comparable'"
        )
    if not isinstance(comparability.get("aggregation_key"), dict):
        raise SystemExit("ASSERT FAIL: comparable 场景 aggregation_key 应为对象")
    if not isinstance(comparability.get("baseline_compare_key"), dict):
        raise SystemExit("ASSERT FAIL: comparable 场景 baseline_compare_key 应为对象")
elif scenario == "follow-timeout":
    if comparability.get("status") == "comparable":
        if not isinstance(comparability.get("aggregation_key"), dict):
            raise SystemExit("ASSERT FAIL: follow-timeout comparable aggregation_key 应为对象")
        if not isinstance(comparability.get("baseline_compare_key"), dict):
            raise SystemExit("ASSERT FAIL: follow-timeout comparable baseline_compare_key 应为对象")
    else:
        if comparability.get("status") != "non_comparable":
            raise SystemExit(
                f"ASSERT FAIL: close summary.comparability.status={comparability.get('status')!r} 非法"
            )
        if comparability.get("aggregation_key") is not None:
            raise SystemExit("ASSERT FAIL: follow-timeout non_comparable aggregation_key 应为 null")
        if comparability.get("baseline_compare_key") is not None:
            raise SystemExit(
                "ASSERT FAIL: follow-timeout non_comparable baseline_compare_key 应为 null"
            )
else:
    if comparability.get("status") != "non_comparable":
        raise SystemExit(
            f"ASSERT FAIL: close summary.comparability.status={comparability.get('status')!r} != 'non_comparable'"
        )
    if comparability.get("aggregation_key") is not None:
        raise SystemExit("ASSERT FAIL: close summary.comparability.aggregation_key 应为 null")
    if comparability.get("baseline_compare_key") is not None:
        raise SystemExit(
            "ASSERT FAIL: close summary.comparability.baseline_compare_key 应为 null"
        )

if summary.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: close summary.seed_provenance 不符合预期: "
        f"{summary.get('seed_provenance')!r}"
    )

phase_context = summary.get("phase_context")
if not isinstance(phase_context, dict):
    raise SystemExit("ASSERT FAIL: close summary.phase_context 应为对象")

state_context = phase_context.get("follow_diff_state")
window_context = phase_context.get("follow_diff_window_summary")
if not isinstance(state_context, dict) or not isinstance(window_context, dict):
    raise SystemExit("ASSERT FAIL: phase_context 缺少 follow_diff_state/window_summary")
if state_context.get("run_id") != run_id:
    raise SystemExit(
        f"ASSERT FAIL: phase_context.follow_diff_state.run_id={state_context.get('run_id')!r} != {run_id!r}"
    )
if window_context.get("run_id") != run_id:
    raise SystemExit(
        "ASSERT FAIL: phase_context.follow_diff_window_summary.run_id="
        f"{window_context.get('run_id')!r} != {run_id!r}"
    )
retry_count = state_context.get("retry_count")
if isinstance(retry_count, bool) or not isinstance(retry_count, int) or retry_count < 0:
    raise SystemExit(
        f"ASSERT FAIL: phase_context.follow_diff_state.retry_count={retry_count!r} 非法"
    )
last_attempt_ts = state_context.get("last_attempt_ts")
if not isinstance(last_attempt_ts, str) or not last_attempt_ts:
    raise SystemExit("ASSERT FAIL: phase_context.follow_diff_state.last_attempt_ts 应为非空字符串")
if window_context.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: phase_context.follow_diff_window_summary.seed_provenance 不符合预期: "
        f"{window_context.get('seed_provenance')!r}"
    )

if scenario == "success":
    expected_denominators = {
        "total_samples": 1,
        "analysis_state": {"included": 1, "excluded": 0, "unknown": 0},
        "comparable_samples": 1,
        "non_comparable_samples": 0,
    }
    if metric_denominators != expected_denominators:
        raise SystemExit(
            f"ASSERT FAIL: success metric_denominators={metric_denominators!r} != {expected_denominators!r}"
        )
    if comparability.get("reason") != "ok":
        raise SystemExit(
            f"ASSERT FAIL: success comparability.reason={comparability.get('reason')!r} != 'ok'"
        )
    if state_context.get("last_exit_reason") != "quiescent":
        raise SystemExit("ASSERT FAIL: success state.last_exit_reason 应为 quiescent")
    if window_context.get("exit_reason") != "quiescent":
        raise SystemExit("ASSERT FAIL: success window.exit_reason 应为 quiescent")
    if retry_count != 0:
        raise SystemExit(f"ASSERT FAIL: success retry_count={retry_count!r} != 0")
elif scenario == "follow-timeout":
    if comparability.get("status") == "comparable":
        if metric_denominators.get("comparable_samples") != total_samples:
            raise SystemExit(
                "ASSERT FAIL: follow-timeout comparable 场景 comparable_samples 应等于 total_samples"
            )
        if metric_denominators.get("non_comparable_samples") != 0:
            raise SystemExit(
                "ASSERT FAIL: follow-timeout comparable 场景 non_comparable_samples 应为 0"
            )
        if comparability.get("reason") != "ok":
            raise SystemExit(
                f"ASSERT FAIL: follow-timeout comparable.reason={comparability.get('reason')!r} != 'ok'"
            )
    else:
        if metric_denominators.get("comparable_samples") != 0:
            raise SystemExit("ASSERT FAIL: follow-timeout non_comparable 场景 comparable_samples 应为 0")
        if metric_denominators.get("non_comparable_samples") != total_samples:
            raise SystemExit(
                "ASSERT FAIL: follow-timeout non_comparable 场景 non_comparable_samples 应等于 total_samples"
            )
        if comparability.get("reason") not in {"no_samples", "missing_comparability_fields"}:
            raise SystemExit(
                "ASSERT FAIL: follow-timeout comparability.reason 非法: "
                f"{comparability.get('reason')!r}"
            )
    if state_context.get("last_exit_reason") != "deadline_exceeded":
        raise SystemExit(
            "ASSERT FAIL: follow-timeout state.last_exit_reason 应为 deadline_exceeded"
        )
    if window_context.get("exit_reason") != "deadline_exceeded":
        raise SystemExit(
            "ASSERT FAIL: follow-timeout window.exit_reason 应为 deadline_exceeded"
        )
    if retry_count != 0:
        raise SystemExit(f"ASSERT FAIL: follow-timeout retry_count={retry_count!r} != 0")
elif scenario == "report-missing":
    expected_denominators = {
        "total_samples": 1,
        "analysis_state": {"included": 1, "excluded": 0, "unknown": 0},
        "comparable_samples": 1,
        "non_comparable_samples": 0,
    }
    if metric_denominators != expected_denominators:
        raise SystemExit(
            f"ASSERT FAIL: report-missing metric_denominators={metric_denominators!r} != {expected_denominators!r}"
        )
    if comparability.get("reason") != "ok":
        raise SystemExit(
            "ASSERT FAIL: report-missing comparability.reason 应为 ok"
        )
    if state_context.get("last_exit_reason") != "quiescent":
        raise SystemExit("ASSERT FAIL: report-missing state.last_exit_reason 应为 quiescent")
    if window_context.get("exit_reason") != "quiescent":
        raise SystemExit("ASSERT FAIL: report-missing window.exit_reason 应为 quiescent")
    if retry_count != 0:
        raise SystemExit(f"ASSERT FAIL: report-missing retry_count={retry_count!r} != 0")
else:
    raise SystemExit(f"ASSERT FAIL: 未知 scenario {scenario!r}")
PY
}

assert_campaign_report_artifacts() {
	local latest_report_dir="$1"
	assert_file_exists "$FOLLOW_ROOT/cluster_summary.tsv"
	assert_file_exists "$FOLLOW_ROOT/status_summary.tsv"
	assert_file_exists "$FOLLOW_ROOT/triage_report.md"
	assert_file_exists "$HIGH_VALUE_MANIFEST"
	assert_file_exists "$latest_report_dir/summary.json"
	assert_file_exists "$latest_report_dir/ablation_matrix.tsv"
	assert_file_exists "$latest_report_dir/cluster_counts.tsv"
	assert_file_exists "$latest_report_dir/repro_rate.tsv"
	assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" $'__total__\t1'
	python3 - "$latest_report_dir/summary.json" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if summary.get("total_samples") != 1:
    raise SystemExit(f"ASSERT FAIL: campaign report total_samples={summary.get('total_samples')!r} != 1")
campaign_id = summary.get("campaign_id")
if not isinstance(campaign_id, str) or not campaign_id:
    raise SystemExit("ASSERT FAIL: campaign report summary.campaign_id 应为非空字符串")
PY
}

emit_campaign_close_evidence() {
	local scenario="$1"
	local summary_path="$2"
	local window_summary_path="$3"
	local report_dir="${4:-}"
	python3 - "$scenario" "$summary_path" "$window_summary_path" "$report_dir" <<'PY'
import json
import pathlib
import sys

scenario, summary_path, window_summary_path, report_dir = sys.argv[1:5]
summary = json.loads(pathlib.Path(summary_path).read_text(encoding="utf-8"))
window_summary = json.loads(pathlib.Path(window_summary_path).read_text(encoding="utf-8"))
seed = summary.get("seed_provenance") or {}
comparability = summary.get("comparability") or {}
metric_denominators = summary.get("metric_denominators") or {}
analysis_state = metric_denominators.get("analysis_state") or {}
phase_window = (summary.get("phase_context") or {}).get("follow_diff_window_summary") or {}


def fmt(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


print(
    "EVIDENCE_T7 campaign_close "
    f"scenario={scenario} "
    f"status={fmt(summary.get('status'))} "
    f"exit_reason={fmt(summary.get('exit_reason'))} "
    f"exit_code={fmt(summary.get('exit_code'))} "
    f"failed_phase={fmt(summary.get('failed_phase') or 'none')} "
    f"queue_tail_id={fmt(summary.get('queue_tail_id'))} "
    f"run_id={fmt(summary.get('run_id'))}"
)
print(
    "EVIDENCE_T7 campaign_close_provenance "
    f"scenario={scenario} "
    f"transcript_format_version={fmt(seed.get('transcript_format_version'))} "
    f"transcript_max_responses={fmt(seed.get('transcript_max_responses'))} "
    f"response_preserve={fmt(seed.get('response_preserve'))} "
    f"seed_materialization_method={fmt(seed.get('seed_materialization_method'))}"
)
print(
    "EVIDENCE_T7 campaign_close_metrics "
    f"scenario={scenario} "
    f"total_samples={fmt(metric_denominators.get('total_samples'))} "
    f"included={fmt(analysis_state.get('included'))} "
    f"excluded={fmt(analysis_state.get('excluded'))} "
    f"unknown={fmt(analysis_state.get('unknown'))} "
    f"comparability_status={fmt(comparability.get('status'))} "
    f"comparability_reason={fmt(comparability.get('reason'))}"
)
print(
    "EVIDENCE_T7 campaign_close_window "
    f"scenario={scenario} "
    f"window_exit_reason={fmt(window_summary.get('exit_reason'))} "
    f"window_run_id={fmt(window_summary.get('run_id'))} "
    f"phase_window_run_id={fmt(phase_window.get('run_id'))}"
)
if report_dir:
    report_summary = json.loads((pathlib.Path(report_dir) / "summary.json").read_text(encoding="utf-8"))
    print(
        "EVIDENCE_T7 campaign_report "
        f"scenario={scenario} "
        f"report_dir={pathlib.Path(report_dir).resolve()} "
        f"campaign_id={fmt(report_summary.get('campaign_id'))} "
        f"total_samples={fmt(report_summary.get('total_samples'))}"
    )
PY
}

init_scenario "success" "dump_success"
run_campaign_close_capture 10
if [ "$CAMPAIGN_EXIT_CODE" -ne 0 ]; then
	printf 'ASSERT FAIL: success 场景期望 campaign-close 返回 0，实际 %s\n' "$CAMPAIGN_EXIT_CODE" >&2
	printf 'stderr:\n' >&2
	cat "$CAMPAIGN_STDERR" >&2
	exit 1
fi
assert_file_exists "$CAMPAIGN_SUMMARY"
assert_file_exists "$WINDOW_SUMMARY"
assert_follow_window_phase_summary "$WINDOW_SUMMARY" "$QUEUE_EVENT_ID" "quiescent" 0
SUCCESS_REPORT_DIR="$(get_latest_report_dir "$CAMPAIGN_REPORT_BASE")"
assert_campaign_report_artifacts "$SUCCESS_REPORT_DIR"
assert_campaign_close_success_summary "$CAMPAIGN_SUMMARY" "$QUEUE_EVENT_ID"
assert_campaign_close_metadata_contract "$CAMPAIGN_SUMMARY" success
emit_campaign_close_evidence "success" "$CAMPAIGN_SUMMARY" "$WINDOW_SUMMARY" "$SUCCESS_REPORT_DIR"

init_scenario "follow-timeout" "timeout"
SEED_TIMEOUT_SEC_OVERRIDE=10
run_campaign_close_capture 1
if [ "$CAMPAIGN_EXIT_CODE" -eq 0 ]; then
	printf 'ASSERT FAIL: follow-diff 预算耗尽场景期望 campaign-close 失败，实际返回 0\n' >&2
	exit 1
fi
if [ "$CAMPAIGN_EXIT_CODE" -eq 124 ]; then
	printf 'ASSERT FAIL: follow-diff 预算耗尽场景不应把 raw 124 当作最终 CLI exit code\n' >&2
	printf 'stderr:\n' >&2
	cat "$CAMPAIGN_STDERR" >&2
	exit 1
fi
assert_file_exists "$CAMPAIGN_SUMMARY"
assert_file_exists "$WINDOW_SUMMARY"
assert_follow_window_phase_summary "$WINDOW_SUMMARY" "$QUEUE_EVENT_ID" "deadline_exceeded" "$CAMPAIGN_EXIT_CODE"
assert_campaign_close_failure_summary \
	"$CAMPAIGN_SUMMARY" \
	"$QUEUE_EVENT_ID" \
	"$CAMPAIGN_EXIT_CODE" \
	"deadline_exceeded" \
	"follow-diff-window" \
	"deadline_exceeded" \
	"-"
assert_campaign_close_metadata_contract "$CAMPAIGN_SUMMARY" follow-timeout
emit_campaign_close_evidence "follow-timeout" "$CAMPAIGN_SUMMARY" "$WINDOW_SUMMARY"

init_scenario "report-missing" "dump_success"
SYMCC_HIGH_VALUE_MANIFEST_OVERRIDE="$SCENARIO_ROOT/high-value-manifest-as-dir"
mkdir -p "$SYMCC_HIGH_VALUE_MANIFEST_OVERRIDE"
run_campaign_close_capture 10
if [ "$CAMPAIGN_EXIT_CODE" -eq 0 ]; then
	printf 'ASSERT FAIL: report artifact 缺失场景期望 campaign-close 失败，实际返回 0\n' >&2
	exit 1
fi
if [ "$CAMPAIGN_EXIT_CODE" -eq 124 ]; then
	printf 'ASSERT FAIL: report artifact 缺失场景不应把 raw 124 当作最终 CLI exit code\n' >&2
	printf 'stderr:\n' >&2
	cat "$CAMPAIGN_STDERR" >&2
	exit 1
fi
assert_file_exists "$CAMPAIGN_SUMMARY"
assert_file_exists "$WINDOW_SUMMARY"
assert_follow_window_phase_summary "$WINDOW_SUMMARY" "$QUEUE_EVENT_ID" "quiescent" 0
assert_campaign_close_failure_summary \
	"$CAMPAIGN_SUMMARY" \
	"$QUEUE_EVENT_ID" \
	"$CAMPAIGN_EXIT_CODE" \
	"phase_failed" \
	"triage-report" \
	"__nonempty__" \
	"high_value_samples.txt"
assert_campaign_close_metadata_contract "$CAMPAIGN_SUMMARY" report-missing
emit_campaign_close_evidence "report-missing" "$CAMPAIGN_SUMMARY" "$WINDOW_SUMMARY"

printf 'PASS: campaign-close contract test passed\n'
