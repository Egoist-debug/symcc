#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-follow-diff-window.XXXXXX")"
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
    "recorded_at": "2026-03-26T00:00:00Z",
}
path = work_dir / "producer_seed_provenance.json"
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
	WINDOW_STDOUT="$SCENARIO_ROOT/follow-diff-window.stdout"
	WINDOW_STDERR="$SCENARIO_ROOT/follow-diff-window.stderr"
	WINDOW_SUMMARY="$SCENARIO_WORK/follow_diff.window.summary.json"
	STATE_FILE="$SCENARIO_WORK/follow_diff.state.json"
	INVOCATION_LOG="$SCENARIO_ROOT/fake-binary.log"
	SEED_TIMEOUT_SEC_OVERRIDE=1

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
	SAMPLE_DIR="$FOLLOW_ROOT/$SAMPLE_ID"
}

assert_command_ready() {
	local stderr_path="$1"
	local command_name="$2"
	if grep -Fq -- "invalid choice: '$command_name'" "$stderr_path"; then
		printf 'ASSERT FAIL: 缺少 %s 子命令；该脚本用于锁定 bounded consumer 红灯契约\n' "$command_name" >&2
		cat "$stderr_path" >&2
		exit 1
	fi
	if grep -Fq -- '尚未实现' "$stderr_path"; then
		printf 'ASSERT FAIL: %s 子命令已接线但仍未实现 bounded 契约\n' "$command_name" >&2
		cat "$stderr_path" >&2
		exit 1
	fi
	if grep -Fq -- 'unrecognized arguments: --budget-sec' "$stderr_path"; then
		printf 'ASSERT FAIL: %s 缺少 --budget-sec 预算契约\n' "$command_name" >&2
		cat "$stderr_path" >&2
		exit 1
	fi
}

run_follow_diff_window_capture() {
	local budget_sec="$1"
	shift || true
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
		ENABLE_DST1_MUTATOR=0 \
		ENABLE_CACHE_DELTA=1 \
		ENABLE_TRIAGE=1 \
		ENABLE_SYMCC=1 \
		FAKE_BINARY_LOG_PATH="$INVOCATION_LOG" \
		python3 -m tools.dns_diff.cli follow-diff-window --budget-sec "$budget_sec" "$@" >"$WINDOW_STDOUT" 2>"$WINDOW_STDERR"
	WINDOW_EXIT_CODE=$?
	set -e
	assert_command_ready "$WINDOW_STDERR" "follow-diff-window"
}

assert_follow_window_summary_contract() {
	local summary_path="$1"
	local expected_exit_reason="$2"
	local expected_exit_code="$3"
	local expected_completed_count="$4"
	local expected_failed_count="$5"
	local expected_queue_tail_id="$6"
	local expected_last_queue_event_id="$7"
	python3 - \
		"$summary_path" \
		"$expected_exit_reason" \
		"$expected_exit_code" \
		"$expected_completed_count" \
		"$expected_failed_count" \
		"$expected_queue_tail_id" \
		"$expected_last_queue_event_id" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_exit_reason = sys.argv[2]
expected_exit_code = int(sys.argv[3])
expected_completed_count = sys.argv[4]
expected_failed_count = sys.argv[5]
expected_queue_tail_id = sys.argv[6]
expected_last_queue_event_id = sys.argv[7]

required_keys = (
    "budget_sec",
    "deadline_ts",
    "queue_tail_id",
    "run_id",
    "exit_reason",
    "exit_code",
    "completed_count",
    "failed_count",
    "last_queue_event_id",
    "aggregation_key",
    "baseline_compare_key",
    "seed_provenance",
)
for key in required_keys:
    if key not in summary:
        raise SystemExit(f"ASSERT FAIL: follow_diff.window.summary.json 缺少字段 {key}")

if not isinstance(summary.get("budget_sec"), (int, float)) or float(summary["budget_sec"]) <= 0:
    raise SystemExit("ASSERT FAIL: summary.budget_sec 应为正数")
if not isinstance(summary.get("deadline_ts"), str) or not summary["deadline_ts"]:
    raise SystemExit("ASSERT FAIL: summary.deadline_ts 应为非空字符串")
if not isinstance(summary.get("run_id"), str) or not summary["run_id"]:
    raise SystemExit("ASSERT FAIL: summary.run_id 应为非空字符串")
if summary.get("queue_tail_id") != expected_queue_tail_id:
    raise SystemExit(
        f"ASSERT FAIL: summary.queue_tail_id={summary.get('queue_tail_id')!r} != {expected_queue_tail_id!r}"
    )
if summary.get("exit_reason") != expected_exit_reason:
    raise SystemExit(
        f"ASSERT FAIL: summary.exit_reason={summary.get('exit_reason')!r} != {expected_exit_reason!r}"
    )
if summary.get("exit_code") != expected_exit_code:
    raise SystemExit(
        f"ASSERT FAIL: summary.exit_code={summary.get('exit_code')!r} != {expected_exit_code!r}"
    )

if expected_completed_count != "__any__" and summary.get("completed_count") != int(expected_completed_count):
    raise SystemExit(
        "ASSERT FAIL: summary.completed_count="
        f"{summary.get('completed_count')!r} != {int(expected_completed_count)!r}"
    )
if expected_failed_count != "__any__" and summary.get("failed_count") != int(expected_failed_count):
    raise SystemExit(
        "ASSERT FAIL: summary.failed_count="
        f"{summary.get('failed_count')!r} != {int(expected_failed_count)!r}"
    )

if expected_last_queue_event_id == "__nonempty_or_null__":
    if "last_queue_event_id" not in summary:
        raise SystemExit("ASSERT FAIL: summary.last_queue_event_id 缺失")
elif summary.get("last_queue_event_id") != expected_last_queue_event_id:
    raise SystemExit(
        "ASSERT FAIL: summary.last_queue_event_id="
        f"{summary.get('last_queue_event_id')!r} != {expected_last_queue_event_id!r}"
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
    "recorded_at": "2026-03-26T00:00:00Z",
}
if summary.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: summary.seed_provenance 不符合预期: "
        f"{summary.get('seed_provenance')!r}"
    )
PY
}

assert_state_contract() {
	local state_path="$1"
	local summary_path="$2"
	local expected_last_queue_event_id="$3"
	local expected_completed_count="$4"
	local expected_failed_count="$5"
	local expected_last_exit_reason="$6"
	local expected_retry_count="$7"
	local expected_source_queue_dir="$8"
	local expected_budget_sec="$9"
	local expected_seed_timeout_sec="${10}"
	local expected_variant_name="${11}"
	local expected_repeat_count="${12}"
	python3 - "$state_path" "$summary_path" "$expected_last_queue_event_id" "$expected_completed_count" "$expected_failed_count" "$expected_last_exit_reason" "$expected_retry_count" "$expected_source_queue_dir" "$expected_budget_sec" "$expected_seed_timeout_sec" "$expected_variant_name" "$expected_repeat_count" <<'PY'
import json
import pathlib
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
expected_last_queue_event_id = sys.argv[3]
expected_completed_count = sys.argv[4]
expected_failed_count = sys.argv[5]
expected_last_exit_reason = sys.argv[6]
expected_retry_count = sys.argv[7]
expected_source_queue_dir = sys.argv[8]
expected_budget_sec = float(sys.argv[9])
if expected_budget_sec.is_integer():
    expected_budget_sec = int(expected_budget_sec)
expected_seed_timeout_sec = int(sys.argv[10])
expected_variant_name = sys.argv[11]
expected_repeat_count = int(sys.argv[12])
expected_ablation_status = {
    "mutator": "off",
    "cache-delta": "on",
    "triage": "on",
    "symcc": "on",
}
expected_seed_dir = str((pathlib.Path(sys.argv[1]).resolve().parent / "stable_transcript_corpus").resolve())
expected_seed_provenance = {
    "cold_start": False,
    "seed_source_dir": expected_seed_dir,
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": expected_seed_dir,
    "recorded_at": "2026-03-26T00:00:00Z",
}


def assert_expected_int_field(payload: dict, owner: str, field_name: str, expected: int) -> None:
    actual = payload.get(field_name)
    if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 int）"
        )


def assert_expected_budget_field(payload: dict, owner: str, field_name: str, expected: int | float) -> None:
    actual = payload.get(field_name)
    if isinstance(expected, int):
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 int）"
            )
        return
    if isinstance(actual, bool) or not isinstance(actual, float) or actual != expected:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 float）"
        )


def assert_comparability_payload(payload: dict, owner: str) -> None:
    if payload.get("resolver_pair") != "bind9_vs_unbound":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.resolver_pair={payload.get('resolver_pair')!r} != 'bind9_vs_unbound'"
        )
    if payload.get("producer_profile") != "poison-stateful":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.producer_profile={payload.get('producer_profile')!r} != 'poison-stateful'"
        )
    if payload.get("input_model") != "DST1 transcript":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.input_model={payload.get('input_model')!r} != 'DST1 transcript'"
        )
    if payload.get("source_queue_dir") != expected_source_queue_dir:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.source_queue_dir={payload.get('source_queue_dir')!r} != {expected_source_queue_dir!r}"
        )
    assert_expected_budget_field(payload, owner, "budget_sec", expected_budget_sec)
    assert_expected_int_field(payload, owner, "seed_timeout_sec", expected_seed_timeout_sec)
    if owner.endswith("aggregation_key"):
        if payload.get("variant_name") != expected_variant_name:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.variant_name={payload.get('variant_name')!r} != {expected_variant_name!r}"
            )
        if payload.get("ablation_status") != expected_ablation_status:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.ablation_status={payload.get('ablation_status')!r} != {expected_ablation_status!r}"
            )
    else:
        assert_expected_int_field(payload, owner, "repeat_count", expected_repeat_count)
    assert_expected_int_field(payload, owner, "contract_version", 1)

for field in (
    "schema_version",
    "last_scan_ts",
    "last_queue_event_id",
    "running_sample_id",
    "completed_count",
    "failed_count",
    "run_id",
    "last_exit_reason",
    "retry_count",
    "last_attempt_ts",
    "aggregation_key",
    "baseline_compare_key",
):
    if field not in state:
        raise SystemExit(f"ASSERT FAIL: follow_diff.state.json 缺少字段 {field}")

expected_aggregation_fields = {
    "resolver_pair",
    "producer_profile",
    "input_model",
    "source_queue_dir",
    "budget_sec",
    "seed_timeout_sec",
    "variant_name",
    "ablation_status",
    "contract_version",
}
expected_baseline_fields = {
    "resolver_pair",
    "producer_profile",
    "input_model",
    "source_queue_dir",
    "budget_sec",
    "seed_timeout_sec",
    "repeat_count",
    "contract_version",
}

for key_name, expected_fields in (
    ("aggregation_key", expected_aggregation_fields),
    ("baseline_compare_key", expected_baseline_fields),
):
    state_key = state.get(key_name)
    summary_key = summary.get(key_name)
    if not isinstance(state_key, dict):
        raise SystemExit(f"ASSERT FAIL: state.{key_name} 应为对象")
    if not isinstance(summary_key, dict):
        raise SystemExit(f"ASSERT FAIL: summary.{key_name} 应为对象")
    if set(state_key.keys()) != expected_fields:
        raise SystemExit(
            f"ASSERT FAIL: state.{key_name} 字段集合异常: {sorted(state_key.keys())!r}"
        )
    if set(summary_key.keys()) != expected_fields:
        raise SystemExit(
            f"ASSERT FAIL: summary.{key_name} 字段集合异常: {sorted(summary_key.keys())!r}"
        )
    if state_key != summary_key:
        raise SystemExit(
            f"ASSERT FAIL: state.{key_name} 与 summary.{key_name} 在同一 run 内不一致"
        )

assert_comparability_payload(state["aggregation_key"], "state.aggregation_key")
assert_comparability_payload(summary["aggregation_key"], "summary.aggregation_key")
assert_comparability_payload(
    state["baseline_compare_key"], "state.baseline_compare_key"
)
assert_comparability_payload(
    summary["baseline_compare_key"], "summary.baseline_compare_key"
)
if summary.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: summary.seed_provenance 不符合预期: "
        f"{summary.get('seed_provenance')!r}"
    )

if state.get("schema_version") != 1:
    raise SystemExit("ASSERT FAIL: state.schema_version 应为 1")
if not isinstance(state.get("last_scan_ts"), str) or not state["last_scan_ts"]:
    raise SystemExit("ASSERT FAIL: state.last_scan_ts 应为非空字符串")
if expected_last_queue_event_id == "__nonempty_or_null__":
    if "last_queue_event_id" not in state:
        raise SystemExit("ASSERT FAIL: state.last_queue_event_id 缺失")
elif state.get("last_queue_event_id") != expected_last_queue_event_id:
    raise SystemExit(
        "ASSERT FAIL: state.last_queue_event_id="
        f"{state.get('last_queue_event_id')!r} != {expected_last_queue_event_id!r}"
    )
if state.get("running_sample_id") not in (None, ""):
    raise SystemExit("ASSERT FAIL: state.running_sample_id 应为空")
if expected_completed_count != "__any__" and state.get("completed_count") != int(expected_completed_count):
    raise SystemExit(
        f"ASSERT FAIL: state.completed_count={state.get('completed_count')!r} != {int(expected_completed_count)!r}"
    )
if expected_failed_count != "__any__" and state.get("failed_count") != int(expected_failed_count):
    raise SystemExit(
        f"ASSERT FAIL: state.failed_count={state.get('failed_count')!r} != {int(expected_failed_count)!r}"
    )

summary_run_id = summary.get("run_id")
if not isinstance(summary_run_id, str) or not summary_run_id:
    raise SystemExit("ASSERT FAIL: summary.run_id 应为非空字符串")
if state.get("run_id") != summary_run_id:
    raise SystemExit(
        f"ASSERT FAIL: state.run_id={state.get('run_id')!r} != summary.run_id={summary_run_id!r}"
    )
if state.get("last_exit_reason") != expected_last_exit_reason:
    raise SystemExit(
        "ASSERT FAIL: state.last_exit_reason="
        f"{state.get('last_exit_reason')!r} != {expected_last_exit_reason!r}"
    )
retry_count = state.get("retry_count")
if isinstance(retry_count, bool) or not isinstance(retry_count, int) or retry_count < 0:
    raise SystemExit("ASSERT FAIL: state.retry_count 应为非负整数")
if expected_retry_count == "__positive__":
    if retry_count <= 0:
        raise SystemExit(
            f"ASSERT FAIL: state.retry_count={retry_count!r} 应大于 0"
        )
elif retry_count != int(expected_retry_count):
    raise SystemExit(
        f"ASSERT FAIL: state.retry_count={retry_count!r} != {int(expected_retry_count)!r}"
    )
if not isinstance(state.get("last_attempt_ts"), str) or not state["last_attempt_ts"]:
    raise SystemExit("ASSERT FAIL: state.last_attempt_ts 应为非空字符串")
PY
}

assert_completed_sample_contract() {
	local sample_dir="$1"
	local expected_sample_id="$2"
	local expected_source_queue_dir="$3"
	local expected_budget_sec="$4"
	local expected_seed_timeout_sec="$5"
	local expected_variant_name="$6"
	local expected_repeat_count="$7"
	assert_file_exists "$sample_dir/sample.meta.json"
	assert_file_exists "$sample_dir/state_fingerprint.json"
	assert_file_exists "$sample_dir/cache_diff.json"
	assert_file_exists "$sample_dir/triage.json"
	python3 - "$sample_dir" "$expected_sample_id" "$expected_source_queue_dir" "$expected_budget_sec" "$expected_seed_timeout_sec" "$expected_variant_name" "$expected_repeat_count" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
expected_sample_id = sys.argv[2]
expected_source_queue_dir = sys.argv[3]
expected_budget_sec = float(sys.argv[4])
if expected_budget_sec.is_integer():
    expected_budget_sec = int(expected_budget_sec)
expected_seed_timeout_sec = int(sys.argv[5])
expected_variant_name = sys.argv[6]
expected_repeat_count = int(sys.argv[7])
meta = json.loads((sample_dir / "sample.meta.json").read_text(encoding="utf-8"))
triage = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))
expected_ablation_status = {
    "mutator": "off",
    "cache-delta": "on",
    "triage": "on",
    "symcc": "on",
}
expected_seed_dir = str((sample_dir.parent.parent / "stable_transcript_corpus").resolve())
expected_seed_provenance = {
    "cold_start": False,
    "seed_source_dir": expected_seed_dir,
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": expected_seed_dir,
    "recorded_at": "2026-03-26T00:00:00Z",
}


def assert_expected_int_field(payload: dict, owner: str, field_name: str, expected: int) -> None:
    actual = payload.get(field_name)
    if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 int）"
        )


def assert_expected_budget_field(payload: dict, owner: str, field_name: str, expected: int | float) -> None:
    actual = payload.get(field_name)
    if isinstance(expected, int):
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 int）"
            )
        return
    if isinstance(actual, bool) or not isinstance(actual, float) or actual != expected:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 float）"
        )


def assert_comparability_payload(payload: object, owner: str, *, baseline: bool) -> None:
    if not isinstance(payload, dict):
        raise SystemExit(f"ASSERT FAIL: {owner} 应为对象")
    if payload.get("resolver_pair") != "bind9_vs_unbound":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.resolver_pair={payload.get('resolver_pair')!r} != 'bind9_vs_unbound'"
        )
    if payload.get("producer_profile") != "poison-stateful":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.producer_profile={payload.get('producer_profile')!r} != 'poison-stateful'"
        )
    if payload.get("input_model") != "DST1 transcript":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.input_model={payload.get('input_model')!r} != 'DST1 transcript'"
        )
    if payload.get("source_queue_dir") != expected_source_queue_dir:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.source_queue_dir={payload.get('source_queue_dir')!r} != {expected_source_queue_dir!r}"
        )
    assert_expected_budget_field(payload, owner, "budget_sec", expected_budget_sec)
    assert_expected_int_field(payload, owner, "seed_timeout_sec", expected_seed_timeout_sec)
    if baseline:
        assert_expected_int_field(payload, owner, "repeat_count", expected_repeat_count)
    else:
        if payload.get("variant_name") != expected_variant_name:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.variant_name={payload.get('variant_name')!r} != {expected_variant_name!r}"
            )
        if payload.get("ablation_status") != expected_ablation_status:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.ablation_status={payload.get('ablation_status')!r} != {expected_ablation_status!r}"
            )
    assert_expected_int_field(payload, owner, "contract_version", 1)

if meta.get("sample_id") != expected_sample_id:
    raise SystemExit(
        f"ASSERT FAIL: sample.meta.json.sample_id={meta.get('sample_id')!r} != {expected_sample_id!r}"
    )
if meta.get("status") != "completed":
    raise SystemExit("ASSERT FAIL: sample.meta.json.status 应为 completed")
if not isinstance(meta.get("first_seen_ts"), str) or not meta["first_seen_ts"]:
    raise SystemExit("ASSERT FAIL: sample.meta.json.first_seen_ts 应为非空字符串")
assert_comparability_payload(meta.get("aggregation_key"), "sample.meta.json.aggregation_key", baseline=False)
assert_comparability_payload(meta.get("baseline_compare_key"), "sample.meta.json.baseline_compare_key", baseline=True)
if meta.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: sample.meta.json.seed_provenance 不符合预期: "
        f"{meta.get('seed_provenance')!r}"
    )
if not isinstance(triage.get("status"), str) or not triage["status"].startswith("completed"):
    raise SystemExit(f"ASSERT FAIL: triage.status 未保持 completed 前缀: {triage.get('status')!r}")
PY
}

assert_failed_sample_contract() {
	local sample_dir="$1"
	local expected_sample_id="$2"
	local expected_reason="$3"
	local expected_source_queue_dir="$4"
	local expected_budget_sec="$5"
	local expected_seed_timeout_sec="$6"
	local expected_variant_name="$7"
	local expected_repeat_count="$8"
	assert_file_exists "$sample_dir/sample.meta.json"
	assert_file_exists "$sample_dir/triage.json"
	python3 - "$sample_dir" "$expected_sample_id" "$expected_reason" "$expected_source_queue_dir" "$expected_budget_sec" "$expected_seed_timeout_sec" "$expected_variant_name" "$expected_repeat_count" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
expected_sample_id = sys.argv[2]
expected_reason = sys.argv[3]
expected_source_queue_dir = sys.argv[4]
expected_budget_sec = float(sys.argv[5])
if expected_budget_sec.is_integer():
    expected_budget_sec = int(expected_budget_sec)
expected_seed_timeout_sec = int(sys.argv[6])
expected_variant_name = sys.argv[7]
expected_repeat_count = int(sys.argv[8])
meta = json.loads((sample_dir / "sample.meta.json").read_text(encoding="utf-8"))
triage = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))
expected_ablation_status = {
    "mutator": "off",
    "cache-delta": "on",
    "triage": "on",
    "symcc": "on",
}
expected_seed_dir = str((sample_dir.parent.parent / "stable_transcript_corpus").resolve())
expected_seed_provenance = {
    "cold_start": False,
    "seed_source_dir": expected_seed_dir,
    "seed_materialization_method": "reused_filtered_corpus",
    "seed_snapshot_id": "1111111111111111111111111111111111111111",
    "regen_seeds": False,
    "refilter_queries": False,
    "stable_input_dir": expected_seed_dir,
    "recorded_at": "2026-03-26T00:00:00Z",
}


def assert_expected_int_field(payload: dict, owner: str, field_name: str, expected: int) -> None:
    actual = payload.get(field_name)
    if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 int）"
        )


def assert_expected_budget_field(payload: dict, owner: str, field_name: str, expected: int | float) -> None:
    actual = payload.get(field_name)
    if isinstance(expected, int):
        if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 int）"
            )
        return
    if isinstance(actual, bool) or not isinstance(actual, float) or actual != expected:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.{field_name}={actual!r} != {expected!r}（应为 float）"
        )


def assert_comparability_payload(payload: object, owner: str, *, baseline: bool) -> None:
    if not isinstance(payload, dict):
        raise SystemExit(f"ASSERT FAIL: {owner} 应为对象")
    if payload.get("resolver_pair") != "bind9_vs_unbound":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.resolver_pair={payload.get('resolver_pair')!r} != 'bind9_vs_unbound'"
        )
    if payload.get("producer_profile") != "poison-stateful":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.producer_profile={payload.get('producer_profile')!r} != 'poison-stateful'"
        )
    if payload.get("input_model") != "DST1 transcript":
        raise SystemExit(
            f"ASSERT FAIL: {owner}.input_model={payload.get('input_model')!r} != 'DST1 transcript'"
        )
    if payload.get("source_queue_dir") != expected_source_queue_dir:
        raise SystemExit(
            f"ASSERT FAIL: {owner}.source_queue_dir={payload.get('source_queue_dir')!r} != {expected_source_queue_dir!r}"
        )
    assert_expected_budget_field(payload, owner, "budget_sec", expected_budget_sec)
    assert_expected_int_field(payload, owner, "seed_timeout_sec", expected_seed_timeout_sec)
    if baseline:
        assert_expected_int_field(payload, owner, "repeat_count", expected_repeat_count)
    else:
        if payload.get("variant_name") != expected_variant_name:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.variant_name={payload.get('variant_name')!r} != {expected_variant_name!r}"
            )
        if payload.get("ablation_status") != expected_ablation_status:
            raise SystemExit(
                f"ASSERT FAIL: {owner}.ablation_status={payload.get('ablation_status')!r} != {expected_ablation_status!r}"
            )
    assert_expected_int_field(payload, owner, "contract_version", 1)

if meta.get("sample_id") != expected_sample_id:
    raise SystemExit(
        f"ASSERT FAIL: sample.meta.json.sample_id={meta.get('sample_id')!r} != {expected_sample_id!r}"
    )
if meta.get("status") != "failed":
    raise SystemExit("ASSERT FAIL: sample.meta.json.status 应为 failed")
failure = meta.get("failure")
if not isinstance(failure, dict):
    raise SystemExit("ASSERT FAIL: sample.meta.json.failure 应为对象")
if failure.get("kind") != "replay_error":
    raise SystemExit("ASSERT FAIL: failure.kind 应为 replay_error")
if failure.get("reason") != expected_reason:
    raise SystemExit(
        f"ASSERT FAIL: failure.reason={failure.get('reason')!r} != {expected_reason!r}"
    )
if not isinstance(failure.get("exit_code"), int) or failure["exit_code"] <= 0:
    raise SystemExit("ASSERT FAIL: failure.exit_code 应为正整数")
assert_comparability_payload(meta.get("aggregation_key"), "sample.meta.json.aggregation_key", baseline=False)
assert_comparability_payload(meta.get("baseline_compare_key"), "sample.meta.json.baseline_compare_key", baseline=True)
if meta.get("seed_provenance") != expected_seed_provenance:
    raise SystemExit(
        "ASSERT FAIL: sample.meta.json.seed_provenance 不符合预期: "
        f"{meta.get('seed_provenance')!r}"
    )
if triage.get("status") != "failed_replay":
    raise SystemExit(f"ASSERT FAIL: triage.status={triage.get('status')!r} != 'failed_replay'")
if triage.get("diff_class") != "replay_incomplete":
    raise SystemExit(
        f"ASSERT FAIL: triage.diff_class={triage.get('diff_class')!r} != 'replay_incomplete'"
    )
PY
}

assert_invocation_count() {
	local log_path="$1"
	local expected_mode="$2"
	local expected_count="$3"
	python3 - "$log_path" "$expected_mode" "$expected_count" <<'PY'
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
expected_mode = sys.argv[2]
expected_count = int(sys.argv[3])

if not log_path.is_file():
    raise SystemExit(f"ASSERT FAIL: 缺少调用日志 {log_path}")

lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
actual_count = sum(1 for line in lines if line.endswith(f"\t{expected_mode}"))
if actual_count != expected_count:
    raise SystemExit(
        f"ASSERT FAIL: 模式 {expected_mode!r} 调用次数 {actual_count!r} != {expected_count!r}; lines={lines!r}"
    )
PY
}

assert_invocation_count_at_least() {
	local log_path="$1"
	local expected_mode="$2"
	local expected_min_count="$3"
	python3 - "$log_path" "$expected_mode" "$expected_min_count" <<'PY'
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
expected_mode = sys.argv[2]
expected_min_count = int(sys.argv[3])

if not log_path.is_file():
    raise SystemExit(f"ASSERT FAIL: 缺少调用日志 {log_path}")

lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
actual_count = sum(1 for line in lines if line.endswith(f"\t{expected_mode}"))
if actual_count < expected_min_count:
    raise SystemExit(
        f"ASSERT FAIL: 模式 {expected_mode!r} 调用次数 {actual_count!r} < {expected_min_count!r}; lines={lines!r}"
    )
PY
}

init_scenario "quiescent" "dump_success"
run_follow_diff_window_capture 5
if [ "$WINDOW_EXIT_CODE" -ne 0 ]; then
	printf 'ASSERT FAIL: quiescent 场景期望 follow-diff-window 返回 0，实际 %s\n' "$WINDOW_EXIT_CODE" >&2
	printf 'stderr:\n' >&2
	cat "$WINDOW_STDERR" >&2
	exit 1
fi
assert_file_exists "$WINDOW_SUMMARY"
assert_file_exists "$STATE_FILE"
assert_completed_sample_contract "$SAMPLE_DIR" "$SAMPLE_ID" "$QUEUE_DIR" 5 1 "no_mutator" 1
assert_follow_window_summary_contract "$WINDOW_SUMMARY" "quiescent" 0 1 0 "$QUEUE_EVENT_ID" "$QUEUE_EVENT_ID"
assert_state_contract "$STATE_FILE" "$WINDOW_SUMMARY" "$QUEUE_EVENT_ID" 1 0 "quiescent" 0 "$QUEUE_DIR" 5 1 "no_mutator" 1

init_scenario "timeout" "timeout"
SEED_TIMEOUT_SEC_OVERRIDE=10
run_follow_diff_window_capture 1
if [ "$WINDOW_EXIT_CODE" -eq 0 ]; then
	printf 'ASSERT FAIL: timeout 场景期望 follow-diff-window 失败，实际返回 0\n' >&2
	exit 1
fi
if [ "$WINDOW_EXIT_CODE" -eq 124 ]; then
	printf 'ASSERT FAIL: timeout 场景不应把 raw 124 当作最终 CLI exit code\n' >&2
	printf 'stderr:\n' >&2
	cat "$WINDOW_STDERR" >&2
	exit 1
fi
assert_file_exists "$WINDOW_SUMMARY"
assert_file_exists "$STATE_FILE"
assert_follow_window_summary_contract \
	"$WINDOW_SUMMARY" \
	"deadline_exceeded" \
	"$WINDOW_EXIT_CODE" \
	"__any__" \
	"__any__" \
	"$QUEUE_EVENT_ID" \
	"__nonempty_or_null__"
assert_state_contract "$STATE_FILE" "$WINDOW_SUMMARY" "__nonempty_or_null__" "__any__" "__any__" "deadline_exceeded" 0 "$QUEUE_DIR" 1 10 "no_mutator" 1

init_scenario "failed-sample" "missing_artifact"
run_follow_diff_window_capture 5
if [ "$WINDOW_EXIT_CODE" -ne 0 ]; then
	printf 'ASSERT FAIL: failed sample 场景期望 bounded run 给出确定终止并返回 0，实际 %s\n' "$WINDOW_EXIT_CODE" >&2
	printf 'stderr:\n' >&2
	cat "$WINDOW_STDERR" >&2
	exit 1
fi
assert_file_exists "$WINDOW_SUMMARY"
assert_file_exists "$STATE_FILE"
assert_failed_sample_contract "$SAMPLE_DIR" "$SAMPLE_ID" "missing_artifact" "$QUEUE_DIR" 5 1 "no_mutator" 1
assert_follow_window_summary_contract "$WINDOW_SUMMARY" "quiescent" 0 0 1 "$QUEUE_EVENT_ID" "$QUEUE_EVENT_ID"
assert_state_contract "$STATE_FILE" "$WINDOW_SUMMARY" "$QUEUE_EVENT_ID" 0 1 "quiescent" 0 "$QUEUE_DIR" 5 1 "no_mutator" 1
assert_invocation_count "$INVOCATION_LOG" "missing_artifact" 1

init_scenario "failed-sample-retry-enabled" "missing_artifact"
run_follow_diff_window_capture 1 --retry-failed
if [ "$WINDOW_EXIT_CODE" -eq 0 ]; then
	printf 'ASSERT FAIL: --retry-failed 场景期望在 budget 内反复重试并最终超时，实际返回 0\n' >&2
	exit 1
fi
if [ "$WINDOW_EXIT_CODE" -eq 124 ]; then
	printf 'ASSERT FAIL: --retry-failed 场景不应把 raw 124 当作最终 CLI exit code\n' >&2
	exit 1
fi
assert_file_exists "$WINDOW_SUMMARY"
assert_file_exists "$STATE_FILE"
assert_follow_window_summary_contract "$WINDOW_SUMMARY" "deadline_exceeded" "$WINDOW_EXIT_CODE" "__any__" "__any__" "$QUEUE_EVENT_ID" "__nonempty_or_null__"
assert_state_contract "$STATE_FILE" "$WINDOW_SUMMARY" "__nonempty_or_null__" "__any__" "__any__" "deadline_exceeded" "__positive__" "$QUEUE_DIR" 1 1 "no_mutator" 1
assert_invocation_count_at_least "$INVOCATION_LOG" "missing_artifact" 2

python3 - "$WINDOW_SUMMARY" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if summary.get("retry_failed") is not True:
    raise SystemExit("ASSERT FAIL: --retry-failed 场景 summary.retry_failed 应为 true")
if not isinstance(summary.get("run_id"), str) or not summary["run_id"]:
    raise SystemExit("ASSERT FAIL: --retry-failed 场景 summary.run_id 应为非空字符串")
PY

init_scenario "stale-running" "dump_success"
STALE_SAMPLE_ID="id:009999,orig:stale__deadbeef"
python3 - "$STATE_FILE" "$STALE_SAMPLE_ID" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
sample_id = sys.argv[2]
path.write_text(
    json.dumps(
        {
            "schema_version": 1,
            "last_scan_ts": "2026-03-24T00:00:00Z",
            "last_queue_event_id": None,
            "running_sample_id": sample_id,
            "completed_count": 0,
            "failed_count": 0,
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
PY
run_follow_diff_window_capture 5
if [ "$WINDOW_EXIT_CODE" -ne 0 ]; then
	printf 'ASSERT FAIL: stale running 场景期望 follow-diff-window 收敛返回 0，实际 %s\n' "$WINDOW_EXIT_CODE" >&2
	cat "$WINDOW_STDERR" >&2
	exit 1
fi
assert_file_exists "$WINDOW_SUMMARY"
assert_file_exists "$STATE_FILE"
assert_file_contains "$WINDOW_STDERR" "queue 中未找到待恢复样本"
assert_state_contract "$STATE_FILE" "$WINDOW_SUMMARY" "$QUEUE_EVENT_ID" 1 0 "quiescent" 0 "$QUEUE_DIR" 5 1 "no_mutator" 1
python3 - "$WINDOW_SUMMARY" "$STALE_SAMPLE_ID" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stale_sample_id = sys.argv[2]

if summary.get("recovery_status") != "cleared":
    raise SystemExit(
        f"ASSERT FAIL: stale recovery summary.recovery_status={summary.get('recovery_status')!r} != 'cleared'"
    )
if summary.get("recovery_detail") != "stale_missing":
    raise SystemExit(
        f"ASSERT FAIL: stale recovery summary.recovery_detail={summary.get('recovery_detail')!r} != 'stale_missing'"
    )
if summary.get("recovery_sample_id") != stale_sample_id:
    raise SystemExit(
        f"ASSERT FAIL: stale recovery summary.recovery_sample_id={summary.get('recovery_sample_id')!r} != {stale_sample_id!r}"
    )
PY

printf 'PASS: follow-diff-window contract test passed\n'
