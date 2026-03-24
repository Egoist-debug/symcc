#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-replay-failure-evidence.XXXXXX")"
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
    "dump_success": """#!/usr/bin/env python3
import os
import pathlib
import sys

dump_path = os.environ.get(\"UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\") or os.environ.get(\"NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH\")
if dump_path:
    path = pathlib.Path(dump_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(\"cache-entry\\n\", encoding=\"utf-8\")
sys.stderr.write(\"ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n\")
sys.exit(0)
""",
    "timeout": """#!/usr/bin/env python3
import sys
import time

sys.stderr.write(\"fake timeout stage\\n\")
sys.stderr.flush()
time.sleep(5)
sys.exit(0)
""",
    "missing_artifact": """#!/usr/bin/env python3
import sys

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
data = path.read_bytes()
sha1 = hashlib.sha1(data).hexdigest()
print(f"{path.name}__{sha1[:8]}")
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

	mkdir -p "$QUEUE_DIR" "$FOLLOW_ROOT" "$RESPONSE_DIR"
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

run_follow_diff_once() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		WORK_DIR="$SCENARIO_WORK" \
		BIND9_AFL_TREE="$BIND9_TREE" \
		AFL_TREE="$UNBOUND_TREE" \
		RESPONSE_CORPUS_DIR="$RESPONSE_DIR" \
		BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
		SEED_TIMEOUT_SEC=1 \
		python3 -m tools.dns_diff.cli follow-diff-once >/dev/null
}

assert_replay_failure() {
	local sample_dir="$1"
	local expected_reason="$2"
	local expected_exit_code="$3"
	local expected_label="$4"
	local expected_message_keyword="$5"
	local expected_stage="$6"
	local expected_resolver="$7"
	local expected_returncode="$8"
	local expected_artifact="$9"
	local expected_stderr="${10}"
	local expected_executable_suffix="${11}"
	local expected_process_started="${12}"
	local expected_analysis_state="${13}"
	local expected_failure_primary="${14}"
	local expected_failure_detail="${15}"
	local expected_exclude_reason="${16}"
	local expected_semantic_outcome="${17}"

	assert_file_exists "$sample_dir/sample.bin"
	assert_file_exists "$sample_dir/sample.meta.json"
	assert_file_exists "$sample_dir/triage.json"

	if [ "$expected_stderr" != "-" ]; then
		assert_file_exists "$sample_dir/$expected_stderr"
	fi

	python3 - \
		"$sample_dir" \
		"$expected_reason" \
		"$expected_exit_code" \
		"$expected_label" \
		"$expected_message_keyword" \
		"$expected_stage" \
		"$expected_resolver" \
		"$expected_returncode" \
		"$expected_artifact" \
		"$expected_stderr" \
		"$expected_executable_suffix" \
		"$expected_process_started" \
		"$expected_analysis_state" \
		"$expected_failure_primary" \
		"$expected_failure_detail" \
		"$expected_exclude_reason" \
		"$expected_semantic_outcome" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
expected_reason = sys.argv[2]
expected_exit_code = int(sys.argv[3])
expected_label = sys.argv[4]
expected_message_keyword = sys.argv[5]
expected_stage = sys.argv[6]
expected_resolver = sys.argv[7]
expected_returncode = sys.argv[8]
expected_artifact = sys.argv[9]
expected_stderr = sys.argv[10]
expected_executable_suffix = sys.argv[11]
expected_process_started = sys.argv[12] == "true"
expected_analysis_state = sys.argv[13]
expected_failure_primary = sys.argv[14]
expected_failure_detail = sys.argv[15]
expected_exclude_reason = sys.argv[16]
expected_semantic_outcome = sys.argv[17]

meta = json.loads((sample_dir / "sample.meta.json").read_text(encoding="utf-8"))
triage = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))

if meta.get("status") != "failed":
    raise SystemExit("ASSERT FAIL: sample.meta.json.status 应为 failed")

failure = meta.get("failure")
if not isinstance(failure, dict):
    raise SystemExit("ASSERT FAIL: sample.meta.json.failure 应为对象")

if failure.get("kind") != "replay_error":
    raise SystemExit("ASSERT FAIL: failure.kind 应为 replay_error")
if failure.get("reason") != expected_reason:
    raise SystemExit(f"ASSERT FAIL: failure.reason={failure.get('reason')!r} != {expected_reason!r}")
if failure.get("exit_code") != expected_exit_code:
    raise SystemExit(
        f"ASSERT FAIL: failure.exit_code={failure.get('exit_code')!r} != {expected_exit_code!r}"
    )
message = failure.get("message")
if not isinstance(message, str) or expected_message_keyword not in message:
    raise SystemExit(
        f"ASSERT FAIL: failure.message 未包含关键字 {expected_message_keyword!r}: {message!r}"
    )
if failure.get("stage") != expected_stage:
    raise SystemExit(f"ASSERT FAIL: failure.stage={failure.get('stage')!r} != {expected_stage!r}")
if failure.get("resolver") != expected_resolver:
    raise SystemExit(
        f"ASSERT FAIL: failure.resolver={failure.get('resolver')!r} != {expected_resolver!r}"
    )
if failure.get("process_started") is not expected_process_started:
    raise SystemExit(
        "ASSERT FAIL: failure.process_started="
        f"{failure.get('process_started')!r} != {expected_process_started!r}"
    )

if expected_returncode == "-":
    if "returncode" in failure and failure.get("returncode") is not None:
        raise SystemExit("ASSERT FAIL: 当前场景不应写入 failure.returncode")
else:
    if failure.get("returncode") != int(expected_returncode):
        raise SystemExit(
            f"ASSERT FAIL: failure.returncode={failure.get('returncode')!r} != {int(expected_returncode)!r}"
        )

if expected_artifact == "-":
    if "artifact_path" in failure and failure.get("artifact_path"):
        raise SystemExit("ASSERT FAIL: 当前场景不应写入 failure.artifact_path")
else:
    artifact_path = failure.get("artifact_path")
    if artifact_path != expected_artifact:
        raise SystemExit(
            f"ASSERT FAIL: failure.artifact_path={artifact_path!r} != {expected_artifact!r}"
        )
    artifact_file = sample_dir / expected_artifact
    if artifact_file.exists() and artifact_file.stat().st_size > 0:
        raise SystemExit("ASSERT FAIL: 缺失 artifact 场景下对应文件应缺失或为空")

if expected_stderr == "-":
    if "stderr_path" in failure and failure.get("stderr_path"):
        raise SystemExit("ASSERT FAIL: 当前场景不应写入 failure.stderr_path")
else:
    stderr_path = failure.get("stderr_path")
    if stderr_path != expected_stderr:
        raise SystemExit(
            f"ASSERT FAIL: failure.stderr_path={stderr_path!r} != {expected_stderr!r}"
        )
    if not (sample_dir / expected_stderr).is_file():
        raise SystemExit("ASSERT FAIL: failure.stderr_path 指向的文件不存在")

if expected_executable_suffix == "-":
    if "executable_path" in failure and failure.get("executable_path"):
        raise SystemExit("ASSERT FAIL: 当前场景不应写入 failure.executable_path")
else:
    executable_path = failure.get("executable_path")
    if not isinstance(executable_path, str) or not executable_path.endswith(expected_executable_suffix):
        raise SystemExit(
            "ASSERT FAIL: failure.executable_path 不符合预期后缀: "
            f"{executable_path!r} !~ {expected_executable_suffix!r}"
        )

if triage.get("status") != "failed_replay":
    raise SystemExit(f"ASSERT FAIL: triage.status={triage.get('status')!r} != 'failed_replay'")
if triage.get("diff_class") != "replay_incomplete":
    raise SystemExit(
        f"ASSERT FAIL: triage.diff_class={triage.get('diff_class')!r} != 'replay_incomplete'"
    )
if triage.get("analysis_state") != expected_analysis_state:
    raise SystemExit(
        f"ASSERT FAIL: triage.analysis_state={triage.get('analysis_state')!r} != {expected_analysis_state!r}"
    )
if triage.get("failure_bucket_primary") != expected_failure_primary:
    raise SystemExit(
        "ASSERT FAIL: triage.failure_bucket_primary="
        f"{triage.get('failure_bucket_primary')!r} != {expected_failure_primary!r}"
    )
if triage.get("failure_bucket_detail") != expected_failure_detail:
    raise SystemExit(
        "ASSERT FAIL: triage.failure_bucket_detail="
        f"{triage.get('failure_bucket_detail')!r} != {expected_failure_detail!r}"
    )
if expected_exclude_reason == "-":
    if triage.get("exclude_reason") is not None:
        raise SystemExit(
            f"ASSERT FAIL: triage.exclude_reason 期望为空，实际 {triage.get('exclude_reason')!r}"
        )
else:
    if triage.get("exclude_reason") != expected_exclude_reason:
        raise SystemExit(
            "ASSERT FAIL: triage.exclude_reason="
            f"{triage.get('exclude_reason')!r} != {expected_exclude_reason!r}"
        )
if triage.get("semantic_outcome") != expected_semantic_outcome:
    raise SystemExit(
        "ASSERT FAIL: triage.semantic_outcome="
        f"{triage.get('semantic_outcome')!r} != {expected_semantic_outcome!r}"
    )

labels = triage.get("filter_labels")
if not isinstance(labels, list):
    raise SystemExit("ASSERT FAIL: triage.filter_labels 应为数组")
for label in ("oracle_missing", expected_label):
    if label not in labels:
        raise SystemExit(f"ASSERT FAIL: triage.filter_labels 缺少 {label!r}: {labels!r}")
if "oracle_parse_incomplete" in labels:
    raise SystemExit("ASSERT FAIL: replay 失败场景不应被标成 oracle_parse_incomplete")
PY
}

init_scenario "missing-executable" "dump_success"
chmod 0644 "$UNBOUND_BIN"
run_follow_diff_once
assert_replay_failure \
	"$SAMPLE_DIR" \
	"missing_executable" \
	3 \
	"replay_missing_executable" \
	"不可执行" \
	"unbound.preflight" \
	"unbound" \
	"-" \
	"-" \
	"-" \
	".libs/unbound-fuzzme" \
	false \
	"excluded" \
	"infra_artifact_failure" \
	"replay_missing_executable" \
	"infra_failure" \
	"infra_failure"

init_scenario "timeout" "timeout"
run_follow_diff_once
assert_replay_failure \
	"$SAMPLE_DIR" \
	"timeout" \
	4 \
	"replay_timeout" \
	"超时" \
	"unbound.before" \
	"unbound" \
	124 \
	"-" \
	"unbound.stderr" \
	"-" \
	true \
	"unknown" \
	"target_runtime_failure" \
	"replay_timeout" \
	"-" \
	"runtime_or_parse_failure"

init_scenario "missing-artifact" "missing_artifact"
run_follow_diff_once
assert_replay_failure \
	"$SAMPLE_DIR" \
	"missing_artifact" \
	5 \
	"replay_missing_artifact" \
	"未生成有效文件" \
	"unbound.before" \
	"unbound" \
	"-" \
	"unbound.before.cache.txt" \
	"unbound.stderr" \
	"-" \
	true \
	"excluded" \
	"infra_artifact_failure" \
	"replay_missing_artifact" \
	"infra_failure" \
	"infra_failure"

echo "PASS: replay failure evidence regression test passed"
