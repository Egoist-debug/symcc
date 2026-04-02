#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-replay-contract.XXXXXX")"
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
	local resolver="$2"
	local mode="$3"
	python3 - "$path" "$resolver" "$mode" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
resolver = sys.argv[2]
mode = sys.argv[3]
path.parent.mkdir(parents=True, exist_ok=True)

script = f"""#!/usr/bin/env python3
import os
import pathlib
import sys
import time


def detect_stage() -> str:
    if {resolver!r} == "bind9":
        has_input_arg = any("input=" in arg for arg in sys.argv[1:])
        return "bind9.after" if has_input_arg else "bind9.before"
    data = sys.stdin.buffer.read()
    return "unbound.after" if data else "unbound.before"


def write_log(stage: str) -> None:
    log_path = os.environ.get("FAKE_BINARY_LOG_PATH")
    if not log_path:
        return
    path = pathlib.Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{{stage}}\t{mode}\\n")


def write_dump(stage: str) -> None:
    dump_path = os.environ.get("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH") or os.environ.get("NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH")
    if not dump_path:
        return
    ttl = "300" if stage.endswith("before") else "299"
    dst = pathlib.Path(dump_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if {resolver!r} == "bind9":
        dst.write_text(
            "\\n".join(
                [
                    ";",
                    "; Cache dump of view '_default' (cache _default)",
                    ";",
                    f"example.com. {{ttl}} IN A 1.2.3.4",
                ]
            )
            + "\\n",
            encoding="utf-8",
        )
    else:
        dst.write_text(
            "\\n".join(
                [
                    "START_RRSET_CACHE",
                    ";rrset 300 2 0 2 1",
                    f"example.com. {{ttl}} IN A 1.2.3.4",
                    "END_RRSET_CACHE",
                    "START_MSG_CACHE",
                    f"msg example.com. IN A 33152 1 {{ttl}} 0 1 0 0 -1",
                    "END_MSG_CACHE",
                    "EOF",
                ]
            )
            + "\\n",
            encoding="utf-8",
        )


stage = detect_stage()
write_log(stage)

if {mode!r} == "timeout":
    sys.stderr.write("fake timeout\\n")
    sys.stderr.flush()
    time.sleep(5)
    sys.exit(0)

if {mode!r} == "missing_artifact":
    sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
    sys.exit(0)

if {mode!r} == "dump_success":
    write_dump(stage)
    sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
    sys.exit(0)

raise SystemExit(f"unknown mode: {mode!r}")
"""

path.write_text(script, encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

init_scenario() {
	local scenario_name="$1"
	local unbound_mode="$2"
	local bind9_mode="${3:-dump_success}"

	SCENARIO_ROOT="$WORKDIR/$scenario_name"
	SCENARIO_WORK="$SCENARIO_ROOT/work"
	BIND9_TREE="$SCENARIO_ROOT/bind9-afl"
	UNBOUND_TREE="$SCENARIO_ROOT/unbound-afl"
	BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
	UNBOUND_BIN="$UNBOUND_TREE/.libs/unbound-fuzzme"
	RESPONSE_DIR="$SCENARIO_WORK/response_corpus"
	NAMED_CONF_TEMPLATE="$SCENARIO_ROOT/named.conf.template"
	SAMPLE_FILE="$SCENARIO_ROOT/sample.bin"

	mkdir -p "$RESPONSE_DIR"
	write_text_file "$NAMED_CONF_TEMPLATE" $'options { directory "__RUNTIME_STATE_DIR__"; };\n'
	python3 - "$SAMPLE_FILE" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(b"\x01\x02\x03\x04")
PY
	write_fake_binary "$UNBOUND_BIN" "unbound" "$unbound_mode"
	write_fake_binary "$BIND9_BIN" "bind9" "$bind9_mode"
}

run_replay_cli_capture() {
	local output_dir="$1"
	local log_path="$2"
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
		FAKE_BINARY_LOG_PATH="$log_path" \
		python3 -m tools.dns_diff.cli replay-diff-cache "$SAMPLE_FILE" "$output_dir" >/dev/null 2>"$output_dir.stderr"
	CLI_EXIT_CODE=$?
	set -e
}

assert_success_artifacts_and_meta() {
	local output_dir="$1"
	assert_file_exists "$output_dir/sample.bin"
	assert_file_exists "$output_dir/bind9.stderr"
	assert_file_exists "$output_dir/unbound.stderr"
	assert_file_exists "$output_dir/bind9.before.cache.txt"
	assert_file_exists "$output_dir/bind9.after.cache.txt"
	assert_file_exists "$output_dir/unbound.before.cache.txt"
	assert_file_exists "$output_dir/unbound.after.cache.txt"
	assert_file_exists "$output_dir/sample.meta.json"
	assert_file_exists "$output_dir/oracle.json"

	python3 - "$output_dir" <<'PY'
import json
import pathlib
import sys

from tools.dns_diff.oracle import ORACLE_FIELDS

output_dir = pathlib.Path(sys.argv[1])
meta = json.loads((output_dir / "sample.meta.json").read_text(encoding="utf-8"))
oracle = json.loads((output_dir / "oracle.json").read_text(encoding="utf-8"))

expected_oracle_fields = (
    "parse_ok",
    "resolver_fetch_started",
    "response_accepted",
    "second_query_hit",
    "cache_entry_created",
    "timeout",
)
if ORACLE_FIELDS != expected_oracle_fields:
    raise SystemExit(f"ASSERT FAIL: ORACLE_FIELDS 发生变更: {ORACLE_FIELDS!r}")

artifacts = meta.get("artifacts")
expected_artifacts = {
    "sample_bin": "sample.bin",
    "bind9_stderr": "bind9.stderr",
    "unbound_stderr": "unbound.stderr",
    "bind9_before_cache": "bind9.before.cache.txt",
    "bind9_after_cache": "bind9.after.cache.txt",
    "unbound_before_cache": "unbound.before.cache.txt",
    "unbound_after_cache": "unbound.after.cache.txt",
    "oracle": "oracle.json",
}
if artifacts != expected_artifacts:
    raise SystemExit(f"ASSERT FAIL: sample.meta.json.artifacts 不匹配: {artifacts!r}")

oracle_provenance = meta.get("oracle_provenance")
if not isinstance(oracle_provenance, dict) or oracle_provenance.get("mode") != "same_replay_after_cache":
    raise SystemExit("ASSERT FAIL: sample.meta.json.oracle_provenance.mode 应为 same_replay_after_cache")

for resolver in ("bind9", "unbound"):
    status = oracle.get(f"{resolver}.stderr_parse_status")
    if status != "ok":
        raise SystemExit(f"ASSERT FAIL: {resolver}.stderr_parse_status={status!r}，期望 'ok'")
    for field in expected_oracle_fields:
        value = oracle.get(f"{resolver}.{field}")
        if not isinstance(value, bool):
            raise SystemExit(
                f"ASSERT FAIL: oracle 字段 {resolver}.{field} 应为 bool，实际 {value!r}"
            )
PY
}

assert_stage_order_log() {
	local log_path="$1"
	python3 - "$log_path" <<'PY'
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
expected = [
    "unbound.before\tdump_success",
    "bind9.before\tdump_success",
    "unbound.after\tdump_success",
    "bind9.after\tdump_success",
]
if lines != expected:
    raise SystemExit(f"ASSERT FAIL: replay 阶段顺序异常: {lines!r} != {expected!r}")
PY
}

assert_repeatability_and_cache_semantics() {
	local output_a="$1"
	local output_b="$2"
	python3 - "$output_a" "$output_b" <<'PY'
import json
import pathlib
import sys

from tools.dns_diff.cache_diff import build_cache_diff
from tools.dns_diff.cache_parser import parse_cache_dump

output_a = pathlib.Path(sys.argv[1])
output_b = pathlib.Path(sys.argv[2])

oracle_a = json.loads((output_a / "oracle.json").read_text(encoding="utf-8"))
oracle_b = json.loads((output_b / "oracle.json").read_text(encoding="utf-8"))
if oracle_a != oracle_b:
    raise SystemExit("ASSERT FAIL: 同样本两次 replay 的 oracle.json 不一致")

meta_a = json.loads((output_a / "sample.meta.json").read_text(encoding="utf-8"))
meta_b = json.loads((output_b / "sample.meta.json").read_text(encoding="utf-8"))
sample_id_a = meta_a.get("sample_id")
sample_id_b = meta_b.get("sample_id")
if not isinstance(sample_id_a, str) or not sample_id_a:
    raise SystemExit("ASSERT FAIL: 第一次 replay sample_id 非法")
if sample_id_a != sample_id_b:
    raise SystemExit("ASSERT FAIL: 两次 replay sample_id 不一致")

def rows(path: pathlib.Path, resolver: str):
    return [tuple(record.to_fields()) for record in parse_cache_dump(resolver, path)]

cache_diff_a = build_cache_diff(
    sample_id_a,
    rows(output_a / "bind9.before.cache.txt", "bind9"),
    rows(output_a / "bind9.after.cache.txt", "bind9"),
    rows(output_a / "unbound.before.cache.txt", "unbound"),
    rows(output_a / "unbound.after.cache.txt", "unbound"),
    True,
)
cache_diff_b = build_cache_diff(
    sample_id_a,
    rows(output_b / "bind9.before.cache.txt", "bind9"),
    rows(output_b / "bind9.after.cache.txt", "bind9"),
    rows(output_b / "unbound.before.cache.txt", "unbound"),
    rows(output_b / "unbound.after.cache.txt", "unbound"),
    True,
)

cache_diff_a.pop("generated_at", None)
cache_diff_b.pop("generated_at", None)

if cache_diff_a != cache_diff_b:
    raise SystemExit("ASSERT FAIL: 同样本两次 replay 推导出的 cache diff 不一致")

for resolver in ("bind9", "unbound"):
    resolver_payload = cache_diff_a.get(resolver) or {}
    if resolver_payload.get("has_cache_diff") is not False:
        raise SystemExit(f"ASSERT FAIL: {resolver}.has_cache_diff 应为 false（TTL 漂移不应触发结构差分）")
    if resolver_payload.get("interesting_delta_count") != 0:
        raise SystemExit(f"ASSERT FAIL: {resolver}.interesting_delta_count 应为 0")
    if resolver_payload.get("delta_items") != []:
        raise SystemExit(f"ASSERT FAIL: {resolver}.delta_items 应为空")
PY
}

assert_structured_failure_missing_artifact() {
	local output_dir="$1"
	python3 - "$SAMPLE_FILE" "$output_dir" <<'PY'
import pathlib
import sys

from tools.dns_diff.replay import ReplayError, replay_diff_cache

sample = pathlib.Path(sys.argv[1])
output_dir = pathlib.Path(sys.argv[2])
try:
    replay_diff_cache(str(sample), str(output_dir))
except ReplayError as exc:
    payload = exc.to_failure_payload()
    if payload.get("kind") != "replay_error":
        raise SystemExit(f"ASSERT FAIL: kind 非 replay_error: {payload!r}")
    if payload.get("reason") != "missing_artifact":
        raise SystemExit(f"ASSERT FAIL: reason 非 missing_artifact: {payload!r}")
    if payload.get("stage") != "unbound.before":
        raise SystemExit(f"ASSERT FAIL: stage 非 unbound.before: {payload!r}")
    if payload.get("resolver") != "unbound":
        raise SystemExit(f"ASSERT FAIL: resolver 非 unbound: {payload!r}")
    if payload.get("artifact_path") != "unbound.before.cache.txt":
        raise SystemExit(f"ASSERT FAIL: artifact_path 非预期: {payload!r}")
    if payload.get("exit_code") != 5:
        raise SystemExit(f"ASSERT FAIL: exit_code 非 5: {payload!r}")
    if payload.get("process_started") is not True:
        raise SystemExit(f"ASSERT FAIL: process_started 应为 true: {payload!r}")
else:
    raise SystemExit("ASSERT FAIL: missing_artifact 场景应抛出 ReplayError")
PY
}

assert_structured_failure_timeout() {
	local output_dir="$1"
	python3 - "$SAMPLE_FILE" "$output_dir" <<'PY'
import pathlib
import sys

from tools.dns_diff.replay import ReplayError, replay_diff_cache

sample = pathlib.Path(sys.argv[1])
output_dir = pathlib.Path(sys.argv[2])
try:
    replay_diff_cache(str(sample), str(output_dir))
except ReplayError as exc:
    payload = exc.to_failure_payload()
    if payload.get("reason") != "timeout":
        raise SystemExit(f"ASSERT FAIL: timeout 场景 reason 非 timeout: {payload!r}")
    if payload.get("stage") != "unbound.before":
        raise SystemExit(f"ASSERT FAIL: timeout 场景 stage 非 unbound.before: {payload!r}")
    if payload.get("resolver") != "unbound":
        raise SystemExit(f"ASSERT FAIL: timeout 场景 resolver 非 unbound: {payload!r}")
    if payload.get("exit_code") != 4:
        raise SystemExit(f"ASSERT FAIL: timeout 场景 exit_code 非 4: {payload!r}")
    if payload.get("process_started") is not True:
        raise SystemExit(f"ASSERT FAIL: timeout 场景 process_started 应为 true: {payload!r}")
    if payload.get("stderr_path") != "unbound.stderr":
        raise SystemExit(f"ASSERT FAIL: timeout 场景 stderr_path 非 unbound.stderr: {payload!r}")
    if payload.get("returncode") not in (124, 137):
        raise SystemExit(f"ASSERT FAIL: timeout 场景 returncode 非 124/137: {payload!r}")
else:
    raise SystemExit("ASSERT FAIL: timeout 场景应抛出 ReplayError")
PY
}

init_scenario "happy" "dump_success" "dump_success"
SUCCESS_OUT_1="$SCENARIO_ROOT/replay_out_1"
SUCCESS_OUT_2="$SCENARIO_ROOT/replay_out_2"
SUCCESS_LOG_1="$SCENARIO_ROOT/invocation.1.log"
SUCCESS_LOG_2="$SCENARIO_ROOT/invocation.2.log"

run_replay_cli_capture "$SUCCESS_OUT_1" "$SUCCESS_LOG_1"
if [ "$CLI_EXIT_CODE" -ne 0 ]; then
	printf 'ASSERT FAIL: happy 场景 replay-diff-cache 退出码应为 0，实际 %s\n' "$CLI_EXIT_CODE" >&2
	cat "$SUCCESS_OUT_1.stderr" >&2 || true
	exit 1
fi
assert_success_artifacts_and_meta "$SUCCESS_OUT_1"
assert_stage_order_log "$SUCCESS_LOG_1"

run_replay_cli_capture "$SUCCESS_OUT_2" "$SUCCESS_LOG_2"
if [ "$CLI_EXIT_CODE" -ne 0 ]; then
	printf 'ASSERT FAIL: happy-repeat 场景 replay-diff-cache 退出码应为 0，实际 %s\n' "$CLI_EXIT_CODE" >&2
	cat "$SUCCESS_OUT_2.stderr" >&2 || true
	exit 1
fi
assert_success_artifacts_and_meta "$SUCCESS_OUT_2"
assert_stage_order_log "$SUCCESS_LOG_2"
assert_repeatability_and_cache_semantics "$SUCCESS_OUT_1" "$SUCCESS_OUT_2"

init_scenario "missing-artifact" "missing_artifact" "dump_success"
MISSING_OUT="$SCENARIO_ROOT/replay_out"
PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
ROOT_DIR="$ROOT_DIR" \
WORK_DIR="$SCENARIO_WORK" \
BIND9_AFL_TREE="$BIND9_TREE" \
AFL_TREE="$UNBOUND_TREE" \
RESPONSE_CORPUS_DIR="$RESPONSE_DIR" \
BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
assert_structured_failure_missing_artifact "$MISSING_OUT"

init_scenario "timeout" "timeout" "dump_success"
TIMEOUT_OUT="$SCENARIO_ROOT/replay_out"
PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
ROOT_DIR="$ROOT_DIR" \
WORK_DIR="$SCENARIO_WORK" \
BIND9_AFL_TREE="$BIND9_TREE" \
AFL_TREE="$UNBOUND_TREE" \
RESPONSE_CORPUS_DIR="$RESPONSE_DIR" \
BIND9_NAMED_CONF_TEMPLATE="$NAMED_CONF_TEMPLATE" \
SEED_TIMEOUT_SEC=1 \
assert_structured_failure_timeout "$TIMEOUT_OUT"

echo "PASS: replay/cache/oracle contract test passed"
