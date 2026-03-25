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
    printf 'ASSERT FAIL: 期望 %s 不包含: %s\n' "$path" "$unexpected" >&2
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

assert_running_count() {
  local log_file="$1"
  local sample="$2"
  local expected_count="$3"
  python3 - "$log_file" "$sample" "$expected_count" <<'PY'
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
sample = sys.argv[2]
expected_count = int(sys.argv[3])
count = 0
for line in log_path.read_text(encoding="utf-8").splitlines():
    marker = "Running SymCC on request sample "
    if marker in line and line.split(marker, 1)[1] == sample:
        count += 1

if count != expected_count:
    full_log = log_path.read_text(encoding="utf-8") if log_path.exists() else "<missing log>"
    raise SystemExit(
        "ASSERT FAIL: helper 运行次数不符合预期:\n"
        f"sample={sample!r}\nactual={count!r}\nexpected={expected_count!r}\nlog=\n{full_log}"
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
        "ASSERT FAIL: semantic-only promotion revisit 不应向 AFL queue 复制新样本:\n"
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
        "ASSERT FAIL: semantic-only promotion revisit 不应生成新的 AFL ',symcc' 队列样本:\n"
        f"queue_dir={queue_dir}\nactual={symcc_samples!r}"
    )
PY
}

write_json_manifest() {
  local manifest_path="$1"
  local root_path="$2"
  shift 2
  python3 - "$manifest_path" "$root_path" "$@" <<'PY'
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
root_path = pathlib.Path(sys.argv[2])
entries = []
for spec in sys.argv[3:]:
    sample_path, tier = spec.split(":::", 1)
    sample_name = pathlib.Path(sample_path).name
    entries.append(
        {
            "sample_path": sample_path,
            "sample_id": sample_name,
            "analysis_state": "included" if int(tier) >= 3 else "excluded",
            "semantic_outcome": "oracle_diff" if int(tier) >= 3 else "no_diff",
            "oracle_audit_candidate": int(tier) >= 2,
            "needs_manual_review": int(tier) >= 1,
            "priority_tier": int(tier),
        }
    )

payload = {
    "contract_name": "semantic_frontier_manifest",
    "contract_version": 1,
    "generated_at": "2026-03-25T00:00:00Z",
    "root": str(root_path),
    "entries": entries,
}
manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
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

scenario_promotion_revisit_obeys_retry_budget() {
  local helper_bin="$1"
  local work_root="$2"
  local queue_dir promoted_sample coverage_sample json_manifest log_file sleep_target timeout_pid

  queue_dir="$(prepare_fixture "$work_root")"
  promoted_sample="$queue_dir/id:000001,src:000000,promoted"
  coverage_sample="$queue_dir/id:000002,src:000000,+cov"
  json_manifest="$work_root/semantic_frontier_manifest.json"
  log_file="$work_root/helper.log"
  sleep_target="$work_root/fake_target.py"

  printf 'promoted\n' > "$promoted_sample"
  printf 'coverage\n' > "$coverage_sample"
  write_json_manifest "$json_manifest" "$queue_dir" "$promoted_sample:::1"
  write_sleep_target "$sleep_target"

  env \
    SYMCC_SEMANTIC_FRONTIER_MANIFEST="$json_manifest" \
    SYMCC_FRONTIER_RELOAD_SEC=1 \
    timeout -k 1 10 "$helper_bin" \
      -a master -o "$work_root/afl_out" -n exp -- "$sleep_target" @@ >"$log_file" 2>&1 &
  timeout_pid=$!

  wait_for_log_line "$log_file" "Running SymCC on request sample $promoted_sample" 5
  advance_manifest_mtime
  write_json_manifest "$json_manifest" "$queue_dir" "$promoted_sample:::3"

  wait "$timeout_pid" || true

  assert_running_sequence "$log_file" "$promoted_sample" "$promoted_sample" "$coverage_sample"
  assert_running_count "$log_file" "$promoted_sample" 2
  assert_file_contains "$log_file" 'SYMCC_FRONTIER_RETRY_LIMIT effective value: 1'
  assert_file_contains "$log_file" 'Reloaded semantic frontier snapshot from semantic JSON manifest'
  assert_file_contains "$log_file" "Allowing semantic frontier revisit for request sample $promoted_sample after strict tier promotion (1 -> 3, retry 1/1)"
  assert_file_contains "$log_file" "Picked high-value request sample from semantic JSON manifest (tier=3): $promoted_sample"
  assert_all_copy_counts_zero "$log_file"
  assert_no_symcc_queue_samples "$queue_dir"
  assert_file_not_contains "$log_file" 'Fatal:'
}

scenario_same_tier_reload_does_not_revisit() {
  local helper_bin="$1"
  local work_root="$2"
  local queue_dir same_tier_sample coverage_sample json_manifest log_file sleep_target timeout_pid

  queue_dir="$(prepare_fixture "$work_root")"
  same_tier_sample="$queue_dir/id:000001,src:000000,same-tier"
  coverage_sample="$queue_dir/id:000002,src:000000,+cov"
  json_manifest="$work_root/semantic_frontier_manifest.json"
  log_file="$work_root/helper.log"
  sleep_target="$work_root/fake_target.py"

  printf 'same-tier\n' > "$same_tier_sample"
  printf 'coverage\n' > "$coverage_sample"
  write_json_manifest "$json_manifest" "$queue_dir" "$same_tier_sample:::2"
  write_sleep_target "$sleep_target"

  env \
    SYMCC_SEMANTIC_FRONTIER_MANIFEST="$json_manifest" \
    SYMCC_FRONTIER_RELOAD_SEC=1 \
    timeout -k 1 8 "$helper_bin" \
      -a master -o "$work_root/afl_out" -n exp -- "$sleep_target" @@ >"$log_file" 2>&1 &
  timeout_pid=$!

  wait_for_log_line "$log_file" "Running SymCC on request sample $same_tier_sample" 5
  advance_manifest_mtime
  write_json_manifest "$json_manifest" "$queue_dir" "$same_tier_sample:::2"

  wait "$timeout_pid" || true

  assert_running_sequence "$log_file" "$same_tier_sample" "$coverage_sample"
  assert_running_count "$log_file" "$same_tier_sample" 1
  assert_file_contains "$log_file" 'Reloaded semantic frontier snapshot from semantic JSON manifest'
  assert_file_not_contains "$log_file" "Allowing semantic frontier revisit for request sample $same_tier_sample"
  assert_file_not_contains "$log_file" 'Fatal:'
}

scenario_downgrade_does_not_revisit() {
  local helper_bin="$1"
  local work_root="$2"
  local queue_dir downgrade_sample coverage_sample json_manifest log_file sleep_target timeout_pid

  queue_dir="$(prepare_fixture "$work_root")"
  downgrade_sample="$queue_dir/id:000001,src:000000,downgrade"
  coverage_sample="$queue_dir/id:000002,src:000000,+cov"
  json_manifest="$work_root/semantic_frontier_manifest.json"
  log_file="$work_root/helper.log"
  sleep_target="$work_root/fake_target.py"

  printf 'downgrade\n' > "$downgrade_sample"
  printf 'coverage\n' > "$coverage_sample"
  write_json_manifest "$json_manifest" "$queue_dir" "$downgrade_sample:::3"
  write_sleep_target "$sleep_target"

  env \
    SYMCC_SEMANTIC_FRONTIER_MANIFEST="$json_manifest" \
    SYMCC_FRONTIER_RELOAD_SEC=1 \
    timeout -k 1 8 "$helper_bin" \
      -a master -o "$work_root/afl_out" -n exp -- "$sleep_target" @@ >"$log_file" 2>&1 &
  timeout_pid=$!

  wait_for_log_line "$log_file" "Running SymCC on request sample $downgrade_sample" 5
  advance_manifest_mtime
  write_json_manifest "$json_manifest" "$queue_dir" "$downgrade_sample:::1"

  wait "$timeout_pid" || true

  assert_running_sequence "$log_file" "$downgrade_sample" "$coverage_sample"
  assert_running_count "$log_file" "$downgrade_sample" 1
  assert_file_contains "$log_file" 'Reloaded semantic frontier snapshot from semantic JSON manifest'
  assert_file_not_contains "$log_file" "Allowing semantic frontier revisit for request sample $downgrade_sample"
  assert_file_not_contains "$log_file" 'Fatal:'
}

scenario_reload_keeps_seen_state() {
  local helper_bin="$1"
  local work_root="$2"
  local queue_dir sticky_sample plain_sample json_manifest log_file sleep_target timeout_pid

  queue_dir="$(prepare_fixture "$work_root")"
  sticky_sample="$queue_dir/id:000001,src:000000,+cov-reset"
  plain_sample="$queue_dir/id:000002,src:000000,plain"
  json_manifest="$work_root/semantic_frontier_manifest.json"
  log_file="$work_root/helper.log"
  sleep_target="$work_root/fake_target.py"

  printf 'sticky\n' > "$sticky_sample"
  printf 'plain\n' > "$plain_sample"
  write_json_manifest "$json_manifest" "$queue_dir" "$sticky_sample:::2"
  write_sleep_target "$sleep_target"

  env \
    SYMCC_SEMANTIC_FRONTIER_MANIFEST="$json_manifest" \
    SYMCC_FRONTIER_RELOAD_SEC=1 \
    timeout -k 1 8 "$helper_bin" \
      -a master -o "$work_root/afl_out" -n exp -- "$sleep_target" @@ >"$log_file" 2>&1 &
  timeout_pid=$!

  wait_for_log_line "$log_file" "Running SymCC on request sample $sticky_sample" 5
  advance_manifest_mtime
  write_json_manifest "$json_manifest" "$queue_dir"

  wait "$timeout_pid" || true

  assert_running_sequence "$log_file" "$sticky_sample" "$plain_sample"
  assert_running_count "$log_file" "$sticky_sample" 1
  assert_file_contains "$log_file" 'Reloaded semantic frontier snapshot from semantic JSON manifest (entries=0, reason=manifest mtime changed)'
  assert_file_not_contains "$log_file" 'Fatal:'
}

scenario_failed_execution_still_consumes_retry_budget() {
  local helper_bin="$1"
  local work_root="$2"
  local queue_dir failing_sample json_manifest log_file timeout_pid

  queue_dir="$(prepare_fixture "$work_root")"
  failing_sample="$queue_dir/id:000001,src:000000,permission-denied"
  json_manifest="$work_root/semantic_frontier_manifest.json"
  log_file="$work_root/helper.log"

  printf 'denied\n' > "$failing_sample"
  chmod 000 "$failing_sample"
  write_json_manifest "$json_manifest" "$queue_dir" "$failing_sample:::1"

  env \
    SYMCC_SEMANTIC_FRONTIER_MANIFEST="$json_manifest" \
    SYMCC_FRONTIER_RELOAD_SEC=1 \
    timeout -k 1 8 "$helper_bin" \
      -a master -o "$work_root/afl_out" -n exp -- /bin/true @@ >"$log_file" 2>&1 &
  timeout_pid=$!

  wait_for_log_line "$log_file" 'SymCC execution failed:' 5
  advance_manifest_mtime
  write_json_manifest "$json_manifest" "$queue_dir" "$failing_sample:::3"

  wait "$timeout_pid" || true

  assert_running_sequence "$log_file" "$failing_sample" "$failing_sample"
  assert_running_count "$log_file" "$failing_sample" 2
  assert_file_contains "$log_file" 'Reloaded semantic frontier snapshot from semantic JSON manifest'
  assert_file_contains "$log_file" "Allowing semantic frontier revisit for request sample $failing_sample after strict tier promotion (1 -> 3, retry 1/1)"
  assert_file_contains "$log_file" 'SymCC execution failed:'
  assert_file_not_contains "$log_file" 'retry 2/1'
  assert_file_not_contains "$log_file" 'Fatal:'
}

main() {
  local helper_bin=""
  local work_root=""

  helper_bin="$(ensure_helper_bin)"
  work_root="$(mktemp -d "${TMPDIR:-/tmp}/symcc-semantic-revisit.XXXXXX")"
  trap 'rm -rf "${work_root:-}"' EXIT

  scenario_promotion_revisit_obeys_retry_budget "$helper_bin" "$work_root/promotion"
  scenario_same_tier_reload_does_not_revisit "$helper_bin" "$work_root/same-tier"
  scenario_downgrade_does_not_revisit "$helper_bin" "$work_root/downgrade"
  scenario_reload_keeps_seen_state "$helper_bin" "$work_root/reload-state"
  scenario_failed_execution_still_consumes_retry_budget "$helper_bin" "$work_root/failure-budget"

  printf 'PASS: semantic revisit regression test passed\n'
}

main "$@"
