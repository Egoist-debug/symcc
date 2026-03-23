#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

resolve_helper_bin() {
  local candidates=(
    "$ROOT_DIR/build/linux/x86_64/release/symcc_fuzzing_helper"
    "$ROOT_DIR/util/symcc_fuzzing_cpp/build/linux/x86_64/release/symcc_fuzzing_helper"
  )
  local p
  for p in "${candidates[@]}"; do
    if [[ -x "$p" ]]; then
      printf '%s\n' "$p"
      return 0
    fi
  done
  return 1
}

run_helper_once() {
  local helper_bin="$1"
  local work_root="$2"
  local with_manifest="$3"

  local out_dir="$work_root/afl_out"
  local run_name="exp"
  local fuzzer_name="master"
  local fuzzer_dir="$out_dir/$run_name/$fuzzer_name"
  local queue_dir="$fuzzer_dir/queue"
  local log_file="$work_root/helper.log"

  mkdir -p "$queue_dir"

  local manifest_sample="$queue_dir/id:000001,src:000000,manifest"
  local normal_cov_sample="$queue_dir/id:000002,src:000000,+cov"
  printf 'manifest\n' > "$manifest_sample"
  printf 'normal\n' > "$normal_cov_sample"

  printf '%s\n' "command_line : /usr/bin/afl-fuzz -i in -o out -- /bin/true @@" > "$fuzzer_dir/fuzzer_stats"

  if [[ "$with_manifest" == "1" ]]; then
    local manifest_file="$work_root/high_value_samples.txt"
    printf '%s\n' "$manifest_sample" > "$manifest_file"
    SYMCC_HIGH_VALUE_MANIFEST="$manifest_file" timeout -k 1 4 "$helper_bin" \
      -a "$fuzzer_name" -o "$out_dir" -n "$run_name" -- /bin/true @@ > "$log_file" 2>&1 || true
  else
    env -u SYMCC_HIGH_VALUE_MANIFEST timeout -k 1 4 "$helper_bin" \
      -a "$fuzzer_name" -o "$out_dir" -n "$run_name" -- /bin/true @@ > "$log_file" 2>&1 || true
  fi

  local first_line
  first_line="$(grep -m1 "Running SymCC on request sample" "$log_file" || true)"
  if [[ -z "$first_line" ]]; then
    echo "未找到首个处理样本日志，helper 可能未正常进入处理循环" >&2
    cat "$log_file" >&2
    return 1
  fi

  if [[ "$with_manifest" == "1" ]]; then
    if [[ "$first_line" != *"$manifest_sample"* ]]; then
      echo "manifest 优先级断言失败：首个处理样本不是 manifest 样本" >&2
      echo "首行: $first_line" >&2
      return 1
    fi
  else
    if [[ "$first_line" != *"$normal_cov_sample"* ]]; then
      echo "无 manifest 回退断言失败：首个处理样本未回到 coverage-first" >&2
      echo "首行: $first_line" >&2
      return 1
    fi
    if grep -q "Fatal:" "$log_file"; then
      echo "无 manifest 场景不应出现 Fatal 错误" >&2
      cat "$log_file" >&2
      return 1
    fi
  fi
}

main() {
  local tmp_root=""
  local helper_bin
  helper_bin="$(resolve_helper_bin)" || {
    echo "未找到 symcc_fuzzing_helper 可执行文件，请先运行 xmake 构建" >&2
    exit 1
  }

  tmp_root="$(mktemp -d)"
  trap 'if [[ -n "${tmp_root:-}" ]]; then rm -rf "$tmp_root"; fi' EXIT

  run_helper_once "$helper_bin" "$tmp_root/with_manifest" 1
  run_helper_once "$helper_bin" "$tmp_root/without_manifest" 0

  echo "高价值优先级夹具测试通过"
}

main "$@"
