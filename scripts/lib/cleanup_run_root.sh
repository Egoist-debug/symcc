#!/usr/bin/env bash
#
# 清理实验 run_root 中的运行时大文件，只保留分析需要的证据文件
#
# 保留：*.cache.txt, *.json, *.stderr, *.native.log, *.lua, sample.bin, 实验报告
# 删除：LMDB working files (data.mdb / lock.mdb / top / ruledb/), bind9_runtime/, defer

cleanup_run_root_artifacts() {
	local run_root="$1"
	if [ -z "$run_root" ] || [ ! -d "$run_root" ]; then
		return 0
	fi

	find "$run_root" -type f \( -name "data.mdb" -o -name "lock.mdb" \) -delete 2>/dev/null || true
	find "$run_root" -type f -name "top" -path "*/knot-resolver/*" -delete 2>/dev/null || true
	find "$run_root" -type f -name "defer" -path "*/knot-resolver/*" -delete 2>/dev/null || true
	find "$run_root" -type d -name "ruledb" -exec rm -rf {} + 2>/dev/null || true
	find "$run_root" -type d -name "bind9_runtime" -exec rm -rf {} + 2>/dev/null || true
}

cleanup_experiment_base() {
	local base_dir="$1"
	if [ -z "$base_dir" ] || [ ! -d "$base_dir" ]; then
		return 0
	fi

	find "$base_dir" -type f \( -name "data.mdb" -o -name "lock.mdb" \) -delete 2>/dev/null || true
	find "$base_dir" -type f -name "top" -path "*/knot-resolver/*" -delete 2>/dev/null || true
	find "$base_dir" -type f -name "defer" -path "*/knot-resolver/*" -delete 2>/dev/null || true
	find "$base_dir" -type d -name "ruledb" -exec rm -rf {} + 2>/dev/null || true
	find "$base_dir" -type d -name "bind9_runtime" -exec rm -rf {} + 2>/dev/null || true
}
