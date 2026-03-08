#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_DIR="$ROOT_DIR/named_experiment"
WORK_DIR="${WORK_DIR:-$EXP_DIR/work}"
PATCH_DIR="$ROOT_DIR/patch"
SRC_TREE="$ROOT_DIR/bind-9.18.46"
AFL_TREE="$ROOT_DIR/bind-9.18.46-afl"
SYMCC_TREE="$ROOT_DIR/bind-9.18.46-symcc"

HELPER_BIN="$ROOT_DIR/build/linux/x86_64/release/symcc_fuzzing_helper"
GEN_INPUT_BIN="$ROOT_DIR/build/linux/x86_64/release/gen_input"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-/usr/local/bin/afl-fuzz}"
AFL_CC_BIN="${AFL_CC_BIN:-/usr/local/bin/afl-clang-fast}"
SYMCC_CC_BIN="${SYMCC_CC_BIN:-$ROOT_DIR/symcc_build_qsym/symcc}"
SYMCC_CXX_BIN="${SYMCC_CXX_BIN:-$ROOT_DIR/symcc_build_qsym/sym++}"

NAMED_CONF="$EXP_DIR/runtime/named.conf"
BIN_DIR="$WORK_DIR/bin"
RUNTIME_STATE_DIR="$WORK_DIR/runtime"
QUERY_CORPUS_DIR="$WORK_DIR/query_corpus"
STABLE_QUERY_CORPUS_DIR="$WORK_DIR/stable_query_corpus"
RESPONSE_CORPUS_DIR="$WORK_DIR/response_corpus"
QUERY_DRIVER="$WORK_DIR/driver_query.bin"
QUERY_PARSER_BIN="$BIN_DIR/dns_parser_sym"
RESPONSE_PARSER_BIN="$BIN_DIR/dns_response_parser_sym"
QUERY_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_parser.c"
RESPONSE_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_response_parser.c"
LOG_DIR="$WORK_DIR/logs"
PID_DIR="$WORK_DIR/pids"
AFL_OUT_DIR="$WORK_DIR/afl_out"
SYMCC_OUTPUT_DIR="$WORK_DIR/symcc_output"
QUERY_GEN_LOG="$WORK_DIR/query_gen.log"
RESPONSE_GEN_LOG="$WORK_DIR/response_gen.log"

MASTER_LOG="$LOG_DIR/afl_master_persistent.log"
SECONDARY_LOG="$LOG_DIR/afl_secondary_persistent.log"
HELPER_LOG="$LOG_DIR/helper_persistent.log"
MASTER_PID="$PID_DIR/afl_master.pid"
SECONDARY_PID="$PID_DIR/afl_secondary.pid"
HELPER_PID="$PID_DIR/helper.pid"

MUTATOR_ADDR="${MUTATOR_ADDR:-127.0.0.1:55300}"
TARGET_ADDR="${TARGET_ADDR:-127.0.0.1:55301}"
REPLY_TIMEOUT_MS="${REPLY_TIMEOUT_MS:-50}"
JOBS="${JOBS:-2}"
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-3000+}"
SEED_TIMEOUT_SEC="${SEED_TIMEOUT_SEC:-15}"
ENABLE_SECONDARY="${ENABLE_SECONDARY:-1}"
REGEN_SEEDS="${REGEN_SEEDS:-0}"
REFILTER_QUERIES="${REFILTER_QUERIES:-0}"
RESET_OUTPUT="${RESET_OUTPUT:-1}"
QUERY_MAX_ITER="${QUERY_MAX_ITER:-40}"
RESPONSE_MAX_ITER="${RESPONSE_MAX_ITER:-500}"
RESPONSE_PRESERVE="${RESPONSE_PRESERVE:-20}"
HELPER_NAME="${HELPER_NAME:-symcc}"
HELPER_RUN_ROOT="${HELPER_RUN_ROOT:-$WORK_DIR}"
HELPER_RUN_NAME="${HELPER_RUN_NAME:-$(basename "$AFL_OUT_DIR")}"
USE_TMUX="${USE_TMUX:-1}"
MASTER_SESSION="${MASTER_SESSION:-named_afl_master}"
SECONDARY_SESSION="${SECONDARY_SESSION:-named_afl_secondary}"
HELPER_SESSION="${HELPER_SESSION:-named_symcc_helper}"

usage() {
	cat <<'EOF'
用法:
  named_experiment/run_named_afl_symcc.sh <命令>

命令:
  build         同步 patch，并构建 helper、AFL 持久模式 named、SymCC named
  gen-seeds     用 gen_input 生成 query_corpus 和 response_corpus
  filter-seeds  筛选对 named 稳定的 query 语料，输出 stable_query_corpus
  prepare       执行 build + gen-seeds(按需) + filter-seeds
  start         以持久模式启动 AFL++ master/secondary + SymCC helper
  stop          停止当前实验进程
  status        查看当前实验状态与关键统计

默认约定:
  1. AFL++ 目标使用 stdin 持久模式，不再依赖 input=@@ 的外部注入线程。
  2. patch/ 作为实验补丁源，会同步到 bind-9.18.46、bind-9.18.46-afl、bind-9.18.46-symcc。
  3. 运行产物统一写入 named_experiment/work/。
  4. start 默认清理旧的 afl_out 和当前日志；如需保留可设置 RESET_OUTPUT=0。

常用环境变量:
  JOBS=2
  ENABLE_SECONDARY=1
  AFL_TIMEOUT_MS=3000+
  REPLY_TIMEOUT_MS=50
  REGEN_SEEDS=0
  REFILTER_QUERIES=0
  RESET_OUTPUT=1
  MUTATOR_ADDR=127.0.0.1:55300
  TARGET_ADDR=127.0.0.1:55301
EOF
}

log() {
	printf '[named-exp] %s\n' "$*"
}

warn() {
	printf '[named-exp][warn] %s\n' "$*" >&2
}

die() {
	printf '[named-exp][error] %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

require_file() {
	[ -e "$1" ] || die "缺少文件: $1"
}

ensure_dirs() {
	mkdir -p "$WORK_DIR" "$BIN_DIR" "$LOG_DIR" "$PID_DIR" "$SYMCC_OUTPUT_DIR" \
		"$RUNTIME_STATE_DIR" "$EXP_DIR/runtime"
}

afl_ld_library_path() {
	local dirs=()
	mapfile -t dirs < <(find "$AFL_TREE" -type d -path '*/.libs' | sort)
	[ "${#dirs[@]}" -gt 0 ] || die "未找到 AFL named 依赖库目录，请先构建 $AFL_TREE"
	(
		IFS=:
		printf '%s' "${dirs[*]}"
	)
}

ensure_tree_exists() {
	local tree="$1"
	if [ ! -d "$tree" ]; then
		log "创建构建树: $tree"
		cp -a "$SRC_TREE" "$tree"
	fi
}

sync_patch_tree() {
	local tree="$1"
	[ -d "$tree" ] || return 0

	copy_if_different() {
		local src="$1"
		local dst="$2"
		if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
			return 0
		fi
		cp "$src" "$dst"
	}

	mkdir -p \
		"$tree/bin/named" \
		"$tree/bin/named/include/named" \
		"$tree/lib/dns" \
		"$tree/lib/dns/include/dns" \
		"$tree/lib/ns"
	copy_if_different "$PATCH_DIR/bin/named/main.c" "$tree/bin/named/main.c"
	copy_if_different "$PATCH_DIR/bin/named/fuzz.c" "$tree/bin/named/fuzz.c"
	copy_if_different "$PATCH_DIR/bin/named/resolver_afl_symcc_orchestrator.c" \
		"$tree/bin/named/resolver_afl_symcc_orchestrator.c"
	copy_if_different "$PATCH_DIR/bin/named/resolver_afl_symcc_mutator_server.c" \
		"$tree/bin/named/resolver_afl_symcc_mutator_server.c"
	copy_if_different "$PATCH_DIR/lib/dns/dispatch.c" \
		"$tree/lib/dns/dispatch.c"
	copy_if_different "$PATCH_DIR/lib/ns/client.c" \
		"$tree/lib/ns/client.c"
	copy_if_different "$PATCH_DIR/include/named/resolver_afl_symcc_orchestrator.h" \
		"$tree/bin/named/include/named/resolver_afl_symcc_orchestrator.h"
	copy_if_different "$PATCH_DIR/include/named/resolver_afl_symcc_mutator_server.h" \
		"$tree/bin/named/include/named/resolver_afl_symcc_mutator_server.h"
	copy_if_different "$PATCH_DIR/lib/dns/include/dns/dispatch.h" \
		"$tree/lib/dns/include/dns/dispatch.h"
}

sync_patch() {
	require_file "$PATCH_DIR/bin/named/main.c"
	require_file "$PATCH_DIR/bin/named/fuzz.c"
	require_file "$PATCH_DIR/bin/named/resolver_afl_symcc_orchestrator.c"
	require_file "$PATCH_DIR/bin/named/resolver_afl_symcc_mutator_server.c"
	require_file "$PATCH_DIR/lib/dns/dispatch.c"
	require_file "$PATCH_DIR/lib/ns/client.c"
	require_file "$PATCH_DIR/include/named/resolver_afl_symcc_orchestrator.h"
	require_file "$PATCH_DIR/include/named/resolver_afl_symcc_mutator_server.h"
	require_file "$PATCH_DIR/lib/dns/include/dns/dispatch.h"

	sync_patch_tree "$SRC_TREE"
	ensure_tree_exists "$AFL_TREE"
	ensure_tree_exists "$SYMCC_TREE"
	sync_patch_tree "$AFL_TREE"
	sync_patch_tree "$SYMCC_TREE"
}

build_helper_and_gen_input() {
	require_cmd xmake
	log "构建 helper 与 gen_input"
	(
		cd "$ROOT_DIR"
		HOME="$ROOT_DIR/.xmake-home" \
		XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
		xmake f --backend=qsym -m release >/dev/null
		HOME="$ROOT_DIR/.xmake-home" \
		XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
		xmake b symcc_fuzzing_helper
		HOME="$ROOT_DIR/.xmake-home" \
		XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
		xmake b gen_input
	)
	require_file "$HELPER_BIN"
	require_file "$GEN_INPUT_BIN"
}

build_seed_parsers() {
	require_file "$SYMCC_CC_BIN"
	require_file "$QUERY_PARSER_SRC"
	require_file "$RESPONSE_PARSER_SRC"
	ensure_dirs

	if [ ! -x "$QUERY_PARSER_BIN" ]; then
		log "构建 query DNS parser"
		"$SYMCC_CC_BIN" "$QUERY_PARSER_SRC" -O2 -o "$QUERY_PARSER_BIN"
	fi

	if [ ! -x "$RESPONSE_PARSER_BIN" ]; then
		log "构建 response DNS parser"
		"$SYMCC_CC_BIN" "$RESPONSE_PARSER_SRC" -O2 -o "$RESPONSE_PARSER_BIN"
	fi
}

build_afl_named() {
	local reconfigure=0

	require_file "$AFL_CC_BIN"
	ensure_tree_exists "$AFL_TREE"
	sync_patch_tree "$AFL_TREE"

	if [ ! -f "$AFL_TREE/config.status" ]; then
		reconfigure=1
	elif grep -q 'NAMED_AFL_NO_PERSISTENT_MODE' "$AFL_TREE/config.status"; then
		reconfigure=1
	fi

	if [ "$reconfigure" -eq 1 ]; then
		log "配置 AFL named（开启持久模式）"
		(
			cd "$AFL_TREE"
			make distclean >/dev/null 2>&1 || true
			CC="$AFL_CC_BIN" \
			CPPFLAGS= \
			./configure \
				--enable-fuzzing=afl \
				--without-libxml2 \
				--without-json-c \
				--without-libidn2 \
				--without-lmdb
		)
	fi

	log "编译 AFL named"
	(
		cd "$AFL_TREE"
		make -j"$JOBS"
	)
	require_file "$AFL_TREE/bin/named/.libs/named"
}

build_symcc_named() {
	local reconfigure=0

	require_file "$SYMCC_CC_BIN"
	require_file "$SYMCC_CXX_BIN"
	ensure_tree_exists "$SYMCC_TREE"
	sync_patch_tree "$SYMCC_TREE"

	if [ ! -f "$SYMCC_TREE/config.status" ]; then
		reconfigure=1
	elif ! grep -q -- '-DENABLE_AFL' "$SYMCC_TREE/config.status"; then
		reconfigure=1
	fi

	mkdir -p "$SYMCC_OUTPUT_DIR/build"

	if [ "$reconfigure" -eq 1 ]; then
		log "配置 SymCC named"
		(
			cd "$SYMCC_TREE"
			make distclean >/dev/null 2>&1 || true
			SYMCC_NO_SYMBOLIC_INPUT=1 \
			SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
			CC="$SYMCC_CC_BIN" \
			CXX="$SYMCC_CXX_BIN" \
			CPPFLAGS='-DENABLE_AFL' \
			./configure \
				--without-libxml2 \
				--without-json-c \
				--without-libidn2 \
				--without-lmdb
		)
	fi

	log "编译 SymCC named"
	(
		cd "$SYMCC_TREE"
		SYMCC_NO_SYMBOLIC_INPUT=1 \
		SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
		make -j"$JOBS"
	)
	require_file "$SYMCC_TREE/bin/named/named"
}

generate_seeds() {
	ensure_dirs
	build_helper_and_gen_input
	build_seed_parsers

	if [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$QUERY_CORPUS_DIR" ] || \
		[ -z "$(find "$QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		require_file "$QUERY_PARSER_BIN"
		rm -rf "$QUERY_CORPUS_DIR"
		mkdir -p "$QUERY_CORPUS_DIR"
		log "生成 query 语料"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns \
			-i "$QUERY_MAX_ITER" \
			-o "$QUERY_CORPUS_DIR" \
			"$QUERY_PARSER_BIN" \
			>"$QUERY_GEN_LOG" 2>&1
	fi

	if [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$RESPONSE_CORPUS_DIR" ] || \
		[ -z "$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		require_file "$RESPONSE_PARSER_BIN"
		rm -rf "$RESPONSE_CORPUS_DIR"
		mkdir -p "$RESPONSE_CORPUS_DIR"
		log "生成 response-tail 语料"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns-response \
			--hybrid \
			--preserve "$RESPONSE_PRESERVE" \
			-i "$RESPONSE_MAX_ITER" \
			-o "$RESPONSE_CORPUS_DIR" \
			"$RESPONSE_PARSER_BIN" \
			>"$RESPONSE_GEN_LOG" 2>&1
	fi
}

sample_is_stable() {
	local sample="$1"
	local stderr_file
	local ld_path

	stderr_file="$(mktemp "$LOG_DIR/filter.XXXXXX.stderr")"
	ld_path="$(afl_ld_library_path)"

	if env \
		LD_LIBRARY_PATH="$ld_path" \
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
		NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
		timeout -k 5 "$SEED_TIMEOUT_SEC" \
		"$AFL_TREE/bin/named/.libs/named" \
		-g \
		-c "$NAMED_CONF" \
		-A "resolver-afl-symcc:${MUTATOR_ADDR},input=$sample" \
		>/dev/null 2>"$stderr_file"
	then
		if grep -q 'Requests sent: 1' "$stderr_file" && \
			grep -q 'Replies received: 1' "$stderr_file"
		then
			rm -f "$stderr_file"
			return 0
		fi
	fi

	rm -f "$stderr_file"
	return 1
}

filter_seeds() {
	local tmp_dir
	local seed_count=0
	local next_id=0

	require_file "$QUERY_DRIVER"
	[ -d "$QUERY_CORPUS_DIR" ] || die "query 语料目录不存在: $QUERY_CORPUS_DIR"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "response 语料目录不存在: $RESPONSE_CORPUS_DIR"

	if [ "$REFILTER_QUERIES" -eq 0 ] && [ -d "$STABLE_QUERY_CORPUS_DIR" ] && \
		[ -n "$(find "$STABLE_QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		log "复用已有 stable_query_corpus"
		return 0
	fi

	build_afl_named
	ensure_dirs
	tmp_dir="$(mktemp -d "$WORK_DIR/.stable_query_tmp.XXXXXX")"

	cp "$QUERY_DRIVER" "$tmp_dir/$(printf 'id_%06d_driver' "$next_id")"
	next_id=$((next_id + 1))
	seed_count=$((seed_count + 1))

	log "筛选稳定 query 语料"
	for sample in "$QUERY_CORPUS_DIR"/*; do
		[ -f "$sample" ] || continue
		if sample_is_stable "$sample"; then
			cp "$sample" "$tmp_dir/$(printf 'id_%06d_%s' "$next_id" "$(basename "$sample")")"
			next_id=$((next_id + 1))
			seed_count=$((seed_count + 1))
		fi
	done

	if [ "$seed_count" -le 0 ]; then
		rm -rf "$tmp_dir"
		die "没有筛出任何稳定 query 语料"
	fi

	rm -rf "$STABLE_QUERY_CORPUS_DIR"
	mv "$tmp_dir" "$STABLE_QUERY_CORPUS_DIR"
	log "stable_query_corpus 已生成，样本数: $seed_count"
}

prepare_all() {
	ensure_dirs
	sync_patch
	build_helper_and_gen_input
	build_afl_named
	build_symcc_named
	generate_seeds
	filter_seeds
}

pid_is_alive() {
	local pidfile="$1"
	[ -f "$pidfile" ] || return 1
	local pid
	pid="$(cat "$pidfile" 2>/dev/null || true)"
	[ -n "$pid" ] || return 1
	kill -0 "$pid" 2>/dev/null
}

tmux_enabled() {
	[ "$USE_TMUX" -eq 1 ] && command -v tmux >/dev/null 2>&1
}

tmux_session_alive() {
	local session="$1"
	tmux_enabled || return 1
	tmux has-session -t "$session" 2>/dev/null
}

quote_cmd() {
	printf '%q ' "$@"
}

stop_pidfile() {
	local pidfile="$1"
	local name="$2"

	if ! pid_is_alive "$pidfile"; then
		rm -f "$pidfile"
		return 0
	fi

	local pid
	pid="$(cat "$pidfile")"
	log "停止 $name (pid=$pid)"
	kill "$pid" 2>/dev/null || true
	for _ in $(seq 1 10); do
		if ! kill -0 "$pid" 2>/dev/null; then
			break
		fi
		sleep 1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$pidfile"
}

stop_all() {
	if tmux_enabled; then
		tmux kill-session -t "$HELPER_SESSION" 2>/dev/null || true
		tmux kill-session -t "$SECONDARY_SESSION" 2>/dev/null || true
		tmux kill-session -t "$MASTER_SESSION" 2>/dev/null || true
	fi
	stop_pidfile "$HELPER_PID" "helper"
	stop_pidfile "$SECONDARY_PID" "afl-secondary"
	stop_pidfile "$MASTER_PID" "afl-master"
	pkill -f "$AFL_TREE/bin/named/.libs/named -g -c $NAMED_CONF -A resolver-afl-symcc:${MUTATOR_ADDR}" \
		2>/dev/null || true
	pkill -f "$SYMCC_TREE/bin/named/named -g -c $NAMED_CONF -A resolver-afl-symcc:${MUTATOR_ADDR}" \
		2>/dev/null || true
}

cleanup_output() {
	if [ "$RESET_OUTPUT" -eq 1 ]; then
		rm -rf "$AFL_OUT_DIR"
		rm -f "$MASTER_LOG" "$SECONDARY_LOG" "$HELPER_LOG"
	fi
	mkdir -p "$AFL_OUT_DIR" "$LOG_DIR" "$PID_DIR"
}

wait_for_master_queue() {
	local stats_file="$AFL_OUT_DIR/master/fuzzer_stats"
	for _ in $(seq 1 30); do
		if [ -f "$stats_file" ]; then
			return 0
		fi
		sleep 1
	done
	die "等待 AFL master 初始化超时: $stats_file"
}

launch_in_background() {
	local logfile="$1"
	local pidfile="$2"
	local pid
	shift 2

	nohup "$@" >>"$logfile" 2>&1 </dev/null &
	pid="$!"
	disown "$pid" 2>/dev/null || true
	echo "$pid" >"$pidfile"
}

launch_in_tmux() {
	local session="$1"
	local logfile="$2"
	shift 2

	local root_quoted logfile_quoted cmd_quoted
	root_quoted="$(printf '%q' "$ROOT_DIR")"
	logfile_quoted="$(printf '%q' "$logfile")"
	cmd_quoted="$(quote_cmd "$@")"

	tmux kill-session -t "$session" 2>/dev/null || true
	tmux new-session -d -s "$session" \
		"cd ${root_quoted} && exec ${cmd_quoted}"
	tmux pipe-pane -o -t "${session}:0.0" "cat >>${logfile_quoted}"
}

launch_shell_in_tmux() {
	local session="$1"
	local logfile="$2"
	local command_text="$3"
	local logfile_quoted

	logfile_quoted="$(printf '%q' "$logfile")"

	tmux kill-session -t "$session" 2>/dev/null || true
	tmux new-session -d -s "$session" "$command_text"
	tmux pipe-pane -o -t "${session}:0.0" "cat >>${logfile_quoted}"
}

start_all() {
	local ld_path
	local helper_target_csv

	prepare_all
	stop_all
	cleanup_output
	ld_path="$(afl_ld_library_path)"
	helper_target_csv="${AFL_TREE}/bin/named/.libs/named,-g,-c,${NAMED_CONF},-A,resolver-afl-symcc:${MUTATOR_ADDR}"

	log "启动 AFL master（持久模式）"
	if tmux_enabled; then
		launch_in_tmux \
			"$MASTER_SESSION" \
			"$MASTER_LOG" \
			env \
			LD_LIBRARY_PATH="$ld_path" \
			AFL_NO_UI=1 \
			AFL_NO_AFFINITY=1 \
			AFL_SKIP_CPUFREQ=1 \
			AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
			NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
			NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
			NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
			"$AFL_FUZZ_BIN" \
			-M master \
			-i "$STABLE_QUERY_CORPUS_DIR" \
			-o "$AFL_OUT_DIR" \
			-m none \
			-t "$AFL_TIMEOUT_MS" \
			-- \
			"$AFL_TREE/bin/named/.libs/named" \
			-g \
			-c "$NAMED_CONF" \
			-A "resolver-afl-symcc:${MUTATOR_ADDR}"
	else
		launch_in_background \
			"$MASTER_LOG" \
			"$MASTER_PID" \
			env \
			LD_LIBRARY_PATH="$ld_path" \
			AFL_NO_UI=1 \
			AFL_NO_AFFINITY=1 \
			AFL_SKIP_CPUFREQ=1 \
			AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
			NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
			NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
			NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
			"$AFL_FUZZ_BIN" \
			-M master \
			-i "$STABLE_QUERY_CORPUS_DIR" \
			-o "$AFL_OUT_DIR" \
			-m none \
			-t "$AFL_TIMEOUT_MS" \
			-- \
			"$AFL_TREE/bin/named/.libs/named" \
			-g \
			-c "$NAMED_CONF" \
			-A "resolver-afl-symcc:${MUTATOR_ADDR}"
	fi

	if [ "$ENABLE_SECONDARY" -eq 1 ]; then
		log "启动 AFL secondary（持久模式）"
		if tmux_enabled; then
			launch_in_tmux \
				"$SECONDARY_SESSION" \
				"$SECONDARY_LOG" \
				env \
				LD_LIBRARY_PATH="$ld_path" \
				AFL_NO_UI=1 \
				AFL_NO_AFFINITY=1 \
				AFL_SKIP_CPUFREQ=1 \
				AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
				NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
				NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
				NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
				"$AFL_FUZZ_BIN" \
				-S secondary \
				-i "$STABLE_QUERY_CORPUS_DIR" \
				-o "$AFL_OUT_DIR" \
				-m none \
				-t "$AFL_TIMEOUT_MS" \
				-- \
				"$AFL_TREE/bin/named/.libs/named" \
				-g \
				-c "$NAMED_CONF" \
				-A "resolver-afl-symcc:${MUTATOR_ADDR}"
		else
			launch_in_background \
				"$SECONDARY_LOG" \
				"$SECONDARY_PID" \
				env \
				LD_LIBRARY_PATH="$ld_path" \
				AFL_NO_UI=1 \
				AFL_NO_AFFINITY=1 \
				AFL_SKIP_CPUFREQ=1 \
				AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
				NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
				NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
				NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
				"$AFL_FUZZ_BIN" \
				-S secondary \
				-i "$STABLE_QUERY_CORPUS_DIR" \
				-o "$AFL_OUT_DIR" \
				-m none \
				-t "$AFL_TIMEOUT_MS" \
				-- \
				"$AFL_TREE/bin/named/.libs/named" \
				-g \
				-c "$NAMED_CONF" \
				-A "resolver-afl-symcc:${MUTATOR_ADDR}"
		fi
	fi

	if [ -d "$AFL_OUT_DIR/$HELPER_NAME" ]; then
		rm -rf "$AFL_OUT_DIR/$HELPER_NAME"
	fi
	if [ -d "$HELPER_RUN_ROOT/$HELPER_RUN_NAME/${HELPER_RUN_NAME}_symcc" ]; then
		rm -rf "$HELPER_RUN_ROOT/$HELPER_RUN_NAME/${HELPER_RUN_NAME}_symcc"
	fi

	log "启动 SymCC helper"
	if tmux_enabled; then
		launch_shell_in_tmux \
			"$HELPER_SESSION" \
			"$HELPER_LOG" \
			"cd $(printf '%q' "$ROOT_DIR") && while [ ! -f $(printf '%q' "$AFL_OUT_DIR/master/fuzzer_stats") ]; do sleep 1; done && exec $(quote_cmd env LD_LIBRARY_PATH="$ld_path" NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" "$HELPER_BIN" -o "$HELPER_RUN_ROOT" -n "$HELPER_RUN_NAME" -a master -v -r "$RESPONSE_CORPUS_DIR" -e NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL -t "$helper_target_csv" -- "$SYMCC_TREE/bin/named/named" -g -c "$NAMED_CONF" -A "resolver-afl-symcc:${MUTATOR_ADDR}")"
	else
		wait_for_master_queue
		launch_in_background \
			"$HELPER_LOG" \
			"$HELPER_PID" \
			env \
			LD_LIBRARY_PATH="$ld_path" \
			NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
			NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
			"$HELPER_BIN" \
			-o "$HELPER_RUN_ROOT" \
			-n "$HELPER_RUN_NAME" \
			-a master \
			-v \
			-r "$RESPONSE_CORPUS_DIR" \
			-e NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL \
			-t "$helper_target_csv" \
			-- \
			"$SYMCC_TREE/bin/named/named" \
			-g \
			-c "$NAMED_CONF" \
			-A "resolver-afl-symcc:${MUTATOR_ADDR}"
	fi

	log "实验已启动"
	status_all
}

show_pid_status() {
	local name="$1"
	local pidfile="$2"
	if [ "$name" = "afl-master" ] && tmux_session_alive "$MASTER_SESSION"; then
		printf '  %-14s running (tmux:%s)\n' "$name" "$MASTER_SESSION"
	elif [ "$name" = "afl-secondary" ] && tmux_session_alive "$SECONDARY_SESSION"; then
		printf '  %-14s running (tmux:%s)\n' "$name" "$SECONDARY_SESSION"
	elif [ "$name" = "helper" ] && tmux_session_alive "$HELPER_SESSION"; then
		printf '  %-14s running (tmux:%s)\n' "$name" "$HELPER_SESSION"
	elif pid_is_alive "$pidfile"; then
		printf '  %-14s running (pid=%s)\n' "$name" "$(cat "$pidfile")"
	else
		printf '  %-14s stopped\n' "$name"
	fi
}

show_fuzzer_stats() {
	local stats_file="$1"
	[ -f "$stats_file" ] || return 0
	printf '  %s\n' "$stats_file"
	grep -E '^(execs_done|cycles_done|corpus_count|saved_crashes|saved_hangs|bitmap_cvg|pending_total|last_find)' \
		"$stats_file" | sed 's/^/    /'
}

status_all() {
	printf '进程状态:\n'
	show_pid_status "afl-master" "$MASTER_PID"
	show_pid_status "afl-secondary" "$SECONDARY_PID"
	show_pid_status "helper" "$HELPER_PID"

	printf '\nAFL 统计:\n'
	show_fuzzer_stats "$AFL_OUT_DIR/master/fuzzer_stats"
	show_fuzzer_stats "$AFL_OUT_DIR/secondary/fuzzer_stats"

	printf '\n日志尾部:\n'
	for log_file in "$MASTER_LOG" "$SECONDARY_LOG" "$HELPER_LOG"; do
		[ -f "$log_file" ] || continue
		printf '  %s\n' "$log_file"
		tail -n 5 "$log_file" | sed 's/^/    /'
	done
}

main() {
	local cmd="${1:-}"

	case "$cmd" in
	build)
		ensure_dirs
		sync_patch
		build_helper_and_gen_input
		build_afl_named
		build_symcc_named
		;;
	gen-seeds)
		generate_seeds
		;;
	filter-seeds)
		filter_seeds
		;;
	prepare)
		prepare_all
		;;
	start)
		start_all
		;;
	stop)
		stop_all
		;;
	status)
		status_all
		;;
	""|-h|--help|help)
		usage
		;;
	*)
		usage
		die "未知命令: $cmd"
		;;
	esac
}

require_cmd timeout
require_cmd make
require_cmd grep
require_cmd sed
require_cmd find
require_file "$SRC_TREE"
require_file "$NAMED_CONF"

main "${1:-}"
