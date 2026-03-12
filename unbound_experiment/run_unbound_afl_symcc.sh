#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_DIR="$ROOT_DIR/unbound_experiment"
PATCH_DIR="$ROOT_DIR/unbound_patch"
WORK_DIR="${WORK_DIR:-$EXP_DIR/work}"
SRC_TREE="${SRC_TREE:-$ROOT_DIR/unbound-1.24.2}"
AFL_TREE="${AFL_TREE:-$ROOT_DIR/unbound-1.24.2-afl}"
SYMCC_TREE="${SYMCC_TREE:-$ROOT_DIR/unbound-1.24.2-symcc}"

HELPER_BIN="$ROOT_DIR/build/linux/x86_64/release/symcc_fuzzing_helper"
GEN_INPUT_BIN="$ROOT_DIR/build/linux/x86_64/release/gen_input"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-/usr/local/bin/afl-fuzz}"
AFL_CC_BIN="${AFL_CC_BIN:-/usr/local/bin/afl-clang-fast}"
SYMCC_CC_BIN="${SYMCC_CC_BIN:-$ROOT_DIR/symcc_build_qsym/symcc}"
SYMCC_CXX_BIN="${SYMCC_CXX_BIN:-$ROOT_DIR/symcc_build_qsym/sym++}"

BIN_DIR="$WORK_DIR/bin"
QUERY_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_parser.c"
RESPONSE_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_response_parser.c"
QUERY_PARSER_BIN="$BIN_DIR/dns_parser_sym"
RESPONSE_PARSER_BIN="$BIN_DIR/dns_response_parser_sym"
QUERY_CORPUS_DIR="$WORK_DIR/query_corpus"
RESPONSE_CORPUS_DIR="$WORK_DIR/response_corpus"
STABLE_QUERY_CORPUS_DIR="$WORK_DIR/stable_query_corpus"
SYMCC_OUTPUT_DIR="$WORK_DIR/symcc_output"
LOG_DIR="$WORK_DIR/logs"
PID_DIR="$WORK_DIR/pids"
AFL_OUT_DIR="$WORK_DIR/afl_out"
QUERY_GEN_LOG="$WORK_DIR/query_gen.log"
RESPONSE_GEN_LOG="$WORK_DIR/response_gen.log"

MASTER_LOG="$LOG_DIR/afl_master.log"
HELPER_LOG="$LOG_DIR/helper.log"
MASTER_PID="$PID_DIR/afl_master.pid"
HELPER_PID="$PID_DIR/helper.pid"

JOBS="${JOBS:-2}"
QUERY_MAX_ITER="${QUERY_MAX_ITER:-128}"
RESPONSE_MAX_ITER="${RESPONSE_MAX_ITER:-64}"
RESPONSE_QUERY_SEEDS="${RESPONSE_QUERY_SEEDS:-8}"
SEED_TIMEOUT_SEC="${SEED_TIMEOUT_SEC:-5}"
SMOKE_TIMEOUT_SEC="${SMOKE_TIMEOUT_SEC:-5}"
# libunbound 初始化与本地 mutator server 启动有固定开销，1000ms 容易被 AFL 误判超时
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-3000+}"
RUN_DURATION_SEC="${RUN_DURATION_SEC:-180}"
REGEN_SEEDS="${REGEN_SEEDS:-0}"
REFILTER_QUERIES="${REFILTER_QUERIES:-0}"
RESET_OUTPUT="${RESET_OUTPUT:-1}"
ENABLE_HELPER="${ENABLE_HELPER:-1}"
UNBOUND_TAG="${UNBOUND_TAG:-release-1.24.2}"
HELPER_RUN_ROOT="${HELPER_RUN_ROOT:-$WORK_DIR}"
HELPER_RUN_NAME="${HELPER_RUN_NAME:-$(basename "$AFL_OUT_DIR")}"

usage() {
	printf '%s\n' \
		'用法:' \
		'  unbound_experiment/run_unbound_afl_symcc.sh <命令>' \
		'' \
		'命令:' \
		'  fetch         拉取 Unbound release-1.24.2 源码树' \
		'  build         同步 unbound_patch，并构建 helper、AFL 与 SymCC 目标' \
		'  gen-seeds     生成 query/response 语料' \
		'  filter-seeds  筛选 legacy-response-tail 稳定 query 语料' \
		'  smoke         对 AFL / SymCC 目标执行最小 smoke' \
		'  prepare       执行 build + gen-seeds + filter-seeds + smoke' \
		'  start         启动 AFL master 与 SymCC helper' \
		'  run [秒数]    启动实验并持续运行指定秒数，结束后自动输出状态并停止' \
		'  stop          停止当前实验进程' \
		'  status        查看当前实验状态与关键统计' \
		'' \
		'默认约定:' \
		'  1. 当前阶段目标是 legacy-response-tail，对齐 BIND9 的第一阶段对照线。' \
		'  2. query 继续复用 gen_input 生成，response 使用 dns-poison-response 综合语料。' \
		'  3. AFL 主跑 stable_query_corpus，SymCC helper 跟进 AFL 队列补洞。'
}

log() {
	printf '[unbound-exp] %s\n' "$*"
}

warn() {
	printf '[unbound-exp][warn] %s\n' "$*" >&2
}

die() {
	printf '[unbound-exp][error] %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

require_file() {
	[ -e "$1" ] || die "缺少文件: $1"
}

ensure_dirs() {
	mkdir -p \
		"$BIN_DIR" \
		"$QUERY_CORPUS_DIR" \
		"$RESPONSE_CORPUS_DIR" \
		"$STABLE_QUERY_CORPUS_DIR" \
		"$SYMCC_OUTPUT_DIR" \
		"$SYMCC_OUTPUT_DIR/build" \
		"$SYMCC_OUTPUT_DIR/smoke" \
		"$LOG_DIR" \
		"$PID_DIR"
}

tree_ld_library_path() {
	local tree="$1"
	local dirs=()

	mapfile -t dirs < <(find "$tree" -type d -path '*/.libs' | sort)
	[ "${#dirs[@]}" -gt 0 ] || die "未找到 $tree 下的 .libs 目录，请先构建"
	(
		IFS=:
		printf '%s' "${dirs[*]}"
	)
}

afl_target_bin() {
	printf '%s' "$AFL_TREE/.libs/unbound-fuzzme"
}

symcc_target_bin() {
	printf '%s' "$SYMCC_TREE/.libs/unbound-fuzzme"
}

fetch_unbound() {
	require_cmd git
	ensure_dirs

	if [ -d "$SRC_TREE/.git" ]; then
		log "Unbound 源码树已存在: $SRC_TREE"
		return 0
	fi

	log "拉取 Unbound $UNBOUND_TAG"
	(
		cd "$ROOT_DIR"
		git clone --depth 1 --branch "$UNBOUND_TAG" \
			https://github.com/NLnetLabs/unbound.git \
			"$(basename "$SRC_TREE")"
	)
}

copy_tree_if_missing() {
	local src="$1"
	local dst="$2"

	if [ ! -d "$dst" ]; then
		log "创建构建树: $dst"
		cp -a "$src" "$dst"
	fi
}

copy_if_different() {
	local src="$1"
	local dst="$2"

	if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
		return 0
	fi
	cp "$src" "$dst"
}

dedupe_make_rule() {
	local makefile="$1"
	local prefix="$2"
	local tmp

	tmp="$(mktemp "$WORK_DIR/.dedupe_make.XXXXXX")"
	awk -v prefix="$prefix" '
		BEGIN { seen = 0; skip = 0 }
		{
			if (skip > 0) { skip--; next }
			if (index($0, prefix) == 1) {
				seen++
				if (seen > 1) { skip = 1; next }
			}
			print
		}
	' "$makefile" >"$tmp"
	mv "$tmp" "$makefile"
}

ensure_fuzzme_patch() {
	local tree="$1"
	local makefile

	require_cmd rg
	require_cmd sed
	require_cmd grep

	log "注入 legacy-response-tail harness -> $tree"

	if ! grep -q '^/unbound-fuzzme$' "$tree/.gitignore"; then
		sed -i '/^\/unbound-control-setup$/a\/unbound-fuzzme' \
			"$tree/.gitignore"
	fi

	for makefile in "$tree/Makefile.in" "$tree/Makefile"; do
		[ -f "$makefile" ] || continue

		# 历史遗留：清理重复规则，避免 overriding recipe 警告
		dedupe_make_rule "$makefile" 'unbound_afl_symcc_orchestrator.lo:'
		dedupe_make_rule "$makefile" 'unbound_afl_symcc_mutator_server.lo:'
		dedupe_make_rule "$makefile" 'unbound-fuzzme.lo:'
		dedupe_make_rule "$makefile" 'unbound-fuzzme$(EXEEXT):'

		if ! rg -q '^FUZZME_SRC=' "$makefile"; then
			sed -i '/^\$(COMPAT_OBJ) @WIN_DAEMON_OBJ_LINK@$/a\
FUZZME_SRC=smallapp/unbound-fuzzme.c\
UNBOUND_AFL_SYMCC_ORCH_SRC=smallapp/unbound_afl_symcc_orchestrator.c\
UNBOUND_AFL_SYMCC_MUTATOR_SRC=smallapp/unbound_afl_symcc_mutator_server.c\
FUZZME_OBJ=unbound-fuzzme.lo\
UNBOUND_AFL_SYMCC_OBJ=unbound_afl_symcc_orchestrator.lo unbound_afl_symcc_mutator_server.lo\
FUZZME_OBJ_LINK=$(FUZZME_OBJ) $(UNBOUND_AFL_SYMCC_OBJ) worker_cb.lo $(COMMON_OBJ_ALL_SYMBOLS) $(SLDNS_OBJ) \\\
$(COMPAT_OBJ)' "$makefile"
		else
			if ! rg -q '^UNBOUND_AFL_SYMCC_ORCH_SRC=' "$makefile"; then
				sed -i '/^FUZZME_SRC=/a\
UNBOUND_AFL_SYMCC_ORCH_SRC=smallapp/unbound_afl_symcc_orchestrator.c\
UNBOUND_AFL_SYMCC_MUTATOR_SRC=smallapp/unbound_afl_symcc_mutator_server.c' \
					"$makefile"
			fi
			if ! rg -q '^UNBOUND_AFL_SYMCC_OBJ=' "$makefile"; then
				sed -i '/^FUZZME_OBJ=/a\
UNBOUND_AFL_SYMCC_OBJ=unbound_afl_symcc_orchestrator.lo unbound_afl_symcc_mutator_server.lo' \
					"$makefile"
			fi
			sed -i '/^FUZZME_OBJ_LINK=/,+1c\
FUZZME_OBJ_LINK=$(FUZZME_OBJ) $(UNBOUND_AFL_SYMCC_OBJ) worker_cb.lo $(COMMON_OBJ_ALL_SYMBOLS) $(SLDNS_OBJ) \\\
$(COMPAT_OBJ)' "$makefile"
		fi

		sed -i 's|\t$(FUZZME_SRC) \\|\t$(FUZZME_SRC) $(UNBOUND_AFL_SYMCC_ORCH_SRC) $(UNBOUND_AFL_SYMCC_MUTATOR_SRC) \\|' \
			"$makefile"
		sed -i 's|\t$(FUZZME_OBJ) \\|\t$(FUZZME_OBJ) $(UNBOUND_AFL_SYMCC_OBJ) \\|' \
			"$makefile"
		sed -i 's|^alltargets:.*$|alltargets:\tunbound$(EXEEXT) unbound-checkconf$(EXEEXT) lib unbound-host$(EXEEXT) unbound-control$(EXEEXT) unbound-anchor$(EXEEXT) unbound-control-setup unbound-fuzzme$(EXEEXT) $(WINAPPS) $(PYUNBOUND_TARGET)|' \
			"$makefile"

		if ! grep -Fq 'unbound-fuzzme$(EXEEXT):' "$makefile"; then
			sed -i '/^unbound-checkconf$(EXEEXT):/i\
unbound-fuzzme$(EXEEXT):\t$(FUZZME_OBJ_LINK) libunbound.la\
\t$(LINK) -o $@ $(FUZZME_OBJ_LINK) libunbound.la $(EXTRALINK) $(SSLLIB) $(LIBS)\
' "$makefile"
		else
			sed -i '/^unbound-fuzzme$(EXEEXT):/,+1c\
unbound-fuzzme$(EXEEXT):\t$(FUZZME_OBJ_LINK) libunbound.la\
\t$(LINK) -o $@ $(FUZZME_OBJ_LINK) libunbound.la $(EXTRALINK) $(SSLLIB) $(LIBS)\
' "$makefile"
		fi

		sed -i 's|^	rm -f unbound$(EXEEXT) unbound-checkconf$(EXEEXT) unbound-host$(EXEEXT) unbound-control$(EXEEXT) unbound-anchor$(EXEEXT) unbound-control-setup libunbound.la unbound.h$|	rm -f unbound$(EXEEXT) unbound-checkconf$(EXEEXT) unbound-fuzzme$(EXEEXT) unbound-host$(EXEEXT) unbound-control$(EXEEXT) unbound-anchor$(EXEEXT) unbound-control-setup libunbound.la unbound.h|' \
			"$makefile"

		if ! rg -q '^unbound_afl_symcc_orchestrator\.lo:' "$makefile"; then
			sed -i '/^unbound-checkconf\.lo unbound-checkconf\.o:/i\
unbound_afl_symcc_orchestrator.lo: $(srcdir)/smallapp/unbound_afl_symcc_orchestrator.c config.h\
\t$(COMPILE) -o $@ -c $(srcdir)/smallapp/unbound_afl_symcc_orchestrator.c\
unbound_afl_symcc_mutator_server.lo: $(srcdir)/smallapp/unbound_afl_symcc_mutator_server.c config.h\
\t$(COMPILE) -o $@ -c $(srcdir)/smallapp/unbound_afl_symcc_mutator_server.c\
unbound-fuzzme.lo: $(srcdir)/smallapp/unbound-fuzzme.c config.h\
\t$(COMPILE) -o $@ -c $(srcdir)/smallapp/unbound-fuzzme.c\
' "$makefile"
		fi
	done
}

sync_patch_tree() {
	local tree="$1"

	mkdir -p "$tree/libunbound"
	mkdir -p "$tree/smallapp"
	copy_if_different "$PATCH_DIR/libunbound/libworker.c" \
		"$tree/libunbound/libworker.c"
	copy_if_different "$PATCH_DIR/smallapp/unbound-fuzzme.c" \
		"$tree/smallapp/unbound-fuzzme.c"
	copy_if_different "$PATCH_DIR/smallapp/worker_cb.c" \
		"$tree/smallapp/worker_cb.c"
	copy_if_different \
		"$PATCH_DIR/smallapp/unbound_afl_symcc_orchestrator.c" \
		"$tree/smallapp/unbound_afl_symcc_orchestrator.c"
	copy_if_different \
		"$PATCH_DIR/smallapp/unbound_afl_symcc_orchestrator.h" \
		"$tree/smallapp/unbound_afl_symcc_orchestrator.h"
	copy_if_different \
		"$PATCH_DIR/smallapp/unbound_afl_symcc_mutator_server.c" \
		"$tree/smallapp/unbound_afl_symcc_mutator_server.c"
	copy_if_different \
		"$PATCH_DIR/smallapp/unbound_afl_symcc_mutator_server.h" \
		"$tree/smallapp/unbound_afl_symcc_mutator_server.h"
	ensure_fuzzme_patch "$tree"
}

sync_patch() {
	require_file "$PATCH_DIR/smallapp/unbound-fuzzme.c"
	require_file "$PATCH_DIR/smallapp/unbound_afl_symcc_orchestrator.c"
	require_file "$PATCH_DIR/smallapp/unbound_afl_symcc_orchestrator.h"
	require_file "$PATCH_DIR/smallapp/unbound_afl_symcc_mutator_server.c"
	require_file "$PATCH_DIR/smallapp/unbound_afl_symcc_mutator_server.h"
	require_file "$PATCH_DIR/libunbound/libworker.c"

	require_file "$SRC_TREE/configure"
	sync_patch_tree "$SRC_TREE"
	copy_tree_if_missing "$SRC_TREE" "$AFL_TREE"
	copy_tree_if_missing "$SRC_TREE" "$SYMCC_TREE"
	sync_patch_tree "$AFL_TREE"
	sync_patch_tree "$SYMCC_TREE"
}

configure_unbound_tree() {
	local tree="$1"
	local cc_bin="$2"
	local cxx_bin="${3:-}"

	require_cmd make
	require_cmd sed

	if [ ! -f "$tree/config.status" ]; then
		log "配置 $(basename "$tree")"
		(
			cd "$tree"
			make distclean >/dev/null 2>&1 || true
			if [ -n "$cxx_bin" ]; then
				SYMCC_NO_SYMBOLIC_INPUT=1 \
				SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
				CC="$cc_bin" \
				CXX="$cxx_bin" \
				./configure --with-libevent=no --without-pythonmodule
			else
				CC="$cc_bin" ./configure --with-libevent=no \
					--without-pythonmodule
			fi
		)
	fi

	if [ -f "$tree/Makefile" ]; then
		sed -i 's/[[:space:]]-flto[[:space:]]/ /g; s/[[:space:]]-flto$//' \
			"$tree/Makefile"
	fi
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
		log "构建 query parser"
		"$SYMCC_CC_BIN" "$QUERY_PARSER_SRC" -O2 -o "$QUERY_PARSER_BIN"
	fi

	if [ ! -x "$RESPONSE_PARSER_BIN" ]; then
		log "构建 response parser"
		"$SYMCC_CC_BIN" "$RESPONSE_PARSER_SRC" -O2 -o \
			"$RESPONSE_PARSER_BIN"
	fi
}

build_afl_unbound() {
	require_file "$AFL_CC_BIN"
	copy_tree_if_missing "$SRC_TREE" "$AFL_TREE"
	sync_patch_tree "$AFL_TREE"
	configure_unbound_tree "$AFL_TREE" "$AFL_CC_BIN"

	log "编译 AFL unbound-fuzzme"
	(
		cd "$AFL_TREE"
		make -j"$JOBS" unbound-fuzzme
	)
	require_file "$(afl_target_bin)"
}

build_symcc_unbound() {
	require_file "$SYMCC_CC_BIN"
	require_file "$SYMCC_CXX_BIN"
	copy_tree_if_missing "$SRC_TREE" "$SYMCC_TREE"
	sync_patch_tree "$SYMCC_TREE"
	configure_unbound_tree "$SYMCC_TREE" "$SYMCC_CC_BIN" "$SYMCC_CXX_BIN"

	log "编译 SymCC unbound-fuzzme"
	(
		cd "$SYMCC_TREE"
		SYMCC_NO_SYMBOLIC_INPUT=1 \
		SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
		make -j"$JOBS" unbound-fuzzme
	)
	require_file "$(symcc_target_bin)"
}

build_all() {
	ensure_dirs
	sync_patch
	build_helper_and_gen_input
	build_seed_parsers
	build_afl_unbound
	build_symcc_unbound
}

generate_seeds() {
	build_helper_and_gen_input
	build_seed_parsers

	if [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$QUERY_CORPUS_DIR" ] || \
		[ -z "$(find "$QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		rm -rf "$QUERY_CORPUS_DIR"
		mkdir -p "$QUERY_CORPUS_DIR"
		log "生成 query 语料"
		"$GEN_INPUT_BIN" \
			-f dns \
			-i "$QUERY_MAX_ITER" \
			-o "$QUERY_CORPUS_DIR" \
			"$QUERY_PARSER_BIN" \
			>"$QUERY_GEN_LOG" 2>&1
	fi

	if [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$RESPONSE_CORPUS_DIR" ] || \
		[ -z "$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		rm -rf "$RESPONSE_CORPUS_DIR"
		mkdir -p "$RESPONSE_CORPUS_DIR"
		log "生成 response-tail 语料"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns-poison-response \
			--hybrid \
			-i "$RESPONSE_MAX_ITER" \
			--seed-dir "$QUERY_CORPUS_DIR" \
			--seed-dir-limit "$RESPONSE_QUERY_SEEDS" \
			-o "$RESPONSE_CORPUS_DIR" \
			"$RESPONSE_PARSER_BIN" \
			>"$RESPONSE_GEN_LOG" 2>&1
	fi
}

sample_is_stable() {
	local sample="$1"
	local stderr_file

	stderr_file="$(mktemp "$LOG_DIR/filter.XXXXXX.stderr")"
	if env \
		LD_LIBRARY_PATH="$(tree_ld_library_path "$AFL_TREE")" \
		UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
		timeout -k 2 "$SEED_TIMEOUT_SEC" \
		"$(afl_target_bin)" \
		<"$sample" \
		>/dev/null 2>"$stderr_file"
	then
		if grep -q 'Oracle parse_ok: 1' "$stderr_file" && \
			grep -q 'Oracle resolver_fetch_started: 1' "$stderr_file" && \
			grep -q 'Oracle response_accepted: 1' "$stderr_file"
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
	local next_id=0
	local seed_count=0
	local sample

	if [ "$REFILTER_QUERIES" -ne 1 ] && \
		[ -d "$STABLE_QUERY_CORPUS_DIR" ] && \
		[ -n "$(find "$STABLE_QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | head -n 1)" ]
	then
		log "稳定 query 语料已存在，跳过筛选（REFILTER_QUERIES=0）"
		return 0
	fi

	build_afl_unbound
	generate_seeds
	tmp_dir="$(mktemp -d "$WORK_DIR/.stable_query_tmp.XXXXXX")"

	log "筛选稳定 query 语料"
	for sample in "$QUERY_CORPUS_DIR"/*; do
		[ -f "$sample" ] || continue
		if sample_is_stable "$sample"; then
			cp "$sample" "$tmp_dir/$(printf 'id_%06d_%s' "$next_id" \
				"$(basename "$sample")")"
			next_id=$((next_id + 1))
			seed_count=$((seed_count + 1))
		fi
	done

	if [ "$seed_count" -eq 0 ]; then
		rm -rf "$tmp_dir"
		die "没有筛出稳定 query 语料，请检查 response-tail 语料或 harness"
	fi

	rm -rf "$STABLE_QUERY_CORPUS_DIR"
	mv "$tmp_dir" "$STABLE_QUERY_CORPUS_DIR"
	log "稳定 query 语料: $seed_count"
}

pick_sample() {
	local source_dir="$1"
	local listing

	listing="$(mktemp "$WORK_DIR/pick-sample.XXXXXX")"
	find "$source_dir" -maxdepth 1 -type f | LC_ALL=C sort >"$listing"
	sed -n '1p' "$listing"
	rm -f "$listing"
}

run_smoke_once() {
	local name="$1"
	local bin="$2"
	local sample="$3"
	local ld_path=""
	local rc=0

	log "smoke: $name <- $(basename "$sample")"
	if [ "$name" = "afl" ]; then
		ld_path="$(tree_ld_library_path "$AFL_TREE")"
	else
		ld_path="$(tree_ld_library_path "$SYMCC_TREE")"
	fi
	if ! env \
		LD_LIBRARY_PATH="$ld_path" \
		SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/smoke" \
		UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
		timeout -k 1 "$SMOKE_TIMEOUT_SEC" "$bin" \
		<"$sample" \
		>/dev/null 2>"$WORK_DIR/${name}.stderr"
	then
		rc=$?
	fi

	case "$rc" in
	0|1)
		printf '  %-12s ok (rc=%s)\n' "$name" "$rc"
		;;
	124|137)
		die "$name smoke 超时: rc=$rc"
		;;
	*)
		die "$name smoke 异常退出: rc=$rc"
		;;
	esac
}

smoke_all() {
	local sample
	local sample_dir="$STABLE_QUERY_CORPUS_DIR"

	if [ ! -d "$sample_dir" ] || \
		[ -z "$(find "$sample_dir" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		sample_dir="$QUERY_CORPUS_DIR"
	fi
	require_file "$(afl_target_bin)"
	require_file "$(symcc_target_bin)"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "缺少 response 语料，请先执行 gen-seeds"
	sample="$(pick_sample "$sample_dir")"
	[ -n "$sample" ] || die "query 语料为空，请先执行 gen-seeds 或 filter-seeds"

	run_smoke_once "afl" "$(afl_target_bin)" "$sample"
	run_smoke_once "symcc" "$(symcc_target_bin)" "$sample"
}

cleanup_output() {
	if [ "$RESET_OUTPUT" -eq 1 ]; then
		rm -rf "$AFL_OUT_DIR"
		rm -f "$MASTER_LOG" "$HELPER_LOG"
	fi
}

launch_in_background() {
	local log_file="$1"
	local pid_file="$2"
	shift 2

	"$@" >"$log_file" 2>&1 &
	echo "$!" >"$pid_file"
}

wait_for_master_queue() {
	local waited=0

	while [ ! -f "$AFL_OUT_DIR/master/fuzzer_stats" ]; do
		sleep 1
		waited=$((waited + 1))
		if [ "$waited" -ge 30 ]; then
			die "等待 AFL master 启动超时"
		fi
	done
}

stop_pid_file() {
	local pid_file="$1"

	if [ ! -f "$pid_file" ]; then
		return 0
	fi

	if kill -0 "$(cat "$pid_file")" >/dev/null 2>&1; then
		kill "$(cat "$pid_file")" >/dev/null 2>&1 || true
		wait "$(cat "$pid_file")" 2>/dev/null || true
	fi
	rm -f "$pid_file"
}

start_all() {
	local input_dir="$STABLE_QUERY_CORPUS_DIR"
	local ld_path_afl
	local ld_path_symcc
	local ld_path_helper

	prepare_all
	stop_all
	cleanup_output

	if [ ! -d "$input_dir" ] || \
		[ -z "$(find "$input_dir" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		input_dir="$QUERY_CORPUS_DIR"
	fi

	log "启动 AFL master"
	ld_path_afl="$(tree_ld_library_path "$AFL_TREE")"
	launch_in_background \
		"$MASTER_LOG" \
		"$MASTER_PID" \
		env \
		AFL_NO_UI=1 \
		AFL_NO_AFFINITY=1 \
		AFL_SKIP_CPUFREQ=1 \
		AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
		LD_LIBRARY_PATH="$ld_path_afl" \
		UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		"$AFL_FUZZ_BIN" \
		-M master \
		-i "$input_dir" \
		-o "$AFL_OUT_DIR" \
		-m none \
		-t "$AFL_TIMEOUT_MS" \
		-- \
		"$(afl_target_bin)"

	if [ "$ENABLE_HELPER" -eq 1 ]; then
		wait_for_master_queue
		log "启动 SymCC helper"
		ld_path_symcc="$(tree_ld_library_path "$SYMCC_TREE")"
		ld_path_helper="$ld_path_symcc:$ld_path_afl"
		launch_in_background \
			"$HELPER_LOG" \
			"$HELPER_PID" \
			env \
			LD_LIBRARY_PATH="$ld_path_helper" \
			UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
			"$HELPER_BIN" \
			-o "$HELPER_RUN_ROOT" \
			-n "$HELPER_RUN_NAME" \
			-a master \
			-v \
			-r "$RESPONSE_CORPUS_DIR" \
			-e UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL \
			-t "$(afl_target_bin)" \
			-- \
			"$(symcc_target_bin)"
	fi

	log "实验已启动"
	status_all
}

run_for_duration() {
	local duration="${1:-$RUN_DURATION_SEC}"

	start_all
	log "实验运行 ${duration}s"
	sleep "$duration"
	status_all
	stop_all
}

stop_all() {
	stop_pid_file "$HELPER_PID"
	stop_pid_file "$MASTER_PID"
}

status_all() {
	printf 'Unbound 源码:\n'
	printf '  src     %s\n' "$SRC_TREE"
	printf '  afl     %s\n' "$AFL_TREE"
	printf '  symcc   %s\n' "$SYMCC_TREE"

	printf '\n构建产物:\n'
	if [ -x "$(afl_target_bin)" ]; then
		printf '  %-16s %s\n' "afl-target" "$(afl_target_bin)"
	else
		printf '  %-16s %s\n' "afl-target" "missing"
	fi
	if [ -x "$(symcc_target_bin)" ]; then
		printf '  %-16s %s\n' "symcc-target" "$(symcc_target_bin)"
	else
		printf '  %-16s %s\n' "symcc-target" "missing"
	fi
	if [ -x "$QUERY_PARSER_BIN" ]; then
		printf '  %-16s %s\n' "query-parser" "$QUERY_PARSER_BIN"
	else
		printf '  %-16s %s\n' "query-parser" "missing"
	fi
	if [ -x "$RESPONSE_PARSER_BIN" ]; then
		printf '  %-16s %s\n' "response-parser" "$RESPONSE_PARSER_BIN"
	else
		printf '  %-16s %s\n' "response-parser" "missing"
	fi

	printf '\n语料状态:\n'
	printf '  %-16s %s\n' "query-corpus" \
		"$(find "$QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "response-corpus" \
		"$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "stable-query" \
		"$(find "$STABLE_QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"

	printf '\n运行状态:\n'
	if [ -f "$MASTER_PID" ] && kill -0 "$(cat "$MASTER_PID")" >/dev/null 2>&1; then
		printf '  %-16s running (%s)\n' "afl-master" "$(cat "$MASTER_PID")"
	else
		printf '  %-16s stopped\n' "afl-master"
	fi
	if [ -f "$HELPER_PID" ] && kill -0 "$(cat "$HELPER_PID")" >/dev/null 2>&1; then
		printf '  %-16s running (%s)\n' "symcc-helper" "$(cat "$HELPER_PID")"
	else
		printf '  %-16s stopped\n' "symcc-helper"
	fi

	if [ -f "$AFL_OUT_DIR/master/fuzzer_stats" ]; then
		printf '\nAFL 统计:\n'
		awk -F: '
			/execs_done|execs_per_sec|corpus_count|corpus_found|saved_crashes|saved_hangs|bitmap_cvg/ {
				gsub(/^ +/, "", $2);
				printf("  %-16s %s\n", $1, $2);
			}
		' "$AFL_OUT_DIR/master/fuzzer_stats"
	fi
}

prepare_all() {
	build_all
	generate_seeds
	filter_seeds
	smoke_all
}

main() {
	local cmd="${1:-}"
	local arg="${2:-}"

	case "$cmd" in
	fetch)
		fetch_unbound
		;;
	build)
		build_all
		;;
	gen-seeds)
		generate_seeds
		;;
	filter-seeds)
		filter_seeds
		;;
	smoke)
		smoke_all
		;;
	prepare)
		prepare_all
		;;
	start)
		start_all
		;;
	run)
		run_for_duration "$arg"
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
require_cmd awk
require_file "$SRC_TREE"
ensure_dirs
main "${1:-}" "${2:-}"
