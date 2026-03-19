#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_DIR="$ROOT_DIR/unbound_experiment"
PROFILE_DIR="$EXP_DIR/profiles"
PATCH_DIR="$ROOT_DIR/patch/unbound"
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

# --- BIND9 差分测试路径 ---
BIND9_AFL_TREE="${BIND9_AFL_TREE:-$ROOT_DIR/bind-9.18.46-afl}"
BIND9_NAMED_EXP="$ROOT_DIR/named_experiment"
BIND9_NAMED_CONF_TEMPLATE="$BIND9_NAMED_EXP/runtime/named.conf"
BIND9_RUNTIME_DIR="$WORK_DIR/bind9_runtime"
BIND9_NAMED_CONF="$BIND9_RUNTIME_DIR/named.conf"
BIND9_TARGET_ADDR="${BIND9_TARGET_ADDR:-127.0.0.1:55301}"
BIND9_MUTATOR_ADDR="${BIND9_MUTATOR_ADDR:-127.0.0.1:55300}"
BIND9_WORK_DIR="${BIND9_WORK_DIR:-$ROOT_DIR/named_experiment/work}"
DIFF_RESULT_DIR="$WORK_DIR/diff_results"
CACHE_DUMP_DIR="$WORK_DIR/cache_dumps"

BIN_DIR="$WORK_DIR/bin"
QUERY_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_parser.c"
RESPONSE_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_response_parser.c"
QUERY_PARSER_BIN="$BIN_DIR/dns_parser_sym"
RESPONSE_PARSER_BIN="$BIN_DIR/dns_response_parser_sym"
QUERY_CORPUS_DIR="$WORK_DIR/query_corpus"
RESPONSE_CORPUS_DIR="$WORK_DIR/response_corpus"
TRANSCRIPT_CORPUS_DIR="$WORK_DIR/transcript_corpus"
TRANSCRIPT_SEED_MIX_DIR="$WORK_DIR/transcript_seed_mix"
STABLE_QUERY_CORPUS_DIR="$WORK_DIR/stable_query_corpus"
STABLE_TRANSCRIPT_CORPUS_DIR="$WORK_DIR/stable_transcript_corpus"
SYMCC_OUTPUT_DIR="$WORK_DIR/symcc_output"
LOG_DIR="$WORK_DIR/logs"
PID_DIR="$WORK_DIR/pids"
AFL_OUT_DIR="$WORK_DIR/afl_out"
QUERY_GEN_LOG="$WORK_DIR/query_gen.log"
RESPONSE_GEN_LOG="$WORK_DIR/response_gen.log"
TRANSCRIPT_GEN_LOG="$WORK_DIR/transcript_gen.log"

MASTER_LOG="$LOG_DIR/afl_master.log"
HELPER_LOG="$LOG_DIR/helper.log"
MASTER_PID="$PID_DIR/afl_master.pid"
HELPER_PID="$PID_DIR/helper.pid"

JOBS="${JOBS:-2}"
FUZZ_PROFILE="${FUZZ_PROFILE:-legacy-response-tail}"
QUERY_MAX_ITER="${QUERY_MAX_ITER:-128}"
RESPONSE_MAX_ITER="${RESPONSE_MAX_ITER:-64}"
RESPONSE_QUERY_SEEDS="${RESPONSE_QUERY_SEEDS:-8}"
TRANSCRIPT_MAX_ITER="${TRANSCRIPT_MAX_ITER:-256}"
TRANSCRIPT_RESPONSE_SEEDS="${TRANSCRIPT_RESPONSE_SEEDS:-24}"
SEED_TIMEOUT_SEC="${SEED_TIMEOUT_SEC:-5}"
SMOKE_TIMEOUT_SEC="${SMOKE_TIMEOUT_SEC:-5}"
SYMCC_SMOKE_TIMEOUT_SEC="${SYMCC_SMOKE_TIMEOUT_SEC:-120}"
# libunbound 初始化与本地 mutator server 启动有固定开销，1000ms 容易被 AFL 误判超时
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-3000+}"
AFL_START_TIMEOUT_SEC="${AFL_START_TIMEOUT_SEC:-300}"
RUN_DURATION_SEC="${RUN_DURATION_SEC:-180}"
REGEN_SEEDS="${REGEN_SEEDS:-0}"
REFILTER_QUERIES="${REFILTER_QUERIES:-0}"
RESET_OUTPUT="${RESET_OUTPUT:-1}"
ENABLE_HELPER="${ENABLE_HELPER:-1}"
EXPLORE_ITER="${EXPLORE_ITER:-256}"
EXPLORE_PRESERVE="${EXPLORE_PRESERVE:-20}"
UNBOUND_TAG="${UNBOUND_TAG:-release-1.24.2}"
HELPER_RUN_ROOT="${HELPER_RUN_ROOT:-$WORK_DIR}"
HELPER_RUN_NAME="${HELPER_RUN_NAME:-$(basename "$AFL_OUT_DIR")}"
TRANSCRIPT_GEN_TARGET="${TRANSCRIPT_GEN_TARGET:-/bin/true}"

usage() {
	printf '%s\n' \
		'用法:' \
		'  unbound_experiment/run_unbound_afl_symcc.sh <命令>' \
		'' \
		'命令:' \
		'  fetch              拉取 Unbound release-1.24.2 源码树' \
		'  build              同步 patch/unbound，并构建 helper、AFL 与 SymCC 目标' \
		'  gen-seeds          生成 query/response 语料' \
		'  explore-response   用 gen_input 探索 response 包 20 字节后内容（尾部探索）' \
			'  filter-seeds       筛选 legacy-response-tail 稳定 query 语料' \
			'  smoke              对 AFL / SymCC 目标执行最小 smoke' \
			'  dump-cache <样本> [输出文件] 以干净实例回放单个样本并导出 Unbound cache dump' \
			'  parse-cache <resolver> <dump文件> [输出文件] 解析 cache dump 为统一 TSV' \
			'  replay-diff-cache <样本> [输出目录] 导出前后 cache dump 并做统一对比' \
			'  prepare            执行 build + gen-seeds + explore-response + filter-seeds + smoke' \
			'  diff-test          差分测试：同一套种子分别喂 BIND9 与 Unbound，比较 oracle 差异' \
			'  start              启动 AFL master 与 SymCC helper' \
		'  run [秒数]         启动实验并持续运行指定秒数，结束后自动输出状态并停止' \
		'  stop               停止当前实验进程' \
		'  status             查看当前实验状态与关键统计' \
		'' \
		'默认约定:' \
		'  1. FUZZ_PROFILE 支持 legacy-response-tail 与 poison-stateful，默认 legacy-response-tail。' \
		'  2. poison-stateful 会额外生成 transcript_corpus / stable_transcript_corpus，并优先用于 smoke、diff-test 和 AFL 输入。' \
		'' \
		'差分测试说明:' \
		'  diff-test 使用同一套输入（legacy query 或 stateful transcript），分别喂给 BIND9 named 和' \
		'  Unbound unbound-fuzzme，比较两者的 oracle 输出差异。差异样本即为潜在的' \
		'  缓存投毒漏洞候选。需要 BIND9 已构建（named_experiment/run_named_afl_symcc.sh build）。'
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
		"$TRANSCRIPT_CORPUS_DIR" \
		"$TRANSCRIPT_SEED_MIX_DIR" \
		"$STABLE_QUERY_CORPUS_DIR" \
		"$STABLE_TRANSCRIPT_CORPUS_DIR" \
		"$SYMCC_OUTPUT_DIR" \
		"$SYMCC_OUTPUT_DIR/build" \
			"$SYMCC_OUTPUT_DIR/smoke" \
			"$LOG_DIR" \
			"$PID_DIR" \
			"$DIFF_RESULT_DIR" \
			"$CACHE_DUMP_DIR" \
			"$BIND9_RUNTIME_DIR"
}

load_profile() {
	local profile_file

	profile_file="$PROFILE_DIR/${FUZZ_PROFILE}.env"
	if [ -f "$profile_file" ]; then
		log "加载 profile: $profile_file"
		# shellcheck disable=SC1090
		. "$profile_file"
	fi

	case "$FUZZ_PROFILE" in
	legacy-response-tail|poison-stateful)
		;;
	*)
		die "未知 FUZZ_PROFILE: $FUZZ_PROFILE"
		;;
	esac
}

require_profile_cmds() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		require_cmd dd
		require_cmd od
	fi
}

force_dns_query_rd_bit() {
	local path="$1"
	local byte_value
	local new_byte_value
	local octal_byte

	byte_value="$(od -An -j2 -N1 -tu1 "$path" 2>/dev/null | tr -d '[:space:]')"
	if [ -z "$byte_value" ]; then
		return 0
	fi

	new_byte_value=$((byte_value | 1))
	printf -v octal_byte '%03o' "$new_byte_value"
	printf "\\$octal_byte" | dd of="$path" bs=1 seek=2 count=1 conv=notrunc \
		status=none 2>/dev/null
}

sample_source_dir() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		printf '%s' "$TRANSCRIPT_CORPUS_DIR"
	else
		printf '%s' "$QUERY_CORPUS_DIR"
	fi
}

active_input_corpus_dir() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		printf '%s' "$STABLE_TRANSCRIPT_CORPUS_DIR"
	else
		printf '%s' "$STABLE_QUERY_CORPUS_DIR"
	fi
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
FUZZME_OBJ_LINK=$(FUZZME_OBJ) $(UNBOUND_AFL_SYMCC_OBJ) worker_cb.lo cachedump.lo $(COMMON_OBJ_ALL_SYMBOLS) $(SLDNS_OBJ) \\\
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
FUZZME_OBJ_LINK=$(FUZZME_OBJ) $(UNBOUND_AFL_SYMCC_OBJ) worker_cb.lo cachedump.lo $(COMMON_OBJ_ALL_SYMBOLS) $(SLDNS_OBJ) \\\
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

prepare_transcript_seed_mix() {
	local seed_index
	local sample
	local query_seed_dir="$STABLE_QUERY_CORPUS_DIR"

	if [ ! -d "$query_seed_dir" ] || \
		[ -z "$(find "$query_seed_dir" -maxdepth 1 -type f 2>/dev/null | head -n 1)" ]
	then
		query_seed_dir="$QUERY_CORPUS_DIR"
	fi

	rm -rf "$TRANSCRIPT_SEED_MIX_DIR"
	mkdir -p "$TRANSCRIPT_SEED_MIX_DIR"

	seed_index=0
	for sample in "$query_seed_dir"/*; do
		local dst
		[ -f "$sample" ] || continue
		dst="$TRANSCRIPT_SEED_MIX_DIR/query_$(printf '%04d' "$seed_index")_$(basename "$sample")"
		cp "$sample" "$dst"
		# poison-stateful 需要递归查询语义；这里在组装 transcript 时强制置 RD=1，
		# 避免把 parser-lite 里接受的非递归 query 带进缓存投毒主线。
		force_dns_query_rd_bit "$dst"
		seed_index=$((seed_index + 1))
	done

	seed_index=0
	while IFS= read -r sample; do
		[ -f "$sample" ] || continue
		cp "$sample" \
			"$TRANSCRIPT_SEED_MIX_DIR/response_$(printf '%04d' "$seed_index")_$(basename "$sample")"
		seed_index=$((seed_index + 1))
	done <<EOF
$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f | LC_ALL=C sort | head -n "$TRANSCRIPT_RESPONSE_SEEDS")
EOF
}

generate_seeds() {
	require_profile_cmds
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

	if [ "$FUZZ_PROFILE" = "poison-stateful" ] && \
		{ [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$TRANSCRIPT_CORPUS_DIR" ] || \
			[ -z "$(find "$TRANSCRIPT_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]; }
	then
		require_file "$TRANSCRIPT_GEN_TARGET"
		rm -rf "$TRANSCRIPT_CORPUS_DIR"
		mkdir -p "$TRANSCRIPT_CORPUS_DIR"
		prepare_transcript_seed_mix
		log "生成 stateful transcript 语料"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns-stateful-transcript \
			--seed-dir "$TRANSCRIPT_SEED_MIX_DIR" \
			-i "$TRANSCRIPT_MAX_ITER" \
			-o "$TRANSCRIPT_CORPUS_DIR" \
			"$TRANSCRIPT_GEN_TARGET" \
			>"$TRANSCRIPT_GEN_LOG" 2>&1
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

sample_is_stateful_stable() {
	local sample="$1"
	local stderr_file

	stderr_file="$(mktemp "$LOG_DIR/filter.stateful.XXXXXX.stderr")"
	if env \
		LD_LIBRARY_PATH="$(tree_ld_library_path "$AFL_TREE")" \
		UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
		timeout -k 2 "$SEED_TIMEOUT_SEC" \
		"$(afl_target_bin)" \
		<"$sample" \
		>/dev/null 2>"$stderr_file"
	then
		if grep -q 'Oracle parse_ok: 1' "$stderr_file" && \
			grep -q 'Oracle resolver_fetch_started: 1' "$stderr_file" && \
			grep -q 'Oracle response_accepted: 1' "$stderr_file" && \
			grep -q 'Oracle second_query_hit: 1' "$stderr_file"
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
	local source_dir
	local target_dir

	source_dir="$(sample_source_dir)"
	target_dir="$(active_input_corpus_dir)"

	if [ "$REFILTER_QUERIES" -ne 1 ] && \
		[ -d "$target_dir" ] && \
		[ -n "$(find "$target_dir" -maxdepth 1 -type f 2>/dev/null | head -n 1)" ]
	then
		log "稳定输入语料已存在，跳过筛选（REFILTER_QUERIES=0）"
		return 0
	fi

	build_afl_unbound
	generate_seeds
	tmp_dir="$(mktemp -d "$WORK_DIR/.stable_query_tmp.XXXXXX")"

	log "筛选稳定输入语料"
	for sample in "$source_dir"/*; do
		[ -f "$sample" ] || continue
		if { [ "$FUZZ_PROFILE" = "poison-stateful" ] && sample_is_stateful_stable "$sample"; } || \
			{ [ "$FUZZ_PROFILE" != "poison-stateful" ] && sample_is_stable "$sample"; }
		then
			cp "$sample" "$tmp_dir/$(printf 'id_%06d_%s' "$next_id" \
				"$(basename "$sample")")"
			next_id=$((next_id + 1))
			seed_count=$((seed_count + 1))
		fi
	done

	if [ "$seed_count" -eq 0 ]; then
		rm -rf "$tmp_dir"
		die "没有筛出稳定输入语料，请检查 response 语料、transcript 语料或 harness"
	fi

	rm -rf "$target_dir"
	mv "$tmp_dir" "$target_dir"
	log "稳定输入语料: $seed_count"
}

# ---------------------------------------------------------------------------
# explore_response: 后台持续运行，从 AFL queue 提取新 query，
#   用 gen_input 探索 response 包 20 字节后的内容，结果回灌 response_corpus。
#   在 start_all 中作为后台进程启动，与 AFL + SymCC helper 协同工作。
# ---------------------------------------------------------------------------
EXPLORE_PID="$PID_DIR/explore.pid"
EXPLORE_LOG="$LOG_DIR/explore.log"
EXPLORE_INTERVAL="${EXPLORE_INTERVAL:-60}"

explore_response_loop() {
	local afl_queue_dir="$AFL_OUT_DIR/master/queue"
	local explore_dir="$WORK_DIR/explore_response"
	local seen_file="$WORK_DIR/.explore_seen"
	local round=0

	mkdir -p "$explore_dir"
	touch "$seen_file"

	log "explore-response 后台循环启动（间隔 ${EXPLORE_INTERVAL}s）"

	while true; do
		# 等待 AFL queue 出现
		if [ ! -d "$afl_queue_dir" ]; then
			sleep 5
			continue
		fi

		# 收集 AFL queue 中的新 query 样本（排除已处理的）
		local new_seeds_dir
		new_seeds_dir="$(mktemp -d "$WORK_DIR/.explore_new.XXXXXX")"
		local new_count=0
		for f in "$afl_queue_dir"/id:*; do
			[ -f "$f" ] || continue
			local fname
			fname="$(basename "$f")"
			if ! grep -qxF "$fname" "$seen_file" 2>/dev/null; then
				cp "$f" "$new_seeds_dir/$fname"
				echo "$fname" >>"$seen_file"
				new_count=$((new_count + 1))
			fi
		done

		if [ "$new_count" -gt 0 ]; then
			round=$((round + 1))
			log "explore round $round: $new_count 个新 query，开始尾部探索"

			rm -rf "$explore_dir"
			mkdir -p "$explore_dir"

			"$GEN_INPUT_BIN" \
				-v \
				-f dns-poison-response \
				--hybrid \
				--preserve "$EXPLORE_PRESERVE" \
				-i "$EXPLORE_ITER" \
				--seed-dir "$new_seeds_dir" \
				--seed-dir-limit "$RESPONSE_QUERY_SEEDS" \
				-o "$explore_dir" \
				"$RESPONSE_PARSER_BIN" \
				>>"$EXPLORE_LOG" 2>&1 || true

			# 合并到 response_corpus
			local merged=0
			for f in "$explore_dir"/*; do
				[ -f "$f" ] || continue
				local dst="$RESPONSE_CORPUS_DIR/explore_r${round}_$(basename "$f")"
				if [ ! -f "$dst" ] || ! cmp -s "$f" "$dst"; then
					cp "$f" "$dst"
					merged=$((merged + 1))
				fi
			done
			log "explore round $round: 新增 $merged 个 response 样本"
		fi

		rm -rf "$new_seeds_dir"
		sleep "$EXPLORE_INTERVAL"
	done
}

# 单次探索（手动调用 explore-response 命令时使用）
explore_response_once() {
	local source_dir="$STABLE_QUERY_CORPUS_DIR"
	local explore_dir="$WORK_DIR/explore_response"
	local merged_count=0

	build_helper_and_gen_input
	build_seed_parsers

	if [ ! -d "$source_dir" ] || \
		[ -z "$(find "$source_dir" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		source_dir="$QUERY_CORPUS_DIR"
	fi
	[ -d "$source_dir" ] || die "缺少 query 语料，请先执行 gen-seeds"

	rm -rf "$explore_dir"
	mkdir -p "$explore_dir"

	log "探索 response 尾部（20 字节后），迭代 $EXPLORE_ITER 次"
	"$GEN_INPUT_BIN" \
		-v \
		-f dns-poison-response \
		--hybrid \
		--preserve "$EXPLORE_PRESERVE" \
		-i "$EXPLORE_ITER" \
		--seed-dir "$source_dir" \
		--seed-dir-limit "$RESPONSE_QUERY_SEEDS" \
		-o "$explore_dir" \
		"$RESPONSE_PARSER_BIN" \
		>"$WORK_DIR/explore_response.log" 2>&1

	for f in "$explore_dir"/*; do
		[ -f "$f" ] || continue
		local dst="$RESPONSE_CORPUS_DIR/explore_$(basename "$f")"
		if [ ! -f "$dst" ] || ! cmp -s "$f" "$dst"; then
			cp "$f" "$dst"
			merged_count=$((merged_count + 1))
		fi
	done

	log "尾部探索完成，新增 $merged_count 个 response 样本到 response_corpus"
}

# ---------------------------------------------------------------------------
# 差分测试：同一套种子分别喂 BIND9 named 和 Unbound unbound-fuzzme
# ---------------------------------------------------------------------------
prepare_bind9_conf() {
	require_file "$BIND9_NAMED_CONF_TEMPLATE"
	local runtime_escaped
	runtime_escaped="$(printf '%s' "$BIND9_RUNTIME_DIR" | sed 's/[&|]/\\&/g')"
	sed "s|__RUNTIME_STATE_DIR__|$runtime_escaped|g" \
		"$BIND9_NAMED_CONF_TEMPLATE" >"$BIND9_NAMED_CONF"
}

bind9_ld_library_path() {
	local dirs=()
	mapfile -t dirs < <(find "$BIND9_AFL_TREE" -type d -path '*/.libs' | sort)
	[ "${#dirs[@]}" -gt 0 ] || die "未找到 $BIND9_AFL_TREE 下的 .libs 目录"
	(
		IFS=:
		printf '%s' "${dirs[*]}"
	)
}

extract_oracle() {
	local stderr_file="$1"
	local -a keys=(
		parse_ok
		resolver_fetch_started
		response_accepted
		second_query_hit
		cache_entry_created
		timeout
	)
	local key
	for key in "${keys[@]}"; do
		local val
		val="$(grep -oP "Oracle ${key}: \K[0-9]+" "$stderr_file" 2>/dev/null || echo "0")"
		printf '%s=%s ' "$key" "$val"
	done
	printf '\n'
}

oracle_value() {
	local oracle="$1"
	local key="$2"
	local token

	for token in $oracle; do
		case "$token" in
		"$key="*)
			printf '%s' "${token#*=}"
			return 0
			;;
		esac
	done

	printf '0'
}

classify_oracle_diff() {
	local ub_oracle="$1"
	local bind9_oracle="$2"

	if [ "$ub_oracle" = "$bind9_oracle" ]; then
		printf '%s' "same"
		return 0
	fi

	if [ "$(oracle_value "$ub_oracle" timeout)" != \
		"$(oracle_value "$bind9_oracle" timeout)" ]; then
		printf '%s' "timeout_diff"
		return 0
	fi

	if [ "$(oracle_value "$ub_oracle" resolver_fetch_started)" != \
		"$(oracle_value "$bind9_oracle" resolver_fetch_started)" ]; then
		printf '%s' "fetch_diff"
		return 0
	fi

	if [ "$(oracle_value "$ub_oracle" response_accepted)" != \
		"$(oracle_value "$bind9_oracle" response_accepted)" ]; then
		printf '%s' "response_accept_diff"
		return 0
	fi

	if [ "$(oracle_value "$ub_oracle" second_query_hit)" != \
		"$(oracle_value "$bind9_oracle" second_query_hit)" ] || \
		[ "$(oracle_value "$ub_oracle" cache_entry_created)" != \
			"$(oracle_value "$bind9_oracle" cache_entry_created)" ]; then
		printf '%s' "cache_behavior_diff"
		return 0
	fi

	if [ "$(oracle_value "$ub_oracle" parse_ok)" != \
		"$(oracle_value "$bind9_oracle" parse_ok)" ]; then
		printf '%s' "parse_diff"
		return 0
	fi

	printf '%s' "oracle_diff"
}

diff_source_dir() {
	local stable_dir
	local source_dir

	stable_dir="$(active_input_corpus_dir)"
	source_dir="$(sample_source_dir)"
	if [ -d "$stable_dir" ] && \
		[ -n "$(find "$stable_dir" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		printf '%s' "$stable_dir"
		return 0
	fi

	printf '%s' "$source_dir"
}

run_unbound_sample() {
	local sample="$1"
	local stderr_file="$2"
	env \
		LD_LIBRARY_PATH="$(tree_ld_library_path "$AFL_TREE")" \
		UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
		timeout -k 2 "$SEED_TIMEOUT_SEC" \
		"$(afl_target_bin)" \
		<"$sample" \
		>/dev/null 2>"$stderr_file" || true
}

run_bind9_sample() {
	local sample="$1"
	local stderr_file="$2"
	env \
		LD_LIBRARY_PATH="$(bind9_ld_library_path)" \
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$BIND9_TARGET_ADDR" \
		NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		NAMED_RESOLVER_AFL_SYMCC_LOG=1 \
		timeout -k 2 "$SEED_TIMEOUT_SEC" \
		"$BIND9_AFL_TREE/bin/named/.libs/named" \
		-g \
		-c "$BIND9_NAMED_CONF" \
		-A "resolver-afl-symcc:${BIND9_MUTATOR_ADDR},input=$sample" \
		>/dev/null 2>"$stderr_file" || true
}

diff_test() {
	local sample
	local total=0
	local diff_count=0
	local ub_stderr bind9_stderr
	local ub_oracle bind9_oracle
	local diff_type="same"
	local source_dir
	local summary_file="$DIFF_RESULT_DIR/summary.tsv"

	# 前置检查
	require_file "$BIND9_AFL_TREE/bin/named/.libs/named"
	require_file "$(afl_target_bin)"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "缺少 response 语料，请先执行 gen-seeds"

	source_dir="$(diff_source_dir)"
	[ -d "$source_dir" ] || die "缺少 query 语料"

	prepare_bind9_conf
	rm -rf "$DIFF_RESULT_DIR"
	mkdir -p "$DIFF_RESULT_DIR"

	log "差分测试开始 — 种子目录: $source_dir"
	printf 'sample\tdiff\tdiff_type\tunbound_oracle\tbind9_oracle\n' \
		>"$summary_file"

	for sample in "$source_dir"/*; do
		[ -f "$sample" ] || continue
		total=$((total + 1))

		ub_stderr="$(mktemp "$LOG_DIR/diff_ub.XXXXXX")"
		bind9_stderr="$(mktemp "$LOG_DIR/diff_b9.XXXXXX")"

		run_unbound_sample "$sample" "$ub_stderr"
		run_bind9_sample "$sample" "$bind9_stderr"

		ub_oracle="$(extract_oracle "$ub_stderr")"
		bind9_oracle="$(extract_oracle "$bind9_stderr")"
		diff_type="$(classify_oracle_diff "$ub_oracle" "$bind9_oracle")"

		local is_diff="NO"
		if [ "$ub_oracle" != "$bind9_oracle" ]; then
			local base
			local ub_saved_stderr
			local bind9_saved_stderr

			is_diff="YES"
			diff_count=$((diff_count + 1))
			# 保存差异样本和 oracle 详情
			base="$(basename "$sample")"
			ub_saved_stderr="$DIFF_RESULT_DIR/${base}.unbound.stderr"
			bind9_saved_stderr="$DIFF_RESULT_DIR/${base}.bind9.stderr"
			cp "$sample" "$DIFF_RESULT_DIR/$base"
			cp "$ub_stderr" "$ub_saved_stderr"
			cp "$bind9_stderr" "$bind9_saved_stderr"
			{
				printf 'sample: %s\n' "$base"
				printf 'sample_path: %s\n' "$sample"
				printf 'source_dir: %s\n' "$source_dir"
				printf 'diff: %s\n' "$is_diff"
				printf 'diff_type: %s\n' "$diff_type"
				printf 'unbound: %s\n' "$ub_oracle"
				printf 'bind9:   %s\n' "$bind9_oracle"
				printf 'unbound_stderr: %s\n' "$(basename "$ub_saved_stderr")"
				printf 'bind9_stderr: %s\n' "$(basename "$bind9_saved_stderr")"
			} >"$DIFF_RESULT_DIR/${base}.detail"
		fi

		printf '%s\t%s\t%s\t%s\t%s\n' \
			"$(basename "$sample")" "$is_diff" "$diff_type" \
			"$ub_oracle" "$bind9_oracle" \
			>>"$summary_file"

		rm -f "$ub_stderr" "$bind9_stderr"
	done

	log "差分测试完成: 共 $total 个样本，$diff_count 个存在 oracle 差异"
	log "详情: $summary_file"
	if [ "$diff_count" -gt 0 ]; then
		log "差异样本保存在: $DIFF_RESULT_DIR/"
	fi
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
	local timeout_sec="$SMOKE_TIMEOUT_SEC"

	log "smoke: $name <- $(basename "$sample")"
	if [ "$name" = "afl" ]; then
		ld_path="$(tree_ld_library_path "$AFL_TREE")"
	else
		ld_path="$(tree_ld_library_path "$SYMCC_TREE")"
		timeout_sec="$SYMCC_SMOKE_TIMEOUT_SEC"
	fi
	set +e
	env \
		LD_LIBRARY_PATH="$ld_path" \
		SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/smoke" \
		UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
		timeout -k 1 "$timeout_sec" "$bin" \
		<"$sample" \
		>/dev/null 2>"$WORK_DIR/${name}.stderr"
	rc=$?
	set -e

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
	local sample_dir

	sample_dir="$(diff_source_dir)"
	require_file "$(afl_target_bin)"
	require_file "$(symcc_target_bin)"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "缺少 response 语料，请先执行 gen-seeds"
	sample="$(pick_sample "$sample_dir")"
	[ -n "$sample" ] || die "输入语料为空，请先执行 gen-seeds 或 filter-seeds"

	run_smoke_once "afl" "$(afl_target_bin)" "$sample"
	run_smoke_once "symcc" "$(symcc_target_bin)" "$sample"
}

dump_unbound_cache() {
	local sample="$1"
	local base_name="empty"
	local output_path
	local stderr_file="$WORK_DIR/unbound_dump_cache.stderr"
	local rc=0

	require_file "$(afl_target_bin)"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "缺少 response 语料，请先执行 gen-seeds"
	if [ -n "$sample" ]; then
		require_file "$sample"
		base_name="$(basename "$sample")"
	fi

	output_path="${2:-$CACHE_DUMP_DIR/${base_name}.unbound.cache.txt}"
	mkdir -p "$(dirname "$output_path")"
	rm -f "$output_path" "$stderr_file"

	if [ -n "$sample" ]; then
		log "dump-cache: 回放 $(basename "$sample")"
	else
		log "dump-cache: 导出空实例 cache"
	fi
	set +e
	if [ -n "$sample" ]; then
		env \
			LD_LIBRARY_PATH="$(tree_ld_library_path "$AFL_TREE")" \
			UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
			UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH="$output_path" \
			UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
			timeout -k 2 "$SEED_TIMEOUT_SEC" \
			"$(afl_target_bin)" \
			<"$sample" \
			>/dev/null 2>"$stderr_file"
	else
		env \
			LD_LIBRARY_PATH="$(tree_ld_library_path "$AFL_TREE")" \
			UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH="$output_path" \
			timeout -k 2 "$SEED_TIMEOUT_SEC" \
			"$(afl_target_bin)" \
			</dev/null \
			>/dev/null 2>"$stderr_file"
	fi
	rc=$?
	set -e

	case "$rc" in
	0|1)
		;;
	124|137)
		die "dump-cache 超时: rc=$rc"
		;;
	*)
		die "dump-cache 异常退出: rc=$rc"
		;;
	esac

	[ -s "$output_path" ] || die "cache dump 为空，stderr: $stderr_file"
	log "cache dump 已写出: $output_path"
}

normalize_unbound_cache_dump() {
	local dump_file="$1"
	local output_path="$2"

	awk '
		function trim(text) {
			sub(/^[[:space:]]+/, "", text);
			sub(/[[:space:]]+$/, "", text);
			return text;
		}

		function join_tokens(tokens, start, count, text, i) {
			text = "";
			for (i = start; i <= count; i++) {
				if (tokens[i] == "") {
					continue;
				}
				text = text (text == "" ? "" : " ") tokens[i];
			}
			return text == "" ? "_" : text;
		}

		function is_class_token(token) {
			return token ~ /^(IN|CH|HS|CLASS[0-9]+)$/;
		}

		function is_type_token(token) {
			return token == "\\-" || token ~ /^\\-(TYPE[0-9]+|[A-Z0-9-]+)$/ || token ~ /^(TYPE[0-9]+|[A-Z0-9-]+)$/;
		}

		function looks_like_rr_header(line, tokens, count, i, ttl_idx, type_idx) {
			line = trim(line);
			if (line == "" || line ~ /^;/ || line ~ /^msg /) {
				return 0;
			}
			count = split(line, tokens, /[[:space:]]+/);
			ttl_idx = 0;
			for (i = 1; i <= count; i++) {
				if (tokens[i] ~ /^[0-9]+$/) {
					ttl_idx = i;
					break;
				}
			}
			if (ttl_idx == 0 || ttl_idx > 2) {
				return 0;
			}
			type_idx = ttl_idx + 1;
			if (type_idx <= count && is_class_token(tokens[type_idx])) {
				type_idx++;
			}
			return type_idx <= count && is_type_token(tokens[type_idx]);
		}

		function emit_msg_record(line, tokens, count, reason_text) {
			line = trim(line);
			count = split(line, tokens, /[[:space:]]+/);
			if (count < 12) {
				return;
			}
			reason_text = join_tokens(tokens, 13, count);
			printf "MSG\t_\t%s\t%s\t%s\tflags=%s qd=%s sec=%s an=%s ns=%s ar=%s bogus=%s reason=%s\n",
				tokens[2], tokens[3], tokens[4], tokens[5], tokens[6],
				tokens[8], tokens[9], tokens[10], tokens[11], tokens[12],
				reason_text;
		}

		function emit_rrset_record(line, tokens, count, i, ttl_idx, owner, class_token, type_idx, type_token, detail_text) {
			if (pending_rrset == "") {
				return;
			}
			line = trim(pending_rrset);
			count = split(line, tokens, /[[:space:]]+/);
			ttl_idx = 0;
			for (i = 1; i <= count; i++) {
				if (tokens[i] ~ /^[0-9]+$/) {
					ttl_idx = i;
					break;
				}
			}
			if (ttl_idx == 0 || ttl_idx > 2) {
				pending_rrset = "";
				return;
			}
			owner = "_";
			class_token = "_";
			type_token = "_";
			if (ttl_idx > 1) {
				owner = tokens[1];
			} else if (last_owner != "") {
				owner = last_owner;
			}
			type_idx = ttl_idx + 1;
			if (type_idx <= count && is_class_token(tokens[type_idx])) {
				class_token = tokens[type_idx];
				type_idx++;
			} else if (last_class != "") {
				class_token = last_class;
			}
			if (type_idx <= count && is_type_token(tokens[type_idx])) {
				type_token = tokens[type_idx];
			}
			detail_text = join_tokens(tokens, type_idx + 1, count);
			if (owner != "_") {
				last_owner = owner;
			}
			if (class_token != "_") {
				last_class = class_token;
			}
			printf "RRSET\t_\t%s\t%s\t%s\t%s\n", owner, class_token, type_token, detail_text;
			pending_rrset = "";
		}

		/^START_RRSET_CACHE$/ {
			section = "RRSET";
			last_owner = "";
			last_class = "";
			next;
		}
		/^START_MSG_CACHE$/ {
			emit_rrset_record();
			section = "MSG";
			next;
		}
		/^END_/ || /^EOF$/ || /^$/ {
			emit_rrset_record();
			next;
		}
		section == "MSG" && /^msg / {
			emit_msg_record($0);
			next;
		}
		section == "MSG" {
			next;
		}
		section == "RRSET" && /^;rrset/ {
			emit_rrset_record();
			last_owner = "";
			last_class = "";
			next;
		}
		section == "RRSET" && /^;/ {
			emit_rrset_record();
			next;
		}
		section == "RRSET" && looks_like_rr_header($0) {
			emit_rrset_record();
			pending_rrset = $0;
			next;
		}
		section == "RRSET" && pending_rrset != "" {
			pending_rrset = pending_rrset " " trim($0);
			next;
		}
		END {
			emit_rrset_record();
		}
	' "$dump_file" >"$output_path"
}

normalize_named_cache_dump() {
	local dump_file="$1"
	local output_path="$2"

	awk '
		function trim(text) {
			sub(/^[[:space:]]+/, "", text);
			sub(/[[:space:]]+$/, "", text);
			return text;
		}

		function join_tokens(tokens, start, count, text, i) {
			text = "";
			for (i = start; i <= count; i++) {
				if (tokens[i] == "") {
					continue;
				}
				text = text (text == "" ? "" : " ") tokens[i];
			}
			return text == "" ? "_" : text;
		}

		function is_class_token(token) {
			return token ~ /^(IN|CH|HS|CLASS[0-9]+)$/;
		}

		function is_type_token(token) {
			return token == "\\-" || token ~ /^\\-(TYPE[0-9]+|[A-Z0-9-]+)$/ || token ~ /^(TYPE[0-9]+|[A-Z0-9-]+)$/;
		}

		function looks_like_rr_header(line, tokens, count, i, ttl_idx, type_idx) {
			line = trim(line);
			if (line == "" || line ~ /^;/ || line ~ /^\$/) {
				return 0;
			}
			count = split(line, tokens, /[[:space:]]+/);
			ttl_idx = 0;
			for (i = 1; i <= count; i++) {
				if (tokens[i] ~ /^[0-9]+$/) {
					ttl_idx = i;
					break;
				}
			}
			if (ttl_idx == 0 || ttl_idx > 2) {
				return 0;
			}
			type_idx = ttl_idx + 1;
			if (type_idx <= count && is_class_token(tokens[type_idx])) {
				type_idx++;
			}
			return type_idx <= count && is_type_token(tokens[type_idx]);
		}

		function emit_cache_entry(kind, raw_line, line) {
			line = substr(raw_line, 3);
			if (match(line, /^([^\/]+)\/([^ ]+) \[ttl [0-9]+\]$/, m)) {
				printf "%s\t%s\t%s\t_\t%s\t_\n", kind, current_view, m[1], m[2];
			}
		}

		function emit_rrset_record(line, tokens, count, i, ttl_idx, owner, class_token, type_idx, type_token, out_section, detail_text) {
			if (pending_rrset == "") {
				return;
			}
			line = trim(pending_rrset);
			count = split(line, tokens, /[[:space:]]+/);
			ttl_idx = 0;
			for (i = 1; i <= count; i++) {
				if (tokens[i] ~ /^[0-9]+$/) {
					ttl_idx = i;
					break;
				}
			}
			if (ttl_idx == 0 || ttl_idx > 2) {
				pending_rrset = "";
				return;
			}
			owner = "_";
			class_token = "_";
			type_token = "_";
			if (ttl_idx > 1) {
				owner = tokens[1];
			} else if (last_owner != "") {
				owner = last_owner;
			}
			type_idx = ttl_idx + 1;
			if (type_idx <= count && is_class_token(tokens[type_idx])) {
				class_token = tokens[type_idx];
				type_idx++;
			} else if (last_class != "") {
				class_token = last_class;
			}
			if (type_idx <= count && is_type_token(tokens[type_idx])) {
				type_token = tokens[type_idx];
			}
			detail_text = join_tokens(tokens, type_idx + 1, count);
			if (owner != "_") {
				last_owner = owner;
			}
			if (class_token != "_") {
				last_class = class_token;
			}
			out_section = (current_section == "" ? "RRSET" : current_section);
			if (out_section != "ADB") {
				printf "%s\t%s\t%s\t%s\t%s\t%s\n", out_section, current_view, owner, class_token, type_token, detail_text;
			}
			pending_rrset = "";
		}

		BEGIN {
			current_view = "_";
			current_section = "RRSET";
		}
		/^; Cache dump of view / {
			emit_rrset_record();
			if (match($0, /'\''([^'\'']+)'\''/, m)) {
				current_view = m[1];
			} else {
				current_view = "_";
			}
			current_section = "RRSET";
			last_owner = "";
			last_class = "";
			next;
		}
		/^; Address database dump$/ {
			emit_rrset_record();
			current_section = "ADB";
			last_owner = "";
			last_class = "";
			next;
		}
		/^; Bad cache$/ {
			emit_rrset_record();
			current_section = "BADCACHE";
			next;
		}
		/^; SERVFAIL cache$/ {
			emit_rrset_record();
			current_section = "SERVFAIL";
			next;
		}
		/^\$DATE/ || /^; using / || /^; \[edns success\/timeout\]/ || /^; \[plain success\/timeout\]/ || /^;$/ || /^$/ {
			emit_rrset_record();
			next;
		}
		current_section == "SERVFAIL" && /^; / {
			emit_rrset_record();
			emit_cache_entry("SERVFAIL", $0);
			next;
		}
		current_section == "BADCACHE" && /^; / {
			emit_rrset_record();
			emit_cache_entry("BADCACHE", $0);
			next;
		}
		/^;/ {
			emit_rrset_record();
			next;
		}
		looks_like_rr_header($0) {
			emit_rrset_record();
			pending_rrset = $0;
			next;
		}
		pending_rrset != "" {
			pending_rrset = pending_rrset " " trim($0);
			next;
		}
		END {
			emit_rrset_record();
		}
	' "$dump_file" >"$output_path"
}

parse_cache_dump() {
	local resolver="$1"
	local dump_file="$2"
	local output_path="${3:-${dump_file}.norm.tsv}"

	[ -n "$resolver" ] || die "parse-cache 需要 resolver 参数"
	require_file "$dump_file"

	case "$resolver" in
	unbound)
		normalize_unbound_cache_dump "$dump_file" "$output_path"
		;;
	bind9|named)
		normalize_named_cache_dump "$dump_file" "$output_path"
		;;
	*)
		die "未知 resolver: $resolver"
		;;
	esac

	log "解析结果已写出: $output_path"
}

compare_normalized_cache_dumps() {
	local before_file="$1"
	local after_file="$2"
	local added_file="$3"
	local removed_file="$4"
	local before_sorted="$5"
	local after_sorted="$6"

	LC_ALL=C sort -u "$before_file" >"$before_sorted"
	LC_ALL=C sort -u "$after_file" >"$after_sorted"
	comm -13 "$before_sorted" "$after_sorted" >"$added_file"
	comm -23 "$before_sorted" "$after_sorted" >"$removed_file"
}

replay_diff_cache() {
	local sample="$1"
	local out_dir="${2:-$CACHE_DUMP_DIR/$(basename "$sample").replay_diff}"
	local unbound_before="$out_dir/unbound.before.cache.txt"
	local unbound_after="$out_dir/unbound.after.cache.txt"
	local bind9_before="$out_dir/bind9.before.cache.txt"
	local bind9_after="$out_dir/bind9.after.cache.txt"
	local unbound_before_norm="$out_dir/unbound.before.norm.tsv"
	local unbound_after_norm="$out_dir/unbound.after.norm.tsv"
	local bind9_before_norm="$out_dir/bind9.before.norm.tsv"
	local bind9_after_norm="$out_dir/bind9.after.norm.tsv"
	local unbound_before_sorted="$out_dir/unbound.before.sorted.tsv"
	local unbound_after_sorted="$out_dir/unbound.after.sorted.tsv"
	local bind9_before_sorted="$out_dir/bind9.before.sorted.tsv"
	local bind9_after_sorted="$out_dir/bind9.after.sorted.tsv"
	local unbound_added="$out_dir/unbound.added.tsv"
	local unbound_removed="$out_dir/unbound.removed.tsv"
	local bind9_added="$out_dir/bind9.added.tsv"
	local bind9_removed="$out_dir/bind9.removed.tsv"
	local summary_file="$out_dir/summary.txt"

	[ -n "$sample" ] || die "replay-diff-cache 需要提供样本路径"
	require_file "$sample"
	mkdir -p "$out_dir"

	dump_unbound_cache "" "$unbound_before"
	dump_unbound_cache "$sample" "$unbound_after"
	WORK_DIR="$BIND9_WORK_DIR" FUZZ_PROFILE="${FUZZ_PROFILE:-poison-stateful}" \
		"$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" dump-cache "" "$bind9_before"
	WORK_DIR="$BIND9_WORK_DIR" FUZZ_PROFILE="${FUZZ_PROFILE:-poison-stateful}" \
		"$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" dump-cache "$sample" "$bind9_after"

	parse_cache_dump unbound "$unbound_before" "$unbound_before_norm"
	parse_cache_dump unbound "$unbound_after" "$unbound_after_norm"
	parse_cache_dump bind9 "$bind9_before" "$bind9_before_norm"
	parse_cache_dump bind9 "$bind9_after" "$bind9_after_norm"

	compare_normalized_cache_dumps "$unbound_before_norm" "$unbound_after_norm" \
		"$unbound_added" "$unbound_removed" "$unbound_before_sorted" "$unbound_after_sorted"
	compare_normalized_cache_dumps "$bind9_before_norm" "$bind9_after_norm" \
		"$bind9_added" "$bind9_removed" "$bind9_before_sorted" "$bind9_after_sorted"

	{
		printf 'sample: %s\n' "$sample"
		printf 'out_dir: %s\n' "$out_dir"
		printf 'unbound_added: %s\n' "$(wc -l < "$unbound_added")"
		printf 'unbound_removed: %s\n' "$(wc -l < "$unbound_removed")"
		printf 'bind9_added: %s\n' "$(wc -l < "$bind9_added")"
		printf 'bind9_removed: %s\n' "$(wc -l < "$bind9_removed")"
	} >"$summary_file"

	log "replay-diff-cache 完成: $out_dir"
}

cleanup_output() {
	if [ "$RESET_OUTPUT" -eq 1 ]; then
		rm -rf "$AFL_OUT_DIR"
		rm -f "$MASTER_LOG" "$HELPER_LOG" "$EXPLORE_LOG"
		rm -f "$WORK_DIR/.explore_seen"
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
		if [ "$waited" -ge "$AFL_START_TIMEOUT_SEC" ]; then
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
	local input_dir
	local ld_path_afl
	local ld_path_symcc
	local ld_path_helper

	prepare_all
	stop_all
	cleanup_output
	input_dir="$(diff_source_dir)"

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

	if [ "$FUZZ_PROFILE" != "poison-stateful" ]; then
		# poison-stateful 下 AFL queue 中是 transcript，不再直接复用为 query seeds。
		log "启动 explore-response 后台循环（间隔 ${EXPLORE_INTERVAL}s）"
		explore_response_loop >>"$EXPLORE_LOG" 2>&1 &
		echo "$!" >"$EXPLORE_PID"
		log "实验已启动（AFL master + SymCC helper + explore-response）"
	else
		log "实验已启动（AFL master + SymCC helper）"
	fi
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
	stop_pid_file "$EXPLORE_PID"
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
	printf '  %-16s %s\n' "profile" "$FUZZ_PROFILE"
	printf '  %-16s %s\n' "query-corpus" \
		"$(find "$QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "response-corpus" \
		"$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "  (from explore)" \
		"$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -name 'explore_*' -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "stable-query" \
		"$(find "$STABLE_QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "transcript" \
		"$(find "$TRANSCRIPT_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"
	printf '  %-16s %s\n' "stable-transcript" \
		"$(find "$STABLE_TRANSCRIPT_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l) files"

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
	if [ -f "$EXPLORE_PID" ] && kill -0 "$(cat "$EXPLORE_PID")" >/dev/null 2>&1; then
		printf '  %-16s running (%s)\n' "explore-resp" "$(cat "$EXPLORE_PID")"
	else
		printf '  %-16s stopped\n' "explore-resp"
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
	local extra="${3:-}"
	local more="${4:-}"

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
	explore-response)
		explore_response_once
		;;
	filter-seeds)
		filter_seeds
		;;
	smoke)
		smoke_all
		;;
	dump-cache)
		dump_unbound_cache "$arg" "$extra"
		;;
	parse-cache)
		parse_cache_dump "$arg" "$extra" "$more"
		;;
	replay-diff-cache)
		replay_diff_cache "$arg" "$extra"
		;;
	prepare)
		prepare_all
		;;
	diff-test)
		diff_test
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
load_profile
ensure_dirs
main "${1:-}" "${2:-}" "${3:-}" "${4:-}"
