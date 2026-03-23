#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_DIR="$ROOT_DIR/unbound_experiment"
PROFILE_DIR="$EXP_DIR/profiles"
WORK_DIR="${WORK_DIR:-$EXP_DIR/work_stateful}"
SRC_TREE="${SRC_TREE:-$ROOT_DIR/unbound-1.24.2}"
AFL_TREE="${AFL_TREE:-$ROOT_DIR/unbound-1.24.2-afl}"
UNBOUND_TAG="${UNBOUND_TAG:-release-1.24.2}"

FUZZ_PROFILE="${FUZZ_PROFILE:-legacy-response-tail}"
SEED_TIMEOUT_SEC="${SEED_TIMEOUT_SEC:-5}"
DNS_DIFF_CLI_TIMEOUT_SEC="${DNS_DIFF_CLI_TIMEOUT_SEC:-}"
DNS_DIFF_CLI_TIMEOUT_GRACE_SEC="${DNS_DIFF_CLI_TIMEOUT_GRACE_SEC:-2}"

BIND9_AFL_TREE="${BIND9_AFL_TREE:-$ROOT_DIR/bind-9.18.46-afl}"
BIND9_NAMED_EXP="$ROOT_DIR/named_experiment"
BIND9_NAMED_CONF_TEMPLATE="$BIND9_NAMED_EXP/runtime/named.conf"
BIND9_WORK_DIR="${BIND9_WORK_DIR:-$ROOT_DIR/named_experiment/work}"
BIND9_TARGET_ADDR="${BIND9_TARGET_ADDR:-127.0.0.1:55301}"
BIND9_MUTATOR_ADDR="${BIND9_MUTATOR_ADDR:-127.0.0.1:55300}"

RESPONSE_CORPUS_DIR="$WORK_DIR/response_corpus"
CACHE_DUMP_DIR="$WORK_DIR/cache_dumps"
SYMCC_HIGH_VALUE_MANIFEST="${SYMCC_HIGH_VALUE_MANIFEST:-$WORK_DIR/high_value_samples.txt}"
export SYMCC_HIGH_VALUE_MANIFEST

usage() {
	printf '%s\n' \
		'用法:' \
		'  unbound_experiment/run_unbound_afl_symcc.sh <命令>' \
		'' \
		'保留的薄包装命令:' \
		'  fetch              直接 git clone Unbound release-1.24.2 源码树' \
		'  dump-cache <样本> [输出文件]' \
		'                     直接调用 unbound-fuzzme 并导出 cache dump' \
		'  parse-cache <resolver> <dump文件> [输出文件]' \
		'                     转发到 python3 -m tools.dns_diff.cli parse-cache' \
		'  replay-diff-cache <样本> [输出目录]' \
		'                     转发到 python3 -m tools.dns_diff.cli replay-diff-cache' \
		'  follow-diff        转发到 python3 -m tools.dns_diff.cli follow-diff' \
		'  follow-diff-once   转发到 python3 -m tools.dns_diff.cli follow-diff-once' \
		'  triage-report      转发到 python3 -m tools.dns_diff.cli triage-report' \
		'  campaign-report    转发到 python3 -m tools.dns_diff.cli campaign-report' \
		'  help               显示帮助' \
		'' \
		'已从 shell 移除的厚编排命令:' \
		'  build / gen-seeds / explore-response / filter-seeds / smoke / prepare' \
		'  start / run / stop / status' \
		'' \
		'边界说明:' \
		'  1. shell 仅保留命令路由、环境注入、路径检查、timeout 外壳与直接外部调用。' \
		'  2. dns-diff 相关逻辑统一以 python3 -m tools.dns_diff.cli 为真入口。' \
		'  3. 旧的 seed/build/explore/status 等业务编排已从本 wrapper 移除。'
}

log() {
	printf '[unbound-exp] %s\n' "$*"
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

require_dir() {
	[ -d "$1" ] || die "缺少目录: $1"
}

ensure_basic_dirs() {
	mkdir -p "$WORK_DIR" "$CACHE_DUMP_DIR"
}

load_profile() {
	local profile_file="$PROFILE_DIR/${FUZZ_PROFILE}.env"

	if [ -f "$profile_file" ]; then
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

fetch_unbound() {
	require_cmd git
	ensure_basic_dirs

	if [ -d "$SRC_TREE/.git" ]; then
		log "Unbound 源码树已存在: $SRC_TREE"
		return 0
	fi

	if [ -e "$SRC_TREE" ]; then
		die "目标路径已存在但不是 git clone 结果: $SRC_TREE"
	fi

	log "拉取 Unbound $UNBOUND_TAG"
	(
		cd "$ROOT_DIR"
		git clone --depth 1 --branch "$UNBOUND_TAG" \
			https://github.com/NLnetLabs/unbound.git \
			"$(basename "$SRC_TREE")"
	)
}

forward_dns_diff_cli() {
	local subcommand="$1"
	shift

	load_profile
	ensure_basic_dirs
	require_cmd python3
	require_file "$ROOT_DIR/tools/dns_diff/cli.py"

	if [ -n "$DNS_DIFF_CLI_TIMEOUT_SEC" ]; then
		env \
			PYTHONDONTWRITEBYTECODE=1 \
			PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
			ROOT_DIR="$ROOT_DIR" \
			WORK_DIR="$WORK_DIR" \
			FUZZ_PROFILE="$FUZZ_PROFILE" \
			BIND9_AFL_TREE="$BIND9_AFL_TREE" \
			BIND9_NAMED_EXP="$BIND9_NAMED_EXP" \
			BIND9_NAMED_CONF_TEMPLATE="$BIND9_NAMED_CONF_TEMPLATE" \
			BIND9_WORK_DIR="$BIND9_WORK_DIR" \
			BIND9_TARGET_ADDR="$BIND9_TARGET_ADDR" \
			BIND9_MUTATOR_ADDR="$BIND9_MUTATOR_ADDR" \
			RESPONSE_CORPUS_DIR="$RESPONSE_CORPUS_DIR" \
			SEED_TIMEOUT_SEC="$SEED_TIMEOUT_SEC" \
			timeout -k "$DNS_DIFF_CLI_TIMEOUT_GRACE_SEC" "$DNS_DIFF_CLI_TIMEOUT_SEC" \
			python3 -m tools.dns_diff.cli "$subcommand" "$@"
		return
	fi

	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		WORK_DIR="$WORK_DIR" \
		FUZZ_PROFILE="$FUZZ_PROFILE" \
		BIND9_AFL_TREE="$BIND9_AFL_TREE" \
		BIND9_NAMED_EXP="$BIND9_NAMED_EXP" \
		BIND9_NAMED_CONF_TEMPLATE="$BIND9_NAMED_CONF_TEMPLATE" \
		BIND9_WORK_DIR="$BIND9_WORK_DIR" \
		BIND9_TARGET_ADDR="$BIND9_TARGET_ADDR" \
		BIND9_MUTATOR_ADDR="$BIND9_MUTATOR_ADDR" \
		RESPONSE_CORPUS_DIR="$RESPONSE_CORPUS_DIR" \
		SEED_TIMEOUT_SEC="$SEED_TIMEOUT_SEC" \
		python3 -m tools.dns_diff.cli "$subcommand" "$@"
}

dump_unbound_cache() {
	local sample="${1:-}"
	local output_path="${2:-}"
	local base_name="empty"
	local target
	local ld_path
	local stderr_file
	local rc=0

	load_profile
	ensure_basic_dirs
	require_cmd timeout

	target="$(afl_target_bin)"
	require_file "$target"
	ld_path="$(tree_ld_library_path "$AFL_TREE")"
	stderr_file="$WORK_DIR/unbound_dump_cache.stderr"

	if [ -n "$sample" ]; then
		require_file "$sample"
		require_dir "$RESPONSE_CORPUS_DIR"
		base_name="$(basename "$sample")"
	fi

	if [ -z "$output_path" ]; then
		output_path="$CACHE_DUMP_DIR/${base_name}.unbound.cache.txt"
	fi

	mkdir -p "$(dirname "$output_path")"
	rm -f "$output_path" "$stderr_file"

	set +e
	if [ -n "$sample" ]; then
		env \
			LD_LIBRARY_PATH="$ld_path" \
			UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
			UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH="$output_path" \
			UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
			timeout -k 2 "$SEED_TIMEOUT_SEC" "$target" \
			<"$sample" \
			>/dev/null 2>"$stderr_file"
	else
		env \
			LD_LIBRARY_PATH="$ld_path" \
			UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH="$output_path" \
			UNBOUND_RESOLVER_AFL_SYMCC_LOG=1 \
			timeout -k 2 "$SEED_TIMEOUT_SEC" "$target" \
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

reject_removed_command() {
	die "命令 '$1' 已从 thin wrapper 中移除；请迁移到 Python/独立工具层，不再在 shell 中承载厚编排"
}

main() {
	local cmd="${1:-help}"

	if [ "$#" -gt 0 ]; then
		shift
	fi

	case "$cmd" in
	fetch)
		fetch_unbound
		;;
	dump-cache)
		dump_unbound_cache "${1:-}" "${2:-}"
		;;
	parse-cache|replay-diff-cache|follow-diff|follow-diff-once|triage-report|campaign-report)
		forward_dns_diff_cli "$cmd" "$@"
		;;
	build|gen-seeds|explore-response|filter-seeds|smoke|prepare|start|run|stop|status)
		reject_removed_command "$cmd"
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

main "$@"
