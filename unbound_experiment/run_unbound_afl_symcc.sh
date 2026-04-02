#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_DIR="$ROOT_DIR/unbound_experiment"
PROFILE_DIR="$EXP_DIR/profiles"
DEFAULT_WORK_DIR="$EXP_DIR/work_stateful"
DEFAULT_BIND9_WORK_DIR="$ROOT_DIR/named_experiment/work"
ENV_WORK_DIR="${WORK_DIR:-}"
WORK_DIR="${ENV_WORK_DIR:-$DEFAULT_WORK_DIR}"
BIND9_WORK_DIR="${BIND9_WORK_DIR:-${ENV_WORK_DIR:-$DEFAULT_BIND9_WORK_DIR}}"
FOLLOW_DIFF_SOURCE_DIR="${FOLLOW_DIFF_SOURCE_DIR:-$BIND9_WORK_DIR/afl_out/master/queue}"
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
BIND9_TARGET_ADDR="${BIND9_TARGET_ADDR:-127.0.0.1:55301}"
BIND9_MUTATOR_ADDR="${BIND9_MUTATOR_ADDR:-127.0.0.1:55300}"

RESPONSE_CORPUS_DIR="$WORK_DIR/response_corpus"
CACHE_DUMP_DIR="$WORK_DIR/cache_dumps"
REPORT_HIGH_VALUE_MANIFEST="$WORK_DIR/high_value_samples.txt"
SYMCC_HIGH_VALUE_MANIFEST="${SYMCC_HIGH_VALUE_MANIFEST:-$REPORT_HIGH_VALUE_MANIFEST}"
export SYMCC_HIGH_VALUE_MANIFEST

usage() {
	printf '%s\n' \
		'用法:' \
		'  unbound_experiment/run_unbound_afl_symcc.sh <命令>' \
		'' \
		'兼容转发命令（真实语义统一由 python3 -m tools.dns_diff.cli 持有）:' \
		'  fetch [--target <目标>]' \
		'                     转发到 python3 -m tools.dns_diff.cli fetch' \
		'  dump-cache [--target <目标>] [样本] [输出文件]' \
		'                     转发到 python3 -m tools.dns_diff.cli dump-cache（默认 target=unbound）' \
		'  parse-cache <resolver> <dump文件> [输出文件]' \
		'                     转发到 python3 -m tools.dns_diff.cli parse-cache' \
		'  replay-diff-cache <样本> [输出目录]' \
		'                     转发到 python3 -m tools.dns_diff.cli replay-diff-cache' \
		'  follow-diff        转发到 python3 -m tools.dns_diff.cli follow-diff' \
		'  follow-diff-once   转发到 python3 -m tools.dns_diff.cli follow-diff-once' \
		'  follow-diff-window 转发到 python3 -m tools.dns_diff.cli follow-diff-window' \
		'  triage-report      转发到 python3 -m tools.dns_diff.cli triage-report' \
		'  campaign-report    转发到 python3 -m tools.dns_diff.cli campaign-report' \
		'  campaign-close     转发到 python3 -m tools.dns_diff.cli campaign-close' \
		'  help               显示帮助' \
		'' \
		'已从 shell 移除的厚编排命令:' \
		'  build / gen-seeds / explore-response / filter-seeds / smoke / prepare' \
		'  start / run / stop / status' \
		'' \
		'边界说明:' \
		'  1. shell 仅保留命令路由、环境注入与兼容性 glue，不再持有业务编排。' \
		'  2. dns-diff 相关逻辑统一以 python3 -m tools.dns_diff.cli 为真入口。' \
		'  3. 旧的 seed/build/explore/status 等业务编排已从本 wrapper 移除。' \
		'  4. triage / report 仅保留在 Python 真入口，不再在 shell wrapper 暴露别名。'
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

forward_dns_diff_cli() {
	local subcommand="$1"
	shift

	case "$subcommand" in
	follow-diff-window|campaign-close)
		if [ -n "$DNS_DIFF_CLI_TIMEOUT_SEC" ]; then
			usage >&2
			die "$subcommand 禁止使用 DNS_DIFF_CLI_TIMEOUT_SEC（shell timeout owner）；请改用 '$subcommand --budget-sec <秒>' 由 Python CLI 持有超时"
		fi
		;;
	esac

	require_cmd python3
	require_file "$ROOT_DIR/tools/dns_diff/cli.py"
	if [ "$subcommand" != 'fetch' ]; then
		load_profile
		ensure_basic_dirs
	fi

	if [ -n "$DNS_DIFF_CLI_TIMEOUT_SEC" ]; then
		env \
			PYTHONDONTWRITEBYTECODE=1 \
			PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
			ROOT_DIR="$ROOT_DIR" \
			WORK_DIR="$WORK_DIR" \
			FOLLOW_DIFF_SOURCE_DIR="$FOLLOW_DIFF_SOURCE_DIR" \
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
		FOLLOW_DIFF_SOURCE_DIR="$FOLLOW_DIFF_SOURCE_DIR" \
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

reject_removed_command() {
	die "命令 '$1' 已从 thin wrapper 中移除；请迁移到 python3 -m tools.dns_diff.cli 或独立工具层，不再在 shell 中承载厚编排"
}

main() {
	local cmd="${1:-help}"

	if [ "$#" -gt 0 ]; then
		shift
	fi

	case "$cmd" in
	build|gen-seeds|explore-response|filter-seeds|smoke|prepare|start|run|stop|status)
		reject_removed_command "$cmd"
		;;
	""|-h|--help|help)
		usage
		;;
	*)
		forward_dns_diff_cli "$cmd" "$@"
		;;
	esac
}

main "$@"
