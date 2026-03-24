#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT_DIR/unbound_experiment/run_unbound_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dns-diff-cli-smoke.XXXXXX")"
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

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

HELP_OUT="$WORKDIR/help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	SRC_TREE="$ROOT_DIR" \
	"$WRAPPER" help >"$HELP_OUT"
assert_file_contains "$HELP_OUT" "follow-diff-once"
assert_file_contains "$HELP_OUT" "parse-cache"

REMOVED_ERR="$WORKDIR/removed-command.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	SRC_TREE="$ROOT_DIR" \
	"$WRAPPER" run >/dev/null 2>"$REMOVED_ERR"; then
	printf 'ASSERT FAIL: 已移除厚命令 run 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$REMOVED_ERR" "命令 'run'"
assert_file_contains "$REMOVED_ERR" "已从 thin wrapper 中移除"

BIND_DUMP="$WORKDIR/bind.cache.txt"
BIND_TSV="$WORKDIR/bind.norm.tsv"
printf '%s\n' \
	';' \
	"; Cache dump of view '_default' (cache _default)" \
	';' \
	'example.com. 300 IN A 1.2.3.4' >"$BIND_DUMP"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	SRC_TREE="$ROOT_DIR" \
	"$WRAPPER" parse-cache bind9 "$BIND_DUMP" "$BIND_TSV" >/dev/null
assert_file_exists "$BIND_TSV"
assert_file_contains "$BIND_TSV" $'bind9\t_default\texample.com.\tA\tA\tRRSET\trrset\t300\t1.2.3.4\tclass=IN'

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	SRC_TREE="$ROOT_DIR" \
	"$WRAPPER" follow-diff-once >/dev/null

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	SRC_TREE="$ROOT_DIR" \
	"$WRAPPER" triage-report >/dev/null
FOLLOW_ROOT="$WORKDIR/work/follow_diff"
assert_file_exists "$FOLLOW_ROOT/cluster_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/status_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/triage_report.md"
assert_file_contains "$FOLLOW_ROOT/cluster_summary.tsv" $'__total__\t0\t-'
assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" $'__total__\t0'

echo "PASS: dns-diff CLI smoke test passed"
