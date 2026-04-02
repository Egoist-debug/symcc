#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT_DIR/unbound_experiment/run_unbound_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-tools-dns-diff-cli.XXXXXX")"
PYTHONPATH_VALUE="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
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

write_fake_unbound_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import os
import pathlib
import sys

dump_path = os.environ.get("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH")
if not dump_path:
    sys.stderr.write("missing dump path\\n")
    sys.exit(9)

stdin_data = sys.stdin.buffer.read()
content = "START_RRSET_CACHE\\n;rrset 300 1 0 1 0\\nexample.com. 300 IN A 1.2.3.4\\nEND_RRSET_CACHE\\nEOF\\n"
pathlib.Path(dump_path).write_text(content, encoding="utf-8")
log_path = os.environ.get("FAKE_UNBOUND_INVOCATION_LOG")
if log_path:
    pathlib.Path(log_path).write_text(
        f"stdin={len(stdin_data)} response_dir={os.environ.get('UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR', '_')}\\n",
        encoding="utf-8",
    )
sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
sys.exit(0)
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

HELP_OUT="$WORKDIR/python-help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli --help >"$HELP_OUT"
assert_file_contains "$HELP_OUT" "fetch"
assert_file_contains "$HELP_OUT" "dump-cache"
assert_file_contains "$HELP_OUT" "parse-cache"
assert_file_contains "$HELP_OUT" "replay-diff-cache"
assert_file_contains "$HELP_OUT" "follow-diff-window"
assert_file_contains "$HELP_OUT" "campaign-close"

WINDOW_HELP_OUT="$WORKDIR/window-help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli follow-diff-window --help >"$WINDOW_HELP_OUT"
assert_file_contains "$WINDOW_HELP_OUT" "--budget-sec"

CLOSE_HELP_OUT="$WORKDIR/close-help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli campaign-close --help >"$CLOSE_HELP_OUT"
assert_file_contains "$CLOSE_HELP_OUT" "--budget-sec"

FETCH_UNKNOWN_ERR="$WORKDIR/fetch-unknown.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli fetch --target not-registered >/dev/null 2>"$FETCH_UNKNOWN_ERR"; then
	printf 'ASSERT FAIL: 未注册 target 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$FETCH_UNKNOWN_ERR" "dns-diff: fetch 失败"
assert_file_contains "$FETCH_UNKNOWN_ERR" "未注册 target: 'not-registered'"
assert_file_contains "$FETCH_UNKNOWN_ERR" "已注册: unbound"

PARSE_UNKNOWN_ERR="$WORKDIR/parse-unknown.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli parse-cache not-registered "$WORKDIR/missing.dump" >/dev/null 2>"$PARSE_UNKNOWN_ERR"; then
	printf 'ASSERT FAIL: 未注册 resolver 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$PARSE_UNKNOWN_ERR" "dns-diff: parse-cache 失败"
assert_file_contains "$PARSE_UNKNOWN_ERR" "未注册 resolver: 'not-registered'"
assert_file_contains "$PARSE_UNKNOWN_ERR" "已注册: bind9, unbound"

FAKE_AFL_TREE="$WORKDIR/unbound-afl"
FAKE_TARGET="$FAKE_AFL_TREE/.libs/unbound-fuzzme"
write_fake_unbound_binary "$FAKE_TARGET"
mkdir -p "$FAKE_AFL_TREE/libworker/.libs" "$WORKDIR/work/response_corpus"
SAMPLE_FILE="$WORKDIR/sample.bin"
DIRECT_DUMP_OUT="$WORKDIR/direct.cache.txt"
WRAPPER_DUMP_OUT="$WORKDIR/wrapper.cache.txt"
DIRECT_LOG="$WORKDIR/direct.log"
WRAPPER_LOG="$WORKDIR/wrapper.log"
printf '\x01\x02\x03\x04' >"$SAMPLE_FILE"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ROOT_DIR" \
	AFL_TREE="$FAKE_AFL_TREE" \
	WORK_DIR="$WORKDIR/work" \
	RESPONSE_CORPUS_DIR="$WORKDIR/work/response_corpus" \
	FAKE_UNBOUND_INVOCATION_LOG="$DIRECT_LOG" \
	python3 -m tools.dns_diff.cli dump-cache --target unbound "$SAMPLE_FILE" "$DIRECT_DUMP_OUT" >/dev/null
assert_file_exists "$DIRECT_DUMP_OUT"
assert_file_contains "$DIRECT_DUMP_OUT" "START_RRSET_CACHE"
assert_file_contains "$DIRECT_LOG" "stdin=4"
assert_file_contains "$DIRECT_LOG" "response_dir=$WORKDIR/work/response_corpus"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	AFL_TREE="$FAKE_AFL_TREE" \
	WORK_DIR="$WORKDIR/work" \
	RESPONSE_CORPUS_DIR="$WORKDIR/work/response_corpus" \
	FAKE_UNBOUND_INVOCATION_LOG="$WRAPPER_LOG" \
	"$WRAPPER" dump-cache "$SAMPLE_FILE" "$WRAPPER_DUMP_OUT" >/dev/null
assert_file_exists "$WRAPPER_DUMP_OUT"
assert_file_contains "$WRAPPER_DUMP_OUT" "START_RRSET_CACHE"
assert_file_contains "$WRAPPER_LOG" "stdin=4"
assert_file_contains "$WRAPPER_LOG" "response_dir=$WORKDIR/work/response_corpus"

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
	"$WRAPPER" parse-cache bind9 "$BIND_DUMP" "$BIND_TSV" >/dev/null
assert_file_exists "$BIND_TSV"
assert_file_contains "$BIND_TSV" $'bind9\t_default\texample.com.\tA\tA\tRRSET\trrset\t300\t1.2.3.4\tclass=IN'

WINDOW_GUARD_ERR="$WORKDIR/window.guard.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	DNS_DIFF_CLI_TIMEOUT_SEC=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" follow-diff-window --budget-sec 0.1 >/dev/null 2>"$WINDOW_GUARD_ERR"; then
	printf 'ASSERT FAIL: follow-diff-window 设置 DNS_DIFF_CLI_TIMEOUT_SEC 时应被 wrapper 拒绝\n' >&2
	exit 1
fi
assert_file_contains "$WINDOW_GUARD_ERR" "DNS_DIFF_CLI_TIMEOUT_SEC"
assert_file_contains "$WINDOW_GUARD_ERR" "follow-diff-window --budget-sec"
assert_file_not_contains "$WINDOW_GUARD_ERR" "dns-diff: follow-diff-window 失败"

REMOVED_ERR="$WORKDIR/removed.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" run >/dev/null 2>"$REMOVED_ERR"; then
	printf 'ASSERT FAIL: 已移除厚命令 run 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$REMOVED_ERR" "命令 'run'"
assert_file_contains "$REMOVED_ERR" "已从 thin wrapper 中移除"

echo "PASS: tools dns-diff CLI contract test passed"
