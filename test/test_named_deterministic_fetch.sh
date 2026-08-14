#!/usr/bin/env bash
# 回归：NAMED_RESOLVER_AFL_SYMCC_DETERMINISTIC 开关下 producer 单发回放正常，
# 且 ORACLE_SUMMARY 与请求/应答计数稳定。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AFL_TREE="${BIND9_AFL_TREE_OVERRIDE:-$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl}"
WORKDIR="$(mktemp -d /tmp/deterministic-fetch.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

SAMPLE="$ROOT_DIR/named_experiment/work/stable_transcript_corpus/id_000000_generated_0"
assert_file_exists() {
	local path="$1"
	if [ ! -f "$path" ]; then
		printf 'ASSERT FAIL: 缺少文件 %s\n' "$path" >&2
		exit 1
	fi
}
assert_file_exists "$SAMPLE"
assert_file_exists "$AFL_TREE/bin/named/.libs/named"

sed "s|__RUNTIME_STATE_DIR__|$WORKDIR|" \
	"$ROOT_DIR/named_experiment/runtime/named.conf" > "$WORKDIR/named.conf"

LD_PATH="$(find "$AFL_TREE" -name .libs -type d | tr '\n' ':')"

replay_once() {
	env \
		LD_LIBRARY_PATH="$LD_PATH" \
		NAMED_RESOLVER_AFL_SYMCC_TARGET=127.0.0.1:55301 \
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS=80 \
		NAMED_RESOLVER_AFL_SYMCC_LOG=1 \
		NAMED_RESOLVER_AFL_SYMCC_DETERMINISTIC=1 \
		timeout 20 \
		"$AFL_TREE/bin/named/.libs/named" \
		-g -c "$WORKDIR/named.conf" \
		-A "resolver-afl-symcc:127.0.0.1:55300,input=$SAMPLE" 2>&1 || true
}

FIRST="$(replay_once | grep -aE 'ORACLE_SUMMARY|Requests sent|Replies received' | tr '\n' '|')"
if [ -z "$FIRST" ]; then
	printf 'ASSERT FAIL: 确定性模式回放无输出\n' >&2
	exit 1
fi
for _ in 1 2; do
	CUR="$(replay_once | grep -aE 'ORACLE_SUMMARY|Requests sent|Replies received' | tr '\n' '|')"
	if [ "$CUR" != "$FIRST" ]; then
		printf 'ASSERT FAIL: 确定性模式回放输出不一致\nfirst=%s\ncur=%s\n' "$FIRST" "$CUR" >&2
		exit 1
	fi
done

printf 'PASS: deterministic fetch replay passed\n'
