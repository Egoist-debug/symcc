#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/build/linux/x86_64/release/gen_input"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-three-phase.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
	printf 'ERROR: 缺少可执行文件 %s\n' "$BIN" >&2
	exit 1
fi

if "$BIN" --three-phase -o "$WORKDIR/output" /bin/true \
	>"$WORKDIR/stdout" 2>"$WORKDIR/stderr"
then
	printf 'ASSERT FAIL: 缺少函数边界反馈时 --three-phase 不应成功\n' >&2
	exit 1
fi

grep -Fq -- \
	'Error: --three-phase is unavailable until function-boundary feedback is implemented' \
	"$WORKDIR/stderr" || {
	printf 'ASSERT FAIL: --three-phase 未返回明确的 unsupported 原因\n' >&2
	cat "$WORKDIR/stderr" >&2
	exit 1
}

if grep -Fq -- 'Three-phase generation complete' "$WORKDIR/stderr"; then
	printf 'ASSERT FAIL: --three-phase 仍报告了误导性的完成统计\n' >&2
	exit 1
fi

printf 'PASS: gen_input three-phase fail-closed regression test passed\n'
