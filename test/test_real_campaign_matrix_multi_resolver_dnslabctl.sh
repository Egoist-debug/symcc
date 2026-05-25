#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-real-campaign-matrix-dnslabctl.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

OUT_DIR="$(
	env \
		RESULT_ROOT_BASE="$WORKDIR/out" \
		REPLAY_BACKEND=dnslabctl \
		BUDGET_SEC="${BUDGET_SEC:-1}" \
		REPEAT_COUNT="${REPEAT_COUNT:-1}" \
		QUEUE_LIMIT="${QUEUE_LIMIT:-1}" \
		"$ROOT_DIR/scripts/run_real_campaign_matrix_multi_resolver.sh"
)"

[ -f "$OUT_DIR/matrix_run_status.tsv" ] || {
	printf 'ASSERT FAIL: 缺少 matrix_run_status.tsv\n' >&2
	exit 1
}
[ -f "$OUT_DIR/_resolver_summary/resolver_full_stack.tsv" ] || {
	printf 'ASSERT FAIL: 缺少 resolver_full_stack.tsv\n' >&2
	exit 1
}
[ -f "$OUT_DIR/_resolver_summary/resolver_variant_summary.tsv" ] || {
	printf 'ASSERT FAIL: 缺少 resolver_variant_summary.tsv\n' >&2
	exit 1
}

python3 - "$OUT_DIR/matrix_run_status.tsv" "$OUT_DIR/_resolver_summary/resolver_full_stack.tsv" <<'PY'
import csv
import pathlib
import sys

status_rows = list(csv.DictReader(pathlib.Path(sys.argv[1]).open(encoding="utf-8"), delimiter="\t"))
summary_rows = list(csv.DictReader(pathlib.Path(sys.argv[2]).open(encoding="utf-8"), delimiter="\t"))

if len(status_rows) != 5:
    raise SystemExit(f"ASSERT FAIL: resolver 状态数应为 5，实际 {len(status_rows)}")
if len(summary_rows) < 1:
    raise SystemExit("ASSERT FAIL: resolver full_stack 汇总至少应有 1 条成功记录")
PY

printf 'PASS: real multi-resolver dnslabctl backend campaign matrix generated at %s\n' "$OUT_DIR"
