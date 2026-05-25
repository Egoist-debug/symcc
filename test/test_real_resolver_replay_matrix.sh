#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-real-resolver-replay-matrix.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

OUT_DIR="$(
	env RESULT_ROOT_BASE="$WORKDIR/out" \
		"$ROOT_DIR/scripts/run_real_resolver_replay_matrix.sh"
)"

[ -f "$OUT_DIR/matrix.tsv" ] || {
	printf 'ASSERT FAIL: 缺少 matrix.tsv\n' >&2
	exit 1
}
[ -f "$OUT_DIR/manifest.json" ] || {
	printf 'ASSERT FAIL: 缺少 manifest.json\n' >&2
	exit 1
}

python3 - "$OUT_DIR/matrix.tsv" "$OUT_DIR/manifest.json" <<'PY'
import csv
import json
import pathlib
import sys

tsv_path = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
rows = list(csv.DictReader(tsv_path.open(encoding="utf-8"), delimiter="\t"))
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

if not rows:
    raise SystemExit("ASSERT FAIL: replay matrix 为空")
if manifest.get("record_count") != len(rows):
    raise SystemExit(
        f"ASSERT FAIL: manifest.record_count={manifest.get('record_count')!r} != {len(rows)!r}"
    )

expected = {
    ("unbound", "build_real"),
    ("unbound", "replay_real"),
    ("dnsmasq", "build_real"),
    ("dnsmasq", "replay_real"),
    ("smartdns", "build_real"),
    ("smartdns", "replay_real"),
    ("maradns", "build_real"),
    ("maradns", "replay_real"),
    ("knot-resolver", "build_real"),
    ("knot-resolver", "replay_real"),
    ("knot-resolver", "sync_secondary_real"),
}
actual = {(row["resolver"], row["capability"]) for row in rows}
missing = sorted(expected - actual)
if missing:
    raise SystemExit(f"ASSERT FAIL: replay matrix 缺少记录 {missing!r}")
PY

printf 'PASS: real resolver replay matrix generated at %s\n' "$OUT_DIR"
