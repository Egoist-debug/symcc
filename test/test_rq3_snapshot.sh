#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-rq3-snapshot.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

SOURCE_TSV="$WORKDIR/resolver_variant_summary.tsv"
OUT_DIR="$WORKDIR/out"

cat >"$SOURCE_TSV" <<'EOF'
matrix_name	matrix_root	resolver_pair	secondary_resolver	producer_profile	input_model	variant_name	run_count	variance_status	mutator	cache-delta	triage	symcc	aggregation_key	baseline_compare_key	runtime_env_json	total_samples_mean	total_samples_stddev	included_samples_mean	included_samples_stddev	excluded_samples_mean	excluded_samples_stddev	unknown_samples_mean	unknown_samples_stddev	needs_review_count_mean	needs_review_count_stddev	cluster_count_mean	cluster_count_stddev	repro_rate_mean	repro_rate_stddev	oracle_audit_candidate_count_mean	oracle_audit_candidate_count_stddev	semantic_diff_count_mean	semantic_diff_count_stddev
poison	/tmp/x	bind9_vs_unbound	unbound	poison-stateful	DST1 transcript	full_stack	2	ok	on	on	on	on	a	b	{}	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000
poison	/tmp/x	bind9_vs_unbound	unbound	poison-stateful	DST1 transcript	afl_only	2	ok	on	on	on	off	a	b	{}	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000
poison	/tmp/x	bind9_vs_unbound	unbound	poison-stateful	DST1 transcript	no_mutator	2	ok	off	on	on	on	a	b	{}	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000
poison	/tmp/x	bind9_vs_unbound	unbound	poison-stateful	DST1 transcript	no_cache_delta	2	ok	on	off	on	on	a	b	{}	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000
poison	/tmp/x	bind9_vs_unbound	unbound	poison-stateful	DST1 transcript	custom_variant	2	ok	on	on	on	on	a	b	{}	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000	0.000000	0.000000	1.000000	0.000000	1.000000	0.000000
EOF

python3 -m tools.dns_diff.cli rq3-snapshot \
  --resolver-variant-summary-tsv "$SOURCE_TSV" \
  --output-dir "$OUT_DIR" >/dev/null

test -f "$OUT_DIR/rq3_hybrid_snapshot.tsv"
test -f "$OUT_DIR/rq3_hybrid_snapshot.json"

python3 - "$OUT_DIR/rq3_hybrid_snapshot.tsv" "$OUT_DIR/rq3_hybrid_snapshot.json" <<'PY'
import csv
import json
import pathlib
import sys

tsv_path = pathlib.Path(sys.argv[1])
json_path = pathlib.Path(sys.argv[2])
rows = list(csv.DictReader(tsv_path.open(encoding="utf-8"), delimiter="\t"))
if len(rows) != 4:
    raise SystemExit(f"ASSERT FAIL: row_count={len(rows)!r} != 4")
variants = [row["variant_name"] for row in rows]
if variants != ["full_stack", "afl_only", "no_mutator", "no_cache_delta"]:
    raise SystemExit(f"ASSERT FAIL: variants={variants!r}")
payload = json.loads(json_path.read_text(encoding="utf-8"))
if payload.get("row_count") != 4:
    raise SystemExit(f"ASSERT FAIL: json row_count={payload.get('row_count')!r} != 4")
PY

printf 'PASS: rq3 snapshot smoke test passed\n'
