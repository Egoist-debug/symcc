#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/cleanup_run_root.sh"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
BASE_DIR="$ROOT_DIR/experiments/results/real_full_stack_multi_resolver_dnslabctl/$STAMP"
TRANSCRIPT_SOURCE_DIR="${TRANSCRIPT_SOURCE_DIR:-$ROOT_DIR/named_experiment/work/stable_transcript_corpus}"
QUEUE_LIMIT="${QUEUE_LIMIT:-4}"
REPEAT_COUNT="${REPEAT_COUNT:-5}"
BUDGET_SEC="${BUDGET_SEC:-12}"
RESOLVERS="${RESOLVERS:-unbound dnsmasq smartdns maradns knot}"
STATUS_TSV="$BASE_DIR/status.tsv"
mkdir -p "$BASE_DIR"
printf 'resolver\trepeat\tstatus\trun_root\treport_dir\n' >"$STATUS_TSV"

prepare_queue() {
	local queue_dir="$1"
	python3 - "$queue_dir" "$TRANSCRIPT_SOURCE_DIR" "$QUEUE_LIMIT" <<'PY'
from pathlib import Path
import json, shutil, sys
queue_dir = Path(sys.argv[1]); src_dir = Path(sys.argv[2]); limit = int(sys.argv[3])
queue_dir.mkdir(parents=True, exist_ok=True)
for i, src in enumerate(sorted(p for p in src_dir.iterdir() if p.is_file())[:limit], start=1):
    shutil.copyfile(src, queue_dir / f"id:{i:06d},orig:{src.name}")
payload = {"cold_start": False, "seed_source_dir": str(queue_dir.resolve()), "seed_materialization_method": "reused_filtered_corpus", "seed_snapshot_id": f"queue{limit:06d}", "regen_seeds": False, "refilter_queries": False, "stable_input_dir": str(queue_dir.resolve()), "recorded_at": "2026-05-22T07:30:00Z"}
(queue_dir.parents[2] / "producer_seed_provenance.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

resolve_report_dir() {
	local run_root="$1"
	find "$run_root" -type f -path '*/campaign_reports/*/summary.json' \
		-printf '%h\n' | sort | tail -n 1
}

salvage_run() {
	local run_root="$1" env_resolver="$2"
	if ! find "$run_root/follow_diff" -name sample.meta.json -print -quit | grep -q .; then
		return 1
	fi
	env ROOT_DIR="$ROOT_DIR" WORK_DIR="$run_root" DNS_DIFF_SECONDARY_RESOLVER="$env_resolver" ENABLE_DST1_MUTATOR=1 ENABLE_CACHE_DELTA=1 ENABLE_TRIAGE=1 ENABLE_SYMCC=1 python3 -m tools.dns_diff.cli triage-report >/dev/null
	env ROOT_DIR="$ROOT_DIR" WORK_DIR="$run_root" DNS_DIFF_SECONDARY_RESOLVER="$env_resolver" ENABLE_DST1_MUTATOR=1 ENABLE_CACHE_DELTA=1 ENABLE_TRIAGE=1 ENABLE_SYMCC=1 python3 -m tools.dns_diff.cli campaign-report --root "$run_root/follow_diff" >/dev/null
}

run_resolver() {
	local resolver="$1" src_var="" build_var="" src="" build="" env_resolver="" queue_dir="$BASE_DIR/$resolver/afl_out/master/queue" agg_root="$BASE_DIR/$resolver/aggregate_input"
	case "$resolver" in
		unbound) src="$ROOT_DIR/experiments/subjects/unbound/release-1.24.2"; build="$ROOT_DIR/experiments/subjects/unbound/release-1.24.2-build/unbound-afl" ;;
		dnsmasq) src="$ROOT_DIR/experiments/subjects/dnsmasq/v2.92"; build="$ROOT_DIR/experiments/subjects/dnsmasq/v2.92-build"; env_resolver="dnsmasq" ;;
		smartdns) src="$ROOT_DIR/experiments/subjects/smartdns/Release47.1"; build="$ROOT_DIR/experiments/subjects/smartdns/Release47.1-build"; env_resolver="smartdns" ;;
		maradns) src="$ROOT_DIR/experiments/subjects/maradns/deadwood-3.3.02"; build="$ROOT_DIR/experiments/subjects/maradns/deadwood-3.3.02-build"; env_resolver="maradns" ;;
		knot) src="$ROOT_DIR/experiments/subjects/knot-resolver/v6.2.0"; build="$ROOT_DIR/experiments/subjects/knot-resolver/v6.2.0-build"; env_resolver="knot-resolver" ;;
		*) printf 'ASSERT FAIL: 未知 resolver %s\n' "$resolver" >&2; exit 1 ;;
	esac
	prepare_queue "$queue_dir"
	mkdir -p "$agg_root"
	for repeat in $(seq 1 "$REPEAT_COUNT"); do
		local run_root="$BASE_DIR/$resolver/run-$(printf '%02d' "$repeat")" report_dir="" run_status="fail"
		mkdir -p "$run_root"
		if env ROOT_DIR="$ROOT_DIR" WORK_DIR="$run_root" FOLLOW_DIFF_SOURCE_DIR="$queue_dir" DNS_DIFF_REPLAY_BACKEND=dnslabctl ENABLE_DST1_MUTATOR=1 ENABLE_CACHE_DELTA=1 ENABLE_TRIAGE=1 ENABLE_SYMCC=1 DNS_DIFF_SECONDARY_RESOLVER="$env_resolver" BIND9_AFL_TREE="$ROOT_DIR/experiments/subjects/bind9/v9.20.22-build/bind9-afl" BIND9_SRC_TREE="$ROOT_DIR/experiments/subjects/bind9/v9.20.22" BIND9_NAMED_CONF_TEMPLATE="$ROOT_DIR/named_experiment/runtime/named.conf" RESPONSE_CORPUS_DIR="$ROOT_DIR/named_experiment/work/response_corpus" UNBOUND_SRC_TREE="$src" DNSMASQ_SRC_TREE="$src" SMARTDNS_SRC_TREE="$src" MARADNS_SRC_TREE="$src" KNOT_RESOLVER_SRC_TREE="$src" AFL_TREE="$build" DNSMASQ_BUILD_TREE="$build" SMARTDNS_BUILD_TREE="$build" MARADNS_BUILD_TREE="$build" KNOT_RESOLVER_BUILD_TREE="$build" python3 -m tools.dns_diff.cli campaign-close --budget-sec "$BUDGET_SEC"; then
			run_status="pass"
		elif salvage_run "$run_root" "$env_resolver"; then
			run_status="salvaged"
		fi
		report_dir="$(resolve_report_dir "$run_root" || true)"
		if [ -n "$report_dir" ]; then
			ln -sfn "$report_dir" "$agg_root/run-$(printf '%02d' "$repeat")"
		fi
		printf '%s\t%s\t%s\t%s\t%s\n' "$resolver" "$repeat" "$run_status" "$run_root" "${report_dir:--}" >>"$STATUS_TSV"
		cleanup_run_root_artifacts "$run_root"
	done
	if find "$agg_root" -maxdepth 1 -mindepth 1 | grep -q .; then
		python3 -m tools.dns_diff.cli campaign-aggregate --reports-root "$agg_root" --output-dir "$BASE_DIR/$resolver" >/dev/null
	fi
}

for resolver in $RESOLVERS; do
	run_resolver "$resolver"
done

python3 - "$BASE_DIR" "$QUEUE_LIMIT" "$BUDGET_SEC" <<'PY'
from pathlib import Path
import csv, json
import sys

base = Path(sys.argv[1])
queue_limit = str(sys.argv[2])
budget_sec = str(sys.argv[3])
rows = []
for resolver_dir in sorted(p for p in base.iterdir() if p.is_dir() and p.name not in ("manual_case_studies",)):
    agg_root = resolver_dir / "campaign_aggregates"
    if not agg_root.is_dir():
        continue
    agg_dir = sorted(p for p in agg_root.iterdir() if p.is_dir())[-1]
    agg_summary = json.loads((agg_dir / "summary.json").read_text(encoding="utf-8"))
    report_dirs = sorted((resolver_dir / "aggregate_input").iterdir())
    semantic_totals = {}
    for report_link in report_dirs:
        payload = json.loads((report_link.resolve() / "summary.json").read_text(encoding="utf-8"))
        for key, value in payload.get("semantic_counts", {}).items():
            semantic_totals[key] = semantic_totals.get(key, 0.0) + float(value)
    semantic_means = {key: round(value / len(report_dirs), 6) for key, value in sorted(semantic_totals.items())} if report_dirs else {}
    aggregates = agg_summary.get("aggregates", {})

    def mean_of(name: str) -> str:
        return f"{float(aggregates.get(name, {}).get('mean', 0.0)):.6f}"

    def std_of(name: str) -> str:
        return f"{float(aggregates.get(name, {}).get('stddev', 0.0)):.6f}"

    rows.append({
        "resolver": agg_summary.get("aggregation_key", {}).get("resolver_pair", "").replace("bind9_vs_", ""),
        "resolver_pair": agg_summary.get("aggregation_key", {}).get("resolver_pair", ""),
        "run_count": str(int(agg_summary.get("run_count", 0))),
        "variance_status": agg_summary.get("variance_status", ""),
        "queue_limit": queue_limit,
        "budget_sec": budget_sec,
        "total_samples_mean": mean_of("total_samples"),
        "total_samples_stddev": std_of("total_samples"),
        "unknown_samples_mean": mean_of("unknown_samples"),
        "unknown_samples_stddev": std_of("unknown_samples"),
        "needs_review_count_mean": mean_of("needs_review_count"),
        "needs_review_count_stddev": std_of("needs_review_count"),
        "cluster_count_mean": mean_of("cluster_count"),
        "cluster_count_stddev": std_of("cluster_count"),
        "oracle_audit_candidate_count_mean": mean_of("oracle_audit_candidate_count"),
        "semantic_diff_count_mean": mean_of("semantic_diff_count"),
        "semantic_counts_mean_json": json.dumps(semantic_means, ensure_ascii=False, sort_keys=True),
        "aggregate_dir": str(agg_dir),
    })

summary_tsv = base / "resolver_summary.tsv"
with summary_tsv.open("w", encoding="utf-8", newline="") as fh:
    fieldnames = list(rows[0].keys())
    writer = csv.DictWriter(fh, fieldnames=fieldnames, delimiter="\t")
    writer.writeheader()
    writer.writerows(rows)
(base / "resolver_summary.json").write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(summary_tsv)
PY

printf 'PASS: real full-stack multi-resolver batch generated at %s\n' "$BASE_DIR"

cleanup_experiment_base "$BASE_DIR"
