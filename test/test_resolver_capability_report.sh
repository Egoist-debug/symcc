#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-resolver-capability-report.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

python3 - "$WORKDIR" <<'PY'
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
replay_dir = root / "replay"
batch_dir = root / "batch"
out_dir = root / "out"
replay_dir.mkdir(parents=True, exist_ok=True)
(batch_dir / "_resolver_summary").mkdir(parents=True, exist_ok=True)

(replay_dir / "matrix.tsv").write_text(
    "\n".join(
        [
            "resolver\tcapability\tstatus\tstarted_at\tfinished_at\tscript",
            "unbound\treplay_real\tpass\t2026-05-14T07:03:00Z\t2026-05-14T07:03:01Z\ttest_unbound.sh",
            "smartdns\tbuild_real\tpass\t2026-05-14T07:03:02Z\t2026-05-14T07:03:04Z\ttest_smartdns_build.sh",
            "smartdns\treplay_real\tpass\t2026-05-14T07:03:04Z\t2026-05-14T07:03:07Z\ttest_smartdns_replay.sh",
        ]
    )
    + "\n",
    encoding="utf-8",
)

(batch_dir / "matrix_run_status.tsv").write_text(
    "\n".join(
        [
            "resolver\tstatus\twork_root\tmatrix_file",
            "unbound\tpass\t/tmp/unbound\tcfg-unbound.json",
            "smartdns\tpass\t/tmp/smartdns\tcfg-smartdns.json",
        ]
    )
    + "\n",
    encoding="utf-8",
)

(batch_dir / "_resolver_summary" / "resolver_full_stack.tsv").write_text(
    "\n".join(
        [
            "matrix_name\tmatrix_root\tresolver_pair\tsecondary_resolver\tproducer_profile\tinput_model\tvariant_name\trun_count\tvariance_status\tmutator\tcache-delta\ttriage\tsymcc\taggregation_key\tbaseline_compare_key\truntime_env_json\ttotal_samples_mean\ttotal_samples_stddev\tincluded_samples_mean\tincluded_samples_stddev\texcluded_samples_mean\texcluded_samples_stddev\tunknown_samples_mean\tunknown_samples_stddev\tneeds_review_count_mean\tneeds_review_count_stddev\tcluster_count_mean\tcluster_count_stddev\trepro_rate_mean\trepro_rate_stddev\toracle_audit_candidate_count_mean\toracle_audit_candidate_count_stddev\tsemantic_diff_count_mean\tsemantic_diff_count_stddev",
            "poison_stateful_longbudget\t/tmp/unbound\tbind9_vs_unbound\tunbound\tpoison-stateful\tDST1 transcript\tfull_stack\t2\tok\ton\ton\ton\ton\tagg1\tbase1\t{}\t1.000000\t0.000000\t1.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000\t1.000000\t0.000000\t1.000000\t0.000000\t0.000000\t0.000000\t1.000000\t0.000000\t1.000000\t0.000000",
            "poison_stateful_smartdns_longbudget\t/tmp/smartdns\tbind9_vs_smartdns\tsmartdns\tpoison-stateful\tDST1 transcript\tfull_stack\t2\tok\ton\ton\ton\ton\tagg2\tbase2\t{\"DNS_DIFF_SECONDARY_RESOLVER\":\"smartdns\"}\t1.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000\t1.000000\t0.000000\t1.000000\t0.000000\t1.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000",
        ]
    )
    + "\n",
    encoding="utf-8",
)

for resolver, payload in {
    "unbound": {"oracle_and_cache_diff": 1},
    "smartdns": {"runtime_or_parse_failure": 1},
}.items():
    report_dir = batch_dir / resolver / "matrix_runs" / "full_stack" / "run-01" / "campaign_reports" / "report-01"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "summary.json").write_text(
        json.dumps({"semantic_counts": payload}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

cmd = [
    "python3",
    "-m",
    "tools.dns_diff.cli",
    "resolver-capability-report",
    "--replay-matrix-dir",
    str(replay_dir),
    "--matrix-batch-dir",
    str(batch_dir),
    "--output-dir",
    str(out_dir),
]
completed = subprocess.run(cmd, cwd=pathlib.Path.cwd(), check=False, capture_output=True, text=True)
if completed.returncode != 0:
    raise SystemExit(
        f"ASSERT FAIL: resolver-capability-report 返回 {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )

summary_tsv = out_dir / "resolver_capability_summary.tsv"
summary_json = out_dir / "resolver_capability_summary.json"
adapter_cost_tsv = out_dir / "resolver_adapter_cost.tsv"
availability_tsv = out_dir / "resolver_build_replay_matrix.tsv"
semantic_tsv = out_dir / "resolver_semantic_distribution.tsv"
if not summary_tsv.is_file() or not summary_json.is_file():
    raise SystemExit("ASSERT FAIL: resolver capability 报告文件缺失")
for path in (adapter_cost_tsv, availability_tsv, semantic_tsv):
    if not path.is_file():
        raise SystemExit(f"ASSERT FAIL: 缺少派生 TSV {path}")

tsv_text = summary_tsv.read_text(encoding="utf-8")
if "unbound\tbind9_vs_unbound\tnative_orchestrator\thigh\tobservable\tpass\t" not in tsv_text:
    raise SystemExit("ASSERT FAIL: summary.tsv 缺少 unbound 行")
if "smartdns\tbind9_vs_smartdns\tpython_harness\tlow\tobservable\tpass\tpass\t2.000000\tpass\t3.000000" not in tsv_text:
    raise SystemExit("ASSERT FAIL: summary.tsv 缺少 smartdns build/replay duration")
if 'oracle_and_cache_diff' not in tsv_text:
    raise SystemExit("ASSERT FAIL: summary.tsv 缺少 semantic_counts 快照")

payload = json.loads(summary_json.read_text(encoding="utf-8"))
if payload.get("record_count") != 2:
    raise SystemExit(f"ASSERT FAIL: record_count={payload.get('record_count')!r} != 2")
outputs = payload.get("outputs", {})
for key in (
    "resolver_adapter_cost_tsv",
    "resolver_build_replay_matrix_tsv",
    "resolver_semantic_distribution_tsv",
):
    if key not in outputs:
        raise SystemExit(f"ASSERT FAIL: outputs 缺少键 {key}")
PY

printf 'PASS: resolver capability report smoke test passed\n'
