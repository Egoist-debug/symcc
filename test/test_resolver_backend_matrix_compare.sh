#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-resolver-backend-compare.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

python3 - "$WORKDIR" <<'PY'
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
baseline = root / "python"
candidate = root / "dnslabctl"
out_dir = root / "out"
(baseline / "_resolver_summary").mkdir(parents=True, exist_ok=True)
(candidate / "_resolver_summary").mkdir(parents=True, exist_ok=True)

(baseline / "matrix_run_status.tsv").write_text(
    "\n".join(
        [
            "resolver\tstatus\twork_root\tmatrix_file",
            "unbound\tpass\t/tmp/python-unbound\tcfg-a.json",
            "dnsmasq\tpass\t/tmp/python-dnsmasq\tcfg-b.json",
        ]
    )
    + "\n",
    encoding="utf-8",
)
(candidate / "matrix_run_status.tsv").write_text(
    "\n".join(
        [
            "resolver\tstatus\twork_root\tmatrix_file",
            "unbound\tpass\t/tmp/cpp-unbound\tcfg-a.json",
            "dnsmasq\tpass\t/tmp/cpp-dnsmasq\tcfg-b.json",
        ]
    )
    + "\n",
    encoding="utf-8",
)

header = "matrix_name\tmatrix_root\tresolver_pair\tsecondary_resolver\tproducer_profile\tinput_model\tvariant_name\trun_count\tvariance_status\tmutator\tcache-delta\ttriage\tsymcc\taggregation_key\tbaseline_compare_key\truntime_env_json\ttotal_samples_mean\ttotal_samples_stddev\tincluded_samples_mean\tincluded_samples_stddev\texcluded_samples_mean\texcluded_samples_stddev\tunknown_samples_mean\tunknown_samples_stddev\tneeds_review_count_mean\tneeds_review_count_stddev\tcluster_count_mean\tcluster_count_stddev\trepro_rate_mean\trepro_rate_stddev\toracle_audit_candidate_count_mean\toracle_audit_candidate_count_stddev\tsemantic_diff_count_mean\tsemantic_diff_count_stddev"
(baseline / "_resolver_summary" / "resolver_full_stack.tsv").write_text(
    "\n".join(
        [
            header,
            "m1\t/tmp/python-unbound\tbind9_vs_unbound\tunbound\tpoison-stateful\tDST1 transcript\tfull_stack\t2\tok\ton\ton\ton\ton\ta\tb\t{}\t1\t0\t1\t0\t0\t0\t0\t0\t1\t0\t1\t0\t0\t0\t1\t0\t1\t0",
            "m2\t/tmp/python-dnsmasq\tbind9_vs_dnsmasq\tdnsmasq\tpoison-stateful\tDST1 transcript\tfull_stack\t2\tok\ton\ton\ton\ton\ta\tb\t{}\t1\t0\t1\t0\t0\t0\t0\t0\t1\t0\t1\t0\t0\t0\t0\t0\t0\t0",
        ]
    )
    + "\n",
    encoding="utf-8",
)
(candidate / "_resolver_summary" / "resolver_full_stack.tsv").write_text(
    "\n".join(
        [
            header,
            "m1\t/tmp/cpp-unbound\tbind9_vs_unbound\tunbound\tpoison-stateful\tDST1 transcript\tfull_stack\t1\tinsufficient_runs\ton\ton\ton\ton\ta\tb\t{}\t1\t0\t1\t0\t0\t0\t0\t0\t1\t0\t1\t0\t0\t0\t1\t0\t1\t0",
            "m2\t/tmp/cpp-dnsmasq\tbind9_vs_dnsmasq\tdnsmasq\tpoison-stateful\tDST1 transcript\tfull_stack\t1\tinsufficient_runs\ton\ton\ton\ton\ta\tb\t{}\t1\t0\t1\t0\t0\t0\t0\t0\t1\t0\t1\t0\t0\t0\t0\t0\t0\t0",
        ]
    )
    + "\n",
    encoding="utf-8",
)

cmd = [
    "python3",
    "-m",
    "tools.dns_diff.cli",
    "resolver-backend-matrix-compare",
    "--baseline-batch-dir",
    str(baseline),
    "--candidate-batch-dir",
    str(candidate),
    "--baseline-label",
    "python",
    "--candidate-label",
    "dnslabctl",
    "--output-dir",
    str(out_dir),
]
completed = subprocess.run(cmd, cwd=pathlib.Path.cwd(), check=False, capture_output=True, text=True)
if completed.returncode != 0:
    raise SystemExit(
        f"ASSERT FAIL: resolver-backend-matrix-compare 返回 {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )

tsv = out_dir / "resolver_backend_compare.tsv"
if not tsv.is_file():
    raise SystemExit("ASSERT FAIL: 缺少 resolver_backend_compare.tsv")
text = tsv.read_text(encoding="utf-8")
if "unbound\tbind9_vs_unbound\tpass\tpass\t2\t1\tok\tinsufficient_runs" not in text:
    raise SystemExit("ASSERT FAIL: compare tsv 缺少 unbound 行")
PY

printf 'PASS: resolver backend matrix compare smoke test passed\n'
