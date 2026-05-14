#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-resolver-matrix-aggregate.XXXXXX")"
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
matrix_a = root / "unbound"
matrix_b = root / "knot"
out_dir = root / "out"

header = [
    "variant_name",
    "run_count",
    "variance_status",
    "mutator",
    "cache-delta",
    "triage",
    "symcc",
    "aggregation_key",
    "baseline_compare_key",
    "total_samples_mean",
    "total_samples_stddev",
    "cluster_count_mean",
    "cluster_count_stddev",
]

def write_matrix_root(base: pathlib.Path, *, matrix_name: str, resolver_pair: str, runtime_env: dict[str, str], total: str, cluster: str) -> None:
    summary_dir = base / "_summary"
    summary_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "matrix_name": matrix_name,
        "resolver_pair": resolver_pair,
        "producer_profile": "poison-stateful",
        "input_model": "DST1 transcript",
        "runtime_env": runtime_env,
    }
    (summary_dir / "matrix_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    rows = [
        header,
        [
            "full_stack",
            "5",
            "ok",
            "on",
            "on",
            "on",
            "on",
            "agg-a",
            "base-a",
            total,
            "1.000000",
            cluster,
            "0.500000",
        ],
        [
            "afl_only",
            "5",
            "ok",
            "on",
            "on",
            "on",
            "off",
            "agg-b",
            "base-a",
            "80.000000",
            "2.000000",
            "15.000000",
            "0.700000",
        ],
    ]
    (summary_dir / "variant_summary.tsv").write_text(
        "\n".join("\t".join(row) for row in rows) + "\n",
        encoding="utf-8",
    )

write_matrix_root(
    matrix_a,
    matrix_name="poison_stateful_unbound_longbudget",
    resolver_pair="bind9_vs_unbound",
    runtime_env={},
    total="100.000000",
    cluster="20.000000",
)
write_matrix_root(
    matrix_b,
    matrix_name="poison_stateful_knot_longbudget",
    resolver_pair="bind9_vs_knot-resolver",
    runtime_env={"DNS_DIFF_SECONDARY_RESOLVER": "knot-resolver"},
    total="96.000000",
    cluster="18.000000",
)

cmd = [
    "python3",
    "-m",
    "tools.dns_diff.cli",
    "resolver-matrix-aggregate",
    "--matrix-root",
    str(matrix_a),
    "--matrix-root",
    str(matrix_b),
    "--output-dir",
    str(out_dir),
]
completed = subprocess.run(
    cmd,
    cwd=pathlib.Path.cwd(),
    check=False,
    capture_output=True,
    text=True,
)
if completed.returncode != 0:
    raise SystemExit(
        f"ASSERT FAIL: resolver-matrix-aggregate 返回 {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )

variant_summary = out_dir / "resolver_variant_summary.tsv"
full_stack = out_dir / "resolver_full_stack.tsv"
manifest = out_dir / "resolver_matrix_manifest.json"
for path in (variant_summary, full_stack, manifest):
    if not path.is_file():
        raise SystemExit(f"ASSERT FAIL: 缺少输出文件 {path}")

variant_lines = variant_summary.read_text(encoding="utf-8").splitlines()
if not any("bind9_vs_unbound\tunbound" in line for line in variant_lines[1:]):
    raise SystemExit("ASSERT FAIL: resolver_variant_summary.tsv 缺少 unbound 行")
if not any("bind9_vs_knot-resolver\tknot-resolver" in line for line in variant_lines[1:]):
    raise SystemExit("ASSERT FAIL: resolver_variant_summary.tsv 缺少 knot-resolver 行")

full_stack_lines = full_stack.read_text(encoding="utf-8").splitlines()
if len(full_stack_lines) != 3:
    raise SystemExit(f"ASSERT FAIL: resolver_full_stack.tsv 行数非法: {len(full_stack_lines)}")
if any("\tafl_only\t" in line for line in full_stack_lines[1:]):
    raise SystemExit("ASSERT FAIL: resolver_full_stack.tsv 不应包含 afl_only")

manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
if manifest_payload.get("record_count") != 4:
    raise SystemExit(f"ASSERT FAIL: record_count={manifest_payload.get('record_count')!r} != 4")
PY

printf 'PASS: resolver matrix aggregate smoke test passed\n'
