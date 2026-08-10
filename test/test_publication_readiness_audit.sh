#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-publication-audit.XXXXXX")"
MATRIX_ROOT="$WORKDIR/matrix"
READY_OUT="$WORKDIR/ready"
TAMPERED_OUT="$WORKDIR/tampered"
BUNDLE_TAMPERED_OUT="$WORKDIR/bundle-tampered"
STATISTICS_TAMPERED_OUT="$WORKDIR/statistics-tampered"
DUPLICATE_CASE_OUT="$WORKDIR/duplicate-case"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

python3 - "$MATRIX_ROOT" <<'PY'
import hashlib
import json
import pathlib
import sys

from tools.dns_diff.aggregate import METRIC_NAMES, _extract_metrics
from tools.dns_diff.matrix import EXPECTED_VARIANT_ORDER
from tools.dns_diff.statistics import compute_metric_statistics

root = pathlib.Path(sys.argv[1]).resolve()
summary_dir = root / "_summary"
summary_dir.mkdir(parents=True, exist_ok=True)

seed_provenance = {
    "cold_start": True,
    "seed_source_dir": str(root / "seeds"),
    "seed_materialization_method": "filtered_from_source_corpus",
    "seed_snapshot_id": "a" * 40,
    "regen_seeds": True,
    "refilter_queries": True,
    "stable_input_dir": str(root / "stable"),
    "recorded_at": "2026-08-10T00:00:00Z",
}


def write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: pathlib.Path, payload: dict) -> None:
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def artifact_reference(path: pathlib.Path) -> dict:
    if not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "optional": False,
            "regeneration_command": "regen",
            "size_bytes": None,
            "sha256": None,
        }
    content = path.read_bytes()
    return {
        "path": str(path),
        "exists": True,
        "optional": False,
        "regeneration_command": "regen",
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def integrity(path: pathlib.Path) -> dict:
    content = path.read_bytes()
    return {
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


variants = []
for variant_index, variant_name in enumerate(EXPECTED_VARIANT_ORDER):
    runs = []
    for repeat_index in range(1, 6):
        run_dir = root / "matrix_runs" / variant_name / f"run-{repeat_index:02d}"
        report_dir = run_dir / "campaign_reports" / "20260810_000000"
        raw_root = run_dir / "follow_diff"
        sample_dir = raw_root / f"sample-{repeat_index:02d}"
        sample_dir.mkdir(parents=True, exist_ok=True)
        write_json(sample_dir / "sample.meta.json", {"sample_id": sample_dir.name})
        write_text(sample_dir / "sample.bin", "sample\n")

        metric_value = variant_index + repeat_index

        summary = {
            "contract_version": 1,
            "total_samples": metric_value * 10,
            "needs_review_count": metric_value,
            "cluster_count": metric_value,
            "repro_rate": metric_value / 10.0,
            "oracle_audit_candidate_count": metric_value,
            "semantic_diff_count": metric_value,
            "metric_denominators": {
                "analysis_state": {
                    "included": metric_value * 8,
                    "excluded": metric_value,
                    "unknown": metric_value,
                }
            },
            "comparability": {
                "status": "comparable",
                "aggregation_key": {"variant_name": variant_name},
                "baseline_compare_key": {"repeat_count": 5},
            },
            "seed_provenance": seed_provenance,
        }
        summary_path = report_dir / "summary.json"
        write_json(summary_path, summary)
        oracle_audit_path = report_dir / "oracle_audit.tsv"
        oracle_reliability_path = report_dir / "oracle_reliability.json"
        failure_taxonomy_path = report_dir / "failure_taxonomy.tsv"
        exclusion_summary_path = report_dir / "exclusion_summary.tsv"
        write_text(oracle_audit_path, "sample_id\toracle_diff\nsample\t1\n")
        write_json(oracle_reliability_path, {"signals": {"oracle_diff_any": True}})
        write_text(
            failure_taxonomy_path,
            "failure_bucket_primary\tfailure_bucket_detail\tcount\n"
            "semantic_diff\toracle_diff\t1\n",
        )
        write_text(
            exclusion_summary_path,
            "failure_bucket_primary\tanalysis_state\tcount\nsemantic_diff\tincluded\t1\n",
        )

        case_study_path = report_dir / "case_studies" / "index.tsv"
        if variant_index == 0 and repeat_index == 1:
            first_case_path = case_study_path.parent / "sample-a.json"
            second_case_path = case_study_path.parent / "sample-b.json"
            write_json(first_case_path, {"sample_id": "sample-a"})
            write_json(second_case_path, {"sample_id": "sample-b"})
            write_text(
                case_study_path,
                "sample_id\tsemantic_outcome\tselection_reason\tcase_study_path\n"
                f"sample-a\toracle_diff\trepresentative\t{first_case_path}\n"
                "sample-b\tcache_diff_interesting\trepresentative\t"
                f"{second_case_path}\n",
            )

        required_claims = (
            "semantic_diff_count",
            "included_samples",
            "excluded_samples",
            "unknown_samples",
            "repro_rate",
            "cluster_count",
        )
        analysis_state = summary["metric_denominators"]["analysis_state"]
        claim_values = {
            "semantic_diff_count": summary["semantic_diff_count"],
            "included_samples": analysis_state["included"],
            "excluded_samples": analysis_state["excluded"],
            "unknown_samples": analysis_state["unknown"],
            "repro_rate": summary["repro_rate"],
            "cluster_count": summary["cluster_count"],
        }
        claim_field_paths = {
            "semantic_diff_count": "semantic_diff_count",
            "included_samples": "metric_denominators.analysis_state.included",
            "excluded_samples": "metric_denominators.analysis_state.excluded",
            "unknown_samples": "metric_denominators.analysis_state.unknown",
            "repro_rate": "repro_rate",
            "cluster_count": "cluster_count",
        }
        case_study_reference = artifact_reference(case_study_path)
        case_study_reference["optional"] = True
        bundle = {
            "contract_name": "publication_evidence_bundle",
            "contract_version": 1,
            "campaign_summary": artifact_reference(summary_path),
            "oracle_audit": artifact_reference(oracle_audit_path),
            "oracle_reliability": artifact_reference(oracle_reliability_path),
            "failure_taxonomy": artifact_reference(failure_taxonomy_path),
            "exclusion_summary": artifact_reference(exclusion_summary_path),
            "case_study_index": case_study_reference,
            "raw_sample_root": {
                "path": str(raw_root),
                "exists": True,
                "sample_dir_pattern": "<raw_sample_root>/<sample_id>/",
                "claim_review_artifacts": ["sample.meta.json", "sample.bin"],
            },
            "seed_provenance": seed_provenance,
            "regeneration_commands": {
                "triage_rewrite": "regen-triage",
                "triage_report": "regen-triage-report",
                "campaign_report": "regen-campaign-report",
                "case_study_export": "regen-case-study",
            },
            "claims": [
                {
                    "claim": claim_name,
                    "artifact": "campaign_summary",
                    "value": claim_values[claim_name],
                    "source_file_path": str(summary_path),
                    "field_path": claim_field_paths[claim_name],
                    "regeneration_command": "regen",
                    "guardrail": "仅用于回归样本。",
                }
                for claim_name in required_claims
            ],
        }
        write_json(report_dir / "evidence_bundle.json", bundle)
        evidence_bundle_path = report_dir / "evidence_bundle.json"
        close_summary_path = run_dir / "campaign_close.summary.json"
        write_json(close_summary_path, {"status": "success", "exit_code": 0})
        runs.append(
            {
                "repeat_index": repeat_index,
                "run_dir": str(run_dir),
                "report_dir": str(report_dir),
                "summary_path": str(summary_path),
                "close_summary_path": str(close_summary_path),
                "evidence_bundle_path": str(evidence_bundle_path),
                "evidence_bundle_integrity": integrity(evidence_bundle_path),
            }
        )

    variants.append(
        {
            "variant_name": variant_name,
            "repeat_count": 5,
            "env": {},
            "runs": runs,
        }
    )

manifest = {
    "matrix_name": "publication-audit-fixture",
    "contract_version": 1,
    "repeat_count": 5,
    "statistics": {
        "confidence_level": 0.95,
        "confidence_interval_method": "student_t_df_le_30_normal_asymptotic",
        "sample_stddev_denominator": "n-1",
        "legacy_stddev_semantics": "population",
    },
    "variants": variants,
}
write_json(summary_dir / "matrix_manifest.json", manifest)

header = [
    "variant_name",
    "run_count",
    "variance_status",
    "aggregation_key",
    "baseline_compare_key",
]
for metric_name in METRIC_NAMES:
    for suffix in (
        "mean",
        "stddev",
        "sample_stddev",
        "standard_error",
        "ci95_lower",
        "ci95_upper",
    ):
        header.append(f"{metric_name}_{suffix}")

lines = ["\t".join(header)]
for variant_name in EXPECTED_VARIANT_ORDER:
    row = {
        "variant_name": variant_name,
        "run_count": "5",
        "variance_status": "ok",
        "aggregation_key": json.dumps({"variant_name": variant_name}),
        "baseline_compare_key": json.dumps({"repeat_count": 5}),
    }
    for metric_name in METRIC_NAMES:
        variant = next(item for item in variants if item["variant_name"] == variant_name)
        run_summaries = [
            json.loads(pathlib.Path(run["summary_path"]).read_text(encoding="utf-8"))
            for run in variant["runs"]
        ]
        stats = compute_metric_statistics(
            [_extract_metrics(summary)[metric_name] for summary in run_summaries]
        )
        for suffix in (
            "mean",
            "stddev",
            "sample_stddev",
            "standard_error",
            "ci95_lower",
            "ci95_upper",
        ):
            row[f"{metric_name}_{suffix}"] = f"{stats[suffix]:.6f}"
    lines.append("\t".join(row.get(column, "") for column in header))
write_text(summary_dir / "variant_summary.tsv", "\n".join(lines) + "\n")
PY

python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$READY_OUT" >/dev/null

python3 - "$READY_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ready":
    raise SystemExit(f"ASSERT FAIL: status={payload.get('status')!r} != 'ready'")
if payload.get("issue_count") != 0:
    raise SystemExit(f"ASSERT FAIL: issue_count={payload.get('issue_count')!r} != 0")
matrix = payload.get("matrices", [{}])[0]
if matrix.get("run_count") != 20:
    raise SystemExit(f"ASSERT FAIL: run_count={matrix.get('run_count')!r} != 20")
if matrix.get("case_study_count") != 2:
    raise SystemExit(
        f"ASSERT FAIL: case_study_count={matrix.get('case_study_count')!r} != 2"
    )
PY

REPORT_PATH="$MATRIX_ROOT/matrix_runs/full_stack/run-01/campaign_reports/20260810_000000"
ORACLE_AUDIT_PATH="$REPORT_PATH/oracle_audit.tsv"
EVIDENCE_BUNDLE_PATH="$REPORT_PATH/evidence_bundle.json"
VARIANT_SUMMARY_PATH="$MATRIX_ROOT/_summary/variant_summary.tsv"

printf '\n篡改\n' >>"$ORACLE_AUDIT_PATH"
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$TAMPERED_OUT" >/dev/null 2>"$WORKDIR/tampered.stderr"; then
	printf 'ASSERT FAIL: 证据被篡改后 publication-audit 应返回非零\n' >&2
	exit 1
fi

python3 - "$TAMPERED_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
codes = {
    issue.get("code")
    for matrix in payload.get("matrices", [])
    for issue in matrix.get("issues", [])
}
if "artifact_sha256_mismatch" not in codes:
    raise SystemExit(
        f"ASSERT FAIL: 篡改场景缺少 artifact_sha256_mismatch: {sorted(codes)!r}"
    )
PY

printf 'sample_id\toracle_diff\nsample\t1\n' >"$ORACLE_AUDIT_PATH"
cp "$EVIDENCE_BUNDLE_PATH" "$WORKDIR/evidence_bundle.original.json"
python3 - "$EVIDENCE_BUNDLE_PATH" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["audit_test_marker"] = "tampered"
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$BUNDLE_TAMPERED_OUT" >/dev/null 2>"$WORKDIR/bundle-tampered.stderr"; then
	printf 'ASSERT FAIL: evidence bundle 被篡改后 publication-audit 应返回非零\n' >&2
	exit 1
fi

python3 - "$BUNDLE_TAMPERED_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
codes = {
    issue.get("code")
    for matrix in payload.get("matrices", [])
    for issue in matrix.get("issues", [])
}
if "evidence_bundle_sha256_mismatch" not in codes:
    raise SystemExit(
        "ASSERT FAIL: 证据包篡改场景缺少 evidence_bundle_sha256_mismatch: "
        f"{sorted(codes)!r}"
    )
PY

cp "$WORKDIR/evidence_bundle.original.json" "$EVIDENCE_BUNDLE_PATH"
python3 - "$VARIANT_SUMMARY_PATH" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
    header = list(rows[0])
rows[0]["total_samples_mean"] = str(float(rows[0]["total_samples_mean"]) + 1.0)
with path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=header, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
PY

if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$STATISTICS_TAMPERED_OUT" >/dev/null 2>"$WORKDIR/statistics-tampered.stderr"; then
	printf 'ASSERT FAIL: 汇总统计被篡改后 publication-audit 应返回非零\n' >&2
	exit 1
fi

python3 - "$STATISTICS_TAMPERED_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
codes = {
    issue.get("code")
    for matrix in payload.get("matrices", [])
    for issue in matrix.get("issues", [])
}
if "statistic_value_mismatch" not in codes:
    raise SystemExit(
        f"ASSERT FAIL: 汇总统计篡改场景缺少 statistic_value_mismatch: {sorted(codes)!r}"
    )
PY

CASE_STUDY_INDEX_PATH="$REPORT_PATH/case_studies/index.tsv"
python3 - "$CASE_STUDY_INDEX_PATH" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open(encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
    header = list(rows[0])
rows[1]["sample_id"] = rows[0]["sample_id"]
with path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=header, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
PY

if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$DUPLICATE_CASE_OUT" >/dev/null 2>"$WORKDIR/duplicate-case.stderr"; then
	printf 'ASSERT FAIL: case study 重复后 publication-audit 应返回非零\n' >&2
	exit 1
fi

python3 - "$DUPLICATE_CASE_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
codes = {
    issue.get("code")
    for matrix in payload.get("matrices", [])
    for issue in matrix.get("issues", [])
}
if "duplicate_case_study" not in codes:
    raise SystemExit(
        f"ASSERT FAIL: 重复案例场景缺少 duplicate_case_study: {sorted(codes)!r}"
    )
PY

printf 'PASS: publication readiness audit regression test passed\n'
