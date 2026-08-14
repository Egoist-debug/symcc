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
INCOMPLETE_KEY_OUT="$WORKDIR/incomplete-key"
INVALID_KEY_VALUE_OUT="$WORKDIR/invalid-key-value"
INCONSISTENT_KEY_OUT="$WORKDIR/inconsistent-key"
EMPTY_CASE_OUT="$WORKDIR/empty-case"
FIXED_QUEUE_OUT="$WORKDIR/fixed-queue"
MISSING_PRODUCER_OUT="$WORKDIR/missing-producer"
PLACEHOLDER_REVIEWER_OUT="$WORKDIR/placeholder-reviewer"
HIGHER_THRESHOLD_OUT="$WORKDIR/higher-threshold"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

assert_audit_issue() {
	local json_path="$1"
	local expected_code="$2"
	python3 - "$json_path" "$expected_code" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
codes = {
    issue.get("code")
    for matrix in payload.get("matrices", [])
    for issue in matrix.get("issues", [])
}
if sys.argv[2] not in codes:
    raise SystemExit(
        f"ASSERT FAIL: 缺少 issue code {sys.argv[2]!r}: {sorted(codes)!r}"
    )
PY
}

python3 - "$MATRIX_ROOT" <<'PY'
import hashlib
import json
import pathlib
import sys

from tools.dns_diff.aggregate import METRIC_NAMES, _extract_metrics
from tools.dns_diff.matrix import EXPECTED_VARIANT_ENVS, EXPECTED_VARIANT_ORDER
from tools.dns_diff.publication_audit import (
    QUEUE_SNAPSHOT_DIGEST_ALGORITHM,
    _queue_snapshot_digest,
)
from tools.dns_diff.statistics import compute_metric_statistics

root = pathlib.Path(sys.argv[1]).resolve()


def manifest_queue_snapshot_digest(path: pathlib.Path):
    """模拟 producer_execution_manifest 写入端的固定摘要算法。"""
    digest = hashlib.sha256()
    file_count = 0
    size_bytes = 0
    for artifact_path in sorted(path.rglob("*")):
        if not artifact_path.is_file():
            continue
        relative_path = artifact_path.relative_to(path).as_posix()
        size = artifact_path.stat().st_size
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(artifact_path.read_bytes())
        digest.update(b"\0")
        file_count += 1
        size_bytes += size
    return digest.hexdigest(), file_count, size_bytes


summary_dir = root / "_summary"
summary_dir.mkdir(parents=True, exist_ok=True)
source_queue_dir = root / "source_queue"
source_queue_dir.mkdir(parents=True, exist_ok=True)
write_source_queue_later = source_queue_dir / "seed"

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


def ablation_status(env: dict) -> dict:
    return {
        "mutator": "on" if env["ENABLE_DST1_MUTATOR"] == "1" else "off",
        "cache-delta": "on" if env["ENABLE_CACHE_DELTA"] == "1" else "off",
        "triage": "on" if env["ENABLE_TRIAGE"] == "1" else "off",
        "symcc": "on" if env["ENABLE_SYMCC"] == "1" else "off",
    }


def aggregation_key(variant_name: str) -> dict:
    return {
        "resolver_pair": "bind9_vs_unbound",
        "producer_profile": "poison-stateful",
        "input_model": "DST1 transcript",
        "source_queue_dir": str(source_queue_dir),
        "budget_sec": 60,
        "seed_timeout_sec": 5,
        "variant_name": variant_name,
        "ablation_status": ablation_status(EXPECTED_VARIANT_ENVS[variant_name]),
        "contract_version": 1,
    }


def baseline_compare_key() -> dict:
    return {
        "resolver_pair": "bind9_vs_unbound",
        "producer_profile": "poison-stateful",
        "input_model": "DST1 transcript",
        "source_queue_dir": str(source_queue_dir),
        "budget_sec": 60,
        "seed_timeout_sec": 5,
        "repeat_count": 5,
        "contract_version": 1,
    }


def create_case_study(
    report_dir: pathlib.Path,
    raw_root: pathlib.Path,
    sample_id: str,
    semantic_outcome: str,
    selection_reason: str,
) -> pathlib.Path:
    sample_dir = raw_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    oracle = {"bind9.parse_ok": True, "unbound.parse_ok": True}
    write_json(sample_dir / "sample.meta.json", {"sample_id": sample_id})
    write_text(sample_dir / "sample.bin", f"DST1-{sample_id}\n")
    write_json(sample_dir / "oracle.json", oracle)
    write_text(sample_dir / "bind9.stderr", "bind9 log\n")
    write_text(sample_dir / "unbound.stderr", "unbound log\n")
    for resolver in ("bind9", "unbound"):
        write_text(sample_dir / f"{resolver}.before.cache.txt", "before\n")
        write_text(sample_dir / f"{resolver}.after.cache.txt", "after\n")

    case_study_path = report_dir / "case_studies" / f"{sample_id}.json"
    paths = {
        "sample_bin_path": str(sample_dir / "sample.bin"),
        "oracle_path": str(sample_dir / "oracle.json"),
        "bind9_stderr_path": str(sample_dir / "bind9.stderr"),
        "unbound_stderr_path": str(sample_dir / "unbound.stderr"),
        "bind9_before_cache_path": str(sample_dir / "bind9.before.cache.txt"),
        "bind9_after_cache_path": str(sample_dir / "bind9.after.cache.txt"),
        "unbound_before_cache_path": str(sample_dir / "unbound.before.cache.txt"),
        "unbound_after_cache_path": str(sample_dir / "unbound.after.cache.txt"),
    }
    write_json(
        case_study_path,
        {
            "sample_id": sample_id,
            "selection_reason": selection_reason,
            "replay_command": f"dnslabctl sync-replay --sample {sample_dir / 'sample.bin'}",
            "raw_evidence": {
                "resolver_context": {"primary": "bind9", "secondary": "unbound"},
                "paths": paths,
                "oracle": oracle,
                "stderr": {
                    "bind9": {
                        "path": paths["bind9_stderr_path"],
                        "exists": True,
                    },
                    "unbound": {
                        "path": paths["unbound_stderr_path"],
                        "exists": True,
                    },
                },
            },
            "automated_summary": {"semantic_outcome": semantic_outcome},
            "manual_truth": {
                "status": "confirmed_relevant",
                "reviewer_primary": "reviewer-a",
                "reviewer_secondary": "reviewer-b",
                "adjudicator": "reviewer-c",
                "judgment": "confirmed",
                "notes": "fixture",
                "decided_at": "2026-08-10T00:00:00Z",
            },
        },
    )
    return case_study_path


write_text(write_source_queue_later, "matrix source\n")


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

        queue_snapshot_dir = run_dir / "producer_queue_snapshot"
        write_text(
            queue_snapshot_dir / f"id:{variant_name},{repeat_index:06d}",
            f"{variant_name}-{repeat_index}\n",
        )
        queue_sha256, queue_file_count, queue_size_bytes = _queue_snapshot_digest(
            queue_snapshot_dir
        )
        manifest_sha256, manifest_file_count, manifest_size_bytes = (
            manifest_queue_snapshot_digest(queue_snapshot_dir)
        )
        if (queue_sha256, queue_file_count, queue_size_bytes) != (
            manifest_sha256,
            manifest_file_count,
            manifest_size_bytes,
        ):
            raise SystemExit(
                "ASSERT FAIL: publication audit queue snapshot 摘要与 producer manifest 契约不一致"
            )
        producer_manifest_path = run_dir / "producer_execution_manifest.json"
        write_json(
            producer_manifest_path,
            {
                "contract_name": "rq3_producer_execution_manifest",
                "contract_version": 1,
                "status": "success",
                "exit_code": 0,
                "variant_name": variant_name,
                "repeat_index": repeat_index,
                "producer_run_id": f"{variant_name}-producer-{repeat_index}",
                "random_seed": f"{variant_index + 1}{repeat_index:02d}",
                "started_at": "2026-08-10T00:00:00Z",
                "finished_at": "2026-08-10T00:01:00Z",
                "toggles": EXPECTED_VARIANT_ENVS[variant_name],
                "components": {
                    "symcc": {
                        "enabled": EXPECTED_VARIANT_ENVS[variant_name]["ENABLE_SYMCC"] == "1",
                        "started": EXPECTED_VARIANT_ENVS[variant_name]["ENABLE_SYMCC"] == "1",
                    }
                },
                "queue_snapshot": {
                    "path": str(queue_snapshot_dir),
                    "snapshot_id": f"{variant_name}-queue-{repeat_index}",
                    "algorithm": QUEUE_SNAPSHOT_DIGEST_ALGORITHM,
                    "file_count": queue_file_count,
                    "size_bytes": queue_size_bytes,
                    "sha256": queue_sha256,
                },
            },
        )

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
                "aggregation_key": aggregation_key(variant_name),
                "baseline_compare_key": baseline_compare_key(),
            },
            "seed_provenance": seed_provenance,
        }
        summary_path = report_dir / "summary.json"
        write_json(summary_path, summary)
        oracle_audit_path = report_dir / "oracle_audit.tsv"
        oracle_reliability_path = report_dir / "oracle_reliability.json"
        failure_taxonomy_path = report_dir / "failure_taxonomy.tsv"
        exclusion_summary_path = report_dir / "exclusion_summary.tsv"
        cluster_path = report_dir / "cluster.tsv"
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
        write_text(
            cluster_path,
            "cluster_key\tsample_count\tsample_ids\n"
            f"cluster-{variant_name}\t1\tsample-{repeat_index:02d}\n",
        )

        case_study_path = report_dir / "case_studies" / "index.tsv"
        if variant_index == 0 and repeat_index == 1:
            first_case_path = create_case_study(
                report_dir,
                raw_root,
                "sample-a",
                "oracle_diff",
                "representative-a",
            )
            second_case_path = create_case_study(
                report_dir,
                raw_root,
                "sample-b",
                "cache_diff_interesting",
                "representative-b",
            )
            write_text(
                case_study_path,
                "sample_id\tsemantic_outcome\tselection_reason\tcase_study_path\n"
                f"sample-a\toracle_diff\trepresentative-a\t{first_case_path}\n"
                "sample-b\tcache_diff_interesting\trepresentative-b\t"
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
            "cluster": artifact_reference(cluster_path),
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
                "producer_execution_manifest_path": str(producer_manifest_path),
            }
        )

    variants.append(
        {
            "variant_name": variant_name,
            "repeat_count": 5,
            "env": EXPECTED_VARIANT_ENVS[variant_name],
            "runs": runs,
        }
    )

manifest = {
    "matrix_name": "publication-audit-fixture",
    "contract_version": 1,
    "resolver_pair": "bind9_vs_unbound",
    "producer_profile": "poison-stateful",
    "input_model": "DST1 transcript",
    "source_queue_dir": str(source_queue_dir),
    "budget_sec": 60,
    "seed_timeout_sec": 5,
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
        "aggregation_key": json.dumps(aggregation_key(variant_name)),
        "baseline_compare_key": json.dumps(baseline_compare_key()),
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

if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--minimum-runs 4 >/dev/null 2>"$WORKDIR/minimum-runs.stderr"; then
	printf 'ASSERT FAIL: --minimum-runs=4 应被论文硬门槛拒绝\n' >&2
	exit 1
fi
grep -F -- '--minimum-runs 不得低于论文硬门槛 5' \
	"$WORKDIR/minimum-runs.stderr" >/dev/null

if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--minimum-case-studies 1 >/dev/null 2>"$WORKDIR/minimum-case-studies.stderr"; then
	printf 'ASSERT FAIL: --minimum-case-studies=1 应被论文硬门槛拒绝\n' >&2
	exit 1
fi
grep -F -- '--minimum-case-studies 不得低于论文硬门槛 2' \
	"$WORKDIR/minimum-case-studies.stderr" >/dev/null

if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--minimum-runs 6 \
	--minimum-case-studies 3 \
	--output-dir "$HIGHER_THRESHOLD_OUT" \
	>/dev/null 2>"$WORKDIR/higher-threshold.stderr"; then
	printf 'ASSERT FAIL: 更高门槛在当前 5-run fixture 上应审计不通过\n' >&2
	exit 1
fi
python3 - "$HIGHER_THRESHOLD_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("minimum_runs") != 6 or payload.get("minimum_case_studies") != 3:
    raise SystemExit("ASSERT FAIL: 更高 publication 门槛未进入实际审计")
PY

REPORT_PATH="$MATRIX_ROOT/matrix_runs/full_stack/run-01/campaign_reports/20260810_000000"
ORACLE_AUDIT_PATH="$REPORT_PATH/oracle_audit.tsv"
EVIDENCE_BUNDLE_PATH="$REPORT_PATH/evidence_bundle.json"
VARIANT_SUMMARY_PATH="$MATRIX_ROOT/_summary/variant_summary.tsv"
RUN_SUMMARY_PATH="$REPORT_PATH/summary.json"
CASE_STUDY_A_PATH="$REPORT_PATH/case_studies/sample-a.json"
PRODUCER_MANIFEST_PATH="$MATRIX_ROOT/matrix_runs/full_stack/run-01/producer_execution_manifest.json"
SECOND_PRODUCER_MANIFEST_PATH="$MATRIX_ROOT/matrix_runs/full_stack/run-02/producer_execution_manifest.json"
FIRST_QUEUE_SNAPSHOT="$MATRIX_ROOT/matrix_runs/full_stack/run-01/producer_queue_snapshot"
SECOND_QUEUE_SNAPSHOT="$MATRIX_ROOT/matrix_runs/full_stack/run-02/producer_queue_snapshot"

cp "$RUN_SUMMARY_PATH" "$WORKDIR/run-summary.original.json"
python3 - "$RUN_SUMMARY_PATH" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
del payload["comparability"]["aggregation_key"]["producer_profile"]
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$INCOMPLETE_KEY_OUT" >/dev/null 2>"$WORKDIR/incomplete-key.stderr"; then
	printf 'ASSERT FAIL: 残缺 aggregation_key 应使 publication-audit 返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$INCOMPLETE_KEY_OUT/publication_readiness.json" \
	"invalid_comparability_key_fields"
cp "$WORKDIR/run-summary.original.json" "$RUN_SUMMARY_PATH"

python3 - "$RUN_SUMMARY_PATH" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["comparability"]["aggregation_key"]["producer_profile"] = "replay-only"
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$INVALID_KEY_VALUE_OUT" >/dev/null 2>"$WORKDIR/invalid-key-value.stderr"; then
	printf 'ASSERT FAIL: aggregation_key 固定语义错误时应返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$INVALID_KEY_VALUE_OUT/publication_readiness.json" \
	"comparability_key_value_mismatch"
cp "$WORKDIR/run-summary.original.json" "$RUN_SUMMARY_PATH"

python3 - "$RUN_SUMMARY_PATH" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["comparability"]["aggregation_key"]["budget_sec"] = 61
payload["comparability"]["baseline_compare_key"]["budget_sec"] = 61
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$INCONSISTENT_KEY_OUT" >/dev/null 2>"$WORKDIR/inconsistent-key.stderr"; then
	printf 'ASSERT FAIL: 跨 run 比较键不一致时应返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$INCONSISTENT_KEY_OUT/publication_readiness.json" \
	"aggregation_key_summary_mismatch"
assert_audit_issue \
	"$INCONSISTENT_KEY_OUT/publication_readiness.json" \
	"baseline_key_summary_mismatch"
cp "$WORKDIR/run-summary.original.json" "$RUN_SUMMARY_PATH"

cp "$CASE_STUDY_A_PATH" "$WORKDIR/case-study-a.original.json"
printf '{"sample_id":"sample-a"}\n' >"$CASE_STUDY_A_PATH"
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$EMPTY_CASE_OUT" >/dev/null 2>"$WORKDIR/empty-case.stderr"; then
	printf 'ASSERT FAIL: 空壳 case study 应使 publication-audit 返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$EMPTY_CASE_OUT/publication_readiness.json" \
	"unadjudicated_case_study"
assert_audit_issue \
	"$EMPTY_CASE_OUT/publication_readiness.json" \
	"insufficient_case_studies"
python3 - "$EMPTY_CASE_OUT/publication_readiness.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matrix = payload.get("matrices", [{}])[0]
if matrix.get("case_study_count") != 1:
    raise SystemExit(
        f"ASSERT FAIL: 空壳案例不应计数，实际 {matrix.get('case_study_count')!r}"
    )
PY
cp "$WORKDIR/case-study-a.original.json" "$CASE_STUDY_A_PATH"

# 占位评审人标识（review1/review2/adjudicator1）应被门禁拒绝
python3 - "$CASE_STUDY_A_PATH" <<'PY'
import json
import pathlib
import sys

case_path = pathlib.Path(sys.argv[1])
payload = json.loads(case_path.read_text(encoding="utf-8"))
payload["manual_truth"]["reviewer_primary"] = "review1"
payload["manual_truth"]["reviewer_secondary"] = "review2"
payload["manual_truth"]["adjudicator"] = "adjudicator1"
case_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
PY
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$PLACEHOLDER_REVIEWER_OUT" >/dev/null 2>"$WORKDIR/placeholder.stderr"; then
	printf 'ASSERT FAIL: 占位评审人标识应使 publication-audit 返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$PLACEHOLDER_REVIEWER_OUT/publication_readiness.json" \
	"placeholder_case_study_reviewer"
cp "$WORKDIR/case-study-a.original.json" "$CASE_STUDY_A_PATH"

mv "$PRODUCER_MANIFEST_PATH" "$WORKDIR/producer-manifest.original.json"
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$MISSING_PRODUCER_OUT" >/dev/null 2>"$WORKDIR/missing-producer.stderr"; then
	printf 'ASSERT FAIL: 缺 producer manifest 应使 publication-audit 返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$MISSING_PRODUCER_OUT/publication_readiness.json" \
	"missing_producer_execution_manifest"
mv "$WORKDIR/producer-manifest.original.json" "$PRODUCER_MANIFEST_PATH"

cp "$SECOND_PRODUCER_MANIFEST_PATH" "$WORKDIR/second-producer-manifest.original.json"
cp -a "$SECOND_QUEUE_SNAPSHOT" "$WORKDIR/second-queue-snapshot.original"
rm -rf "$SECOND_QUEUE_SNAPSHOT"
mkdir -p "$SECOND_QUEUE_SNAPSHOT"
cp -a "$FIRST_QUEUE_SNAPSHOT/." "$SECOND_QUEUE_SNAPSHOT/"
python3 - "$SECOND_PRODUCER_MANIFEST_PATH" "$SECOND_QUEUE_SNAPSHOT" <<'PY'
import json
import pathlib
import sys

from tools.dns_diff.publication_audit import _queue_snapshot_digest

manifest_path = pathlib.Path(sys.argv[1])
snapshot_path = pathlib.Path(sys.argv[2])
payload = json.loads(manifest_path.read_text(encoding="utf-8"))
sha256, file_count, size_bytes = _queue_snapshot_digest(snapshot_path)
payload["queue_snapshot"].update(
    {"sha256": sha256, "file_count": file_count, "size_bytes": size_bytes}
)
manifest_path.write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
PY
if python3 -m tools.dns_diff.cli publication-audit \
	--matrix-root "$MATRIX_ROOT" \
	--output-dir "$FIXED_QUEUE_OUT" >/dev/null 2>"$WORKDIR/fixed-queue.stderr"; then
	printf 'ASSERT FAIL: 固定 queue 被多个 run 复用时应返回非零\n' >&2
	exit 1
fi
assert_audit_issue \
	"$FIXED_QUEUE_OUT/publication_readiness.json" \
	"duplicate_queue_snapshot"
cp "$WORKDIR/second-producer-manifest.original.json" "$SECOND_PRODUCER_MANIFEST_PATH"
rm -rf "$SECOND_QUEUE_SNAPSHOT"
mv "$WORKDIR/second-queue-snapshot.original" "$SECOND_QUEUE_SNAPSHOT"

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
