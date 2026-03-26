import json
import os
import shlex
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from .audit import (
    AUDIT_COLUMNS,
    collect_audit_records,
    write_oracle_audit_tsv,
    write_oracle_reliability_json,
)
from .report import (
    _resolve_root_dir,
    collect_report_snapshot,
    derive_semantic_diff_count,
    resolve_high_value_manifest_path,
)
from .schema import CONTRACT_VERSION
from .taxonomy import EXCLUSION_STATE_BY_PRIMARY, FAILURE_BUCKET_PRIMARY_ORDER

EXIT_USAGE = 2
PUBLICATION_EVIDENCE_CONTRACT_NAME = "publication_evidence_bundle"
FAILURE_TAXONOMY_COLUMNS: Tuple[str, ...] = (
    "failure_bucket_primary",
    "failure_bucket_detail",
    "count",
)
EXCLUSION_SUMMARY_COLUMNS: Tuple[str, ...] = (
    "failure_bucket_primary",
    "analysis_state",
    "count",
)
CASE_STUDY_INDEX_COLUMNS: Tuple[str, ...] = (
    "sample_id",
    "semantic_outcome",
    "selection_reason",
    "case_study_path",
)


class CampaignReportError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _write_failure_taxonomy_tsv(
    report_dir: Path,
    *,
    failure_taxonomy_counter: Counter,
    total_samples: int,
) -> None:
    lines = ["failure_bucket_primary\tfailure_bucket_detail\tcount"]
    for primary, detail in sorted(failure_taxonomy_counter.keys()):
        lines.append(
            f"{primary}\t{detail}\t{failure_taxonomy_counter[(primary, detail)]}"
        )
    lines.append(f"__total__\t-\t{total_samples}")
    (report_dir / "failure_taxonomy.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _write_exclusion_summary_tsv(
    report_dir: Path,
    *,
    failure_bucket_primary_counter: Counter,
    total_samples: int,
) -> None:
    lines = ["failure_bucket_primary\tanalysis_state\tcount"]
    for primary in FAILURE_BUCKET_PRIMARY_ORDER:
        analysis_state = EXCLUSION_STATE_BY_PRIMARY[primary]
        lines.append(
            f"{primary}\t{analysis_state}\t{failure_bucket_primary_counter.get(primary, 0)}"
        )
    lines.append(f"__total__\t-\t{total_samples}")
    (report_dir / "exclusion_summary.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _get_ablation_status() -> Dict[str, str]:
    return {
        "mutator": "on" if os.environ.get("ENABLE_DST1_MUTATOR", "0") == "1" else "off",
        "cache-delta": "on"
        if os.environ.get("ENABLE_CACHE_DELTA", "1") == "1"
        else "off",
        "triage": "on" if os.environ.get("ENABLE_TRIAGE", "1") == "1" else "off",
        "symcc": "on" if os.environ.get("ENABLE_SYMCC", "1") == "1" else "off",
    }


def _load_manifest_index(high_value_manifest: Path) -> Tuple[Set[Path], Set[Path]]:
    manifest_paths: Set[Path] = set()
    manifest_sample_dirs: Set[Path] = set()
    if not high_value_manifest.exists():
        return manifest_paths, manifest_sample_dirs

    try:
        for raw_line in high_value_manifest.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            manifest_path = Path(line).expanduser().resolve()
            manifest_paths.add(manifest_path)
            manifest_sample_dirs.add(manifest_path.parent)
    except OSError as exc:
        sys.stderr.write(
            f"dns-diff: campaign-report 读取 high-value manifest 失败 {high_value_manifest}: {exc}\n"
        )

    return manifest_paths, manifest_sample_dirs


def _shell_quote_path(path: Path) -> str:
    return shlex.quote(str(path))


def _build_regeneration_commands(root_path: Path, report_dir: Path) -> Dict[str, str]:
    root_arg = _shell_quote_path(root_path)
    report_dir_arg = _shell_quote_path(report_dir)
    return {
        "triage_rewrite": (
            f"python3 -m tools.dns_diff.cli triage --root {root_arg} --rewrite"
        ),
        "triage_report": f"python3 -m tools.dns_diff.cli report --root {root_arg}",
        "campaign_report": (
            f"python3 -m tools.dns_diff.cli campaign-report --root {root_arg}"
        ),
        "case_study_export": (
            "python3 -m tools.dns_diff.cli case-study-export "
            f"--root {root_arg} --campaign-report-dir {report_dir_arg}"
        ),
    }


def _build_artifact_reference(
    path: Path,
    *,
    regeneration_command: str,
    field_paths: Optional[List[str]] = None,
    column_paths: Optional[List[str]] = None,
    optional: bool = False,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "path": str(path.resolve()),
        "exists": path.is_file(),
        "optional": optional,
        "regeneration_command": regeneration_command,
    }
    if field_paths is not None:
        payload["field_paths"] = list(field_paths)
    if column_paths is not None:
        payload["column_paths"] = list(column_paths)
    return payload


def _build_claim(
    *,
    claim: str,
    value: Any,
    artifact: str,
    source_file_path: Path,
    field_path: str,
    regeneration_command: str,
    guardrail: str,
    supporting_sources: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "claim": claim,
        "value": value,
        "artifact": artifact,
        "source_file_path": str(source_file_path.resolve()),
        "field_path": field_path,
        "regeneration_command": regeneration_command,
        "guardrail": guardrail,
    }
    if supporting_sources:
        payload["supporting_sources"] = list(supporting_sources)
    return payload


def _build_publication_claims(
    *,
    summary: Mapping[str, Any],
    summary_path: Path,
    failure_taxonomy_path: Path,
    regeneration_commands: Mapping[str, str],
) -> List[Dict[str, Any]]:
    metric_denominators = summary.get("metric_denominators")
    if isinstance(metric_denominators, dict):
        analysis_state = metric_denominators.get("analysis_state")
        if not isinstance(analysis_state, dict):
            analysis_state = {}
    else:
        analysis_state = {}

    campaign_report_command = regeneration_commands["campaign_report"]
    publication_state_guardrail = (
        "included、excluded、unknown 只是 publication-facing 状态，不等于人工确认真值。"
    )
    proxy_guardrail = "该统计只能说明候选样本的复现或聚类情况，不能把 proxy signal 直接写成漏洞已证实。"
    return [
        _build_claim(
            claim="semantic_diff_count",
            value=summary.get("semantic_diff_count", 0),
            artifact="campaign_summary",
            source_file_path=summary_path,
            field_path="semantic_diff_count",
            regeneration_command=campaign_report_command,
            guardrail=publication_state_guardrail,
            supporting_sources=[
                {
                    "artifact": "failure_taxonomy",
                    "source_file_path": str(failure_taxonomy_path.resolve()),
                    "field_path": "rows[failure_bucket_primary=semantic_diff].count(sum)",
                }
            ],
        ),
        _build_claim(
            claim="included_samples",
            value=analysis_state.get("included", 0),
            artifact="campaign_summary",
            source_file_path=summary_path,
            field_path="metric_denominators.analysis_state.included",
            regeneration_command=campaign_report_command,
            guardrail=publication_state_guardrail,
        ),
        _build_claim(
            claim="excluded_samples",
            value=analysis_state.get("excluded", 0),
            artifact="campaign_summary",
            source_file_path=summary_path,
            field_path="metric_denominators.analysis_state.excluded",
            regeneration_command=campaign_report_command,
            guardrail=publication_state_guardrail,
        ),
        _build_claim(
            claim="unknown_samples",
            value=analysis_state.get("unknown", 0),
            artifact="campaign_summary",
            source_file_path=summary_path,
            field_path="metric_denominators.analysis_state.unknown",
            regeneration_command=campaign_report_command,
            guardrail=publication_state_guardrail,
        ),
        _build_claim(
            claim="repro_rate",
            value=summary.get("repro_rate", 0.0),
            artifact="campaign_summary",
            source_file_path=summary_path,
            field_path="repro_rate",
            regeneration_command=campaign_report_command,
            guardrail=proxy_guardrail,
        ),
        _build_claim(
            claim="cluster_count",
            value=summary.get("cluster_count", 0),
            artifact="campaign_summary",
            source_file_path=summary_path,
            field_path="cluster_count",
            regeneration_command=campaign_report_command,
            guardrail=proxy_guardrail,
        ),
    ]


def _write_evidence_bundle(
    *,
    report_dir: Path,
    root_path: Path,
    summary: Mapping[str, Any],
) -> Path:
    summary_path = report_dir / "summary.json"
    oracle_audit_path = report_dir / "oracle_audit.tsv"
    oracle_reliability_path = report_dir / "oracle_reliability.json"
    failure_taxonomy_path = report_dir / "failure_taxonomy.tsv"
    exclusion_summary_path = report_dir / "exclusion_summary.tsv"
    case_study_index_path = report_dir / "case_studies" / "index.tsv"
    regeneration_commands = _build_regeneration_commands(root_path, report_dir)

    payload = {
        "contract_name": PUBLICATION_EVIDENCE_CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "campaign_summary": _build_artifact_reference(
            summary_path,
            regeneration_command=regeneration_commands["campaign_report"],
            field_paths=[
                "campaign_id",
                "total_samples",
                "needs_review_count",
                "cluster_count",
                "semantic_diff_count",
                "metric_denominators.analysis_state.included",
                "metric_denominators.analysis_state.excluded",
                "metric_denominators.analysis_state.unknown",
                "repro_rate",
                "seed_provenance",
            ],
        ),
        "oracle_audit": _build_artifact_reference(
            oracle_audit_path,
            regeneration_command=regeneration_commands["campaign_report"],
            column_paths=list(AUDIT_COLUMNS),
        ),
        "oracle_reliability": _build_artifact_reference(
            oracle_reliability_path,
            regeneration_command=regeneration_commands["campaign_report"],
            field_paths=[
                "signals.response_accepted_any",
                "signals.second_query_hit_any",
                "signals.cache_entry_created_any",
                "signals.oracle_diff_any",
                "signal_combos.oracle_diff_plus_cache_diff",
            ],
        ),
        "failure_taxonomy": _build_artifact_reference(
            failure_taxonomy_path,
            regeneration_command=regeneration_commands["campaign_report"],
            column_paths=list(FAILURE_TAXONOMY_COLUMNS),
        ),
        "exclusion_summary": _build_artifact_reference(
            exclusion_summary_path,
            regeneration_command=regeneration_commands["campaign_report"],
            column_paths=list(EXCLUSION_SUMMARY_COLUMNS),
        ),
        "case_study_index": _build_artifact_reference(
            case_study_index_path,
            regeneration_command=regeneration_commands["case_study_export"],
            column_paths=list(CASE_STUDY_INDEX_COLUMNS),
            optional=True,
        ),
        "raw_sample_root": {
            "path": str(root_path.resolve()),
            "exists": root_path.is_dir(),
            "sample_dir_pattern": "<raw_sample_root>/<sample_id>/",
            "claim_review_artifacts": [
                "sample.meta.json",
                "oracle.json",
                "cache_diff.json",
                "triage.json",
                "sample.bin",
                "bind9.stderr",
                "unbound.stderr",
            ],
        },
        "seed_provenance": summary.get("seed_provenance"),
        "regeneration_commands": regeneration_commands,
        "claims": _build_publication_claims(
            summary=summary,
            summary_path=summary_path,
            failure_taxonomy_path=failure_taxonomy_path,
            regeneration_commands=regeneration_commands,
        ),
    }
    output_path = report_dir / "evidence_bundle.json"
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def generate_campaign_report(root: Path, is_custom_root: bool = False) -> int:
    root_path = Path(root).expanduser().resolve()
    snapshot = collect_report_snapshot(root_path, require_root=False)
    sample_dirs: List[Path] = list(snapshot["sample_dirs"])

    if is_custom_root:
        report_base = root_path / "campaign_reports"
    else:
        work_dir = Path(
            os.environ.get(
                "WORK_DIR",
                str(_resolve_root_dir() / "unbound_experiment" / "work_stateful"),
            )
        ).resolve()
        report_base = work_dir / "campaign_reports"
    timestamp = _get_timestamp()
    report_dir = report_base / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)

    cluster_counter: Counter = snapshot["cluster_counter"]
    failure_taxonomy_counter: Counter = snapshot["failure_taxonomy_counter"]
    failure_bucket_primary_counter: Counter = snapshot["failure_bucket_primary_counter"]
    total_samples = int(snapshot["total_samples"])
    needs_review_count = int(snapshot["needs_review_count"])

    high_value_manifest = resolve_high_value_manifest_path(root_path)
    manifest_paths, manifest_sample_dirs = _load_manifest_index(high_value_manifest)
    semantic_diff_count = derive_semantic_diff_count(
        snapshot["failure_bucket_primary_counter"]
    )

    reproduced_count = len(
        {sample_dir.resolve() for sample_dir in sample_dirs} & manifest_sample_dirs
    )
    manifest_size = len(manifest_paths)
    repro_rate = 0.0
    if manifest_size > 0:
        repro_rate = reproduced_count / manifest_size

    try:
        audit_records = collect_audit_records(sample_dirs)
    except Exception as exc:
        raise CampaignReportError(f"采集 oracle audit 记录失败: {exc}") from exc

    oracle_audit_candidate_count = sum(
        1 for record in audit_records if record.oracle_audit_candidate
    )

    ablation = _get_ablation_status()
    summary = {
        "campaign_id": timestamp,
        "total_samples": total_samples,
        "needs_review_count": needs_review_count,
        "cluster_count": len(cluster_counter),
        "contract_version": CONTRACT_VERSION,
        "metric_denominators": snapshot["metric_denominators"],
        "semantic_counts": snapshot["semantic_counts"],
        "semantic_diff_count": semantic_diff_count,
        "oracle_audit_candidate_count": oracle_audit_candidate_count,
        "comparability": snapshot["comparability"],
        "run_id": snapshot["run_id"],
        "ablation_status": ablation,
        "seed_provenance": snapshot["seed_provenance"],
        "manifest_size": manifest_size,
        "reproduced_count": reproduced_count,
        "repro_rate": repro_rate,
    }
    (report_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    ablation_lines = ["module\tstatus"]
    for k, v in sorted(ablation.items()):
        ablation_lines.append(f"{k}\t{v}")
    (report_dir / "ablation_matrix.tsv").write_text(
        "\n".join(ablation_lines) + "\n", encoding="utf-8"
    )

    cluster_lines = ["cluster_key\tcount"]
    if not cluster_counter:
        cluster_lines.append("_\t0")
    else:
        for k in sorted(cluster_counter.keys()):
            cluster_lines.append(f"{k}\t{cluster_counter[k]}")
    (report_dir / "cluster_counts.tsv").write_text(
        "\n".join(cluster_lines) + "\n", encoding="utf-8"
    )

    _write_failure_taxonomy_tsv(
        report_dir,
        failure_taxonomy_counter=failure_taxonomy_counter,
        total_samples=total_samples,
    )
    _write_exclusion_summary_tsv(
        report_dir,
        failure_bucket_primary_counter=failure_bucket_primary_counter,
        total_samples=total_samples,
    )

    repro_lines = [
        "metric\tvalue",
        f"manifest_size\t{manifest_size}",
        f"reproduced_count\t{reproduced_count}",
        f"repro_rate\t{repro_rate:.4f}",
    ]
    (report_dir / "repro_rate.tsv").write_text(
        "\n".join(repro_lines) + "\n", encoding="utf-8"
    )

    try:
        write_oracle_audit_tsv(report_dir, audit_records)
        write_oracle_reliability_json(report_dir, audit_records)
        _write_evidence_bundle(
            report_dir=report_dir, root_path=root_path, summary=summary
        )
    except Exception as exc:
        raise CampaignReportError(f"写入 campaign 报告产物失败: {exc}") from exc

    sys.stdout.write(f"dns-diff: campaign-report 落盘完成 -> {report_dir}\n")
    return 0
