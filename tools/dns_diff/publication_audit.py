import csv
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .aggregate import METRIC_NAMES, _extract_metrics
from .artifact_digest import sha256_file
from .io import atomic_write_json
from .matrix import EXPECTED_VARIANT_ORDER
from .schema import CONTRACT_VERSION, SEED_PROVENANCE_FIELDS
from .statistics import compute_metric_statistics, statistics_contract

EXIT_USAGE = 2
PUBLICATION_EVIDENCE_CONTRACT_NAME = "publication_evidence_bundle"
REQUIRED_EVIDENCE_ARTIFACTS: Tuple[str, ...] = (
    "campaign_summary",
    "oracle_audit",
    "oracle_reliability",
    "failure_taxonomy",
    "exclusion_summary",
)
EVIDENCE_ARTIFACT_PATHS = {
    "campaign_summary": "summary.json",
    "oracle_audit": "oracle_audit.tsv",
    "oracle_reliability": "oracle_reliability.json",
    "failure_taxonomy": "failure_taxonomy.tsv",
    "exclusion_summary": "exclusion_summary.tsv",
    "case_study_index": "case_studies/index.tsv",
}
REQUIRED_CLAIMS: Tuple[str, ...] = (
    "semantic_diff_count",
    "included_samples",
    "excluded_samples",
    "unknown_samples",
    "repro_rate",
    "cluster_count",
)
REQUIRED_STATISTIC_SUFFIXES: Tuple[str, ...] = (
    "mean",
    "stddev",
    "sample_stddev",
    "standard_error",
    "ci95_lower",
    "ci95_upper",
)
REQUIRED_REGENERATION_COMMANDS: Tuple[str, ...] = (
    "triage_rewrite",
    "triage_report",
    "campaign_report",
    "case_study_export",
)


class PublicationAuditError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _directory_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicationAuditError(f"读取 JSON 失败 {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PublicationAuditError(f"JSON 顶层必须是对象: {path}")
    return dict(payload)


def _read_tsv(path: Path) -> List[Dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter="\t"))
    except OSError as exc:
        raise PublicationAuditError(f"读取 TSV 失败 {path}: {exc}") from exc


def _issue(
    issues: List[Dict[str, str]],
    *,
    code: str,
    matrix_root: Path,
    scope: str,
    path: Path,
    detail: str,
) -> None:
    issues.append(
        {
            "severity": "error",
            "code": code,
            "matrix_root": str(matrix_root),
            "scope": scope,
            "path": str(path),
            "detail": detail,
        }
    )


def _resolve_path(value: Any, *, base_dir: Path) -> Optional[Path]:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _coerce_positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if parsed >= 1 else None
    return None


def _coerce_finite_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _lookup_field(payload: Mapping[str, Any], field_path: str) -> Tuple[bool, Any]:
    value: Any = payload
    for component in field_path.split("."):
        if not isinstance(value, Mapping) or component not in value:
            return False, None
        value = value[component]
    return True, value


def _audit_artifact_reference(
    *,
    bundle: Mapping[str, Any],
    artifact_name: str,
    report_dir: Path,
    matrix_root: Path,
    scope: str,
    issues: List[Dict[str, str]],
    optional: bool = False,
) -> None:
    raw_reference = bundle.get(artifact_name)
    if not isinstance(raw_reference, Mapping):
        _issue(
            issues,
            code="missing_artifact_reference",
            matrix_root=matrix_root,
            scope=scope,
            path=report_dir / "evidence_bundle.json",
            detail=f"缺少 {artifact_name} 产物引用",
        )
        return

    artifact_path = _resolve_path(raw_reference.get("path"), base_dir=report_dir)
    expected_path = report_dir / EVIDENCE_ARTIFACT_PATHS[artifact_name]
    if artifact_path != expected_path.resolve():
        _issue(
            issues,
            code="artifact_path_mismatch",
            matrix_root=matrix_root,
            scope=scope,
            path=artifact_path or report_dir,
            detail=f"{artifact_name} 必须位于 {expected_path}",
        )

    if optional and not expected_path.is_file():
        if raw_reference.get("exists") is not False:
            _issue(
                issues,
                code="artifact_exists_flag_mismatch",
                matrix_root=matrix_root,
                scope=scope,
                path=expected_path,
                detail=f"缺失的 {artifact_name}.exists 必须为 false",
            )
        if raw_reference.get("optional") is not True:
            _issue(
                issues,
                code="invalid_optional_artifact",
                matrix_root=matrix_root,
                scope=scope,
                path=expected_path,
                detail=f"{artifact_name}.optional 必须为 true",
            )
        if (
            raw_reference.get("size_bytes") is not None
            or raw_reference.get("sha256") is not None
        ):
            _issue(
                issues,
                code="invalid_missing_artifact_integrity",
                matrix_root=matrix_root,
                scope=scope,
                path=expected_path,
                detail=f"缺失的 {artifact_name} 必须使用 null 完整性字段",
            )
        return

    if not expected_path.is_file():
        _issue(
            issues,
            code="missing_artifact_file",
            matrix_root=matrix_root,
            scope=scope,
            path=expected_path,
            detail=f"{artifact_name} 引用文件不存在",
        )
        return

    if raw_reference.get("exists") is not True:
        _issue(
            issues,
            code="artifact_exists_flag_mismatch",
            matrix_root=matrix_root,
            scope=scope,
            path=expected_path,
            detail=f"{artifact_name}.exists 必须为 true",
        )
    if raw_reference.get("optional") is not optional:
        _issue(
            issues,
            code="invalid_optional_artifact",
            matrix_root=matrix_root,
            scope=scope,
            path=expected_path,
            detail=f"{artifact_name}.optional 必须为 {str(optional).lower()}",
        )

    expected_size = raw_reference.get("size_bytes")
    if expected_size != expected_path.stat().st_size:
        _issue(
            issues,
            code="artifact_size_mismatch",
            matrix_root=matrix_root,
            scope=scope,
            path=expected_path,
            detail=(
                f"{artifact_name}.size_bytes={expected_size!r}，"
                f"实际为 {expected_path.stat().st_size}"
            ),
        )

    expected_sha256 = raw_reference.get("sha256")
    actual_sha256 = sha256_file(expected_path)
    if expected_sha256 != actual_sha256:
        _issue(
            issues,
            code="artifact_sha256_mismatch",
            matrix_root=matrix_root,
            scope=scope,
            path=expected_path,
            detail=f"{artifact_name} 的 SHA-256 与 evidence bundle 不一致",
        )


def _audit_evidence_bundle(
    *,
    report_dir: Path,
    matrix_root: Path,
    scope: str,
    issues: List[Dict[str, str]],
    run_summary: Optional[Mapping[str, Any]],
) -> Set[str]:
    bundle_path = report_dir / "evidence_bundle.json"
    if not bundle_path.is_file():
        _issue(
            issues,
            code="missing_evidence_bundle",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail="运行报告缺少 publication evidence bundle",
        )
        return set()

    try:
        bundle = _read_json(bundle_path)
    except PublicationAuditError as exc:
        _issue(
            issues,
            code="invalid_evidence_bundle",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail=str(exc),
        )
        return set()

    if bundle.get("contract_name") != PUBLICATION_EVIDENCE_CONTRACT_NAME:
        _issue(
            issues,
            code="invalid_evidence_contract",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail="contract_name 不是 publication_evidence_bundle",
        )
    if bundle.get("contract_version") != CONTRACT_VERSION:
        _issue(
            issues,
            code="stale_evidence_contract",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail=(
                f"contract_version={bundle.get('contract_version')!r}，"
                f"当前要求 {CONTRACT_VERSION}"
            ),
        )

    seed_provenance = bundle.get("seed_provenance")
    if not isinstance(seed_provenance, Mapping):
        _issue(
            issues,
            code="missing_seed_provenance",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail="论文证据缺少 seed_provenance",
        )
    else:
        missing_fields = [
            field for field in SEED_PROVENANCE_FIELDS if field not in seed_provenance
        ]
        if missing_fields:
            _issue(
                issues,
                code="incomplete_seed_provenance",
                matrix_root=matrix_root,
                scope=scope,
                path=bundle_path,
                detail=f"seed_provenance 缺少字段: {','.join(missing_fields)}",
            )
        if (
            isinstance(run_summary, Mapping)
            and seed_provenance != run_summary.get("seed_provenance")
        ):
            _issue(
                issues,
                code="seed_provenance_mismatch",
                matrix_root=matrix_root,
                scope=scope,
                path=bundle_path,
                detail="evidence bundle 与运行摘要的 seed_provenance 不一致",
            )

    for artifact_name in REQUIRED_EVIDENCE_ARTIFACTS:
        _audit_artifact_reference(
            bundle=bundle,
            artifact_name=artifact_name,
            report_dir=report_dir,
            matrix_root=matrix_root,
            scope=scope,
            issues=issues,
        )
    _audit_artifact_reference(
        bundle=bundle,
        artifact_name="case_study_index",
        report_dir=report_dir,
        matrix_root=matrix_root,
        scope=scope,
        issues=issues,
        optional=True,
    )

    raw_sample_root = bundle.get("raw_sample_root")
    if not isinstance(raw_sample_root, Mapping):
        _issue(
            issues,
            code="missing_raw_sample_root",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail="缺少 raw_sample_root 引用",
        )
    else:
        raw_root_path = _resolve_path(
            raw_sample_root.get("path"), base_dir=report_dir
        )
        if raw_root_path is None or not raw_root_path.is_dir():
            _issue(
                issues,
                code="missing_raw_sample_directory",
                matrix_root=matrix_root,
                scope=scope,
                path=raw_root_path or report_dir,
                detail="raw_sample_root 目录不存在",
            )
        else:
            if raw_sample_root.get("exists") is not True:
                _issue(
                    issues,
                    code="raw_sample_exists_flag_mismatch",
                    matrix_root=matrix_root,
                    scope=scope,
                    path=raw_root_path,
                    detail="raw_sample_root.exists 必须为 true",
                )
            if (
                raw_sample_root.get("sample_dir_pattern")
                != "<raw_sample_root>/<sample_id>/"
            ):
                _issue(
                    issues,
                    code="invalid_raw_sample_pattern",
                    matrix_root=matrix_root,
                    scope=scope,
                    path=raw_root_path,
                    detail="raw_sample_root.sample_dir_pattern 不符合证据契约",
                )
            claim_artifacts = raw_sample_root.get("claim_review_artifacts")
            if (
                not isinstance(claim_artifacts, list)
                or not claim_artifacts
                or any(
                    not isinstance(item, str) or not item
                    for item in claim_artifacts
                )
            ):
                _issue(
                    issues,
                    code="invalid_claim_review_artifacts",
                    matrix_root=matrix_root,
                    scope=scope,
                    path=raw_root_path,
                    detail="claim_review_artifacts 必须是非空字符串列表",
                )
            sample_dirs = [
                path
                for path in raw_root_path.iterdir()
                if path.is_dir()
                and (path / "sample.meta.json").is_file()
                and (path / "sample.bin").is_file()
            ]
            if not sample_dirs:
                _issue(
                    issues,
                    code="missing_raw_samples",
                    matrix_root=matrix_root,
                    scope=scope,
                    path=raw_root_path,
                    detail=(
                        "raw_sample_root 下没有同时包含元数据和输入的样本目录"
                    ),
                )

    regeneration_commands = bundle.get("regeneration_commands")
    missing_commands = [
        command
        for command in REQUIRED_REGENERATION_COMMANDS
        if not isinstance(regeneration_commands, Mapping)
        or not isinstance(regeneration_commands.get(command), str)
        or not regeneration_commands.get(command)
    ]
    if missing_commands:
        _issue(
            issues,
            code="missing_regeneration_command",
            matrix_root=matrix_root,
            scope=scope,
            path=bundle_path,
            detail=f"缺少可执行的重建命令: {','.join(missing_commands)}",
        )

    claims = bundle.get("claims")
    claim_map: Dict[str, Mapping[str, Any]] = {}
    if isinstance(claims, list):
        claim_map = {
            str(item.get("claim")): item
            for item in claims
            if isinstance(item, Mapping) and isinstance(item.get("claim"), str)
        }
    for claim_name in REQUIRED_CLAIMS:
        claim = claim_map.get(claim_name)
        if claim is None:
            _issue(
                issues,
                code="missing_publication_claim",
                matrix_root=matrix_root,
                scope=scope,
                path=bundle_path,
                detail=f"缺少 claim: {claim_name}",
            )
            continue
        source_path = _resolve_path(
            claim.get("source_file_path"), base_dir=report_dir
        )
        required_text_fields = ("field_path", "regeneration_command", "guardrail")
        missing_text = [
            field
            for field in required_text_fields
            if not isinstance(claim.get(field), str) or not claim.get(field)
        ]
        if source_path is None or not source_path.is_file() or missing_text:
            _issue(
                issues,
                code="invalid_publication_claim",
                matrix_root=matrix_root,
                scope=scope,
                path=source_path or bundle_path,
                detail=(
                    f"claim={claim_name} 来源不存在或缺少字段: "
                    f"{','.join(missing_text) if missing_text else '-'}"
                ),
            )
            continue
        expected_source_path = (report_dir / "summary.json").resolve()
        if (
            source_path != expected_source_path
            or claim.get("artifact") != "campaign_summary"
        ):
            _issue(
                issues,
                code="invalid_claim_source",
                matrix_root=matrix_root,
                scope=scope,
                path=source_path,
                detail=f"claim={claim_name} 必须引用 campaign_summary",
            )
            continue
        field_path = str(claim["field_path"])
        field_exists, source_value = (
            _lookup_field(run_summary, field_path)
            if isinstance(run_summary, Mapping)
            else (False, None)
        )
        if not field_exists or claim.get("value") != source_value:
            _issue(
                issues,
                code="claim_value_mismatch",
                matrix_root=matrix_root,
                scope=scope,
                path=source_path,
                detail=(
                    f"claim={claim_name} value={claim.get('value')!r}，"
                    f"来源值={source_value!r}"
                ),
            )

    case_study_reference = bundle.get("case_study_index")
    if not isinstance(case_study_reference, Mapping):
        return set()
    case_study_path = _resolve_path(
        case_study_reference.get("path"), base_dir=report_dir
    )
    if case_study_path is None or not case_study_path.is_file():
        return set()
    try:
        rows = _read_tsv(case_study_path)
    except PublicationAuditError as exc:
        _issue(
            issues,
            code="invalid_case_study_index",
            matrix_root=matrix_root,
            scope=scope,
            path=case_study_path,
            detail=str(exc),
        )
        return set()

    case_study_ids: Set[str] = set()
    for row_index, row in enumerate(rows, start=2):
        sample_id = row.get("sample_id", "")
        missing_fields = [
            field
            for field in (
                "sample_id",
                "semantic_outcome",
                "selection_reason",
                "case_study_path",
            )
            if not row.get(field)
        ]
        artifact_path = _resolve_path(
            row.get("case_study_path"), base_dir=case_study_path.parent
        )
        if missing_fields or artifact_path is None or not artifact_path.is_file():
            _issue(
                issues,
                code="invalid_case_study_entry",
                matrix_root=matrix_root,
                scope=scope,
                path=artifact_path or case_study_path,
                detail=(
                    f"case study 第 {row_index} 行缺少字段或产物: "
                    f"{','.join(missing_fields) if missing_fields else '-'}"
                ),
            )
            continue
        try:
            artifact_path.relative_to(case_study_path.parent.resolve())
        except ValueError:
            _issue(
                issues,
                code="case_study_path_escape",
                matrix_root=matrix_root,
                scope=scope,
                path=artifact_path,
                detail="case_study_path 必须位于 case_studies 目录内",
            )
            continue
        if sample_id in case_study_ids:
            _issue(
                issues,
                code="duplicate_case_study",
                matrix_root=matrix_root,
                scope=scope,
                path=case_study_path,
                detail=f"case study 重复 sample_id: {sample_id}",
            )
            continue
        case_study_ids.add(sample_id)
    return case_study_ids


def _audit_variant_statistics(
    *,
    row: Mapping[str, str],
    variant_name: str,
    matrix_root: Path,
    summary_path: Path,
    minimum_runs: int,
    issues: List[Dict[str, str]],
) -> None:
    scope = f"variant:{variant_name}"
    run_count = _coerce_positive_int(row.get("run_count"))
    if run_count is None or run_count < minimum_runs:
        _issue(
            issues,
            code="insufficient_repetitions",
            matrix_root=matrix_root,
            scope=scope,
            path=summary_path,
            detail=f"run_count={row.get('run_count')!r}，最低要求 {minimum_runs}",
        )
    if row.get("variance_status") != "ok":
        _issue(
            issues,
            code="unavailable_statistics",
            matrix_root=matrix_root,
            scope=scope,
            path=summary_path,
            detail=f"variance_status={row.get('variance_status')!r}",
        )

    for key_name in ("aggregation_key", "baseline_compare_key"):
        value = row.get(key_name, "")
        if not value or value in {"<missing>", "<mixed>", "<null>"}:
            _issue(
                issues,
                code="invalid_comparability_key",
                matrix_root=matrix_root,
                scope=scope,
                path=summary_path,
                detail=f"{key_name}={value!r}",
            )

    for metric_name in METRIC_NAMES:
        values: Dict[str, float] = {}
        for suffix in REQUIRED_STATISTIC_SUFFIXES:
            column = f"{metric_name}_{suffix}"
            parsed = _coerce_finite_float(row.get(column))
            if parsed is None:
                _issue(
                    issues,
                    code="missing_statistical_field",
                    matrix_root=matrix_root,
                    scope=scope,
                    path=summary_path,
                    detail=f"缺少有限统计值: {column}",
                )
            else:
                values[suffix] = parsed
        if (
            "mean" in values
            and "ci95_lower" in values
            and "ci95_upper" in values
            and not (
                values["ci95_lower"] <= values["mean"] <= values["ci95_upper"]
            )
        ):
            _issue(
                issues,
                code="invalid_confidence_interval",
                matrix_root=matrix_root,
                scope=scope,
                path=summary_path,
                detail=f"{metric_name} 的均值不在 95% 置信区间内",
            )


def _audit_run_metrics(
    *,
    summary: Mapping[str, Any],
    summary_path: Path,
    matrix_root: Path,
    scope: str,
    issues: List[Dict[str, str]],
) -> Optional[Dict[str, float]]:
    field_paths = {
        "total_samples": "total_samples",
        "included_samples": "metric_denominators.analysis_state.included",
        "excluded_samples": "metric_denominators.analysis_state.excluded",
        "unknown_samples": "metric_denominators.analysis_state.unknown",
        "needs_review_count": "needs_review_count",
        "cluster_count": "cluster_count",
        "repro_rate": "repro_rate",
        "oracle_audit_candidate_count": "oracle_audit_candidate_count",
        "semantic_diff_count": "semantic_diff_count",
    }
    valid = True
    for metric_name, field_path in field_paths.items():
        exists, value = _lookup_field(summary, field_path)
        parsed = _coerce_finite_float(value) if exists else None
        is_integer_metric = metric_name != "repro_rate"
        invalid_integer = (
            is_integer_metric
            and (
                isinstance(value, bool)
                or parsed is None
                or not parsed.is_integer()
            )
        )
        invalid_rate = metric_name == "repro_rate" and (
            parsed is None or not 0.0 <= parsed <= 1.0
        )
        if parsed is None or parsed < 0.0 or invalid_integer or invalid_rate:
            valid = False
            _issue(
                issues,
                code="invalid_run_metric",
                matrix_root=matrix_root,
                scope=scope,
                path=summary_path,
                detail=f"{field_path} 不是合法的非负统计值: {value!r}",
            )
    if not valid:
        return None
    return _extract_metrics(summary)


def _audit_statistics_against_runs(
    *,
    row: Mapping[str, str],
    variant_name: str,
    run_metrics: Sequence[Mapping[str, float]],
    matrix_root: Path,
    summary_path: Path,
    issues: List[Dict[str, str]],
) -> None:
    if len(run_metrics) < 2:
        return
    scope = f"variant:{variant_name}"
    for metric_name in METRIC_NAMES:
        expected = compute_metric_statistics(
            [metrics[metric_name] for metrics in run_metrics]
        )
        for suffix in REQUIRED_STATISTIC_SUFFIXES:
            column = f"{metric_name}_{suffix}"
            actual = _coerce_finite_float(row.get(column))
            if actual is None:
                continue
            if not math.isclose(
                actual,
                expected[suffix],
                rel_tol=1e-9,
                abs_tol=1e-6,
            ):
                _issue(
                    issues,
                    code="statistic_value_mismatch",
                    matrix_root=matrix_root,
                    scope=scope,
                    path=summary_path,
                    detail=(
                        f"{column}={actual!r}，"
                        f"从运行摘要重算为 {expected[suffix]!r}"
                    ),
                )


def _audit_matrix_root(
    *,
    matrix_root: Path,
    minimum_runs: int,
    minimum_case_studies: int,
) -> Dict[str, Any]:
    root = Path(matrix_root).expanduser().resolve()
    issues: List[Dict[str, str]] = []
    summary_dir = root / "_summary"
    manifest_path = summary_dir / "matrix_manifest.json"
    variant_summary_path = summary_dir / "variant_summary.tsv"

    if not manifest_path.is_file() or not variant_summary_path.is_file():
        missing_path = manifest_path if not manifest_path.is_file() else variant_summary_path
        _issue(
            issues,
            code="missing_matrix_summary",
            matrix_root=root,
            scope="matrix",
            path=missing_path,
            detail="缺少 matrix_manifest.json 或 variant_summary.tsv",
        )
        return {
            "matrix_root": str(root),
            "status": "not_ready",
            "variant_count": 0,
            "run_count": 0,
            "case_study_count": 0,
            "issues": issues,
        }

    try:
        manifest = _read_json(manifest_path)
        summary_rows = _read_tsv(variant_summary_path)
    except PublicationAuditError as exc:
        _issue(
            issues,
            code="invalid_matrix_summary",
            matrix_root=root,
            scope="matrix",
            path=summary_dir,
            detail=str(exc),
        )
        return {
            "matrix_root": str(root),
            "status": "not_ready",
            "variant_count": 0,
            "run_count": 0,
            "case_study_count": 0,
            "issues": issues,
        }

    manifest_repeat_count = _coerce_positive_int(manifest.get("repeat_count"))
    if manifest_repeat_count is None or manifest_repeat_count < minimum_runs:
        _issue(
            issues,
            code="insufficient_matrix_repetitions",
            matrix_root=root,
            scope="matrix",
            path=manifest_path,
            detail=(
                f"repeat_count={manifest.get('repeat_count')!r}，"
                f"最低要求 {minimum_runs}"
            ),
        )
    if manifest.get("contract_version") != CONTRACT_VERSION:
        _issue(
            issues,
            code="stale_matrix_contract",
            matrix_root=root,
            scope="matrix",
            path=manifest_path,
            detail=(
                f"contract_version={manifest.get('contract_version')!r}，"
                f"当前要求 {CONTRACT_VERSION}"
            ),
        )

    statistics = manifest.get("statistics")
    expected_statistics = statistics_contract()
    if statistics != expected_statistics:
        _issue(
            issues,
            code="invalid_statistical_method",
            matrix_root=root,
            scope="matrix",
            path=manifest_path,
            detail=(
                f"statistics={statistics!r}，要求 {expected_statistics!r}"
            ),
        )

    raw_variants = manifest.get("variants")
    variants = (
        [item for item in raw_variants if isinstance(item, Mapping)]
        if isinstance(raw_variants, list)
        else []
    )
    variant_names = [
        str(item.get("variant_name"))
        for item in variants
        if isinstance(item.get("variant_name"), str)
    ]
    if tuple(variant_names) != EXPECTED_VARIANT_ORDER:
        _issue(
            issues,
            code="incomplete_ablation_matrix",
            matrix_root=root,
            scope="matrix",
            path=manifest_path,
            detail=(
                f"variants={variant_names!r}，要求顺序为 {list(EXPECTED_VARIANT_ORDER)!r}"
            ),
        )

    rows_by_variant = {
        row.get("variant_name", ""): row
        for row in summary_rows
        if row.get("variant_name")
    }
    if len(rows_by_variant) != len(summary_rows):
        _issue(
            issues,
            code="invalid_variant_statistics_rows",
            matrix_root=root,
            scope="matrix",
            path=variant_summary_path,
            detail="variant_summary.tsv 包含重复或缺少 variant_name 的行",
        )
    unexpected_rows = sorted(set(rows_by_variant) - set(EXPECTED_VARIANT_ORDER))
    if unexpected_rows:
        _issue(
            issues,
            code="unexpected_variant_statistics",
            matrix_root=root,
            scope="matrix",
            path=variant_summary_path,
            detail=f"variant_summary.tsv 包含未知变体: {unexpected_rows!r}",
        )
    total_runs = 0
    case_study_ids: Set[str] = set()
    for variant in variants:
        variant_name = str(variant.get("variant_name", ""))
        row = rows_by_variant.get(variant_name)
        if row is None:
            _issue(
                issues,
                code="missing_variant_statistics",
                matrix_root=root,
                scope=f"variant:{variant_name or '<unknown>'}",
                path=variant_summary_path,
                detail="variant_summary.tsv 缺少对应变体行",
            )
        else:
            _audit_variant_statistics(
                row=row,
                variant_name=variant_name,
                matrix_root=root,
                summary_path=variant_summary_path,
                minimum_runs=minimum_runs,
                issues=issues,
            )

        raw_runs = variant.get("runs")
        runs = (
            [item for item in raw_runs if isinstance(item, Mapping)]
            if isinstance(raw_runs, list)
            else []
        )
        total_runs += len(runs)
        variant_repeat_count = _coerce_positive_int(variant.get("repeat_count"))
        if len(runs) < minimum_runs:
            _issue(
                issues,
                code="missing_run_evidence",
                matrix_root=root,
                scope=f"variant:{variant_name}",
                path=manifest_path,
                detail=f"manifest 仅记录 {len(runs)} 次运行，最低要求 {minimum_runs}",
            )
        if variant_repeat_count != manifest_repeat_count or len(runs) != variant_repeat_count:
            _issue(
                issues,
                code="run_count_mismatch",
                matrix_root=root,
                scope=f"variant:{variant_name}",
                path=manifest_path,
                detail=(
                    f"matrix_repeat={manifest_repeat_count!r}, "
                    f"variant_repeat={variant_repeat_count!r}, runs={len(runs)}"
                ),
            )
        if row is not None and _coerce_positive_int(row.get("run_count")) != len(runs):
            _issue(
                issues,
                code="summary_run_count_mismatch",
                matrix_root=root,
                scope=f"variant:{variant_name}",
                path=variant_summary_path,
                detail=(
                    f"summary run_count={row.get('run_count')!r}, "
                    f"manifest runs={len(runs)}"
                ),
            )

        repeat_indexes = [
            _coerce_positive_int(run.get("repeat_index")) for run in runs
        ]
        if repeat_indexes != list(range(1, len(runs) + 1)):
            _issue(
                issues,
                code="invalid_repeat_index_sequence",
                matrix_root=root,
                scope=f"variant:{variant_name}",
                path=manifest_path,
                detail=f"repeat_index 序列非法: {repeat_indexes!r}",
            )

        run_metrics: List[Mapping[str, float]] = []
        for index, run in enumerate(runs, start=1):
            run_scope = f"variant:{variant_name}/run:{index}"
            expected_run_dir = (
                root / "matrix_runs" / variant_name / f"run-{index:02d}"
            ).resolve()
            run_dir = _resolve_path(run.get("run_dir"), base_dir=root)
            if run_dir != expected_run_dir or not expected_run_dir.is_dir():
                _issue(
                    issues,
                    code="run_directory_mismatch",
                    matrix_root=root,
                    scope=run_scope,
                    path=run_dir or root,
                    detail=f"run_dir 必须指向 {expected_run_dir}",
                )
            report_dir = _resolve_path(run.get("report_dir"), base_dir=root)
            if report_dir is None or not report_dir.is_dir():
                _issue(
                    issues,
                    code="missing_run_report_directory",
                    matrix_root=root,
                    scope=run_scope,
                    path=report_dir or root,
                    detail="matrix manifest 引用的 report_dir 不存在",
                )
                continue
            try:
                report_dir.relative_to(expected_run_dir / "campaign_reports")
            except ValueError:
                _issue(
                    issues,
                    code="report_directory_mismatch",
                    matrix_root=root,
                    scope=run_scope,
                    path=report_dir,
                    detail="report_dir 不在对应 run 的 campaign_reports 下",
                )

            summary_path = report_dir / "summary.json"
            manifest_summary_path = _resolve_path(
                run.get("summary_path"), base_dir=root
            )
            if manifest_summary_path != summary_path.resolve():
                _issue(
                    issues,
                    code="run_summary_path_mismatch",
                    matrix_root=root,
                    scope=run_scope,
                    path=manifest_summary_path or report_dir,
                    detail=f"summary_path 必须指向 {summary_path}",
                )
            if not summary_path.is_file():
                _issue(
                    issues,
                    code="missing_run_summary",
                    matrix_root=root,
                    scope=run_scope,
                    path=summary_path,
                    detail="run report 缺少 summary.json",
                )
                run_summary: Optional[Mapping[str, Any]] = None
            else:
                try:
                    run_summary = _read_json(summary_path)
                    metrics = _audit_run_metrics(
                        summary=run_summary,
                        summary_path=summary_path,
                        matrix_root=root,
                        scope=run_scope,
                        issues=issues,
                    )
                    if metrics is not None:
                        run_metrics.append(metrics)
                    comparability = run_summary.get("comparability")
                    if (
                        not isinstance(comparability, Mapping)
                        or comparability.get("status") != "comparable"
                    ):
                        _issue(
                            issues,
                            code="non_comparable_run",
                            matrix_root=root,
                            scope=run_scope,
                            path=summary_path,
                            detail="run summary 的 comparability.status 不是 comparable",
                        )
                except PublicationAuditError as exc:
                    _issue(
                        issues,
                        code="invalid_run_summary",
                        matrix_root=root,
                        scope=run_scope,
                        path=summary_path,
                        detail=str(exc),
                    )
                    run_summary = None

            close_summary_path = _resolve_path(
                run.get("close_summary_path"), base_dir=root
            )
            expected_close_summary_path = (
                expected_run_dir / "campaign_close.summary.json"
            )
            if close_summary_path != expected_close_summary_path:
                _issue(
                    issues,
                    code="close_summary_path_mismatch",
                    matrix_root=root,
                    scope=run_scope,
                    path=close_summary_path or expected_run_dir,
                    detail=f"close_summary_path 必须指向 {expected_close_summary_path}",
                )
            if not expected_close_summary_path.is_file():
                _issue(
                    issues,
                    code="missing_close_summary",
                    matrix_root=root,
                    scope=run_scope,
                    path=expected_close_summary_path,
                    detail="matrix run 缺少 campaign_close.summary.json",
                )
            else:
                try:
                    close_summary = _read_json(expected_close_summary_path)
                    if (
                        close_summary.get("status") != "success"
                        or close_summary.get("exit_code") != 0
                    ):
                        _issue(
                            issues,
                            code="unsuccessful_close_summary",
                            matrix_root=root,
                            scope=run_scope,
                            path=expected_close_summary_path,
                            detail="campaign close 未记录 status=success 且 exit_code=0",
                        )
                except PublicationAuditError as exc:
                    _issue(
                        issues,
                        code="invalid_close_summary",
                        matrix_root=root,
                        scope=run_scope,
                        path=expected_close_summary_path,
                        detail=str(exc),
                    )

            evidence_bundle_path = report_dir / "evidence_bundle.json"
            manifest_bundle_path = _resolve_path(
                run.get("evidence_bundle_path"), base_dir=root
            )
            if manifest_bundle_path != evidence_bundle_path.resolve():
                _issue(
                    issues,
                    code="evidence_bundle_path_mismatch",
                    matrix_root=root,
                    scope=run_scope,
                    path=manifest_bundle_path or report_dir,
                    detail=f"evidence_bundle_path 必须指向 {evidence_bundle_path}",
                )
            integrity = run.get("evidence_bundle_integrity")
            if not isinstance(integrity, Mapping):
                _issue(
                    issues,
                    code="missing_evidence_bundle_integrity",
                    matrix_root=root,
                    scope=run_scope,
                    path=manifest_path,
                    detail="matrix manifest 缺少 evidence_bundle_integrity",
                )
            elif evidence_bundle_path.is_file():
                actual_size = evidence_bundle_path.stat().st_size
                actual_sha256 = sha256_file(evidence_bundle_path)
                if integrity.get("size_bytes") != actual_size:
                    _issue(
                        issues,
                        code="evidence_bundle_size_mismatch",
                        matrix_root=root,
                        scope=run_scope,
                        path=evidence_bundle_path,
                        detail="evidence bundle 大小与 matrix manifest 不一致",
                    )
                if integrity.get("sha256") != actual_sha256:
                    _issue(
                        issues,
                        code="evidence_bundle_sha256_mismatch",
                        matrix_root=root,
                        scope=run_scope,
                        path=evidence_bundle_path,
                        detail="evidence bundle SHA-256 与 matrix manifest 不一致",
                    )

            case_study_ids.update(
                _audit_evidence_bundle(
                    report_dir=report_dir,
                    matrix_root=root,
                    scope=run_scope,
                    issues=issues,
                    run_summary=run_summary,
                )
            )

        if row is not None and len(run_metrics) == len(runs):
            _audit_statistics_against_runs(
                row=row,
                variant_name=variant_name,
                run_metrics=run_metrics,
                matrix_root=root,
                summary_path=variant_summary_path,
                issues=issues,
            )

    case_study_count = len(case_study_ids)
    if case_study_count < minimum_case_studies:
        _issue(
            issues,
            code="insufficient_case_studies",
            matrix_root=root,
            scope="matrix",
            path=summary_dir,
            detail=(
                f"case study 共 {case_study_count} 个，"
                f"最低要求 {minimum_case_studies}"
            ),
        )

    return {
        "matrix_root": str(root),
        "status": "ready" if not issues else "not_ready",
        "variant_count": len(variants),
        "run_count": total_runs,
        "case_study_count": case_study_count,
        "issues": issues,
    }


def _write_issues_tsv(path: Path, issues: Sequence[Mapping[str, str]]) -> None:
    columns = ("severity", "code", "matrix_root", "scope", "path", "detail")

    def clean(value: Any) -> str:
        return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")

    lines = ["\t".join(columns)]
    for issue in issues:
        lines.append("\t".join(clean(issue.get(column, "")) for column in columns))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_publication_audit(
    *,
    matrix_roots: Sequence[Path],
    output_dir: Optional[Path] = None,
    minimum_runs: int = 5,
    minimum_case_studies: int = 2,
) -> int:
    if not matrix_roots:
        raise PublicationAuditError("至少提供一个 --matrix-root")
    if minimum_runs < 2:
        raise PublicationAuditError("--minimum-runs 必须大于等于 2")
    if minimum_case_studies < 0:
        raise PublicationAuditError("--minimum-case-studies 必须大于等于 0")

    resolved_roots = [Path(path).expanduser().resolve() for path in matrix_roots]
    if output_dir is None:
        target_dir = (
            resolved_roots[0].parent
            / "publication_audits"
            / _directory_timestamp()
        )
    else:
        target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    matrix_results = [
        _audit_matrix_root(
            matrix_root=root,
            minimum_runs=minimum_runs,
            minimum_case_studies=minimum_case_studies,
        )
        for root in resolved_roots
    ]
    issues = [
        issue
        for result in matrix_results
        for issue in result.get("issues", [])
        if isinstance(issue, Mapping)
    ]
    payload = {
        "contract_name": "publication_readiness_audit",
        "contract_version": CONTRACT_VERSION,
        "generated_at": _utc_timestamp(),
        "status": "ready" if not issues else "not_ready",
        "minimum_runs": minimum_runs,
        "minimum_case_studies": minimum_case_studies,
        "matrix_count": len(matrix_results),
        "ready_matrix_count": sum(
            1 for result in matrix_results if result.get("status") == "ready"
        ),
        "issue_count": len(issues),
        "matrices": matrix_results,
    }
    json_path = atomic_write_json(target_dir / "publication_readiness.json", payload)
    _write_issues_tsv(target_dir / "publication_readiness_issues.tsv", issues)

    if issues:
        raise PublicationAuditError(
            "论文证据审计未通过，共 "
            f"{len(issues)} 个问题；结果已写入 {json_path}"
        )
    return 0


__all__ = ["PublicationAuditError", "run_publication_audit"]
