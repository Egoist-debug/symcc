import json
import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

EXIT_USAGE = 2

METRIC_NAMES: Sequence[str] = (
    "total_samples",
    "included_samples",
    "excluded_samples",
    "unknown_samples",
    "needs_review_count",
    "cluster_count",
    "repro_rate",
    "oracle_audit_candidate_count",
    "semantic_diff_count",
)

REQUIRED_CANONICAL_METRICS: Sequence[str] = (
    "oracle_audit_candidate_count",
    "semantic_diff_count",
)


class CampaignAggregateError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _coerce_non_negative_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value if value >= 0 else default
    if isinstance(value, float) and value.is_integer():
        parsed = int(value)
        return parsed if parsed >= 0 else default
    return default


def _coerce_non_negative_int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer():
        parsed = int(value)
        return parsed if parsed >= 0 else None
    return None


def _coerce_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _normalize_json_payload(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    return dict(value)


def _collect_run_records(reports_root: Path) -> List[Dict[str, Any]]:
    root = Path(reports_root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise CampaignAggregateError(f"reports-root 不存在或不是目录: {root}")

    records: List[Dict[str, Any]] = []
    for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        summary_path = run_dir / "summary.json"
        if not summary_path.is_file():
            continue
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CampaignAggregateError(
                f"读取 summary.json 失败 {summary_path}: {exc}"
            ) from exc

        if not isinstance(payload, Mapping):
            raise CampaignAggregateError(f"summary.json 顶层必须是对象: {summary_path}")

        records.append(
            {
                "run_id": run_dir.name,
                "run_dir": run_dir,
                "summary_path": summary_path,
                "summary": dict(payload),
            }
        )

    if not records:
        raise CampaignAggregateError(
            f"未在 {root} 下发现任何 campaign_reports/*/summary.json"
        )
    return records


def _missing_canonical_metric_fields(summary: Mapping[str, Any]) -> List[str]:
    missing_fields: List[str] = []
    for field_name in REQUIRED_CANONICAL_METRICS:
        if _coerce_non_negative_int_or_none(summary.get(field_name)) is None:
            missing_fields.append(field_name)
    return missing_fields


def _extract_metrics(summary: Mapping[str, Any]) -> Dict[str, float]:
    metric_denominators = summary.get("metric_denominators")
    analysis_state: Mapping[str, Any] = {}
    if isinstance(metric_denominators, Mapping):
        nested = metric_denominators.get("analysis_state")
        if isinstance(nested, Mapping):
            analysis_state = nested

    oracle_audit_candidate_count = _coerce_non_negative_int_or_none(
        summary.get("oracle_audit_candidate_count")
    )
    semantic_diff_count = _coerce_non_negative_int_or_none(
        summary.get("semantic_diff_count")
    )

    return {
        "total_samples": float(_coerce_non_negative_int(summary.get("total_samples"))),
        "included_samples": float(
            _coerce_non_negative_int(analysis_state.get("included"))
        ),
        "excluded_samples": float(
            _coerce_non_negative_int(analysis_state.get("excluded"))
        ),
        "unknown_samples": float(
            _coerce_non_negative_int(analysis_state.get("unknown"))
        ),
        "needs_review_count": float(
            _coerce_non_negative_int(summary.get("needs_review_count"))
        ),
        "cluster_count": float(_coerce_non_negative_int(summary.get("cluster_count"))),
        "repro_rate": _coerce_float(summary.get("repro_rate"), default=0.0),
        "oracle_audit_candidate_count": float(oracle_audit_candidate_count)
        if oracle_audit_candidate_count is not None
        else math.nan,
        "semantic_diff_count": float(semantic_diff_count)
        if semantic_diff_count is not None
        else math.nan,
    }


def _stable_key_fingerprint(payload: Optional[Mapping[str, Any]]) -> str:
    if payload is None:
        return "<null>"
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _write_run_matrix_tsv(output_dir: Path, records: Sequence[Dict[str, Any]]) -> None:
    header = [
        "run_id",
        "summary_path",
        *METRIC_NAMES,
    ]
    lines = ["\t".join(header)]

    for record in records:
        summary = record["summary"]
        metrics = _extract_metrics(summary)
        row = [record["run_id"], str(record["summary_path"])]
        for metric_name in METRIC_NAMES:
            value = metrics[metric_name]
            if math.isnan(value):
                row.append("NA")
                continue
            if metric_name == "repro_rate":
                row.append(f"{value:.6f}")
            else:
                row.append(str(int(value)))
        lines.append("\t".join(row))

    (output_dir / "run_matrix.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _write_comparability_tsv(
    output_dir: Path, records: Sequence[Dict[str, Any]]
) -> None:
    header = [
        "run_id",
        "comparability_status",
        "comparability_reason",
        "aggregation_key",
        "baseline_compare_key",
        "aggregation_key_conflict_fields",
        "baseline_compare_key_conflict_fields",
    ]
    lines = ["\t".join(header)]

    for record in records:
        summary = record["summary"]
        comparability = _normalize_json_payload(summary.get("comparability")) or {}
        aggregation_key = _normalize_json_payload(comparability.get("aggregation_key"))
        baseline_compare_key = _normalize_json_payload(
            comparability.get("baseline_compare_key")
        )

        aggregation_conflicts = comparability.get("aggregation_key_conflict_fields")
        baseline_conflicts = comparability.get("baseline_compare_key_conflict_fields")
        aggregation_conflict_text = (
            ",".join(str(item) for item in aggregation_conflicts)
            if isinstance(aggregation_conflicts, list)
            else "-"
        )
        baseline_conflict_text = (
            ",".join(str(item) for item in baseline_conflicts)
            if isinstance(baseline_conflicts, list)
            else "-"
        )

        lines.append(
            "\t".join(
                [
                    record["run_id"],
                    str(comparability.get("status", "non_comparable")),
                    str(comparability.get("reason", "missing_comparability")),
                    _stable_key_fingerprint(aggregation_key),
                    _stable_key_fingerprint(baseline_compare_key),
                    aggregation_conflict_text,
                    baseline_conflict_text,
                ]
            )
        )

    (output_dir / "comparability.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _aggregation_key_signature(record: Dict[str, Any]) -> str:
    comparability = (
        _normalize_json_payload(record["summary"].get("comparability")) or {}
    )
    aggregation_key = _normalize_json_payload(comparability.get("aggregation_key"))
    return _stable_key_fingerprint(aggregation_key)


def _has_missing_comparability_metadata(record: Dict[str, Any]) -> bool:
    summary = record["summary"]
    comparability = _normalize_json_payload(summary.get("comparability"))
    if comparability is None:
        return True
    aggregation_key = _normalize_json_payload(comparability.get("aggregation_key"))
    if aggregation_key is None:
        return True
    if not aggregation_key:
        return True
    return False


def _shared_aggregation_key(
    records: Sequence[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not records:
        return None
    comparability = (
        _normalize_json_payload(records[0]["summary"].get("comparability")) or {}
    )
    return _normalize_json_payload(comparability.get("aggregation_key"))


def _compute_metric_statistics(values: Sequence[float]) -> Dict[str, float]:
    if not values:
        raise CampaignAggregateError("统计指标不能为空")
    count = float(len(values))
    mean = sum(values) / count
    variance = sum((value - mean) ** 2 for value in values) / count
    return {
        "mean": mean,
        "min": min(values),
        "max": max(values),
        "stddev": math.sqrt(variance),
    }


def _write_variance_tsv(
    output_dir: Path,
    *,
    variance_status: str,
    aggregates: Mapping[str, Mapping[str, float]],
) -> None:
    lines = ["metric\tmean\tmin\tmax\tstddev"]
    if variance_status == "ok":
        for metric_name in METRIC_NAMES:
            stats = aggregates.get(metric_name)
            if not isinstance(stats, Mapping):
                continue
            lines.append(
                "\t".join(
                    [
                        metric_name,
                        f"{_coerce_float(stats.get('mean')):.6f}",
                        f"{_coerce_float(stats.get('min')):.6f}",
                        f"{_coerce_float(stats.get('max')):.6f}",
                        f"{_coerce_float(stats.get('stddev')):.6f}",
                    ]
                )
            )
    else:
        lines.append(f"__status__\t{variance_status}\t-\t-\t-")

    (output_dir / "variance.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_summary_payload(
    *,
    reports_root: Path,
    output_dir: Path,
    run_count: int,
    variance_status: str,
    mixed_aggregation_key: bool,
    shared_aggregation_key: Optional[Mapping[str, Any]],
    aggregates: Mapping[str, Mapping[str, float]],
) -> Dict[str, Any]:
    return {
        "run_count": run_count,
        "variance_status": variance_status,
        "aggregate_metrics": list(METRIC_NAMES),
        "reports_root": str(reports_root),
        "output_dir": str(output_dir),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mixed_aggregation_key": mixed_aggregation_key,
        "aggregation_key": dict(shared_aggregation_key)
        if shared_aggregation_key
        else None,
        "aggregates": aggregates,
    }


def run_campaign_aggregate(
    reports_root: Path, output_dir: Optional[Path] = None
) -> int:
    records = _collect_run_records(Path(reports_root))
    resolved_reports_root = Path(reports_root).expanduser().resolve()
    output_base = (
        Path(output_dir).expanduser().resolve()
        if output_dir is not None
        else resolved_reports_root
    )
    aggregate_dir = output_base / "campaign_aggregates" / _get_timestamp()
    aggregate_dir.mkdir(parents=True, exist_ok=True)

    _write_run_matrix_tsv(aggregate_dir, records)
    _write_comparability_tsv(aggregate_dir, records)

    signatures = {_aggregation_key_signature(record) for record in records}
    mixed_aggregation_key = len(signatures) > 1
    run_count = len(records)
    shared_key = _shared_aggregation_key(records)

    aggregates: Dict[str, Dict[str, float]] = {}
    missing_comparability_metadata = any(
        _has_missing_comparability_metadata(record) for record in records
    )
    missing_canonical_metrics = {
        record["run_id"]: _missing_canonical_metric_fields(record["summary"])
        for record in records
    }
    missing_canonical_metrics = {
        run_id: missing_fields
        for run_id, missing_fields in missing_canonical_metrics.items()
        if missing_fields
    }

    if mixed_aggregation_key:
        variance_status = "incompatible_aggregation_key"
    elif missing_comparability_metadata:
        variance_status = "missing_comparability_metadata"
    elif missing_canonical_metrics:
        variance_status = "missing_canonical_metrics"
    elif run_count < 2:
        variance_status = "insufficient_runs"
    else:
        variance_status = "ok"
        for metric_name in METRIC_NAMES:
            metric_values = [
                _extract_metrics(record["summary"])[metric_name] for record in records
            ]
            aggregates[metric_name] = _compute_metric_statistics(metric_values)

    _write_variance_tsv(
        aggregate_dir,
        variance_status=variance_status,
        aggregates=aggregates,
    )

    summary_payload = _build_summary_payload(
        reports_root=resolved_reports_root,
        output_dir=aggregate_dir,
        run_count=run_count,
        variance_status=variance_status,
        mixed_aggregation_key=mixed_aggregation_key,
        shared_aggregation_key=shared_key,
        aggregates=aggregates,
    )
    (aggregate_dir / "summary.json").write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    if mixed_aggregation_key:
        raise CampaignAggregateError(
            "检测到多个不同 comparability.aggregation_key，已写入 comparability.tsv 并拒绝聚合"
        )
    if missing_comparability_metadata:
        raise CampaignAggregateError(
            "检测到 run summary 缺失 comparability 元数据，已写入 comparability.tsv 并拒绝聚合"
        )
    if missing_canonical_metrics:
        missing_details = "; ".join(
            f"{run_id}: {','.join(fields)}"
            for run_id, fields in sorted(missing_canonical_metrics.items())
        )
        raise CampaignAggregateError(
            "检测到 run summary 缺失 canonical 指标字段，已写入 run_matrix.tsv 并拒绝聚合: "
            f"{missing_details}"
        )

    return 0


__all__ = [
    "CampaignAggregateError",
    "METRIC_NAMES",
    "run_campaign_aggregate",
]
