import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from .aggregate import (
    METRIC_NAMES,
    _aggregation_key_signature,
    _compute_metric_statistics,
    _extract_metrics,
    _has_missing_comparability_metadata,
    _normalize_json_payload,
    _shared_aggregation_key,
    _stable_key_fingerprint,
)
from .close_loop import CampaignCloseError, run_campaign_close
from .schema import (
    AGGREGATION_KEY_FIELDS,
    BASELINE_COMPARE_KEY_FIELDS,
    CONTRACT_VERSION,
    utc_timestamp,
)

EXIT_USAGE = 2
BASELINE_VARIANT_NAME = "full_stack"
TOGGLE_ENV_ORDER: Tuple[str, ...] = (
    "ENABLE_DST1_MUTATOR",
    "ENABLE_CACHE_DELTA",
    "ENABLE_TRIAGE",
    "ENABLE_SYMCC",
)
TOGGLE_ENV_TO_ABLATION_KEY = {
    "ENABLE_DST1_MUTATOR": "mutator",
    "ENABLE_CACHE_DELTA": "cache-delta",
    "ENABLE_TRIAGE": "triage",
    "ENABLE_SYMCC": "symcc",
}
EXPECTED_VARIANT_ENVS: Dict[str, Dict[str, str]] = {
    "full_stack": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
    "afl_only": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "0",
    },
    "no_mutator": {
        "ENABLE_DST1_MUTATOR": "0",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
    "no_cache_delta": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "0",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
}
EXPECTED_VARIANT_ORDER: Tuple[str, ...] = tuple(EXPECTED_VARIANT_ENVS.keys())


class CampaignMatrixError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class MatrixVariant:
    variant_name: str
    env: Dict[str, str]


@dataclass(frozen=True)
class MatrixConfig:
    matrix_name: str
    matrix_file: Path
    source_queue_dir: Path
    resolver_pair: str
    producer_profile: str
    input_model: str
    seed_timeout_sec: int | float
    contract_version: int
    variants: Tuple[MatrixVariant, ...]


@dataclass(frozen=True)
class MatrixRunRecord:
    variant_name: str
    repeat_index: int
    run_dir: Path
    report_dir: Path
    summary_path: Path
    close_summary_path: Path
    summary: Dict[str, Any]

    @property
    def run_id(self) -> str:
        return f"{self.variant_name}/{self.run_dir.name}"


@dataclass(frozen=True)
class VariantAggregate:
    variant_name: str
    env: Dict[str, str]
    run_records: Tuple[MatrixRunRecord, ...]
    run_count: int
    variance_status: str
    aggregation_key: Optional[Dict[str, Any]]
    baseline_compare_key: Optional[Dict[str, Any]]
    baseline_compare_key_status: str
    aggregates: Dict[str, Dict[str, float]]


def _require_mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CampaignMatrixError(f"{label} 必须是对象")
    return dict(value)


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CampaignMatrixError(f"{label} 必须是非空字符串")
    return value.strip()


def _normalize_toggle_value(value: Any, label: str) -> str:
    if isinstance(value, bool):
        raise CampaignMatrixError(f"{label} 只能是 0 或 1")
    if isinstance(value, int) and value in {0, 1}:
        return str(value)
    if isinstance(value, str) and value in {"0", "1"}:
        return value
    raise CampaignMatrixError(f"{label} 只能是 0 或 1")


def _normalize_key_number(value: int | float) -> int | float:
    if isinstance(value, int):
        return value
    if float(value).is_integer():
        return int(value)
    return float(value)


def _normalize_env_payload(variant_name: str, payload: Any) -> Dict[str, str]:
    env_payload = _require_mapping(payload, f"variants[{variant_name}].env")
    normalized: Dict[str, str] = {}
    for env_name in TOGGLE_ENV_ORDER:
        normalized[env_name] = _normalize_toggle_value(
            env_payload.get(env_name), f"variants[{variant_name}].env.{env_name}"
        )

    extra_keys = sorted(set(env_payload.keys()) - set(TOGGLE_ENV_ORDER))
    if extra_keys:
        raise CampaignMatrixError(
            f"variants[{variant_name}].env 包含未支持键: {', '.join(extra_keys)}"
        )
    return normalized


def _build_ablation_status(env: Mapping[str, str]) -> Dict[str, str]:
    return {
        "mutator": "on" if env.get("ENABLE_DST1_MUTATOR") == "1" else "off",
        "cache-delta": "on" if env.get("ENABLE_CACHE_DELTA") == "1" else "off",
        "triage": "on" if env.get("ENABLE_TRIAGE") == "1" else "off",
        "symcc": "on" if env.get("ENABLE_SYMCC") == "1" else "off",
    }


def _toggle_diff_fields(
    baseline_env: Mapping[str, str], candidate_env: Mapping[str, str]
) -> List[str]:
    diff_fields: List[str] = []
    for env_name in TOGGLE_ENV_ORDER:
        if baseline_env.get(env_name) != candidate_env.get(env_name):
            diff_fields.append(TOGGLE_ENV_TO_ABLATION_KEY[env_name])
    return diff_fields


def _resolve_source_queue_dir(raw_value: str, work_root: Path) -> Path:
    candidate = Path(raw_value).expanduser()
    if not candidate.is_absolute():
        candidate = work_root / candidate
    return candidate.resolve()


def _load_matrix_config(matrix_file: Path, work_root: Path) -> MatrixConfig:
    matrix_path = Path(matrix_file).expanduser().resolve()
    if not matrix_path.is_file():
        raise CampaignMatrixError(f"matrix-file 不存在或不是文件: {matrix_path}")

    try:
        payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CampaignMatrixError(
            f"读取 matrix-file 失败 {matrix_path}: {exc}"
        ) from exc

    root_payload = _require_mapping(payload, "matrix-file")
    matrix_name = _require_text(
        root_payload.get("matrix_name", matrix_path.stem), "matrix_name"
    )
    comparability_payload = _require_mapping(
        root_payload.get("comparability"), "comparability"
    )

    source_queue_dir = _resolve_source_queue_dir(
        _require_text(
            comparability_payload.get("source_queue_dir"),
            "comparability.source_queue_dir",
        ),
        work_root,
    )
    seed_timeout_sec = comparability_payload.get("seed_timeout_sec")
    if isinstance(seed_timeout_sec, bool) or not isinstance(
        seed_timeout_sec, (int, float)
    ):
        raise CampaignMatrixError("comparability.seed_timeout_sec 必须是正数")
    if float(seed_timeout_sec) <= 0:
        raise CampaignMatrixError("comparability.seed_timeout_sec 必须大于 0")

    contract_version = comparability_payload.get("contract_version", CONTRACT_VERSION)
    if isinstance(contract_version, bool) or not isinstance(contract_version, int):
        raise CampaignMatrixError("comparability.contract_version 必须是正整数")
    if contract_version < 1:
        raise CampaignMatrixError("comparability.contract_version 必须大于等于 1")

    variants_payload = root_payload.get("variants")
    if not isinstance(variants_payload, list):
        raise CampaignMatrixError("variants 必须是数组")
    if len(variants_payload) != len(EXPECTED_VARIANT_ORDER):
        raise CampaignMatrixError(
            f"variants 必须固定包含 {len(EXPECTED_VARIANT_ORDER)} 个变体"
        )

    variants: List[MatrixVariant] = []
    variant_names: List[str] = []
    for index, entry in enumerate(variants_payload):
        variant_payload = _require_mapping(entry, f"variants[{index}]")
        variant_name = _require_text(
            variant_payload.get("variant_name"), f"variants[{index}].variant_name"
        )
        variant_names.append(variant_name)
        env = _normalize_env_payload(variant_name, variant_payload.get("env"))

        expected_env = EXPECTED_VARIANT_ENVS.get(variant_name)
        if expected_env is None:
            raise CampaignMatrixError(f"variants[{index}] 含未支持变体: {variant_name}")
        if env != expected_env:
            raise CampaignMatrixError(
                f"variants[{variant_name}] env 必须固定为 {expected_env}，实际 {env}"
            )
        variants.append(MatrixVariant(variant_name=variant_name, env=env))

    if tuple(variant_names) != EXPECTED_VARIANT_ORDER:
        raise CampaignMatrixError(
            "variants 顺序必须固定为 full_stack, afl_only, no_mutator, no_cache_delta"
        )

    baseline_env = EXPECTED_VARIANT_ENVS[BASELINE_VARIANT_NAME]
    for variant in variants:
        if variant.variant_name == BASELINE_VARIANT_NAME:
            continue
        diff_fields = _toggle_diff_fields(baseline_env, variant.env)
        if len(diff_fields) != 1:
            raise CampaignMatrixError(
                f"变体 {variant.variant_name} 与 baseline 必须只差一个 toggle，实际差异 {diff_fields}"
            )

    return MatrixConfig(
        matrix_name=matrix_name,
        matrix_file=matrix_path,
        source_queue_dir=source_queue_dir,
        resolver_pair=_require_text(
            comparability_payload.get("resolver_pair"), "comparability.resolver_pair"
        ),
        producer_profile=_require_text(
            comparability_payload.get("producer_profile"),
            "comparability.producer_profile",
        ),
        input_model=_require_text(
            comparability_payload.get("input_model"), "comparability.input_model"
        ),
        seed_timeout_sec=_normalize_key_number(float(seed_timeout_sec)),
        contract_version=contract_version,
        variants=tuple(variants),
    )


@contextmanager
def _temporary_environ(overrides: Mapping[str, str]) -> Iterator[None]:
    sentinel = object()
    previous_values: Dict[str, object] = {}
    for key in overrides:
        previous_values[key] = os.environ.get(key, sentinel)

    try:
        for key, value in overrides.items():
            os.environ[key] = value
        yield
    finally:
        for key, previous in previous_values.items():
            if previous is sentinel:
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(previous)


def _ensure_empty_run_dir(run_dir: Path) -> None:
    if run_dir.exists():
        if any(run_dir.iterdir()):
            raise CampaignMatrixError(f"run 目录非空，拒绝覆盖: {run_dir}")
        return
    run_dir.mkdir(parents=True, exist_ok=False)


def _resolve_latest_report_dir(run_dir: Path) -> Path:
    report_base = run_dir / "campaign_reports"
    if not report_base.is_dir():
        raise CampaignMatrixError(
            f"campaign-close 未生成 campaign_reports: {report_base}"
        )

    report_dirs = sorted(path for path in report_base.iterdir() if path.is_dir())
    if not report_dirs:
        raise CampaignMatrixError(f"campaign-close 未生成 report 目录: {report_base}")
    return report_dirs[-1]


def _load_summary_json(summary_path: Path) -> Dict[str, Any]:
    if not summary_path.is_file():
        raise CampaignMatrixError(f"summary.json 缺失: {summary_path}")
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CampaignMatrixError(
            f"读取 summary.json 失败 {summary_path}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise CampaignMatrixError(f"summary.json 顶层必须是对象: {summary_path}")
    return dict(payload)


def _is_complete_contract_key(
    payload: Optional[Mapping[str, Any]], fields: Sequence[str]
) -> bool:
    if not isinstance(payload, Mapping):
        return False
    for field in fields:
        if field not in payload:
            return False
        value = payload.get(field)
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
    return True


def _run_single_matrix_entry(
    *,
    config: MatrixConfig,
    variant: MatrixVariant,
    repeat_index: int,
    budget_sec: float,
    repeat_count: int,
    run_dir: Path,
) -> MatrixRunRecord:
    _ensure_empty_run_dir(run_dir)

    env_overrides = dict(variant.env)
    env_overrides.update(
        {
            "WORK_DIR": str(run_dir),
            "FOLLOW_DIFF_SOURCE_DIR": str(config.source_queue_dir),
        }
    )

    try:
        with _temporary_environ(env_overrides):
            exit_code = run_campaign_close(budget_sec=budget_sec)
    except CampaignCloseError as exc:
        raise CampaignMatrixError(
            f"variant={variant.variant_name} run-{repeat_index:02d} campaign-close 异常: {exc}",
            exit_code=exc.exit_code,
        ) from exc

    if exit_code != 0:
        raise CampaignMatrixError(
            f"variant={variant.variant_name} run-{repeat_index:02d} campaign-close 返回非零退出码: {exit_code}",
            exit_code=int(exit_code),
        )

    report_dir = _resolve_latest_report_dir(run_dir)
    summary_path = report_dir / "summary.json"
    close_summary_path = run_dir / "campaign_close.summary.json"
    summary = _load_summary_json(summary_path)
    return MatrixRunRecord(
        variant_name=variant.variant_name,
        repeat_index=repeat_index,
        run_dir=run_dir,
        report_dir=report_dir,
        summary_path=summary_path,
        close_summary_path=close_summary_path,
        summary=summary,
    )


def _build_aggregate_records(
    run_records: Sequence[MatrixRunRecord],
) -> List[Dict[str, Any]]:
    return [
        {
            "run_id": record.run_id,
            "run_dir": record.report_dir,
            "summary_path": record.summary_path,
            "summary": dict(record.summary),
        }
        for record in run_records
    ]


def _evaluate_shared_contract_key(
    records: Sequence[Dict[str, Any]],
    *,
    key_name: str,
    fields: Sequence[str],
    incompatible_status: str,
) -> tuple[str, Optional[Dict[str, Any]]]:
    shared_key: Optional[Dict[str, Any]] = None
    signatures = set()

    for record in records:
        comparability = (
            _normalize_json_payload(record["summary"].get("comparability")) or {}
        )
        payload = _normalize_json_payload(comparability.get(key_name))
        if not _is_complete_contract_key(payload, fields):
            return "missing_comparability_metadata", None
        assert payload is not None
        signatures.add(_stable_key_fingerprint(payload))
        if shared_key is None:
            shared_key = dict(payload)

    if len(signatures) > 1:
        return incompatible_status, None
    return "ok", shared_key


def _aggregate_variant(
    variant: MatrixVariant, run_records: Sequence[MatrixRunRecord]
) -> VariantAggregate:
    records = _build_aggregate_records(run_records)
    signatures = {_aggregation_key_signature(record) for record in records}
    mixed_aggregation_key = len(signatures) > 1
    missing_comparability_metadata = any(
        _has_missing_comparability_metadata(record) for record in records
    )
    shared_aggregation_key = _shared_aggregation_key(records)

    if mixed_aggregation_key:
        variance_status = "incompatible_aggregation_key"
    elif missing_comparability_metadata:
        variance_status = "missing_comparability_metadata"
    elif len(records) < 2:
        variance_status = "insufficient_runs"
    else:
        variance_status = "ok"

    aggregates: Dict[str, Dict[str, float]] = {}
    if variance_status == "ok":
        for metric_name in METRIC_NAMES:
            aggregates[metric_name] = _compute_metric_statistics(
                [_extract_metrics(record["summary"])[metric_name] for record in records]
            )

    baseline_compare_key_status, baseline_compare_key = _evaluate_shared_contract_key(
        records,
        key_name="baseline_compare_key",
        fields=BASELINE_COMPARE_KEY_FIELDS,
        incompatible_status="incompatible_baseline_compare_key",
    )

    return VariantAggregate(
        variant_name=variant.variant_name,
        env=dict(variant.env),
        run_records=tuple(run_records),
        run_count=len(run_records),
        variance_status=variance_status,
        aggregation_key=dict(shared_aggregation_key)
        if shared_aggregation_key
        else None,
        baseline_compare_key=baseline_compare_key,
        baseline_compare_key_status=baseline_compare_key_status,
        aggregates=aggregates,
    )


def _format_metric_value(value: Optional[float]) -> str:
    if value is None:
        return ""
    return f"{float(value):.6f}"


def _format_key_cell(
    payload: Optional[Mapping[str, Any]],
    *,
    status: str,
    mixed_status: str,
) -> str:
    if status == "missing_comparability_metadata":
        return "<missing>"
    if status == mixed_status:
        return "<mixed>"
    return _stable_key_fingerprint(payload)


def _baseline_delta_status(
    baseline: VariantAggregate, candidate: VariantAggregate
) -> tuple[str, str, List[str]]:
    if candidate.variant_name == baseline.variant_name:
        return "baseline", "baseline", []

    diff_fields = _toggle_diff_fields(baseline.env, candidate.env)
    if baseline.baseline_compare_key_status != "ok":
        return "non-comparable", "baseline_missing_baseline_compare_key", diff_fields
    if candidate.baseline_compare_key_status != "ok":
        return (
            "non-comparable",
            f"{candidate.baseline_compare_key_status}",
            diff_fields,
        )

    if _stable_key_fingerprint(
        baseline.baseline_compare_key
    ) != _stable_key_fingerprint(candidate.baseline_compare_key):
        return "non-comparable", "baseline_compare_key_mismatch", diff_fields

    if len(diff_fields) != 1:
        return "non-comparable", "toggle_diff_count_ne_1", diff_fields

    if baseline.variance_status != "ok" or candidate.variance_status != "ok":
        return (
            "aggregate-unavailable",
            f"baseline={baseline.variance_status};candidate={candidate.variance_status}",
            diff_fields,
        )

    return "ok", "ok", diff_fields


def _write_matrix_manifest(
    output_dir: Path,
    *,
    config: MatrixConfig,
    budget_sec: float,
    repeat_count: int,
    work_root: Path,
    run_records_by_variant: Mapping[str, Sequence[MatrixRunRecord]],
) -> None:
    payload = {
        "generated_at": utc_timestamp(),
        "matrix_name": config.matrix_name,
        "matrix_file": str(config.matrix_file),
        "baseline_variant_name": BASELINE_VARIANT_NAME,
        "budget_sec": _normalize_key_number(float(budget_sec)),
        "repeat_count": int(repeat_count),
        "work_root": str(work_root),
        "source_queue_dir": str(config.source_queue_dir),
        "variants": [],
        "summary_outputs": {
            "matrix_manifest_json": str(output_dir / "matrix_manifest.json"),
            "variant_summary_tsv": str(output_dir / "variant_summary.tsv"),
            "delta_vs_baseline_tsv": str(output_dir / "delta_vs_baseline.tsv"),
            "comparability_tsv": str(output_dir / "comparability.tsv"),
        },
    }

    for variant in config.variants:
        records = run_records_by_variant.get(variant.variant_name, ())
        payload["variants"].append(
            {
                "variant_name": variant.variant_name,
                "repeat_count": int(repeat_count),
                "env": dict(variant.env),
                "runs": [
                    {
                        "repeat_index": record.repeat_index,
                        "run_dir": str(record.run_dir),
                        "report_dir": str(record.report_dir),
                        "summary_path": str(record.summary_path),
                        "close_summary_path": str(record.close_summary_path),
                    }
                    for record in records
                ],
            }
        )

    (output_dir / "matrix_manifest.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_variant_summary_tsv(
    output_dir: Path, aggregates_by_variant: Mapping[str, VariantAggregate]
) -> None:
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
    ]
    for metric_name in METRIC_NAMES:
        header.extend([f"{metric_name}_mean", f"{metric_name}_stddev"])

    lines = ["\t".join(header)]
    for variant_name in EXPECTED_VARIANT_ORDER:
        aggregate = aggregates_by_variant[variant_name]
        ablation = _build_ablation_status(aggregate.env)
        row = [
            variant_name,
            str(aggregate.run_count),
            aggregate.variance_status,
            ablation["mutator"],
            ablation["cache-delta"],
            ablation["triage"],
            ablation["symcc"],
            _format_key_cell(
                aggregate.aggregation_key,
                status=(
                    "missing_comparability_metadata"
                    if aggregate.aggregation_key is None
                    and aggregate.variance_status == "missing_comparability_metadata"
                    else (
                        "incompatible_aggregation_key"
                        if aggregate.variance_status == "incompatible_aggregation_key"
                        else "ok"
                    )
                ),
                mixed_status="incompatible_aggregation_key",
            ),
            _format_key_cell(
                aggregate.baseline_compare_key,
                status=aggregate.baseline_compare_key_status,
                mixed_status="incompatible_baseline_compare_key",
            ),
        ]
        for metric_name in METRIC_NAMES:
            stats = aggregate.aggregates.get(metric_name)
            if isinstance(stats, Mapping):
                row.append(_format_metric_value(float(stats.get("mean", 0.0))))
                row.append(_format_metric_value(float(stats.get("stddev", 0.0))))
            else:
                row.extend(["", ""])
        lines.append("\t".join(row))

    (output_dir / "variant_summary.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _write_comparability_tsv(
    output_dir: Path,
    *,
    baseline: VariantAggregate,
    aggregates_by_variant: Mapping[str, VariantAggregate],
) -> None:
    header = [
        "variant_name",
        "run_count",
        "variance_status",
        "baseline_delta_status",
        "baseline_delta_reason",
        "toggle_diff_fields",
        "aggregation_key",
        "baseline_compare_key",
        "baseline_compare_key_status",
    ]
    lines = ["\t".join(header)]

    for variant_name in EXPECTED_VARIANT_ORDER:
        aggregate = aggregates_by_variant[variant_name]
        delta_status, delta_reason, diff_fields = _baseline_delta_status(
            baseline, aggregate
        )
        lines.append(
            "\t".join(
                [
                    variant_name,
                    str(aggregate.run_count),
                    aggregate.variance_status,
                    delta_status,
                    delta_reason,
                    ",".join(diff_fields) if diff_fields else "-",
                    _format_key_cell(
                        aggregate.aggregation_key,
                        status=(
                            "missing_comparability_metadata"
                            if aggregate.aggregation_key is None
                            and aggregate.variance_status
                            == "missing_comparability_metadata"
                            else (
                                "incompatible_aggregation_key"
                                if aggregate.variance_status
                                == "incompatible_aggregation_key"
                                else "ok"
                            )
                        ),
                        mixed_status="incompatible_aggregation_key",
                    ),
                    _format_key_cell(
                        aggregate.baseline_compare_key,
                        status=aggregate.baseline_compare_key_status,
                        mixed_status="incompatible_baseline_compare_key",
                    ),
                    aggregate.baseline_compare_key_status,
                ]
            )
        )

    (output_dir / "comparability.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _write_delta_vs_baseline_tsv(
    output_dir: Path,
    *,
    baseline: VariantAggregate,
    aggregates_by_variant: Mapping[str, VariantAggregate],
) -> None:
    header = [
        "baseline_variant",
        "variant_name",
        "metric",
        "status",
        "reason",
        "toggle_diff_field",
        "baseline_mean",
        "variant_mean",
        "delta",
    ]
    lines = ["\t".join(header)]

    for variant_name in EXPECTED_VARIANT_ORDER:
        if variant_name == BASELINE_VARIANT_NAME:
            continue
        aggregate = aggregates_by_variant[variant_name]
        delta_status, delta_reason, diff_fields = _baseline_delta_status(
            baseline, aggregate
        )
        diff_field = diff_fields[0] if len(diff_fields) == 1 else "-"
        for metric_name in METRIC_NAMES:
            baseline_stats = baseline.aggregates.get(metric_name)
            variant_stats = aggregate.aggregates.get(metric_name)
            baseline_mean: Optional[float] = None
            variant_mean: Optional[float] = None
            delta_value: Optional[float] = None
            if (
                delta_status == "ok"
                and isinstance(baseline_stats, Mapping)
                and isinstance(variant_stats, Mapping)
            ):
                baseline_mean = float(baseline_stats.get("mean", 0.0))
                variant_mean = float(variant_stats.get("mean", 0.0))
                delta_value = variant_mean - baseline_mean

            lines.append(
                "\t".join(
                    [
                        BASELINE_VARIANT_NAME,
                        variant_name,
                        metric_name,
                        delta_status,
                        delta_reason,
                        diff_field,
                        _format_metric_value(baseline_mean),
                        _format_metric_value(variant_mean),
                        _format_metric_value(delta_value),
                    ]
                )
            )

    (output_dir / "delta_vs_baseline.tsv").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def run_campaign_matrix(
    *,
    matrix_file: Path,
    budget_sec: float,
    repeat: int,
    work_root: Path,
) -> int:
    if budget_sec <= 0:
        raise CampaignMatrixError("--budget-sec 必须大于 0")
    if repeat <= 0:
        raise CampaignMatrixError("--repeat 必须大于 0")

    resolved_work_root = Path(work_root).expanduser().resolve()
    resolved_work_root.mkdir(parents=True, exist_ok=True)
    config = _load_matrix_config(matrix_file, resolved_work_root)
    if not config.source_queue_dir.is_dir():
        raise CampaignMatrixError(
            f"matrix source queue 目录不存在或不是目录: {config.source_queue_dir}"
        )

    run_records_by_variant: Dict[str, List[MatrixRunRecord]] = {
        variant_name: [] for variant_name in EXPECTED_VARIANT_ORDER
    }

    matrix_runs_root = resolved_work_root / "matrix_runs"
    summary_output_dir = resolved_work_root / "_summary"
    summary_output_dir.mkdir(parents=True, exist_ok=True)

    for variant in config.variants:
        variant_root = matrix_runs_root / variant.variant_name
        variant_root.mkdir(parents=True, exist_ok=True)
        for repeat_index in range(1, repeat + 1):
            run_dir = variant_root / f"run-{repeat_index:02d}"
            run_record = _run_single_matrix_entry(
                config=config,
                variant=variant,
                repeat_index=repeat_index,
                budget_sec=budget_sec,
                repeat_count=repeat,
                run_dir=run_dir,
            )
            run_records_by_variant[variant.variant_name].append(run_record)

    aggregates_by_variant = {
        variant.variant_name: _aggregate_variant(
            variant, run_records_by_variant[variant.variant_name]
        )
        for variant in config.variants
    }
    baseline = aggregates_by_variant[BASELINE_VARIANT_NAME]

    _write_matrix_manifest(
        summary_output_dir,
        config=config,
        budget_sec=budget_sec,
        repeat_count=repeat,
        work_root=resolved_work_root,
        run_records_by_variant=run_records_by_variant,
    )
    _write_variant_summary_tsv(summary_output_dir, aggregates_by_variant)
    _write_delta_vs_baseline_tsv(
        summary_output_dir,
        baseline=baseline,
        aggregates_by_variant=aggregates_by_variant,
    )
    _write_comparability_tsv(
        summary_output_dir,
        baseline=baseline,
        aggregates_by_variant=aggregates_by_variant,
    )
    return 0


__all__ = ["CampaignMatrixError", "run_campaign_matrix"]
