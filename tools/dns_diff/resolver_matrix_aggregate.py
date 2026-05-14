import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

EXIT_USAGE = 2


class ResolverMatrixAggregateError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResolverMatrixAggregateError(f"读取 JSON 失败 {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ResolverMatrixAggregateError(f"JSON 顶层必须是对象: {path}")
    return dict(payload)


def _read_tsv(path: Path) -> List[Dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter="\t"))
    except OSError as exc:
        raise ResolverMatrixAggregateError(f"读取 TSV 失败 {path}: {exc}") from exc


def _coerce_text(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _normalize_runtime_env(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    output: Dict[str, str] = {}
    for key, raw_value in value.items():
        if not isinstance(key, str) or not isinstance(raw_value, str):
            continue
        if not key.strip() or not raw_value.strip():
            continue
        output[key] = raw_value
    return output


def _secondary_resolver(runtime_env: Mapping[str, str]) -> str:
    value = runtime_env.get("DNS_DIFF_SECONDARY_RESOLVER", "unbound").strip().lower()
    if value == "kresd":
        return "knot-resolver"
    return value or "unbound"


def _load_matrix_root(matrix_root: Path) -> List[Dict[str, str]]:
    root = Path(matrix_root).expanduser().resolve()
    summary_dir = root / "_summary"
    manifest_path = summary_dir / "matrix_manifest.json"
    variant_summary_path = summary_dir / "variant_summary.tsv"
    if not manifest_path.is_file():
        raise ResolverMatrixAggregateError(f"缺少 matrix manifest: {manifest_path}")
    if not variant_summary_path.is_file():
        raise ResolverMatrixAggregateError(
            f"缺少 variant summary: {variant_summary_path}"
        )

    manifest = _read_json(manifest_path)
    runtime_env = _normalize_runtime_env(manifest.get("runtime_env"))
    secondary = _secondary_resolver(runtime_env)
    matrix_name = _coerce_text(manifest.get("matrix_name"), root.name)
    resolver_pair = _coerce_text(manifest.get("resolver_pair"), f"bind9_vs_{secondary}")
    producer_profile = _coerce_text(manifest.get("producer_profile"), "_")
    input_model = _coerce_text(manifest.get("input_model"), "_")

    rows = _read_tsv(variant_summary_path)
    output: List[Dict[str, str]] = []
    for row in rows:
        record = dict(row)
        record["matrix_root"] = str(root)
        record["matrix_name"] = matrix_name
        record["resolver_pair"] = resolver_pair
        record["secondary_resolver"] = secondary
        record["producer_profile"] = producer_profile
        record["input_model"] = input_model
        record["runtime_env_json"] = json.dumps(
            runtime_env, ensure_ascii=False, sort_keys=True
        )
        output.append(record)
    return output


def _write_tsv(path: Path, rows: Sequence[Mapping[str, str]], header: Sequence[str]) -> None:
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(row.get(column, "") for column in header))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_resolver_matrix_aggregate(
    *,
    matrix_roots: Sequence[Path],
    output_dir: Optional[Path] = None,
) -> int:
    if not matrix_roots:
        raise ResolverMatrixAggregateError("至少提供一个 --matrix-root")

    collected: List[Dict[str, str]] = []
    for matrix_root in matrix_roots:
        collected.extend(_load_matrix_root(matrix_root))

    if output_dir is None:
        base_dir = Path(matrix_roots[0]).expanduser().resolve().parent
        target_dir = base_dir / "resolver_matrix_aggregates" / _get_timestamp()
    else:
        target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    manifest_payload = {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "matrix_roots": [str(Path(path).expanduser().resolve()) for path in matrix_roots],
        "record_count": len(collected),
        "outputs": {
            "resolver_variant_summary_tsv": str(
                target_dir / "resolver_variant_summary.tsv"
            ),
            "resolver_full_stack_tsv": str(target_dir / "resolver_full_stack.tsv"),
        },
    }
    (target_dir / "resolver_matrix_manifest.json").write_text(
        json.dumps(manifest_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    if not collected:
        raise ResolverMatrixAggregateError("未从任何 matrix root 读取到 variant 记录")

    preferred_columns = [
        "matrix_name",
        "matrix_root",
        "resolver_pair",
        "secondary_resolver",
        "producer_profile",
        "input_model",
        "variant_name",
        "run_count",
        "variance_status",
        "mutator",
        "cache-delta",
        "triage",
        "symcc",
        "aggregation_key",
        "baseline_compare_key",
        "runtime_env_json",
    ]
    metric_columns = [
        key
        for key in collected[0].keys()
        if key.endswith("_mean") or key.endswith("_stddev")
    ]
    header = preferred_columns + [
        key for key in metric_columns if key not in preferred_columns
    ]

    _write_tsv(target_dir / "resolver_variant_summary.tsv", collected, header)
    full_stack_rows = [
        row for row in collected if row.get("variant_name") == "full_stack"
    ]
    _write_tsv(target_dir / "resolver_full_stack.tsv", full_stack_rows, header)
    return 0


__all__ = ["ResolverMatrixAggregateError", "run_resolver_matrix_aggregate"]
