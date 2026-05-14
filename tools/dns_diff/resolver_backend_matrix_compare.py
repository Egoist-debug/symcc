import csv
import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

EXIT_USAGE = 2


class ResolverBackendMatrixCompareError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _read_tsv(path: Path) -> List[Dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter="\t"))
    except OSError as exc:
        raise ResolverBackendMatrixCompareError(
            f"读取 TSV 失败 {path}: {exc}"
        ) from exc


def _canonical_resolver_name(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"knot", "kresd", "knot-resolver"}:
        return "knot-resolver"
    return normalized


def _load_full_stack(batch_dir: Path) -> Dict[str, Dict[str, str]]:
    full_stack = batch_dir / "_resolver_summary" / "resolver_full_stack.tsv"
    if not full_stack.is_file():
        raise ResolverBackendMatrixCompareError(
            f"缺少 resolver_full_stack.tsv: {full_stack}"
        )
    rows = _read_tsv(full_stack)
    output: Dict[str, Dict[str, str]] = {}
    for row in rows:
        resolver = _canonical_resolver_name(row.get("secondary_resolver", ""))
        if resolver:
            output[resolver] = row
    return output


def _load_status(batch_dir: Path) -> Dict[str, Dict[str, str]]:
    status_path = batch_dir / "matrix_run_status.tsv"
    if not status_path.is_file():
        raise ResolverBackendMatrixCompareError(
            f"缺少 matrix_run_status.tsv: {status_path}"
        )
    rows = _read_tsv(status_path)
    output: Dict[str, Dict[str, str]] = {}
    for row in rows:
        resolver = _canonical_resolver_name(row.get("resolver", ""))
        if resolver:
            output[resolver] = row
    return output


def _load_full_stack_semantic_counts(batch_dir: Path) -> Dict[str, str]:
    output: Dict[str, str] = {}
    for summary_path in Path(batch_dir).expanduser().resolve().glob(
        "*/matrix_runs/full_stack/run-*/campaign_reports/*/summary.json"
    ):
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, Mapping):
            continue
        semantic_counts = payload.get("semantic_counts")
        if not isinstance(semantic_counts, Mapping):
            continue
        resolver = _canonical_resolver_name(summary_path.parts[-7])
        if resolver in output:
            continue
        output[resolver] = json.dumps(semantic_counts, ensure_ascii=False, sort_keys=True)
    return output


def _write_tsv(path: Path, rows: Sequence[Mapping[str, str]], header: Sequence[str]) -> None:
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(row.get(column, "") for column in header))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_resolver_backend_matrix_compare(
    *,
    baseline_batch_dir: Path,
    candidate_batch_dir: Path,
    baseline_label: str,
    candidate_label: str,
    output_dir: Optional[Path] = None,
) -> int:
    baseline_root = Path(baseline_batch_dir).expanduser().resolve()
    candidate_root = Path(candidate_batch_dir).expanduser().resolve()
    baseline_rows = _load_full_stack(baseline_root)
    candidate_rows = _load_full_stack(candidate_root)
    baseline_status = _load_status(baseline_root)
    candidate_status = _load_status(candidate_root)
    baseline_semantic_counts = _load_full_stack_semantic_counts(baseline_root)
    candidate_semantic_counts = _load_full_stack_semantic_counts(candidate_root)

    resolvers = sorted(set(baseline_rows) | set(candidate_rows) | set(baseline_status) | set(candidate_status))
    if not resolvers:
        raise ResolverBackendMatrixCompareError("未找到任何 resolver 记录")

    if output_dir is None:
        target_dir = candidate_root / "_backend_compare"
    else:
        target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    header = [
        "resolver",
        "resolver_pair",
        f"{baseline_label}_matrix_status",
        f"{candidate_label}_matrix_status",
        f"{baseline_label}_run_count",
        f"{candidate_label}_run_count",
        f"{baseline_label}_variance_status",
        f"{candidate_label}_variance_status",
        f"{baseline_label}_semantic_counts_json",
        f"{candidate_label}_semantic_counts_json",
    ]
    rows: List[Dict[str, str]] = []
    for resolver in resolvers:
        base = baseline_rows.get(resolver, {})
        cand = candidate_rows.get(resolver, {})
        base_status = baseline_status.get(resolver, {})
        cand_status = candidate_status.get(resolver, {})
        rows.append(
            {
                "resolver": resolver,
                "resolver_pair": cand.get("resolver_pair", base.get("resolver_pair", "")),
                f"{baseline_label}_matrix_status": base_status.get("status", ""),
                f"{candidate_label}_matrix_status": cand_status.get("status", ""),
                f"{baseline_label}_run_count": base.get("run_count", ""),
                f"{candidate_label}_run_count": cand.get("run_count", ""),
                f"{baseline_label}_variance_status": base.get("variance_status", ""),
                f"{candidate_label}_variance_status": cand.get("variance_status", ""),
                f"{baseline_label}_semantic_counts_json": baseline_semantic_counts.get(resolver, ""),
                f"{candidate_label}_semantic_counts_json": candidate_semantic_counts.get(resolver, ""),
            }
        )

    _write_tsv(target_dir / "resolver_backend_compare.tsv", rows, header)
    payload = {
        "baseline_batch_dir": str(baseline_root),
        "candidate_batch_dir": str(candidate_root),
        "baseline_label": baseline_label,
        "candidate_label": candidate_label,
        "record_count": len(rows),
        "rows": rows,
    }
    (target_dir / "resolver_backend_compare.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


__all__ = ["ResolverBackendMatrixCompareError", "run_resolver_backend_matrix_compare"]
