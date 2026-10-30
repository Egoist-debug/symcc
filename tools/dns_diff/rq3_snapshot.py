import csv
import json
import math
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from .matrix import EXPECTED_VARIANT_ORDER

EXIT_USAGE = 2
EXPECTED_VARIANTS: Sequence[str] = EXPECTED_VARIANT_ORDER


class RQ3SnapshotError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _read_tsv(path: Path) -> List[Dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter="\t"))
    except OSError as exc:
        raise RQ3SnapshotError(f"读取 TSV 失败 {path}: {exc}") from exc


def _write_tsv(path: Path, rows: Sequence[Mapping[str, str]], header: Sequence[str]) -> None:
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(row.get(column, "") for column in header))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_rq3_snapshot(
    *,
    resolver_variant_summary_tsv: Path,
    output_dir: Path,
) -> int:
    source_path = Path(resolver_variant_summary_tsv).expanduser().resolve()
    if not source_path.is_file():
        raise RQ3SnapshotError(f"缺少 resolver_variant_summary.tsv: {source_path}")

    rows = _read_tsv(source_path)
    filtered = [
        row
        for row in rows
        if row.get("variant_name") in EXPECTED_VARIANTS
    ]
    if not filtered:
        raise RQ3SnapshotError("未找到任何 RQ3 variant 行")

    output_root = Path(output_dir).expanduser().resolve()
    if source_path == output_root / "rq3_hybrid_snapshot.tsv":
        raise RQ3SnapshotError("输出路径不能覆盖输入 TSV，请使用新的报告目录")
    output_root.mkdir(parents=True, exist_ok=True)

    header = [
        "resolver_pair",
        "secondary_resolver",
        "variant_name",
        "run_count",
        "variance_status",
        "mutator",
        "cache-delta",
        "triage",
        "symcc",
        "total_samples_mean",
        "total_samples_sample_stddev",
        "total_samples_ci95_lower",
        "total_samples_ci95_upper",
        "needs_review_count_mean",
        "needs_review_count_sample_stddev",
        "needs_review_count_ci95_lower",
        "needs_review_count_ci95_upper",
        "cluster_count_mean",
        "cluster_count_sample_stddev",
        "cluster_count_ci95_lower",
        "cluster_count_ci95_upper",
        "oracle_audit_candidate_count_mean",
        "oracle_audit_candidate_count_sample_stddev",
        "oracle_audit_candidate_count_ci95_lower",
        "oracle_audit_candidate_count_ci95_upper",
        "semantic_diff_count_mean",
        "semantic_diff_count_sample_stddev",
        "semantic_diff_count_ci95_lower",
        "semantic_diff_count_ci95_upper",
    ]
    rows_out: List[Dict[str, str]] = []
    for row in filtered:
        normalized = {column: row.get(column) or "" for column in header}
        try:
            run_count = int(row.get("run_count", ""))
            sufficient = run_count >= 2 and row.get("variance_status") == "ok"
            if run_count < 2:
                normalized["variance_status"] = "insufficient_runs"
        except (TypeError, ValueError):
            sufficient = False
            normalized["run_count"] = "NA"
            normalized["variance_status"] = "unknown"
        if not normalized["variance_status"]:
            normalized["variance_status"] = "unknown"
        for column in header[9:]:
            value = row.get(column)
            try:
                valid = value is not None and math.isfinite(float(value))
            except (TypeError, ValueError):
                valid = False
            # 旧单 run 表的均值也可能来自空 aggregates 的补零，不能单独保留。
            normalized[column] = value if sufficient and valid else "NA"
        rows_out.append(normalized)

    _write_tsv(output_root / "rq3_hybrid_snapshot.tsv", rows_out, header)
    (output_root / "rq3_hybrid_snapshot.json").write_text(
        json.dumps(
            {
                "source": str(source_path),
                "row_count": len(rows_out),
                "variants": list(EXPECTED_VARIANTS),
                "rows": rows_out,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


__all__ = ["RQ3SnapshotError", "run_rq3_snapshot"]
