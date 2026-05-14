import csv
import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

EXIT_USAGE = 2
EXPECTED_VARIANTS: Sequence[str] = (
    "full_stack",
    "afl_only",
    "no_mutator",
    "no_cache_delta",
)


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
        "needs_review_count_mean",
        "cluster_count_mean",
        "oracle_audit_candidate_count_mean",
        "semantic_diff_count_mean",
    ]
    rows_out: List[Dict[str, str]] = []
    for row in filtered:
        rows_out.append({column: row.get(column, "") for column in header})

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
