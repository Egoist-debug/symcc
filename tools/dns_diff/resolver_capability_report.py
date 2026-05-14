import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

EXIT_USAGE = 2


class ResolverCapabilityReportError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _read_tsv(path: Path) -> List[Dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle, delimiter="\t"))
    except OSError as exc:
        raise ResolverCapabilityReportError(f"读取 TSV 失败 {path}: {exc}") from exc


def _write_tsv(path: Path, rows: Sequence[Mapping[str, str]], header: Sequence[str]) -> None:
    lines = ["\t".join(header)]
    for row in rows:
        lines.append("\t".join(row.get(column, "") for column in header))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_formal_rq5_tables(target_dir: Path, rows: Sequence[Mapping[str, str]]) -> None:
    adapter_header = [
        "resolver",
        "resolver_pair",
        "integration_mode",
        "adapter_cost_proxy",
        "build_real_status",
        "build_real_duration_sec",
    ]
    _write_tsv(target_dir / "resolver_adapter_cost.tsv", rows, adapter_header)

    availability_header = [
        "resolver",
        "resolver_pair",
        "build_real_status",
        "replay_real_status",
        "sync_secondary_real_status",
        "matrix_status",
        "cache_observable_status",
        "full_stack_run_count",
        "full_stack_variance_status",
    ]
    _write_tsv(
        target_dir / "resolver_build_replay_matrix.tsv", rows, availability_header
    )

    semantic_header = [
        "resolver",
        "resolver_pair",
        "full_stack_oracle_audit_candidate_count_mean",
        "full_stack_semantic_diff_count_mean",
        "full_stack_semantic_counts_json",
    ]
    _write_tsv(
        target_dir / "resolver_semantic_distribution.tsv", rows, semantic_header
    )


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1] + "+00:00")
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _duration_sec(started_at: str, finished_at: str) -> str:
    start = _parse_ts(started_at)
    finish = _parse_ts(finished_at)
    if start is None or finish is None:
        return ""
    return f"{(finish - start).total_seconds():.6f}"


def _canonical_resolver_name(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"kresd", "knot", "knot-resolver"}:
        return "knot-resolver"
    if normalized in {"named", "bind9"}:
        return "bind9"
    return normalized


def _load_replay_matrix(replay_matrix_dir: Path) -> Dict[str, Dict[str, str]]:
    matrix_path = replay_matrix_dir / "matrix.tsv"
    if not matrix_path.is_file():
        raise ResolverCapabilityReportError(f"缺少 replay matrix: {matrix_path}")

    grouped: Dict[str, Dict[str, str]] = {}
    for row in _read_tsv(matrix_path):
        resolver = _canonical_resolver_name(row.get("resolver", ""))
        capability = row.get("capability", "")
        if not resolver or not capability:
            continue
        bucket = grouped.setdefault(resolver, {})
        bucket[f"{capability}_status"] = row.get("status", "")
        bucket[f"{capability}_script"] = row.get("script", "")
        bucket[f"{capability}_duration_sec"] = _duration_sec(
            row.get("started_at", ""), row.get("finished_at", "")
        )
    return grouped


def _load_matrix_status(batch_dir: Path) -> Dict[str, Dict[str, str]]:
    status_path = batch_dir / "matrix_run_status.tsv"
    if not status_path.is_file():
        raise ResolverCapabilityReportError(f"缺少 matrix status: {status_path}")

    grouped: Dict[str, Dict[str, str]] = {}
    for row in _read_tsv(status_path):
        resolver = _canonical_resolver_name(row.get("resolver", ""))
        if not resolver:
            continue
        grouped[resolver] = {
            "matrix_status": row.get("status", ""),
            "matrix_work_root": row.get("work_root", ""),
            "matrix_file": row.get("matrix_file", ""),
        }
    return grouped


def _load_full_stack_summary(batch_dir: Path) -> Dict[str, Dict[str, str]]:
    full_stack_path = batch_dir / "_resolver_summary" / "resolver_full_stack.tsv"
    if not full_stack_path.is_file():
        raise ResolverCapabilityReportError(
            f"缺少 resolver_full_stack.tsv: {full_stack_path}"
        )

    grouped: Dict[str, Dict[str, str]] = {}
    for row in _read_tsv(full_stack_path):
        resolver = _canonical_resolver_name(row.get("secondary_resolver", ""))
        if not resolver:
            continue
        grouped[resolver] = dict(row)
    return grouped


def _integration_mode(resolver: str) -> str:
    mapping = {
        "unbound": "native_orchestrator",
        "dnsmasq": "python_harness",
        "smartdns": "python_harness",
        "maradns": "python_harness_with_preload_shim",
        "knot-resolver": "python_harness_with_selfcontained_runtime",
    }
    return mapping.get(resolver, "unknown")


def _adapter_cost_proxy(integration_mode: str) -> str:
    mapping = {
        "native_orchestrator": "high",
        "python_harness": "low",
        "python_harness_with_preload_shim": "medium",
        "python_harness_with_selfcontained_runtime": "medium",
    }
    return mapping.get(integration_mode, "unknown")


def _load_full_stack_semantic_counts(batch_dir: Path) -> Dict[str, str]:
    grouped: Dict[str, Dict[str, float]] = {}
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
        bucket = grouped.setdefault(resolver, {})
        bucket["__run_count__"] = bucket.get("__run_count__", 0.0) + 1.0
        for key, value in semantic_counts.items():
            if isinstance(key, str) and isinstance(value, (int, float)) and not isinstance(value, bool):
                bucket[key] = bucket.get(key, 0.0) + float(value)

    output: Dict[str, str] = {}
    for resolver, bucket in grouped.items():
        run_count = bucket.get("__run_count__", 0.0)
        if run_count <= 0:
            continue
        payload = {
            key: round(value / run_count, 6)
            for key, value in bucket.items()
            if key != "__run_count__"
        }
        output[resolver] = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return output


def run_resolver_capability_report(
    *,
    replay_matrix_dir: Path,
    matrix_batch_dir: Path,
    output_dir: Optional[Path] = None,
) -> int:
    replay_root = Path(replay_matrix_dir).expanduser().resolve()
    batch_root = Path(matrix_batch_dir).expanduser().resolve()
    if not replay_root.is_dir():
        raise ResolverCapabilityReportError(
            f"replay-matrix-dir 不存在或不是目录: {replay_root}"
        )
    if not batch_root.is_dir():
        raise ResolverCapabilityReportError(
            f"matrix-batch-dir 不存在或不是目录: {batch_root}"
        )

    replay_rows = _load_replay_matrix(replay_root)
    matrix_status = _load_matrix_status(batch_root)
    full_stack_rows = _load_full_stack_summary(batch_root)
    semantic_counts = _load_full_stack_semantic_counts(batch_root)

    resolvers = sorted(set(replay_rows) | set(matrix_status) | set(full_stack_rows))
    if not resolvers:
        raise ResolverCapabilityReportError("未找到任何 resolver 记录")

    if output_dir is None:
        target_dir = batch_root / "_resolver_capability"
    else:
        target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    header = [
        "resolver",
        "resolver_pair",
        "integration_mode",
        "adapter_cost_proxy",
        "cache_observable_status",
        "matrix_status",
        "build_real_status",
        "build_real_duration_sec",
        "replay_real_status",
        "replay_real_duration_sec",
        "sync_secondary_real_status",
        "sync_secondary_real_duration_sec",
        "full_stack_run_count",
        "full_stack_variance_status",
        "full_stack_total_samples_mean",
        "full_stack_cluster_count_mean",
        "full_stack_needs_review_count_mean",
        "full_stack_oracle_audit_candidate_count_mean",
        "full_stack_semantic_diff_count_mean",
        "full_stack_semantic_counts_json",
        "matrix_work_root",
        "matrix_file",
    ]
    rows: List[Dict[str, str]] = []
    for resolver in resolvers:
        replay = replay_rows.get(resolver, {})
        matrix = matrix_status.get(resolver, {})
        full_stack = full_stack_rows.get(resolver, {})
        integration_mode = _integration_mode(resolver)
        rows.append(
            {
                "resolver": resolver,
                "resolver_pair": full_stack.get("resolver_pair", ""),
                "integration_mode": integration_mode,
                "adapter_cost_proxy": _adapter_cost_proxy(integration_mode),
                "cache_observable_status": (
                    "observable" if replay.get("replay_real_status") == "pass" else ""
                ),
                "matrix_status": matrix.get("matrix_status", ""),
                "build_real_status": replay.get("build_real_status", ""),
                "build_real_duration_sec": replay.get("build_real_duration_sec", ""),
                "replay_real_status": replay.get("replay_real_status", ""),
                "replay_real_duration_sec": replay.get("replay_real_duration_sec", ""),
                "sync_secondary_real_status": replay.get("sync_secondary_real_status", ""),
                "sync_secondary_real_duration_sec": replay.get(
                    "sync_secondary_real_duration_sec", ""
                ),
                "full_stack_run_count": full_stack.get("run_count", ""),
                "full_stack_variance_status": full_stack.get("variance_status", ""),
                "full_stack_total_samples_mean": full_stack.get(
                    "total_samples_mean", ""
                ),
                "full_stack_cluster_count_mean": full_stack.get(
                    "cluster_count_mean", ""
                ),
                "full_stack_needs_review_count_mean": full_stack.get(
                    "needs_review_count_mean", ""
                ),
                "full_stack_oracle_audit_candidate_count_mean": full_stack.get(
                    "oracle_audit_candidate_count_mean", ""
                ),
                "full_stack_semantic_diff_count_mean": full_stack.get(
                    "semantic_diff_count_mean", ""
                ),
                "full_stack_semantic_counts_json": semantic_counts.get(resolver, ""),
                "matrix_work_root": matrix.get("matrix_work_root", ""),
                "matrix_file": matrix.get("matrix_file", ""),
            }
        )

    _write_tsv(target_dir / "resolver_capability_summary.tsv", rows, header)
    payload = {
        "replay_matrix_dir": str(replay_root),
        "matrix_batch_dir": str(batch_root),
        "record_count": len(rows),
        "outputs": {
            "resolver_capability_summary_tsv": str(
                target_dir / "resolver_capability_summary.tsv"
            ),
            "resolver_capability_summary_json": str(
                target_dir / "resolver_capability_summary.json"
            ),
            "resolver_adapter_cost_tsv": str(target_dir / "resolver_adapter_cost.tsv"),
            "resolver_build_replay_matrix_tsv": str(
                target_dir / "resolver_build_replay_matrix.tsv"
            ),
            "resolver_semantic_distribution_tsv": str(
                target_dir / "resolver_semantic_distribution.tsv"
            ),
        },
        "rows": rows,
    }
    _write_formal_rq5_tables(target_dir, rows)
    (target_dir / "resolver_capability_summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


__all__ = ["ResolverCapabilityReportError", "run_resolver_capability_report"]
