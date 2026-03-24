import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .follow_diff import (
    FOLLOW_DIFF_STATE_FILE_NAME,
    FOLLOW_DIFF_WINDOW_SUMMARY_FILE_NAME,
    default_follow_diff_output_root,
    resolve_follow_diff_work_dir,
)
from .io import load_json_with_fallback
from .schema import ANALYSIS_STATES, CONTRACT_VERSION, build_run_comparability_payload
from .taxonomy import (
    FAILURE_BUCKET_DETAIL_ORDER,
    FAILURE_BUCKET_PRIMARY_ORDER,
)

EXIT_USAGE = 2
ANALYSIS_STATE_ORDER: Tuple[str, ...] = ("included", "excluded", "unknown")


class ReportError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _resolve_root_dir() -> Path:
    env_root = os.environ.get("ROOT_DIR")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _resolve_work_dir(
    *,
    work_dir: Optional[Path] = None,
    root_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    if work_dir is not None:
        return Path(work_dir).expanduser().resolve()

    effective_root_dir = _resolve_root_dir() if root_dir is None else Path(root_dir)
    return resolve_follow_diff_work_dir(
        root_dir=effective_root_dir.expanduser().resolve(),
        environ=environ,
    )


def default_follow_diff_root(*, work_dir: Optional[Path] = None) -> Path:
    return default_follow_diff_output_root(_resolve_work_dir(work_dir=work_dir))


def default_high_value_manifest_path(
    root: Path,
    *,
    work_dir: Optional[Path] = None,
) -> Path:
    root_path = Path(root).expanduser().resolve()
    resolved_work_dir = _resolve_work_dir(work_dir=work_dir)
    if root_path == default_follow_diff_root(work_dir=resolved_work_dir):
        return (resolved_work_dir / "high_value_samples.txt").resolve()
    return (root_path / "high_value_samples.txt").resolve()


def resolve_high_value_manifest_path(
    root: Path,
    *,
    work_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    env = os.environ if environ is None else environ
    env_manifest = env.get("SYMCC_HIGH_VALUE_MANIFEST")
    if env_manifest:
        return Path(env_manifest).expanduser().resolve()

    return default_high_value_manifest_path(root, work_dir=work_dir)


def _coerce_text(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _coerce_optional_text(value: Any) -> Optional[str]:
    if isinstance(value, str) and value:
        return value
    return None


def _coerce_analysis_state(value: Any) -> str:
    if isinstance(value, str) and value in ANALYSIS_STATES:
        return value
    return "unknown"


def _coerce_failure_bucket_primary(value: Any) -> str:
    if isinstance(value, str) and value in FAILURE_BUCKET_PRIMARY_ORDER:
        return value
    return "missing_failure_bucket_primary"


def _coerce_failure_bucket_detail(value: Any) -> str:
    if isinstance(value, str) and value in FAILURE_BUCKET_DETAIL_ORDER:
        return value
    return "missing_failure_bucket_detail"


def _coerce_labels(value: Any) -> List[str]:
    if isinstance(value, list):
        labels = [item for item in value if isinstance(item, str) and item]
        return sorted(set(labels))
    return []


def _is_sample_dir(path: Path) -> bool:
    candidate = Path(path)
    if not candidate.is_dir():
        return False

    return (candidate / "triage.json").is_file() or (
        candidate / "sample.meta.json"
    ).is_file()


def _iter_sample_dirs(root: Path) -> Iterable[Path]:
    return sorted(path for path in root.iterdir() if _is_sample_dir(path))


def collect_sample_dirs(root: Path, *, require_root: bool = True) -> List[Path]:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists() or not root_path.is_dir():
        if require_root:
            raise ReportError(f"follow_diff 根目录不存在或不是目录: {root_path}")
        return []
    return list(_iter_sample_dirs(root_path))


def _load_triage_payload(sample_dir: Path) -> Dict[str, Any]:
    triage_path = sample_dir / "triage.json"
    load_result = load_json_with_fallback(triage_path)
    if load_result.downgraded and triage_path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: report 读取 triage 降级，已回退默认值 {triage_path}: {detail}\n"
        )
    payload = dict(load_result.data)
    payload.setdefault("sample_id", sample_dir.name)
    payload.setdefault("status", "unknown")
    payload.setdefault("cluster_key", "_")
    payload.setdefault("diff_class", "unknown")
    payload.setdefault("analysis_state", "unknown")
    payload.setdefault("semantic_outcome", "unknown")
    payload.setdefault("filter_labels", [])
    return payload


def _load_sample_meta_payload(sample_dir: Path) -> Dict[str, Any]:
    meta_path = sample_dir / "sample.meta.json"
    load_result = load_json_with_fallback(meta_path)
    if load_result.downgraded and meta_path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: report 读取 sample.meta 降级，已回退默认值 {meta_path}: {detail}\n"
        )
    payload = dict(load_result.data)
    payload.setdefault("sample_id", sample_dir.name)
    return payload


def _load_auxiliary_payload(path: Path, *, label: str) -> Dict[str, Any]:
    load_result = load_json_with_fallback(path)
    if load_result.downgraded and path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: report 读取 {label} 降级，已回退默认值 {path}: {detail}\n"
        )
    return dict(load_result.data)


def _resolve_associated_work_dir(
    root: Path,
    *,
    work_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[Path]:
    if work_dir is not None:
        return Path(work_dir).expanduser().resolve()

    resolved_root = Path(root).expanduser().resolve()
    effective_work_dir = _resolve_work_dir(environ=environ)
    if resolved_root == default_follow_diff_root(work_dir=effective_work_dir):
        return effective_work_dir
    return None


def _load_run_metadata(
    root: Path,
    *,
    work_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    associated_work_dir = _resolve_associated_work_dir(
        root,
        work_dir=work_dir,
        environ=environ,
    )
    if associated_work_dir is None:
        return {
            "run_id": None,
            "state": {},
            "window_summary": {},
        }

    state_payload = _load_auxiliary_payload(
        associated_work_dir / FOLLOW_DIFF_STATE_FILE_NAME,
        label="follow_diff.state.json",
    )
    window_summary_payload = _load_auxiliary_payload(
        associated_work_dir / FOLLOW_DIFF_WINDOW_SUMMARY_FILE_NAME,
        label="follow_diff.window.summary.json",
    )
    run_id = _coerce_optional_text(window_summary_payload.get("run_id"))
    if run_id is None:
        run_id = _coerce_optional_text(state_payload.get("run_id"))

    return {
        "run_id": run_id,
        "state": state_payload,
        "window_summary": window_summary_payload,
    }


def _build_metric_denominators(
    *,
    total_samples: int,
    analysis_state_counter: Counter[str],
    comparability: Mapping[str, Any],
) -> Dict[str, Any]:
    comparable_sample_count = comparability.get("comparable_sample_count")
    if isinstance(comparable_sample_count, bool) or not isinstance(
        comparable_sample_count, int
    ):
        comparable_sample_count = 0
    non_comparable_sample_count = comparability.get("non_comparable_sample_count")
    if isinstance(non_comparable_sample_count, bool) or not isinstance(
        non_comparable_sample_count, int
    ):
        non_comparable_sample_count = max(0, total_samples - comparable_sample_count)

    analysis_state_totals = {
        state: int(analysis_state_counter.get(state, 0))
        for state in ANALYSIS_STATE_ORDER
    }
    if sum(analysis_state_totals.values()) != total_samples:
        raise ReportError(
            "metric_denominators.analysis_state 不守恒: "
            f"included+excluded+unknown={sum(analysis_state_totals.values())} "
            f"!= total_samples={total_samples}"
        )

    return {
        "total_samples": total_samples,
        "analysis_state": analysis_state_totals,
        "comparable_samples": comparable_sample_count,
        "non_comparable_samples": non_comparable_sample_count,
    }


def derive_semantic_diff_count(
    failure_bucket_primary_counter: Mapping[str, Any],
) -> int:
    raw_value = failure_bucket_primary_counter.get("semantic_diff", 0)
    if isinstance(raw_value, bool):
        return 0
    if isinstance(raw_value, int):
        return max(0, raw_value)
    if isinstance(raw_value, float) and raw_value.is_integer():
        return max(0, int(raw_value))
    return 0


def _write_cluster_summary(
    root: Path,
    *,
    cluster_counter: Counter[str],
    cluster_samples: Mapping[str, List[str]],
    total_samples: int,
) -> Path:
    output = root / "cluster_summary.tsv"
    lines = ["cluster_key\tcount\tsample_ids"]
    for cluster_key in sorted(cluster_counter.keys()):
        sample_ids = sorted(cluster_samples.get(cluster_key, []))
        lines.append(
            f"{cluster_key}\t{cluster_counter[cluster_key]}\t{','.join(sample_ids) if sample_ids else '-'}"
        )
    lines.append(f"__total__\t{total_samples}\t-")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def _write_status_summary(
    root: Path,
    *,
    status_counter: Counter[str],
    total_samples: int,
) -> Path:
    output = root / "status_summary.tsv"
    lines = ["status\tcount"]
    for status in sorted(status_counter.keys()):
        lines.append(f"{status}\t{status_counter[status]}")
    lines.append(f"__total__\t{total_samples}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def _write_high_value_manifest(
    root: Path,
    *,
    high_value_paths: List[Path],
) -> Path:
    manifest_path = resolve_high_value_manifest_path(root)
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        lines: List[str] = []
        seen_paths = set()
        for candidate in sorted(high_value_paths):
            resolved_path = candidate.expanduser().resolve()
            if not resolved_path.is_file():
                continue

            resolved_text = str(resolved_path)
            if resolved_text in seen_paths:
                continue

            seen_paths.add(resolved_text)
            lines.append(resolved_text)

        content = "\n".join(lines)
        if content:
            content += "\n"

        manifest_path.write_text(content, encoding="utf-8")
        return manifest_path
    except Exception as exc:
        raise ReportError(f"写入 high_value_samples.txt 失败: {exc}") from exc


def _write_triage_report_md(
    root: Path,
    *,
    total_samples: int,
    status_counter: Counter[str],
    cluster_counter: Counter[str],
) -> Path:
    output = root / "triage_report.md"
    lines = [
        "# DNS Diff Triage Report",
        "",
        f"- root: `{root}`",
        f"- total_samples: {total_samples}",
        f"- status_bucket_count: {len(status_counter)}",
        f"- cluster_bucket_count: {len(cluster_counter)}",
        "",
        "## Status Summary",
        "",
        "| status | count |",
        "|---|---:|",
    ]
    if status_counter:
        for status in sorted(status_counter.keys()):
            lines.append(f"| {status} | {status_counter[status]} |")
    else:
        lines.append("| (none) | 0 |")

    lines.extend(
        ["", "## Cluster Summary", "", "| cluster_key | count |", "|---|---:|"]
    )
    if cluster_counter:
        for cluster_key in sorted(cluster_counter.keys()):
            lines.append(f"| {cluster_key} | {cluster_counter[cluster_key]} |")
    else:
        lines.append("| (none) | 0 |")

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def collect_report_snapshot(
    root: Path,
    *,
    work_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
    require_root: bool = True,
) -> Dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    sample_dirs = collect_sample_dirs(root_path, require_root=require_root)
    if not root_path.exists() or not root_path.is_dir():
        if require_root:
            raise ReportError(f"follow_diff 根目录不存在或不是目录: {root_path}")

        empty_comparability = build_run_comparability_payload(())
        return {
            "root": root_path,
            "sample_dirs": sample_dirs,
            "status_counter": Counter(),
            "cluster_counter": Counter(),
            "cluster_samples": {},
            "high_value_paths": [],
            "total_samples": 0,
            "needs_review_count": 0,
            "analysis_state_counter": Counter(),
            "failure_bucket_primary_counter": Counter(),
            "failure_bucket_detail_counter": Counter(),
            "failure_taxonomy_counter": Counter(),
            "semantic_counts": {},
            "metric_denominators": _build_metric_denominators(
                total_samples=0,
                analysis_state_counter=Counter(),
                comparability=empty_comparability,
            ),
            "comparability": empty_comparability,
            "run_id": None,
            "run_metadata": _load_run_metadata(
                root_path,
                work_dir=work_dir,
                environ=environ,
            ),
        }

    status_counter: Counter[str] = Counter()
    cluster_counter: Counter[str] = Counter()
    cluster_samples: Dict[str, List[str]] = defaultdict(list)
    high_value_paths: List[Path] = []
    analysis_state_counter: Counter[str] = Counter()
    failure_bucket_primary_counter: Counter[str] = Counter()
    failure_bucket_detail_counter: Counter[str] = Counter()
    failure_taxonomy_counter: Counter[Tuple[str, str]] = Counter()
    semantic_outcome_counter: Counter[str] = Counter()
    sample_meta_payloads: List[Mapping[str, Any]] = []
    total_samples = 0
    needs_review_count = 0
    for sample_dir in sample_dirs:
        payload = _load_triage_payload(sample_dir)
        sample_meta_payload = _load_sample_meta_payload(sample_dir)
        sample_meta_payloads.append(sample_meta_payload)

        sample_id = _coerce_text(payload.get("sample_id"), sample_dir.name)
        status = _coerce_text(payload.get("status"), "unknown")
        cluster_key = _coerce_text(payload.get("cluster_key"), "_")
        analysis_state = _coerce_analysis_state(payload.get("analysis_state"))
        failure_bucket_primary = _coerce_failure_bucket_primary(
            payload.get("failure_bucket_primary")
        )
        failure_bucket_detail = _coerce_failure_bucket_detail(
            payload.get("failure_bucket_detail")
        )
        semantic_outcome = _coerce_text(payload.get("semantic_outcome"), "unknown")
        labels = _coerce_labels(payload.get("filter_labels"))
        if labels and cluster_key == "_":
            cluster_key = ",".join(labels)

        total_samples += 1
        status_counter[status] += 1
        cluster_counter[cluster_key] += 1
        cluster_samples[cluster_key].append(sample_id)
        analysis_state_counter[analysis_state] += 1
        failure_bucket_primary_counter[failure_bucket_primary] += 1
        failure_bucket_detail_counter[failure_bucket_detail] += 1
        failure_taxonomy_counter[(failure_bucket_primary, failure_bucket_detail)] += 1
        semantic_outcome_counter[semantic_outcome] += 1

        if payload.get("needs_manual_review"):
            needs_review_count += 1
            sample_path = sample_dir / "sample.bin"
            if not sample_path.is_file():
                sample_path = sample_dir / "transcript"

            if sample_path.is_file():
                high_value_paths.append(sample_path)

    comparability = build_run_comparability_payload(sample_meta_payloads)
    run_metadata = _load_run_metadata(root_path, work_dir=work_dir, environ=environ)
    return {
        "root": root_path,
        "sample_dirs": sample_dirs,
        "status_counter": status_counter,
        "cluster_counter": cluster_counter,
        "cluster_samples": cluster_samples,
        "high_value_paths": high_value_paths,
        "total_samples": total_samples,
        "needs_review_count": needs_review_count,
        "analysis_state_counter": analysis_state_counter,
        "failure_bucket_primary_counter": failure_bucket_primary_counter,
        "failure_bucket_detail_counter": failure_bucket_detail_counter,
        "failure_taxonomy_counter": failure_taxonomy_counter,
        "semantic_counts": {
            outcome: semantic_outcome_counter[outcome]
            for outcome in sorted(semantic_outcome_counter.keys())
        },
        "metric_denominators": _build_metric_denominators(
            total_samples=total_samples,
            analysis_state_counter=analysis_state_counter,
            comparability=comparability,
        ),
        "comparability": comparability,
        "run_id": run_metadata["run_id"],
        "run_metadata": run_metadata,
    }


def generate_report(root: Path) -> int:
    snapshot = collect_report_snapshot(root)
    root_path = snapshot["root"]

    _write_cluster_summary(
        root_path,
        cluster_counter=snapshot["cluster_counter"],
        cluster_samples=snapshot["cluster_samples"],
        total_samples=snapshot["total_samples"],
    )
    _write_status_summary(
        root_path,
        status_counter=snapshot["status_counter"],
        total_samples=snapshot["total_samples"],
    )
    _write_high_value_manifest(
        root_path,
        high_value_paths=snapshot["high_value_paths"],
    )
    _write_triage_report_md(
        root_path,
        total_samples=snapshot["total_samples"],
        status_counter=snapshot["status_counter"],
        cluster_counter=snapshot["cluster_counter"],
    )

    sys.stdout.write(
        f"dns-diff: report 生成完成 root={root_path} samples={snapshot['total_samples']}\n"
    )
    return 0


__all__ = [
    "ReportError",
    "collect_report_snapshot",
    "default_high_value_manifest_path",
    "default_follow_diff_root",
    "derive_semantic_diff_count",
    "generate_report",
    "resolve_high_value_manifest_path",
]
