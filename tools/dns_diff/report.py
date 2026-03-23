import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .io import load_json_with_fallback

EXIT_USAGE = 2


class ReportError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _resolve_root_dir() -> Path:
    env_root = os.environ.get("ROOT_DIR")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _resolve_work_dir() -> Path:
    root_dir = _resolve_root_dir()
    return (
        Path(
            os.environ.get(
                "WORK_DIR", str(root_dir / "unbound_experiment" / "work_stateful")
            )
        )
        .expanduser()
        .resolve()
    )


def default_follow_diff_root() -> Path:
    return (_resolve_work_dir() / "follow_diff").resolve()


def resolve_high_value_manifest_path(root: Path) -> Path:
    root_path = Path(root).expanduser().resolve()
    if root_path != default_follow_diff_root():
        return (root_path / "high_value_samples.txt").resolve()

    env_manifest = os.environ.get("SYMCC_HIGH_VALUE_MANIFEST")
    if env_manifest:
        return Path(env_manifest).expanduser().resolve()

    return (_resolve_work_dir() / "high_value_samples.txt").resolve()


def _coerce_text(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _coerce_labels(value: Any) -> List[str]:
    if isinstance(value, list):
        labels = [item for item in value if isinstance(item, str) and item]
        return sorted(set(labels))
    return []


def _iter_sample_dirs(root: Path) -> Iterable[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir())


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
    payload.setdefault("filter_labels", [])
    return payload


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
) -> Optional[Path]:
    manifest_path = resolve_high_value_manifest_path(root)
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [str(p.resolve()) for p in sorted(high_value_paths)]
        manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return manifest_path
    except Exception as exc:
        sys.stderr.write(f"dns-diff: 写入 high_value_samples.txt 失败: {exc}\n")
        return None


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


def generate_report(root: Path) -> int:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise ReportError(f"follow_diff 根目录不存在或不是目录: {root_path}")

    status_counter: Counter[str] = Counter()
    cluster_counter: Counter[str] = Counter()
    cluster_samples: Dict[str, List[str]] = defaultdict(list)
    high_value_paths: List[Path] = []

    total_samples = 0
    for sample_dir in _iter_sample_dirs(root_path):
        payload = _load_triage_payload(sample_dir)
        sample_id = _coerce_text(payload.get("sample_id"), sample_dir.name)
        status = _coerce_text(payload.get("status"), "unknown")
        cluster_key = _coerce_text(payload.get("cluster_key"), "_")
        labels = _coerce_labels(payload.get("filter_labels"))
        if labels and cluster_key == "_":
            cluster_key = ",".join(labels)

        total_samples += 1
        status_counter[status] += 1
        cluster_counter[cluster_key] += 1
        cluster_samples[cluster_key].append(sample_id)

        if payload.get("needs_manual_review"):
            sample_path = sample_dir / "sample.bin"
            if not sample_path.exists():
                sample_path = sample_dir / "transcript"

            if sample_path.exists():
                high_value_paths.append(sample_path)

    _write_cluster_summary(
        root_path,
        cluster_counter=cluster_counter,
        cluster_samples=cluster_samples,
        total_samples=total_samples,
    )
    _write_status_summary(
        root_path,
        status_counter=status_counter,
        total_samples=total_samples,
    )
    _write_high_value_manifest(
        root_path,
        high_value_paths=high_value_paths,
    )
    _write_triage_report_md(
        root_path,
        total_samples=total_samples,
        status_counter=status_counter,
        cluster_counter=cluster_counter,
    )

    sys.stdout.write(
        f"dns-diff: report 生成完成 root={root_path} samples={total_samples}\n"
    )
    return 0


__all__ = [
    "ReportError",
    "default_follow_diff_root",
    "generate_report",
    "resolve_high_value_manifest_path",
]
