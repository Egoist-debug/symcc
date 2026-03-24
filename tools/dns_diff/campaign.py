import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .report import (
    _iter_sample_dirs,
    _load_triage_payload,
    _resolve_root_dir,
    resolve_high_value_manifest_path,
)


def _get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _get_ablation_status() -> Dict[str, str]:
    return {
        "mutator": "on" if os.environ.get("ENABLE_DST1_MUTATOR", "0") == "1" else "off",
        "cache-delta": "on"
        if os.environ.get("ENABLE_CACHE_DELTA", "1") == "1"
        else "off",
        "triage": "on" if os.environ.get("ENABLE_TRIAGE", "1") == "1" else "off",
        "symcc": "on" if os.environ.get("ENABLE_SYMCC", "1") == "1" else "off",
    }


def _load_manifest_index(high_value_manifest: Path) -> Tuple[Set[Path], Set[Path]]:
    manifest_paths: Set[Path] = set()
    manifest_sample_dirs: Set[Path] = set()
    if not high_value_manifest.exists():
        return manifest_paths, manifest_sample_dirs

    try:
        for raw_line in high_value_manifest.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            manifest_path = Path(line).expanduser().resolve()
            manifest_paths.add(manifest_path)
            manifest_sample_dirs.add(manifest_path.parent)
    except OSError as exc:
        sys.stderr.write(
            f"dns-diff: campaign-report 读取 high-value manifest 失败 {high_value_manifest}: {exc}\n"
        )

    return manifest_paths, manifest_sample_dirs


def generate_campaign_report(root: Path, is_custom_root: bool = False) -> int:
    root_path = Path(root).expanduser().resolve()
    sample_dirs: List[Path] = []
    if root_path.exists() and root_path.is_dir():
        sample_dirs = list(_iter_sample_dirs(root_path))

    if is_custom_root:
        report_base = root_path / "campaign_reports"
    else:
        work_dir = Path(
            os.environ.get(
                "WORK_DIR",
                str(_resolve_root_dir() / "unbound_experiment" / "work_stateful"),
            )
        ).resolve()
        report_base = work_dir / "campaign_reports"
    timestamp = _get_timestamp()
    report_dir = report_base / timestamp
    report_dir.mkdir(parents=True, exist_ok=True)

    status_counter: Counter = Counter()
    cluster_counter: Counter = Counter()
    total_samples = 0
    needs_review_count = 0

    high_value_manifest = resolve_high_value_manifest_path(root_path)
    manifest_paths, manifest_sample_dirs = _load_manifest_index(high_value_manifest)

    for sample_dir in sample_dirs:
        total_samples += 1
        payload = _load_triage_payload(sample_dir)
        status = payload.get("status", "unknown")
        cluster_key = payload.get("cluster_key", "_")
        status_counter[status] += 1
        cluster_counter[cluster_key] += 1

        if payload.get("needs_manual_review"):
            needs_review_count += 1

    reproduced_count = len(
        {sample_dir.resolve() for sample_dir in sample_dirs} & manifest_sample_dirs
    )
    manifest_size = len(manifest_paths)
    repro_rate = 0.0
    if manifest_size > 0:
        repro_rate = reproduced_count / manifest_size

    ablation = _get_ablation_status()
    summary = {
        "campaign_id": timestamp,
        "total_samples": total_samples,
        "needs_review_count": needs_review_count,
        "cluster_count": len(cluster_counter),
        "ablation_status": ablation,
        "manifest_size": manifest_size,
        "reproduced_count": reproduced_count,
        "repro_rate": repro_rate,
    }
    (report_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    ablation_lines = ["module\tstatus"]
    for k, v in sorted(ablation.items()):
        ablation_lines.append(f"{k}\t{v}")
    (report_dir / "ablation_matrix.tsv").write_text(
        "\n".join(ablation_lines) + "\n", encoding="utf-8"
    )

    cluster_lines = ["cluster_key\tcount"]
    if not cluster_counter:
        cluster_lines.append("_\t0")
    else:
        for k in sorted(cluster_counter.keys()):
            cluster_lines.append(f"{k}\t{cluster_counter[k]}")
    (report_dir / "cluster_counts.tsv").write_text(
        "\n".join(cluster_lines) + "\n", encoding="utf-8"
    )

    repro_lines = [
        "metric\tvalue",
        f"manifest_size\t{manifest_size}",
        f"reproduced_count\t{reproduced_count}",
        f"repro_rate\t{repro_rate:.4f}",
    ]
    (report_dir / "repro_rate.tsv").write_text(
        "\n".join(repro_lines) + "\n", encoding="utf-8"
    )

    sys.stdout.write(f"dns-diff: campaign-report 落盘完成 -> {report_dir}\n")
    return 0
