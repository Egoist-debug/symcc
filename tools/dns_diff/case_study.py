import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .io import atomic_write_json, load_json_with_fallback
from .oracle import ORACLE_FIELDS
from .report import ReportError, collect_sample_dirs

EXIT_USAGE = 2
MAX_CASE_STUDIES = 5
CASE_STUDY_INDEX_COLUMNS: Tuple[str, ...] = (
    "sample_id",
    "semantic_outcome",
    "selection_reason",
    "case_study_path",
)
ELIGIBLE_SEMANTIC_OUTCOMES = {
    "oracle_diff",
    "oracle_and_cache_diff",
    "cache_diff_interesting",
}
_PRIORITY_BY_OUTCOME = {
    "oracle_and_cache_diff": 0,
    "oracle_diff": 0,
    "cache_diff_interesting": 1,
}


class CaseStudyError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class CaseStudyCandidate:
    sample_id: str
    sample_dir: Path
    semantic_outcome: str
    selection_reason: str
    triage_payload: Mapping[str, Any]


def _coerce_text(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _coerce_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _coerce_int(value: Any, fallback: int = 0) -> int:
    if isinstance(value, bool):
        return fallback
    if isinstance(value, int):
        return value
    return fallback


def _load_json_artifact(path: Path, *, label: str) -> Dict[str, Any]:
    load_result = load_json_with_fallback(path)
    if load_result.downgraded and path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: case-study-export 读取 {label} 降级，已回退默认值 {path}: {detail}\n"
        )
    return dict(load_result.data)


def _resolve_sample_artifact(sample_dir: Path, relative_name: str) -> Path:
    sample_root = sample_dir.resolve()
    artifact_path = (sample_root / relative_name).resolve()
    try:
        artifact_path.relative_to(sample_root)
    except ValueError as exc:
        raise CaseStudyError(
            f"样本证据路径越界: sample_dir={sample_root} artifact={artifact_path}"
        ) from exc
    return artifact_path


def _selection_reason(semantic_outcome: str) -> str:
    if semantic_outcome in {"oracle_and_cache_diff", "oracle_diff"}:
        return (
            f"analysis_state=included 且 semantic_outcome={semantic_outcome}，"
            "属于高优先级 oracle 语义差异 case study 候选"
        )
    return (
        "analysis_state=included 且 semantic_outcome=cache_diff_interesting，"
        "属于次优先级 cache 差异兴趣样本候选"
    )


def _candidate_sort_key(candidate: CaseStudyCandidate) -> Tuple[int, str]:
    return (_PRIORITY_BY_OUTCOME[candidate.semantic_outcome], candidate.sample_id)


def collect_case_study_candidates(root: Path) -> List[CaseStudyCandidate]:
    root_path = Path(root).expanduser().resolve()
    try:
        sample_dirs = collect_sample_dirs(root_path)
    except ReportError as exc:
        raise CaseStudyError(str(exc), exit_code=exc.exit_code) from exc

    candidates: List[CaseStudyCandidate] = []
    for sample_dir in sample_dirs:
        triage_payload = _load_json_artifact(
            sample_dir / "triage.json", label="triage.json"
        )
        sample_id = _coerce_text(triage_payload.get("sample_id"), sample_dir.name)
        analysis_state = _coerce_text(triage_payload.get("analysis_state"), "unknown")
        semantic_outcome = _coerce_text(
            triage_payload.get("semantic_outcome"),
            "unknown",
        )
        if analysis_state != "included":
            continue
        if semantic_outcome not in ELIGIBLE_SEMANTIC_OUTCOMES:
            continue
        candidates.append(
            CaseStudyCandidate(
                sample_id=sample_id,
                sample_dir=sample_dir.resolve(),
                semantic_outcome=semantic_outcome,
                selection_reason=_selection_reason(semantic_outcome),
                triage_payload=triage_payload,
            )
        )

    return sorted(candidates, key=_candidate_sort_key)


def _oracle_diff_fields(oracle_payload: Mapping[str, Any]) -> List[str]:
    fields: List[str] = []
    for field in ORACLE_FIELDS:
        if oracle_payload.get(f"bind9.{field}") != oracle_payload.get(
            f"unbound.{field}"
        ):
            fields.append(field)
    return fields


def _resolver_bool(
    cache_diff_payload: Mapping[str, Any], resolver: str, key: str
) -> bool:
    resolver_payload = cache_diff_payload.get(resolver)
    if not isinstance(resolver_payload, Mapping):
        return False
    return bool(resolver_payload.get(key))


def _resolver_int(
    cache_diff_payload: Mapping[str, Any], resolver: str, key: str
) -> int:
    resolver_payload = cache_diff_payload.get(resolver)
    if not isinstance(resolver_payload, Mapping):
        return 0
    return _coerce_int(resolver_payload.get(key), 0)


def _stderr_preview(path: Path, *, max_lines: int = 20) -> Dict[str, Any]:
    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "tail_preview": [],
        }

    if not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "tail_preview": [],
        }

    preview = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return {
        "path": str(path),
        "exists": True,
        "tail_preview": preview[-max_lines:],
    }


def _sample_bin_evidence(path: Path) -> Dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {
            "path": str(path),
            "exists": False,
            "size": 0,
        }
    return {
        "path": str(path),
        "exists": True,
        "size": path.stat().st_size,
    }


def _build_automated_summary(
    *,
    semantic_outcome: str,
    triage_payload: Mapping[str, Any],
    oracle_payload: Mapping[str, Any],
    cache_diff_payload: Mapping[str, Any],
) -> Dict[str, Any]:
    oracle_diff_fields = _oracle_diff_fields(oracle_payload)
    triage_status = _coerce_text(triage_payload.get("status"), "unknown")
    interesting_delta_count = _coerce_int(
        triage_payload.get("interesting_delta_count"), 0
    )
    needs_manual_review = bool(triage_payload.get("needs_manual_review"))

    if semantic_outcome == "oracle_and_cache_diff":
        summary_text = "oracle 与 cache_diff 同时命中结构化差异，按固定规则属于最高优先级 case study。"
    elif semantic_outcome == "oracle_diff":
        summary_text = (
            "oracle 存在 resolver 间字段差异，按固定规则属于最高优先级 case study。"
        )
    else:
        summary_text = (
            "oracle 未命中优先差异，但 cache_diff 达到 interesting 阈值，"
            "按固定规则作为次优先级 case study。"
        )

    return {
        "triage_status": triage_status,
        "semantic_outcome": semantic_outcome,
        "oracle_diff_fields": oracle_diff_fields,
        "cache_delta_triggered": bool(cache_diff_payload.get("cache_delta_triggered")),
        "interesting_delta_count": interesting_delta_count,
        "needs_manual_review": needs_manual_review,
        "filter_labels": _coerce_string_list(triage_payload.get("filter_labels")),
        "notes": _coerce_string_list(triage_payload.get("notes")),
        "bind9_has_cache_diff": _resolver_bool(
            cache_diff_payload, "bind9", "has_cache_diff"
        ),
        "unbound_has_cache_diff": _resolver_bool(
            cache_diff_payload, "unbound", "has_cache_diff"
        ),
        "bind9_interesting_delta_count": _resolver_int(
            cache_diff_payload, "bind9", "interesting_delta_count"
        ),
        "unbound_interesting_delta_count": _resolver_int(
            cache_diff_payload, "unbound", "interesting_delta_count"
        ),
        "summary_text": summary_text,
    }


def _build_raw_evidence(candidate: CaseStudyCandidate) -> Dict[str, Any]:
    sample_dir = candidate.sample_dir
    sample_meta_path = _resolve_sample_artifact(sample_dir, "sample.meta.json")
    oracle_path = _resolve_sample_artifact(sample_dir, "oracle.json")
    cache_diff_path = _resolve_sample_artifact(sample_dir, "cache_diff.json")
    triage_path = _resolve_sample_artifact(sample_dir, "triage.json")
    sample_bin_path = _resolve_sample_artifact(sample_dir, "sample.bin")
    bind9_stderr_path = _resolve_sample_artifact(sample_dir, "bind9.stderr")
    unbound_stderr_path = _resolve_sample_artifact(sample_dir, "unbound.stderr")

    return {
        "paths": {
            "sample_meta_path": str(sample_meta_path),
            "oracle_path": str(oracle_path),
            "cache_diff_path": str(cache_diff_path),
            "triage_path": str(triage_path),
            "sample_bin_path": str(sample_bin_path),
            "bind9_stderr_path": str(bind9_stderr_path),
            "unbound_stderr_path": str(unbound_stderr_path),
        },
        "sample_meta": _load_json_artifact(sample_meta_path, label="sample.meta.json"),
        "oracle": _load_json_artifact(oracle_path, label="oracle.json"),
        "cache_diff": _load_json_artifact(cache_diff_path, label="cache_diff.json"),
        "triage": dict(candidate.triage_payload),
        "sample_bin": _sample_bin_evidence(sample_bin_path),
        "stderr": {
            "bind9": _stderr_preview(bind9_stderr_path),
            "unbound": _stderr_preview(unbound_stderr_path),
        },
    }


def _build_case_study_payload(candidate: CaseStudyCandidate) -> Dict[str, Any]:
    raw_evidence = _build_raw_evidence(candidate)
    triage_payload = raw_evidence["triage"]
    oracle_payload = raw_evidence["oracle"]
    cache_diff_payload = raw_evidence["cache_diff"]

    automated_summary = _build_automated_summary(
        semantic_outcome=candidate.semantic_outcome,
        triage_payload=triage_payload,
        oracle_payload=oracle_payload,
        cache_diff_payload=cache_diff_payload,
    )

    return {
        "sample_id": candidate.sample_id,
        "selection_reason": candidate.selection_reason,
        "raw_evidence": raw_evidence,
        "automated_summary": automated_summary,
        "manual_truth": {
            "status": "not_started",
            "reviewer_primary": "",
            "reviewer_secondary": "",
            "adjudicator": "",
            "judgment": "",
            "notes": "",
            "decided_at": "",
        },
        "claim_scope": [
            "选样仅消费 triage.json 中已冻结的 analysis_state 与 semantic_outcome，不重算 publication 语义。",
            "原始证据路径严格限定在当前 sample_dir 的 sample.meta.json、oracle.json、cache_diff.json、triage.json、sample.bin、bind9.stderr、unbound.stderr。",
        ],
        "limitations": [
            "manual_truth 仅为 not_started scaffold，当前尚无人工双评或 adjudication 结论。",
            "stderr 仅收录尾部预览；如需完整上下文，必须回看 raw_evidence.paths 指向的原始文件。",
            "automated_summary 仅基于现有 triage/oracle/cache_diff 工件自动整理，不能替代人工判断。",
        ],
    }


def _write_index_tsv(
    output_dir: Path, candidates: Sequence[CaseStudyCandidate]
) -> Path:
    lines = ["\t".join(CASE_STUDY_INDEX_COLUMNS)]
    for candidate in candidates:
        case_study_path = (output_dir / f"{candidate.sample_id}.json").resolve()
        lines.append(
            "\t".join(
                [
                    candidate.sample_id,
                    candidate.semantic_outcome,
                    candidate.selection_reason,
                    str(case_study_path),
                ]
            )
        )
    index_path = output_dir / "index.tsv"
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index_path


def export_case_studies(
    root: Path, campaign_report_dir: Path, *, top_n: int = 5
) -> int:
    if top_n < 0:
        raise CaseStudyError(f"--top-n 不能为负数: {top_n}")

    root_path = Path(root).expanduser().resolve()
    report_dir = Path(campaign_report_dir).expanduser().resolve()
    limited_top_n = min(top_n, MAX_CASE_STUDIES)
    try:
        selected_candidates = collect_case_study_candidates(root_path)[:limited_top_n]
        output_dir = report_dir / "case_studies"
        output_dir.mkdir(parents=True, exist_ok=True)

        for candidate in selected_candidates:
            payload = _build_case_study_payload(candidate)
            atomic_write_json(output_dir / f"{candidate.sample_id}.json", payload)

        _write_index_tsv(output_dir, selected_candidates)
    except OSError as exc:
        raise CaseStudyError(f"写入 case study 产物失败: {exc}") from exc

    sys.stdout.write(
        f"dns-diff: case-study-export 落盘完成 -> {output_dir} selected={len(selected_candidates)}\n"
    )
    return 0


__all__ = [
    "CASE_STUDY_INDEX_COLUMNS",
    "CaseStudyError",
    "ELIGIBLE_SEMANTIC_OUTCOMES",
    "MAX_CASE_STUDIES",
    "collect_case_study_candidates",
    "export_case_studies",
]
