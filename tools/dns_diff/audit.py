import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .io import load_json_with_fallback
from .oracle import ORACLE_FIELDS

AUDIT_COLUMNS: Tuple[str, ...] = (
    "sample_id",
    "triage_status",
    "analysis_state",
    "semantic_outcome",
    "oracle_audit_candidate",
    "manual_truth_status",
    "bind9.parse_ok",
    "unbound.parse_ok",
    "bind9.response_accepted",
    "unbound.response_accepted",
    "bind9.second_query_hit",
    "unbound.second_query_hit",
    "bind9.cache_entry_created",
    "unbound.cache_entry_created",
    "oracle_diff_fields",
    "sample_meta_path",
    "oracle_path",
    "cache_diff_path",
    "triage_path",
)

SIGNAL_NAMES: Tuple[str, ...] = (
    "response_accepted_any",
    "second_query_hit_any",
    "cache_entry_created_any",
    "oracle_diff_any",
)
SIGNAL_COMBO_NAMES: Tuple[str, ...] = ("oracle_diff_plus_cache_diff",)

_PENDING_MANUAL_STATUSES = {"not_started", "pending", "in_progress"}
_MANUAL_TRUTH_JUDGED_MAPPING = {
    "confirmed_relevant": "confirmed_relevant_count",
    "false_positive": "false_positive_count",
    "inconclusive": "inconclusive_count",
}


@dataclass(frozen=True)
class AuditSampleRecord:
    sample_id: str
    triage_status: str
    analysis_state: str
    semantic_outcome: str
    oracle_audit_candidate: bool
    manual_truth_status: str
    bind9_parse_ok: Optional[bool]
    unbound_parse_ok: Optional[bool]
    bind9_response_accepted: Optional[bool]
    unbound_response_accepted: Optional[bool]
    bind9_second_query_hit: Optional[bool]
    unbound_second_query_hit: Optional[bool]
    bind9_cache_entry_created: Optional[bool]
    unbound_cache_entry_created: Optional[bool]
    oracle_diff_fields: Tuple[str, ...]
    sample_meta_path: Path
    oracle_path: Path
    cache_diff_path: Path
    triage_path: Path
    signal_response_accepted_any: bool
    signal_second_query_hit_any: bool
    signal_cache_entry_created_any: bool
    signal_oracle_diff_any: bool
    signal_oracle_diff_plus_cache_diff: bool


def _coerce_text(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    return None


def _coerce_oracle_bool(oracle_payload: Mapping[str, Any], key: str) -> Optional[bool]:
    return _coerce_bool(oracle_payload.get(key))


def _format_bool_text(value: Optional[bool]) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _load_json_artifact(path: Path, *, label: str) -> Dict[str, Any]:
    load_result = load_json_with_fallback(path)
    if load_result.downgraded and path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: campaign-report 读取 {label} 降级，已回退默认值 {path}: {detail}\n"
        )
    return dict(load_result.data)


def _oracle_diff_fields(oracle_payload: Mapping[str, Any]) -> Tuple[str, ...]:
    fields: List[str] = []
    for field in ORACLE_FIELDS:
        if oracle_payload.get(f"bind9.{field}") != oracle_payload.get(
            f"unbound.{field}"
        ):
            fields.append(field)
    return tuple(fields)


def _cache_diff_any(cache_diff_payload: Mapping[str, Any]) -> bool:
    for resolver in ("bind9", "unbound"):
        resolver_payload = cache_diff_payload.get(resolver)
        if not isinstance(resolver_payload, Mapping):
            continue
        if bool(resolver_payload.get("has_cache_diff")):
            return True
    return False


def _build_sample_record(sample_dir: Path) -> AuditSampleRecord:
    triage_path = sample_dir / "triage.json"
    sample_meta_path = sample_dir / "sample.meta.json"
    oracle_path = sample_dir / "oracle.json"
    cache_diff_path = sample_dir / "cache_diff.json"

    triage_payload = _load_json_artifact(triage_path, label="triage")
    oracle_payload = _load_json_artifact(oracle_path, label="oracle")
    cache_diff_payload = _load_json_artifact(cache_diff_path, label="cache_diff")

    sample_id = _coerce_text(triage_payload.get("sample_id"), sample_dir.name)
    triage_status = _coerce_text(triage_payload.get("status"), "unknown")
    analysis_state = _coerce_text(triage_payload.get("analysis_state"), "unknown")
    semantic_outcome = _coerce_text(triage_payload.get("semantic_outcome"), "unknown")
    oracle_audit_candidate = bool(triage_payload.get("oracle_audit_candidate"))
    manual_truth_status = _coerce_text(
        triage_payload.get("manual_truth_status"),
        "not_applicable",
    )

    bind9_parse_ok = _coerce_oracle_bool(oracle_payload, "bind9.parse_ok")
    unbound_parse_ok = _coerce_oracle_bool(oracle_payload, "unbound.parse_ok")
    bind9_response_accepted = _coerce_oracle_bool(
        oracle_payload, "bind9.response_accepted"
    )
    unbound_response_accepted = _coerce_oracle_bool(
        oracle_payload,
        "unbound.response_accepted",
    )
    bind9_second_query_hit = _coerce_oracle_bool(
        oracle_payload, "bind9.second_query_hit"
    )
    unbound_second_query_hit = _coerce_oracle_bool(
        oracle_payload,
        "unbound.second_query_hit",
    )
    bind9_cache_entry_created = _coerce_oracle_bool(
        oracle_payload,
        "bind9.cache_entry_created",
    )
    unbound_cache_entry_created = _coerce_oracle_bool(
        oracle_payload,
        "unbound.cache_entry_created",
    )

    oracle_diff_fields = _oracle_diff_fields(oracle_payload)
    response_accepted_any = bool(bind9_response_accepted) or bool(
        unbound_response_accepted
    )
    second_query_hit_any = bool(bind9_second_query_hit) or bool(
        unbound_second_query_hit
    )
    cache_entry_created_any = bool(bind9_cache_entry_created) or bool(
        unbound_cache_entry_created
    )
    oracle_diff_any = len(oracle_diff_fields) > 0
    oracle_diff_plus_cache_diff = oracle_diff_any and _cache_diff_any(
        cache_diff_payload
    )

    return AuditSampleRecord(
        sample_id=sample_id,
        triage_status=triage_status,
        analysis_state=analysis_state,
        semantic_outcome=semantic_outcome,
        oracle_audit_candidate=oracle_audit_candidate,
        manual_truth_status=manual_truth_status,
        bind9_parse_ok=bind9_parse_ok,
        unbound_parse_ok=unbound_parse_ok,
        bind9_response_accepted=bind9_response_accepted,
        unbound_response_accepted=unbound_response_accepted,
        bind9_second_query_hit=bind9_second_query_hit,
        unbound_second_query_hit=unbound_second_query_hit,
        bind9_cache_entry_created=bind9_cache_entry_created,
        unbound_cache_entry_created=unbound_cache_entry_created,
        oracle_diff_fields=oracle_diff_fields,
        sample_meta_path=sample_meta_path.resolve(),
        oracle_path=oracle_path.resolve(),
        cache_diff_path=cache_diff_path.resolve(),
        triage_path=triage_path.resolve(),
        signal_response_accepted_any=response_accepted_any,
        signal_second_query_hit_any=second_query_hit_any,
        signal_cache_entry_created_any=cache_entry_created_any,
        signal_oracle_diff_any=oracle_diff_any,
        signal_oracle_diff_plus_cache_diff=oracle_diff_plus_cache_diff,
    )


def collect_audit_records(sample_dirs: Iterable[Path]) -> List[AuditSampleRecord]:
    return [_build_sample_record(sample_dir) for sample_dir in sample_dirs]


def _audit_row(record: AuditSampleRecord) -> List[str]:
    oracle_diff_fields = (
        ",".join(record.oracle_diff_fields) if record.oracle_diff_fields else "-"
    )
    return [
        record.sample_id,
        record.triage_status,
        record.analysis_state,
        record.semantic_outcome,
        "true" if record.oracle_audit_candidate else "false",
        record.manual_truth_status,
        _format_bool_text(record.bind9_parse_ok),
        _format_bool_text(record.unbound_parse_ok),
        _format_bool_text(record.bind9_response_accepted),
        _format_bool_text(record.unbound_response_accepted),
        _format_bool_text(record.bind9_second_query_hit),
        _format_bool_text(record.unbound_second_query_hit),
        _format_bool_text(record.bind9_cache_entry_created),
        _format_bool_text(record.unbound_cache_entry_created),
        oracle_diff_fields,
        str(record.sample_meta_path),
        str(record.oracle_path),
        str(record.cache_diff_path),
        str(record.triage_path),
    ]


def write_oracle_audit_tsv(
    report_dir: Path, records: Sequence[AuditSampleRecord]
) -> Path:
    output_path = report_dir / "oracle_audit.tsv"
    lines = ["\t".join(AUDIT_COLUMNS)]
    for record in records:
        lines.append("\t".join(_audit_row(record)))
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def _new_reliability_bucket() -> Dict[str, int]:
    return {
        "eligible_count": 0,
        "pending_manual_count": 0,
        "judged_count": 0,
        "confirmed_relevant_count": 0,
        "false_positive_count": 0,
        "inconclusive_count": 0,
    }


def _update_reliability_bucket(
    bucket: Dict[str, int], record: AuditSampleRecord
) -> None:
    bucket["eligible_count"] += 1

    manual_truth_status = record.manual_truth_status
    judged_key = _MANUAL_TRUTH_JUDGED_MAPPING.get(manual_truth_status)
    if judged_key is not None:
        bucket["judged_count"] += 1
        bucket[judged_key] += 1
        return

    if manual_truth_status in _PENDING_MANUAL_STATUSES:
        bucket["pending_manual_count"] += 1


def _is_reliability_eligible(record: AuditSampleRecord) -> bool:
    return record.analysis_state == "included" and record.oracle_audit_candidate


def build_oracle_reliability(records: Sequence[AuditSampleRecord]) -> Dict[str, Any]:
    signals = {name: _new_reliability_bucket() for name in SIGNAL_NAMES}
    signal_combos = {name: _new_reliability_bucket() for name in SIGNAL_COMBO_NAMES}

    for record in records:
        if not _is_reliability_eligible(record):
            continue

        if record.signal_response_accepted_any:
            _update_reliability_bucket(signals["response_accepted_any"], record)
        if record.signal_second_query_hit_any:
            _update_reliability_bucket(signals["second_query_hit_any"], record)
        if record.signal_cache_entry_created_any:
            _update_reliability_bucket(signals["cache_entry_created_any"], record)
        if record.signal_oracle_diff_any:
            _update_reliability_bucket(signals["oracle_diff_any"], record)
        if record.signal_oracle_diff_plus_cache_diff:
            _update_reliability_bucket(
                signal_combos["oracle_diff_plus_cache_diff"], record
            )

    return {
        "signals": signals,
        "signal_combos": signal_combos,
    }


def write_oracle_reliability_json(
    report_dir: Path,
    records: Sequence[AuditSampleRecord],
) -> Path:
    output_path = report_dir / "oracle_reliability.json"
    payload = build_oracle_reliability(records)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


__all__ = [
    "AUDIT_COLUMNS",
    "SIGNAL_COMBO_NAMES",
    "SIGNAL_NAMES",
    "AuditSampleRecord",
    "build_oracle_reliability",
    "collect_audit_records",
    "write_oracle_audit_tsv",
    "write_oracle_reliability_json",
]
