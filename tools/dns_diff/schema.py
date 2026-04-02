from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

SCHEMA_VERSION = 1
CONTRACT_VERSION = SCHEMA_VERSION
_LAST_FOLLOW_DIFF_RUN_ID: Optional[str] = None

ANALYSIS_STATES = {"included", "excluded", "unknown"}

AGGREGATION_KEY_FIELDS: Sequence[str] = (
    "resolver_pair",
    "producer_profile",
    "input_model",
    "source_queue_dir",
    "budget_sec",
    "seed_timeout_sec",
    "variant_name",
    "ablation_status",
    "contract_version",
)

BASELINE_COMPARE_KEY_FIELDS: Sequence[str] = (
    "resolver_pair",
    "producer_profile",
    "input_model",
    "source_queue_dir",
    "budget_sec",
    "seed_timeout_sec",
    "repeat_count",
    "contract_version",
)

SEED_PROVENANCE_FIELDS: Sequence[str] = (
    "cold_start",
    "seed_source_dir",
    "seed_materialization_method",
    "seed_snapshot_id",
    "regen_seeds",
    "refilter_queries",
    "stable_input_dir",
    "recorded_at",
)

SEED_PROVENANCE_OPTIONAL_INTEGER_FIELDS: Sequence[str] = (
    "transcript_format_version",
    "transcript_max_responses",
    "response_preserve",
)

SAMPLE_META_REQUIRED_FIELDS: Sequence[str] = (
    "schema_version",
    "contract_version",
    "generated_at",
    "sample_id",
    "queue_event_id",
    "source_queue_file",
    "source_resolver",
    "sample_sha1",
    "sample_size",
    "is_stateful",
    "afl_tags",
    "first_seen_ts",
    "status",
    "analysis_state",
    "exclude_reason",
    "aggregation_key",
    "baseline_compare_key",
)

FOLLOW_DIFF_STATE_REQUIRED_FIELDS: Sequence[str] = (
    "schema_version",
    "last_scan_ts",
    "last_queue_event_id",
    "running_sample_id",
    "completed_count",
    "failed_count",
    "aggregation_key",
    "baseline_compare_key",
)

FOLLOW_DIFF_STATE_OPTIONAL_AUDIT_FIELDS: Sequence[str] = (
    "run_id",
    "last_exit_reason",
    "retry_count",
    "last_attempt_ts",
)

FOLLOW_DIFF_WINDOW_SUMMARY_REQUIRED_FIELDS: Sequence[str] = (
    "budget_sec",
    "deadline_ts",
    "queue_tail_id",
    "exit_reason",
    "exit_code",
    "completed_count",
    "failed_count",
    "last_queue_event_id",
    "aggregation_key",
    "baseline_compare_key",
)

STATE_FINGERPRINT_REQUIRED_FIELDS: Sequence[str] = (
    "bind9.forwarding_path",
    "bind9.retry_seen",
    "bind9.msg_cache_seen",
    "bind9.rrset_cache_seen",
    "bind9.negative_cache_seen",
    "unbound.forwarding_path",
    "unbound.retry_seen",
    "unbound.msg_cache_seen",
    "unbound.rrset_cache_seen",
    "unbound.negative_cache_seen",
)

FOLLOW_DIFF_STATUSES = {"pending", "running", "completed", "failed", "skipped"}


def utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _coerce_contract_version(
    value: Any,
    *,
    schema_version: Any = None,
) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    if (
        isinstance(schema_version, int)
        and not isinstance(schema_version, bool)
        and schema_version >= 1
    ):
        return schema_version
    return CONTRACT_VERSION


def _coerce_analysis_state(value: Any) -> str:
    if isinstance(value, str) and value in ANALYSIS_STATES:
        return value
    return "unknown"


def _coerce_optional_text(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _coerce_optional_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    return None


def _coerce_optional_int(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _is_missing_contract_value(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    return False


def _extract_contract_key_payload(
    data: Mapping[str, Any],
    *,
    key_name: str,
    fields: Sequence[str],
) -> tuple[Optional[Dict[str, Any]], List[str]]:
    key_payload = data.get(key_name)
    if not isinstance(key_payload, Mapping):
        return None, list(fields)

    normalized: Dict[str, Any] = {}
    missing_fields: List[str] = []
    for field in fields:
        value = key_payload.get(field)
        if field not in key_payload or _is_missing_contract_value(value):
            missing_fields.append(field)
            continue
        normalized[field] = value

    if missing_fields:
        return None, missing_fields
    return normalized, []


def _conflicting_contract_fields(
    reference: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    fields: Sequence[str],
) -> List[str]:
    return [field for field in fields if reference.get(field) != candidate.get(field)]


def build_run_comparability_payload(
    records: Iterable[Mapping[str, Any]],
) -> Dict[str, Any]:
    record_list = list(records)
    reference_aggregation_key: Optional[Dict[str, Any]] = None
    reference_baseline_compare_key: Optional[Dict[str, Any]] = None
    non_comparable_sample_ids: List[str] = []
    issues: List[Dict[str, Any]] = []
    aggregation_key_conflict_fields = set()
    baseline_compare_key_conflict_fields = set()
    full_key_sample_count = 0

    for index, record in enumerate(record_list, start=1):
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id.strip():
            sample_id = f"sample-{index}"

        aggregation_key, missing_aggregation_fields = _extract_contract_key_payload(
            record,
            key_name="aggregation_key",
            fields=AGGREGATION_KEY_FIELDS,
        )
        (
            baseline_compare_key,
            missing_baseline_fields,
        ) = _extract_contract_key_payload(
            record,
            key_name="baseline_compare_key",
            fields=BASELINE_COMPARE_KEY_FIELDS,
        )

        if missing_aggregation_fields or missing_baseline_fields:
            non_comparable_sample_ids.append(sample_id)
            issue: Dict[str, Any] = {
                "sample_id": sample_id,
                "reason": "missing_comparability_fields",
            }
            if missing_aggregation_fields:
                issue["missing_aggregation_key_fields"] = missing_aggregation_fields
            if missing_baseline_fields:
                issue["missing_baseline_compare_key_fields"] = missing_baseline_fields
            issues.append(issue)
            continue

        if aggregation_key is None or baseline_compare_key is None:
            continue

        full_key_sample_count += 1

        current_issue: Dict[str, Any] = {"sample_id": sample_id}
        if reference_aggregation_key is None:
            reference_aggregation_key = dict(aggregation_key)
        else:
            conflicting_fields = _conflicting_contract_fields(
                reference_aggregation_key,
                aggregation_key,
                fields=AGGREGATION_KEY_FIELDS,
            )
            if conflicting_fields:
                aggregation_key_conflict_fields.update(conflicting_fields)
                non_comparable_sample_ids.append(sample_id)
                current_issue["reason"] = "aggregation_key_conflict"
                current_issue["aggregation_key_conflict_fields"] = conflicting_fields

        if reference_baseline_compare_key is None:
            reference_baseline_compare_key = dict(baseline_compare_key)
        else:
            conflicting_fields = _conflicting_contract_fields(
                reference_baseline_compare_key,
                baseline_compare_key,
                fields=BASELINE_COMPARE_KEY_FIELDS,
            )
            if conflicting_fields:
                baseline_compare_key_conflict_fields.update(conflicting_fields)
                non_comparable_sample_ids.append(sample_id)
                existing_reason = current_issue.get("reason")
                if existing_reason is None:
                    current_issue["reason"] = "baseline_compare_key_conflict"
                elif existing_reason != "baseline_compare_key_conflict":
                    current_issue["reason"] = "multiple_key_conflicts"
                current_issue["baseline_compare_key_conflict_fields"] = (
                    conflicting_fields
                )

        if len(current_issue) > 1:
            issues.append(current_issue)

    aggregation_comparable = (
        bool(record_list)
        and full_key_sample_count == len(record_list)
        and not aggregation_key_conflict_fields
    )
    baseline_comparable = (
        bool(record_list)
        and full_key_sample_count == len(record_list)
        and not baseline_compare_key_conflict_fields
    )
    comparable = aggregation_comparable and baseline_comparable
    comparable_sample_count = len(record_list) if comparable else 0

    if not record_list:
        reason = "no_samples"
    elif any(issue.get("reason") == "missing_comparability_fields" for issue in issues):
        reason = "missing_comparability_fields"
    elif aggregation_key_conflict_fields:
        reason = "aggregation_key_conflict"
    elif baseline_compare_key_conflict_fields:
        reason = "baseline_compare_key_conflict"
    else:
        reason = "ok"

    comparable_aggregation_key: Optional[Dict[str, Any]] = None
    if aggregation_comparable and reference_aggregation_key is not None:
        comparable_aggregation_key = dict(reference_aggregation_key)

    comparable_baseline_compare_key: Optional[Dict[str, Any]] = None
    if baseline_comparable and reference_baseline_compare_key is not None:
        comparable_baseline_compare_key = dict(reference_baseline_compare_key)

    return {
        "status": "comparable" if comparable else "non_comparable",
        "comparable": comparable,
        "aggregation_comparable": aggregation_comparable,
        "baseline_comparable": baseline_comparable,
        "reason": reason,
        "sample_count": len(record_list),
        "full_key_sample_count": full_key_sample_count,
        "comparable_sample_count": comparable_sample_count,
        "non_comparable_sample_count": len(record_list) - comparable_sample_count,
        "non_comparable_sample_ids": sorted(set(non_comparable_sample_ids)),
        "aggregation_key_conflict_fields": sorted(aggregation_key_conflict_fields),
        "baseline_compare_key_conflict_fields": sorted(
            baseline_compare_key_conflict_fields
        ),
        "aggregation_key": comparable_aggregation_key,
        "baseline_compare_key": comparable_baseline_compare_key,
        "issues": issues,
    }


def _build_semantic_key(
    *,
    fields: Sequence[str],
    base: Any,
    contract_version: int,
) -> Dict[str, Any]:
    base_mapping: Mapping[str, Any] = {}
    if isinstance(base, Mapping):
        base_mapping = base

    payload: Dict[str, Any] = {}
    for field in fields:
        if field == "contract_version":
            payload[field] = contract_version
            continue
        payload[field] = base_mapping.get(field)
    return payload


def apply_sample_meta_contract_defaults(data: Mapping[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = dict(data)

    contract_version = _coerce_contract_version(
        payload.get("contract_version"),
        schema_version=payload.get("schema_version"),
    )
    analysis_state = _coerce_analysis_state(payload.get("analysis_state"))

    payload["contract_version"] = contract_version
    payload["analysis_state"] = analysis_state
    payload["exclude_reason"] = _coerce_optional_text(payload.get("exclude_reason"))

    payload["aggregation_key"] = _build_semantic_key(
        fields=AGGREGATION_KEY_FIELDS,
        base=payload.get("aggregation_key"),
        contract_version=contract_version,
    )
    payload["baseline_compare_key"] = _build_semantic_key(
        fields=BASELINE_COMPARE_KEY_FIELDS,
        base=payload.get("baseline_compare_key"),
        contract_version=contract_version,
    )

    seed_provenance = normalize_seed_provenance_payload(payload.get("seed_provenance"))
    if seed_provenance is None:
        payload.pop("seed_provenance", None)
    else:
        payload["seed_provenance"] = seed_provenance
    return payload


def build_seed_provenance_payload(
    *,
    cold_start: Optional[bool] = None,
    seed_source_dir: Optional[str] = None,
    seed_materialization_method: Optional[str] = None,
    seed_snapshot_id: Optional[str] = None,
    regen_seeds: Optional[bool] = None,
    refilter_queries: Optional[bool] = None,
    stable_input_dir: Optional[str] = None,
    transcript_format_version: Optional[int] = None,
    transcript_max_responses: Optional[int] = None,
    response_preserve: Optional[int] = None,
    recorded_at: Optional[str] = None,
    base_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = dict(base_payload or {})

    base_cold_start = _coerce_optional_bool(payload.get("cold_start"))
    base_regen_seeds = _coerce_optional_bool(payload.get("regen_seeds"))
    base_refilter_queries = _coerce_optional_bool(payload.get("refilter_queries"))
    base_transcript_format_version = _coerce_optional_int(
        payload.get("transcript_format_version")
    )
    base_transcript_max_responses = _coerce_optional_int(
        payload.get("transcript_max_responses")
    )
    base_response_preserve = _coerce_optional_int(payload.get("response_preserve"))

    payload["cold_start"] = (
        cold_start if isinstance(cold_start, bool) else bool(base_cold_start)
    )
    payload["seed_source_dir"] = _coerce_optional_text(
        seed_source_dir
        if seed_source_dir is not None
        else payload.get("seed_source_dir")
    )
    payload["seed_materialization_method"] = _coerce_optional_text(
        seed_materialization_method
        if seed_materialization_method is not None
        else payload.get("seed_materialization_method")
    )
    payload["seed_snapshot_id"] = _coerce_optional_text(
        seed_snapshot_id
        if seed_snapshot_id is not None
        else payload.get("seed_snapshot_id")
    )
    payload["regen_seeds"] = (
        regen_seeds if isinstance(regen_seeds, bool) else bool(base_regen_seeds)
    )
    payload["refilter_queries"] = (
        refilter_queries
        if isinstance(refilter_queries, bool)
        else bool(base_refilter_queries)
    )
    payload["stable_input_dir"] = _coerce_optional_text(
        stable_input_dir
        if stable_input_dir is not None
        else payload.get("stable_input_dir")
    )
    normalized_transcript_format_version = (
        transcript_format_version
        if isinstance(transcript_format_version, int)
        and not isinstance(transcript_format_version, bool)
        else base_transcript_format_version
    )
    if normalized_transcript_format_version is None:
        payload.pop("transcript_format_version", None)
    else:
        payload["transcript_format_version"] = normalized_transcript_format_version

    normalized_transcript_max_responses = (
        transcript_max_responses
        if isinstance(transcript_max_responses, int)
        and not isinstance(transcript_max_responses, bool)
        else base_transcript_max_responses
    )
    if normalized_transcript_max_responses is None:
        payload.pop("transcript_max_responses", None)
    else:
        payload["transcript_max_responses"] = normalized_transcript_max_responses

    normalized_response_preserve = (
        response_preserve
        if isinstance(response_preserve, int)
        and not isinstance(response_preserve, bool)
        else base_response_preserve
    )
    if normalized_response_preserve is None:
        payload.pop("response_preserve", None)
    else:
        payload["response_preserve"] = normalized_response_preserve

    payload["recorded_at"] = _coerce_optional_text(
        recorded_at if recorded_at is not None else payload.get("recorded_at")
    )
    return payload


def normalize_seed_provenance_payload(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    return build_seed_provenance_payload(base_payload=value)


def build_shared_meta(
    *,
    sample_id: Optional[str] = None,
    schema_version: int = SCHEMA_VERSION,
    generated_at: Optional[str] = None,
    extra_fields: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "schema_version": schema_version,
        "generated_at": generated_at or utc_timestamp(),
    }
    if sample_id is not None:
        meta["sample_id"] = sample_id
    if extra_fields:
        meta.update(extra_fields)
    return meta


def stamp_with_shared_meta(
    payload: Mapping[str, Any],
    *,
    sample_id: Optional[str] = None,
    schema_version: int = SCHEMA_VERSION,
    generated_at: Optional[str] = None,
    extra_fields: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    merged: Dict[str, Any] = dict(payload)
    merged.update(
        build_shared_meta(
            sample_id=sample_id,
            schema_version=schema_version,
            generated_at=generated_at,
            extra_fields=extra_fields,
        )
    )
    return merged


def build_sample_meta_payload(
    *,
    sample_id: str,
    queue_event_id: Optional[str],
    source_queue_file: Optional[str],
    sample_sha1: Optional[str],
    sample_size: Optional[int],
    status: Optional[str],
    source_resolver: Optional[str],
    is_stateful: Optional[bool],
    afl_tags: Optional[List[str]],
    first_seen_ts: Optional[str] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
    base_payload: Optional[Mapping[str, Any]] = None,
    generated_at: Optional[str] = None,
    extra_fields: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = dict(base_payload or {})

    if not isinstance(first_seen_ts, str) or not first_seen_ts:
        base_first_seen = payload.get("first_seen_ts")
        if isinstance(base_first_seen, str) and base_first_seen:
            first_seen_ts = base_first_seen
        else:
            base_generated_at = payload.get("generated_at")
            if isinstance(base_generated_at, str) and base_generated_at:
                first_seen_ts = base_generated_at
            else:
                first_seen_ts = utc_timestamp()

    payload.update(
        {
            "queue_event_id": queue_event_id,
            "source_queue_file": source_queue_file,
            "source_resolver": source_resolver,
            "sample_sha1": sample_sha1,
            "sample_size": sample_size,
            "is_stateful": is_stateful,
            "afl_tags": afl_tags,
            "first_seen_ts": first_seen_ts,
            "status": status,
        }
    )
    if extra_fields:
        payload.update(extra_fields)

    normalized_seed_provenance = normalize_seed_provenance_payload(
        seed_provenance
        if seed_provenance is not None
        else payload.get("seed_provenance")
    )
    if normalized_seed_provenance is None:
        payload.pop("seed_provenance", None)
    else:
        payload["seed_provenance"] = normalized_seed_provenance

    stamped = stamp_with_shared_meta(
        payload, sample_id=sample_id, generated_at=generated_at
    )
    stamped = apply_sample_meta_contract_defaults(stamped)
    for field in SAMPLE_META_REQUIRED_FIELDS:
        stamped.setdefault(field, None)
    return stamped


def build_follow_diff_state_payload(
    *,
    schema_version: int,
    last_scan_ts: str,
    last_queue_event_id: Optional[str],
    running_sample_id: Optional[str],
    completed_count: int,
    failed_count: int,
    run_id: Optional[str] = None,
    last_exit_reason: Optional[str] = None,
    retry_count: Optional[int] = None,
    last_attempt_ts: Optional[str] = None,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    global _LAST_FOLLOW_DIFF_RUN_ID

    effective_run_id = _coerce_optional_text(run_id)
    if effective_run_id is not None:
        _LAST_FOLLOW_DIFF_RUN_ID = effective_run_id
    elif _LAST_FOLLOW_DIFF_RUN_ID is not None and (
        _coerce_optional_text(last_exit_reason) is not None
        or _coerce_optional_text(last_attempt_ts) is not None
    ):
        effective_run_id = _LAST_FOLLOW_DIFF_RUN_ID

    payload: Dict[str, Any] = {
        "schema_version": schema_version,
        "last_scan_ts": last_scan_ts,
        "last_queue_event_id": last_queue_event_id,
        "running_sample_id": running_sample_id,
        "completed_count": completed_count,
        "failed_count": failed_count,
        "run_id": effective_run_id,
        "last_exit_reason": last_exit_reason,
        "retry_count": retry_count,
        "last_attempt_ts": last_attempt_ts,
        "aggregation_key": _build_semantic_key(
            fields=AGGREGATION_KEY_FIELDS,
            base=aggregation_key,
            contract_version=CONTRACT_VERSION,
        ),
        "baseline_compare_key": _build_semantic_key(
            fields=BASELINE_COMPARE_KEY_FIELDS,
            base=baseline_compare_key,
            contract_version=CONTRACT_VERSION,
        ),
    }
    for field in FOLLOW_DIFF_STATE_REQUIRED_FIELDS:
        payload.setdefault(field, None)
    return payload


def build_follow_diff_window_summary_payload(
    *,
    budget_sec: float,
    deadline_ts: str,
    queue_tail_id: Optional[str],
    exit_reason: str,
    exit_code: int,
    completed_count: int,
    failed_count: int,
    last_queue_event_id: Optional[str],
    base_payload: Optional[Mapping[str, Any]] = None,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = dict(base_payload or {})
    normalized_seed_provenance = normalize_seed_provenance_payload(
        seed_provenance
        if seed_provenance is not None
        else payload.get("seed_provenance")
    )
    payload.update(
        {
            "budget_sec": budget_sec,
            "deadline_ts": deadline_ts,
            "queue_tail_id": queue_tail_id,
            "exit_reason": exit_reason,
            "exit_code": exit_code,
            "completed_count": completed_count,
            "failed_count": failed_count,
            "last_queue_event_id": last_queue_event_id,
            "aggregation_key": _build_semantic_key(
                fields=AGGREGATION_KEY_FIELDS,
                base=aggregation_key,
                contract_version=CONTRACT_VERSION,
            ),
            "baseline_compare_key": _build_semantic_key(
                fields=BASELINE_COMPARE_KEY_FIELDS,
                base=baseline_compare_key,
                contract_version=CONTRACT_VERSION,
            ),
        }
    )
    if normalized_seed_provenance is None:
        payload.pop("seed_provenance", None)
    else:
        payload["seed_provenance"] = normalized_seed_provenance
    for field in FOLLOW_DIFF_WINDOW_SUMMARY_REQUIRED_FIELDS:
        payload.setdefault(field, None)
    return payload


def build_state_fingerprint_payload(
    *,
    sample_id: Optional[str],
    base_payload: Optional[Mapping[str, Any]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = dict(base_payload or {})
    for field in STATE_FINGERPRINT_REQUIRED_FIELDS:
        payload.setdefault(field, None)
    if overrides:
        payload.update(overrides)
    for field in STATE_FINGERPRINT_REQUIRED_FIELDS:
        payload.setdefault(field, None)
    return stamp_with_shared_meta(
        payload, sample_id=sample_id, generated_at=generated_at
    )


def validate_shared_fields(
    data: Mapping[str, Any],
    *,
    require_sample_id: bool = False,
    required_fields: Optional[Iterable[str]] = None,
) -> List[str]:
    errors: List[str] = []

    schema_version = data.get("schema_version")
    if not isinstance(schema_version, int) or schema_version < 1:
        errors.append("schema_version 必须是 >=1 的整数")

    generated_at = data.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        errors.append("generated_at 必须是非空字符串")
    else:
        ts = generated_at.replace("Z", "+00:00")
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            errors.append("generated_at 必须是 ISO-8601 时间戳")

    sample_id = data.get("sample_id")
    if require_sample_id and (not isinstance(sample_id, str) or not sample_id.strip()):
        errors.append("sample_id 为必填且必须是非空字符串")
    elif sample_id is not None and (
        not isinstance(sample_id, str) or not sample_id.strip()
    ):
        errors.append("sample_id 若提供则必须是非空字符串")

    if required_fields:
        for field in required_fields:
            if field not in data:
                errors.append(f"缺少必填字段: {field}")

    return errors


def is_shared_schema_valid(
    data: Mapping[str, Any],
    *,
    require_sample_id: bool = False,
    required_fields: Optional[Iterable[str]] = None,
) -> bool:
    return not validate_shared_fields(
        data,
        require_sample_id=require_sample_id,
        required_fields=required_fields,
    )


def validate_sample_meta_fields(data: Mapping[str, Any]) -> List[str]:
    normalized = apply_sample_meta_contract_defaults(data)
    errors = validate_shared_fields(
        normalized,
        require_sample_id=True,
        required_fields=SAMPLE_META_REQUIRED_FIELDS,
    )
    status = normalized.get("status")
    if status is not None and status not in FOLLOW_DIFF_STATUSES:
        errors.append("status 必须是 pending/running/completed/failed/skipped 之一")

    analysis_state = normalized.get("analysis_state")
    if analysis_state not in ANALYSIS_STATES:
        errors.append("analysis_state 必须是 included/excluded/unknown 之一")

    exclude_reason = normalized.get("exclude_reason")
    if exclude_reason is not None and (
        not isinstance(exclude_reason, str) or not exclude_reason.strip()
    ):
        errors.append("exclude_reason 若提供则必须是非空字符串")

    if analysis_state == "excluded" and exclude_reason is None:
        errors.append("analysis_state=excluded 时必须提供 exclude_reason")

    for key_name, fields in (
        ("aggregation_key", AGGREGATION_KEY_FIELDS),
        ("baseline_compare_key", BASELINE_COMPARE_KEY_FIELDS),
    ):
        key_payload = normalized.get(key_name)
        if not isinstance(key_payload, Mapping):
            errors.append(f"{key_name} 必须是对象")
            continue
        for field in fields:
            if field not in key_payload:
                errors.append(f"{key_name} 缺少字段: {field}")

        key_contract_version = key_payload.get("contract_version")
        if (
            isinstance(key_contract_version, bool)
            or not isinstance(key_contract_version, int)
            or key_contract_version < 1
        ):
            errors.append(f"{key_name}.contract_version 必须是 >=1 的整数")
        elif key_contract_version != normalized.get("contract_version"):
            errors.append(f"{key_name}.contract_version 必须与 contract_version 一致")

    seed_provenance = data.get("seed_provenance")
    if seed_provenance is not None:
        if not isinstance(seed_provenance, Mapping):
            errors.append("seed_provenance 必须是对象")
        else:
            errors.extend(
                f"seed_provenance.{error}"
                for error in validate_seed_provenance_fields(seed_provenance)
            )

    return errors


def validate_seed_provenance_fields(data: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    for field in SEED_PROVENANCE_FIELDS:
        if field not in data:
            errors.append(f"缺少字段: {field}")

    for field in ("cold_start", "regen_seeds", "refilter_queries"):
        value = data.get(field)
        if not isinstance(value, bool):
            errors.append(f"{field} 必须是布尔值")

    for field in (
        "seed_source_dir",
        "seed_materialization_method",
        "seed_snapshot_id",
        "stable_input_dir",
        "recorded_at",
    ):
        value = data.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{field} 若提供则必须是非空字符串")

    recorded_at = data.get("recorded_at")
    if isinstance(recorded_at, str) and recorded_at.strip():
        ts = recorded_at.replace("Z", "+00:00")
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            errors.append("recorded_at 必须是 ISO-8601 时间戳")

    transcript_format_version = data.get("transcript_format_version")
    if "transcript_format_version" in data and (
        transcript_format_version is not None
        and (
            isinstance(transcript_format_version, bool)
            or not isinstance(transcript_format_version, int)
            or transcript_format_version < 1
        )
    ):
        errors.append("transcript_format_version 若提供则必须是 >=1 的整数")

    transcript_max_responses = data.get("transcript_max_responses")
    if "transcript_max_responses" in data and (
        transcript_max_responses is not None
        and (
            isinstance(transcript_max_responses, bool)
            or not isinstance(transcript_max_responses, int)
            or transcript_max_responses < 1
        )
    ):
        errors.append("transcript_max_responses 若提供则必须是 >=1 的整数")

    response_preserve = data.get("response_preserve")
    if "response_preserve" in data and (
        response_preserve is not None
        and (
            isinstance(response_preserve, bool)
            or not isinstance(response_preserve, int)
            or response_preserve < 0
        )
    ):
        errors.append("response_preserve 若提供则必须是 >=0 的整数")

    return errors


def validate_state_fingerprint_fields(data: Mapping[str, Any]) -> List[str]:
    return validate_shared_fields(
        data,
        require_sample_id=False,
        required_fields=STATE_FINGERPRINT_REQUIRED_FIELDS,
    )


def validate_follow_diff_state_fields(data: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    for field in FOLLOW_DIFF_STATE_REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"缺少必填字段: {field}")

    schema_version = data.get("schema_version")
    if not isinstance(schema_version, int) or schema_version < 1:
        errors.append("schema_version 必须是 >=1 的整数")

    last_scan_ts = data.get("last_scan_ts")
    if not isinstance(last_scan_ts, str):
        errors.append("last_scan_ts 必须是字符串")

    last_queue_event_id = data.get("last_queue_event_id")
    if last_queue_event_id is not None and (
        not isinstance(last_queue_event_id, str) or not last_queue_event_id.strip()
    ):
        errors.append("last_queue_event_id 若提供则必须是非空字符串")

    running_sample_id = data.get("running_sample_id")
    if running_sample_id is not None and (
        not isinstance(running_sample_id, str) or not running_sample_id.strip()
    ):
        errors.append("running_sample_id 若提供则必须是非空字符串")

    for field in ("completed_count", "failed_count"):
        value = data.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{field} 必须是非负整数")

    run_id = data.get("run_id")
    if run_id is not None and (not isinstance(run_id, str) or not run_id.strip()):
        errors.append("run_id 若提供则必须是非空字符串")

    last_exit_reason = data.get("last_exit_reason")
    if last_exit_reason is not None and (
        not isinstance(last_exit_reason, str) or not last_exit_reason.strip()
    ):
        errors.append("last_exit_reason 若提供则必须是非空字符串")

    retry_count = data.get("retry_count")
    if retry_count is not None and (
        isinstance(retry_count, bool)
        or not isinstance(retry_count, int)
        or retry_count < 0
    ):
        errors.append("retry_count 若提供则必须是非负整数")

    last_attempt_ts = data.get("last_attempt_ts")
    if last_attempt_ts is not None and (
        not isinstance(last_attempt_ts, str) or not last_attempt_ts.strip()
    ):
        errors.append("last_attempt_ts 若提供则必须是非空字符串")

    for key_name, fields in (
        ("aggregation_key", AGGREGATION_KEY_FIELDS),
        ("baseline_compare_key", BASELINE_COMPARE_KEY_FIELDS),
    ):
        key_payload = data.get(key_name)
        if not isinstance(key_payload, Mapping):
            errors.append(f"{key_name} 必须是对象")
            continue
        for field in fields:
            if field not in key_payload:
                errors.append(f"{key_name} 缺少字段: {field}")

    return errors


def validate_follow_diff_window_summary_fields(data: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    for field in FOLLOW_DIFF_WINDOW_SUMMARY_REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"缺少必填字段: {field}")

    budget_sec = data.get("budget_sec")
    if isinstance(budget_sec, bool) or not isinstance(budget_sec, (int, float)):
        errors.append("budget_sec 必须是正数")
    elif float(budget_sec) <= 0:
        errors.append("budget_sec 必须大于 0")

    deadline_ts = data.get("deadline_ts")
    if not isinstance(deadline_ts, str) or not deadline_ts.strip():
        errors.append("deadline_ts 必须是非空字符串")

    queue_tail_id = data.get("queue_tail_id")
    if queue_tail_id is not None and (
        not isinstance(queue_tail_id, str) or not queue_tail_id.strip()
    ):
        errors.append("queue_tail_id 若提供则必须是非空字符串")

    exit_reason = data.get("exit_reason")
    if not isinstance(exit_reason, str) or not exit_reason.strip():
        errors.append("exit_reason 必须是非空字符串")

    exit_code = data.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        errors.append("exit_code 必须是整数")

    for field in ("completed_count", "failed_count"):
        value = data.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{field} 必须是非负整数")

    last_queue_event_id = data.get("last_queue_event_id")
    if last_queue_event_id is not None and (
        not isinstance(last_queue_event_id, str) or not last_queue_event_id.strip()
    ):
        errors.append("last_queue_event_id 若提供则必须是非空字符串")

    for key_name, fields in (
        ("aggregation_key", AGGREGATION_KEY_FIELDS),
        ("baseline_compare_key", BASELINE_COMPARE_KEY_FIELDS),
    ):
        key_payload = data.get(key_name)
        if not isinstance(key_payload, Mapping):
            errors.append(f"{key_name} 必须是对象")
            continue
        for field in fields:
            if field not in key_payload:
                errors.append(f"{key_name} 缺少字段: {field}")

    seed_provenance = data.get("seed_provenance")
    if seed_provenance is not None:
        if not isinstance(seed_provenance, Mapping):
            errors.append("seed_provenance 必须是对象")
        else:
            errors.extend(
                f"seed_provenance.{error}"
                for error in validate_seed_provenance_fields(seed_provenance)
            )

    return errors


__all__ = [
    "AGGREGATION_KEY_FIELDS",
    "ANALYSIS_STATES",
    "BASELINE_COMPARE_KEY_FIELDS",
    "CONTRACT_VERSION",
    "FOLLOW_DIFF_STATE_OPTIONAL_AUDIT_FIELDS",
    "FOLLOW_DIFF_STATE_REQUIRED_FIELDS",
    "FOLLOW_DIFF_WINDOW_SUMMARY_REQUIRED_FIELDS",
    "FOLLOW_DIFF_STATUSES",
    "SCHEMA_VERSION",
    "SEED_PROVENANCE_FIELDS",
    "SAMPLE_META_REQUIRED_FIELDS",
    "STATE_FINGERPRINT_REQUIRED_FIELDS",
    "apply_sample_meta_contract_defaults",
    "build_follow_diff_state_payload",
    "build_follow_diff_window_summary_payload",
    "build_run_comparability_payload",
    "build_sample_meta_payload",
    "build_seed_provenance_payload",
    "build_shared_meta",
    "build_state_fingerprint_payload",
    "is_shared_schema_valid",
    "normalize_seed_provenance_payload",
    "stamp_with_shared_meta",
    "utc_timestamp",
    "validate_follow_diff_state_fields",
    "validate_follow_diff_window_summary_fields",
    "validate_sample_meta_fields",
    "validate_seed_provenance_fields",
    "validate_shared_fields",
    "validate_state_fingerprint_fields",
]
