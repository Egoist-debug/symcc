from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

SCHEMA_VERSION = 1

SAMPLE_META_REQUIRED_FIELDS: Sequence[str] = (
    "schema_version",
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
)

FOLLOW_DIFF_STATE_REQUIRED_FIELDS: Sequence[str] = (
    "schema_version",
    "last_scan_ts",
    "last_queue_event_id",
    "running_sample_id",
    "completed_count",
    "failed_count",
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

    stamped = stamp_with_shared_meta(
        payload, sample_id=sample_id, generated_at=generated_at
    )
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
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema_version": schema_version,
        "last_scan_ts": last_scan_ts,
        "last_queue_event_id": last_queue_event_id,
        "running_sample_id": running_sample_id,
        "completed_count": completed_count,
        "failed_count": failed_count,
    }
    for field in FOLLOW_DIFF_STATE_REQUIRED_FIELDS:
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
    errors = validate_shared_fields(
        data,
        require_sample_id=True,
        required_fields=SAMPLE_META_REQUIRED_FIELDS,
    )
    status = data.get("status")
    if status is not None and status not in FOLLOW_DIFF_STATUSES:
        errors.append("status 必须是 pending/running/completed/failed/skipped 之一")
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

    return errors


__all__ = [
    "FOLLOW_DIFF_STATE_REQUIRED_FIELDS",
    "FOLLOW_DIFF_STATUSES",
    "SCHEMA_VERSION",
    "SAMPLE_META_REQUIRED_FIELDS",
    "STATE_FINGERPRINT_REQUIRED_FIELDS",
    "build_follow_diff_state_payload",
    "build_sample_meta_payload",
    "build_shared_meta",
    "build_state_fingerprint_payload",
    "is_shared_schema_valid",
    "stamp_with_shared_meta",
    "utc_timestamp",
    "validate_follow_diff_state_fields",
    "validate_sample_meta_fields",
    "validate_shared_fields",
    "validate_state_fingerprint_fields",
]
