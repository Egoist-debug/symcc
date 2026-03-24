from typing import Any, Dict, Mapping, Optional, Sequence

FAILURE_TAXONOMY_VERSION = 1

FAILURE_BUCKET_PRIMARY_ORDER: Sequence[str] = (
    "semantic_diff",
    "valid_negative",
    "input_parse_failure",
    "infra_artifact_failure",
    "orchestrator_compat_failure",
    "target_runtime_failure",
)

FAILURE_BUCKET_DETAIL_ORDER: Sequence[str] = (
    "oracle_diff",
    "oracle_and_cache_diff",
    "cache_diff_interesting",
    "cache_diff_benign",
    "no_diff",
    "oracle_parse_incomplete",
    "replay_missing_artifact",
    "replay_missing_executable",
    "replay_subprocess_launch_error",
    "replay_timeout",
    "replay_subprocess_failed",
)

_PRIMARY_BY_DETAIL: Dict[str, str] = {
    "oracle_diff": "semantic_diff",
    "oracle_and_cache_diff": "semantic_diff",
    "cache_diff_interesting": "semantic_diff",
    "cache_diff_benign": "valid_negative",
    "no_diff": "valid_negative",
    "oracle_parse_incomplete": "input_parse_failure",
    "replay_missing_artifact": "infra_artifact_failure",
    "replay_missing_executable": "infra_artifact_failure",
    "replay_subprocess_launch_error": "orchestrator_compat_failure",
    "replay_timeout": "target_runtime_failure",
    "replay_subprocess_failed": "target_runtime_failure",
}

EXCLUSION_STATE_BY_PRIMARY: Dict[str, str] = {
    "semantic_diff": "included",
    "valid_negative": "included",
    "input_parse_failure": "unknown",
    "infra_artifact_failure": "excluded",
    "orchestrator_compat_failure": "excluded",
    "target_runtime_failure": "unknown",
}

_DETAIL_BY_REPLAY_REASON: Dict[str, str] = {
    "missing_artifact": "replay_missing_artifact",
    "missing_executable": "replay_missing_executable",
    "subprocess_launch_error": "replay_subprocess_launch_error",
    "timeout": "replay_timeout",
    "subprocess_failed": "replay_subprocess_failed",
}

_PUBLICATION_SEMANTIC_OUTCOME_BY_DETAIL: Dict[str, str] = {
    "oracle_diff": "oracle_diff",
    "oracle_and_cache_diff": "oracle_and_cache_diff",
    "cache_diff_interesting": "cache_diff_interesting",
    "cache_diff_benign": "cache_diff_benign",
    "no_diff": "no_diff",
    "oracle_parse_incomplete": "runtime_or_parse_failure",
    "replay_timeout": "runtime_or_parse_failure",
    "replay_subprocess_failed": "runtime_or_parse_failure",
    "replay_missing_artifact": "infra_failure",
    "replay_missing_executable": "infra_failure",
    "replay_subprocess_launch_error": "infra_failure",
}


def _failure_text_field(failure: Mapping[str, Any], field: str) -> Optional[str]:
    value = failure.get(field)
    if isinstance(value, str) and value:
        return value
    return None


def infer_replay_failure_reason(failure: Mapping[str, Any]) -> Optional[str]:
    reason = _failure_text_field(failure, "reason")
    if reason:
        return reason

    message = _failure_text_field(failure, "message") or ""
    returncode = failure.get("returncode")
    if returncode in (124, 137) or "超时" in message:
        return "timeout"
    if _failure_text_field(failure, "artifact_path") or "未生成有效文件" in message:
        return "missing_artifact"
    if _failure_text_field(failure, "executable_path") or any(
        token in message for token in ("不可执行", "缺少可执行文件")
    ):
        return "missing_executable"
    return None


def _detail_from_status(
    *,
    status: Optional[str],
    diff_class: Optional[str],
    replay_failure_reason: Optional[str],
) -> str:
    if diff_class == "oracle_and_cache_diff":
        return "oracle_and_cache_diff"
    if status == "completed_oracle_diff" or diff_class == "oracle_diff":
        return "oracle_diff"
    if (
        status == "completed_cache_changed_needs_review"
        or diff_class == "cache_diff_interesting"
    ):
        return "cache_diff_interesting"
    if (
        status == "completed_cache_changed_but_benign"
        or diff_class == "cache_diff_benign"
    ):
        return "cache_diff_benign"
    if status == "completed_no_diff" or diff_class == "no_diff":
        return "no_diff"
    if status == "failed_parse" or diff_class == "oracle_parse_incomplete":
        return "oracle_parse_incomplete"
    if status == "failed_replay" or diff_class == "replay_incomplete":
        if replay_failure_reason is not None:
            mapped = _DETAIL_BY_REPLAY_REASON.get(replay_failure_reason)
            if mapped is not None:
                return mapped
        return "replay_subprocess_failed"
    return "replay_subprocess_failed"


def normalize_failure_taxonomy(
    *,
    status: Optional[str],
    diff_class: Optional[str],
    sample_failure: Mapping[str, Any],
) -> Dict[str, Any]:
    replay_failure_reason = infer_replay_failure_reason(sample_failure)
    failure_bucket_detail = _detail_from_status(
        status=status,
        diff_class=diff_class,
        replay_failure_reason=replay_failure_reason,
    )
    failure_bucket_primary = _PRIMARY_BY_DETAIL[failure_bucket_detail]
    analysis_state = EXCLUSION_STATE_BY_PRIMARY[failure_bucket_primary]
    semantic_outcome = _PUBLICATION_SEMANTIC_OUTCOME_BY_DETAIL[failure_bucket_detail]
    exclude_reason = "infra_failure" if analysis_state == "excluded" else None

    if failure_bucket_primary not in FAILURE_BUCKET_PRIMARY_ORDER:
        raise ValueError(
            f"unsupported failure_bucket_primary: {failure_bucket_primary}"
        )
    if failure_bucket_detail not in FAILURE_BUCKET_DETAIL_ORDER:
        raise ValueError(f"unsupported failure_bucket_detail: {failure_bucket_detail}")

    oracle_audit_candidate = failure_bucket_detail in {
        "oracle_diff",
        "oracle_and_cache_diff",
        "cache_diff_interesting",
    }

    return {
        "failure_taxonomy_version": FAILURE_TAXONOMY_VERSION,
        "failure_bucket_primary": failure_bucket_primary,
        "failure_bucket_detail": failure_bucket_detail,
        "analysis_state": analysis_state,
        "exclude_reason": exclude_reason,
        "semantic_outcome": semantic_outcome,
        "oracle_audit_candidate": oracle_audit_candidate,
    }


__all__ = [
    "EXCLUSION_STATE_BY_PRIMARY",
    "FAILURE_BUCKET_DETAIL_ORDER",
    "FAILURE_BUCKET_PRIMARY_ORDER",
    "FAILURE_TAXONOMY_VERSION",
    "infer_replay_failure_reason",
    "normalize_failure_taxonomy",
]
