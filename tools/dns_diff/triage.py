import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .io import atomic_write_json, load_json_with_fallback
from .oracle import ORACLE_FIELDS
from .schema import STATE_FINGERPRINT_REQUIRED_FIELDS, stamp_with_shared_meta

RESOLVERS: Tuple[str, str] = ("bind9", "unbound")
TRIAGE_REQUIRED_FIELDS: Sequence[str] = (
    "schema_version",
    "generated_at",
    "sample_id",
    "status",
    "diff_class",
    "filter_labels",
    "cluster_key",
    "cache_delta_triggered",
    "interesting_delta_count",
    "needs_manual_review",
    "notes",
)

_CLUSTER_TOKEN_RE = re.compile(r"[^a-z0-9._-]+")
EXIT_USAGE = 2


class TriageError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _cluster_token(value: Any) -> str:
    if value is None:
        return "_"
    text = str(value).strip().lower()
    if not text:
        return "_"
    normalized = _CLUSTER_TOKEN_RE.sub("-", text).strip("-")
    return normalized or "_"


def _append_filter_label(labels: List[str], label: str) -> None:
    if label not in labels:
        labels.append(label)


def _resolver_payload(
    cache_diff: Mapping[str, Any], resolver: str
) -> Mapping[str, Any]:
    payload = cache_diff.get(resolver)
    if isinstance(payload, Mapping):
        return payload
    return {}


def _interesting_delta_count(resolver_payload: Mapping[str, Any]) -> int:
    count = resolver_payload.get("interesting_delta_count")
    if isinstance(count, int) and count >= 0:
        return count
    delta_items = resolver_payload.get("delta_items")
    if isinstance(delta_items, list):
        return len(delta_items)
    return 0


def _cache_has_diff(cache_diff: Mapping[str, Any]) -> bool:
    return any(
        bool(_resolver_payload(cache_diff, resolver).get("has_cache_diff"))
        for resolver in RESOLVERS
    )


def _cache_interesting_delta_count(cache_diff: Mapping[str, Any]) -> int:
    return sum(
        _interesting_delta_count(_resolver_payload(cache_diff, resolver))
        for resolver in RESOLVERS
    )


def _oracle_statuses(oracle: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    return {
        resolver: oracle.get(f"{resolver}.stderr_parse_status")
        if isinstance(oracle.get(f"{resolver}.stderr_parse_status"), str)
        else None
        for resolver in RESOLVERS
    }


def _oracle_artifact_missing(statuses: Mapping[str, Optional[str]]) -> bool:
    return all(status is None for status in statuses.values())


def _oracle_parse_incomplete(statuses: Mapping[str, Optional[str]]) -> bool:
    return any(status != "ok" for status in statuses.values())


def _oracle_diff_fields(oracle: Mapping[str, Any]) -> List[str]:
    differing_fields: List[str] = []
    for field in ORACLE_FIELDS:
        if oracle.get(f"bind9.{field}") != oracle.get(f"unbound.{field}"):
            differing_fields.append(field)
    return differing_fields


def _forwarding_pair(
    fingerprint: Mapping[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    bind9_value = fingerprint.get("bind9.forwarding_path")
    unbound_value = fingerprint.get("unbound.forwarding_path")
    bind9_path = bind9_value if isinstance(bind9_value, str) and bind9_value else None
    unbound_path = (
        unbound_value if isinstance(unbound_value, str) and unbound_value else None
    )
    return bind9_path, unbound_path


def _fingerprint_is_partial(fingerprint: Mapping[str, Any]) -> bool:
    for field in STATE_FINGERPRINT_REQUIRED_FIELDS:
        if field not in fingerprint or fingerprint.get(field) is None:
            return True
    return False


def _classify_triage_branch(
    *,
    status: Optional[str],
    diff_class: Optional[str],
    oracle: Mapping[str, Any],
    cache_diff: Mapping[str, Any],
) -> str:
    if status == "failed_replay" or diff_class == "replay_incomplete":
        return "oracle_missing"
    if status == "failed_parse" or diff_class == "oracle_parse_incomplete":
        return "oracle_parse_incomplete"
    if status == "completed_oracle_diff" or diff_class in {
        "oracle_diff",
        "oracle_and_cache_diff",
    }:
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

    statuses = _oracle_statuses(oracle)
    if _oracle_artifact_missing(statuses):
        return "oracle_missing"
    if _oracle_parse_incomplete(statuses):
        return "oracle_parse_incomplete"
    if _oracle_diff_fields(oracle):
        return "oracle_diff"

    if _cache_has_diff(cache_diff):
        cache_delta_triggered = bool(cache_diff.get("cache_delta_triggered"))
        interesting_delta_count = _cache_interesting_delta_count(cache_diff)
        if cache_delta_triggered and interesting_delta_count > 0:
            return "cache_diff_interesting"
        return "cache_diff_benign"

    return "no_diff"


def _rewrite_filter_labels(
    *,
    status: Optional[str],
    diff_class: Optional[str],
    oracle: Mapping[str, Any],
    cache_diff: Mapping[str, Any],
    fingerprint: Mapping[str, Any],
) -> List[str]:
    labels: List[str] = []
    triage_branch = _classify_triage_branch(
        status=status,
        diff_class=diff_class,
        oracle=oracle,
        cache_diff=cache_diff,
    )
    cache_delta_triggered = bool(cache_diff.get("cache_delta_triggered"))
    interesting_delta_count = _cache_interesting_delta_count(cache_diff)
    bind9_forwarding_path, unbound_forwarding_path = _forwarding_pair(fingerprint)

    if triage_branch == "oracle_missing":
        _append_filter_label(labels, "oracle_missing")
    elif triage_branch == "oracle_parse_incomplete":
        _append_filter_label(labels, "oracle_parse_incomplete")
    elif triage_branch == "oracle_diff":
        _append_filter_label(labels, "oracle_diff")
    elif triage_branch == "cache_diff_interesting":
        _append_filter_label(labels, "cache_diff_present")
        _append_filter_label(labels, "cache_delta_review")
    elif triage_branch == "cache_diff_benign":
        _append_filter_label(labels, "cache_diff_present")

    if cache_delta_triggered:
        _append_filter_label(labels, "cache_delta_triggered")
    if interesting_delta_count > 0:
        _append_filter_label(labels, "cache_delta_items_present")
    if _fingerprint_is_partial(fingerprint):
        _append_filter_label(labels, "partial_fingerprint")
    if bind9_forwarding_path is not None or unbound_forwarding_path is not None:
        _append_filter_label(labels, "forwarding_path_seen")
    if (
        bind9_forwarding_path is not None
        and unbound_forwarding_path is not None
        and bind9_forwarding_path != unbound_forwarding_path
    ):
        _append_filter_label(labels, "forwarding_path_mismatch")
    return labels


def _load_json_artifact(path: Path) -> Dict[str, Any]:
    load_result = load_json_with_fallback(path)
    if load_result.downgraded and path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: triage rewrite 读取降级，已回退默认值 {path}: {detail}\n"
        )
    return dict(load_result.data)


def _resolve_sample_id(sample_dir: Path, *payloads: Mapping[str, Any]) -> str:
    for payload in payloads:
        sample_id = payload.get("sample_id")
        if isinstance(sample_id, str) and sample_id:
            return sample_id
    return sample_dir.name


def _build_cluster_key(
    *,
    status: str,
    diff_class: str,
    filter_labels: Sequence[str],
    bind9_forwarding_path: Optional[str],
    unbound_forwarding_path: Optional[str],
) -> str:
    label_token = ",".join(_cluster_token(label) for label in filter_labels) or "_"
    return "|".join(
        (
            _cluster_token(status),
            _cluster_token(diff_class),
            label_token,
            f"fp:{_cluster_token(bind9_forwarding_path)}->{_cluster_token(unbound_forwarding_path)}",
        )
    )


def build_triage(
    sample_id: str,
    oracle: dict,
    cache_diff: dict,
    fingerprint: dict,
) -> dict:
    statuses = _oracle_statuses(oracle)
    cache_delta_triggered = bool(cache_diff.get("cache_delta_triggered"))
    cache_has_diff = _cache_has_diff(cache_diff)
    interesting_delta_count = _cache_interesting_delta_count(cache_diff)
    bind9_forwarding_path, unbound_forwarding_path = _forwarding_pair(fingerprint)
    forwarding_mismatch = (
        bind9_forwarding_path is not None
        and unbound_forwarding_path is not None
        and bind9_forwarding_path != unbound_forwarding_path
    )

    filter_labels: List[str] = []
    notes: List[str] = []
    needs_manual_review = False

    if _oracle_artifact_missing(statuses):
        status = "failed_replay"
        diff_class = "replay_incomplete"
        filter_labels.append("oracle_missing")
        notes.append("oracle.json 缺失，当前样本按 replay 失败处理")
        needs_manual_review = True
    elif _oracle_parse_incomplete(statuses):
        status = "failed_parse"
        diff_class = "oracle_parse_incomplete"
        filter_labels.append("oracle_parse_incomplete")
        notes.append(
            "oracle 解析不完整: "
            + ", ".join(
                f"{resolver}={statuses[resolver] or 'missing'}"
                for resolver in RESOLVERS
            )
        )
        needs_manual_review = True
    else:
        oracle_diff_fields = _oracle_diff_fields(oracle)
        if oracle_diff_fields:
            status = "completed_oracle_diff"
            diff_class = "oracle_and_cache_diff" if cache_has_diff else "oracle_diff"
            filter_labels.append("oracle_diff")
            notes.append(
                "oracle 字段存在 resolver 间差异: " + ", ".join(oracle_diff_fields)
            )
            needs_manual_review = True
        elif cache_has_diff:
            if cache_delta_triggered and interesting_delta_count > 0:
                status = "completed_cache_changed_needs_review"
                diff_class = "cache_diff_interesting"
                filter_labels.append("cache_diff_present")
                filter_labels.append("cache_delta_review")
                notes.append(
                    f"cache 结构差异已触发明细输出，interesting_delta_count={interesting_delta_count}"
                )
                needs_manual_review = True
            else:
                status = "completed_cache_changed_but_benign"
                diff_class = "cache_diff_benign"
                filter_labels.append("cache_diff_present")
                notes.append("cache 存在结构差异，但当前未命中需要人工复核的触发条件")
        else:
            status = "completed_no_diff"
            diff_class = "no_diff"
            notes.append("oracle 与 cache_diff 均未发现需升级处理的结构化差异")

    if cache_delta_triggered:
        filter_labels.append("cache_delta_triggered")
    if interesting_delta_count > 0:
        filter_labels.append("cache_delta_items_present")
    if bind9_forwarding_path is not None or unbound_forwarding_path is not None:
        filter_labels.append("forwarding_path_seen")
    if forwarding_mismatch:
        filter_labels.append("forwarding_path_mismatch")
        notes.append("state_fingerprint 记录到 resolver forwarding_path 不一致")
        needs_manual_review = True

    payload: Dict[str, Any] = stamp_with_shared_meta(
        {
            "status": status,
            "diff_class": diff_class,
            "filter_labels": filter_labels,
            "cluster_key": _build_cluster_key(
                status=status,
                diff_class=diff_class,
                filter_labels=filter_labels,
                bind9_forwarding_path=bind9_forwarding_path,
                unbound_forwarding_path=unbound_forwarding_path,
            ),
            "cache_delta_triggered": cache_delta_triggered,
            "interesting_delta_count": interesting_delta_count,
            "needs_manual_review": needs_manual_review,
            "notes": notes,
        },
        sample_id=sample_id,
    )

    for field in TRIAGE_REQUIRED_FIELDS:
        payload.setdefault(field, None)
    return payload


def rewrite_triage_payload(
    sample_dir: Path,
    *,
    oracle: Optional[Mapping[str, Any]] = None,
    cache_diff: Optional[Mapping[str, Any]] = None,
    fingerprint: Optional[Mapping[str, Any]] = None,
    existing_triage: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_oracle = (
        dict(oracle)
        if oracle is not None
        else _load_json_artifact(sample_dir / "oracle.json")
    )
    resolved_cache_diff = (
        dict(cache_diff)
        if cache_diff is not None
        else _load_json_artifact(sample_dir / "cache_diff.json")
    )
    resolved_fingerprint = (
        dict(fingerprint)
        if fingerprint is not None
        else _load_json_artifact(sample_dir / "state_fingerprint.json")
    )
    resolved_existing_triage = (
        dict(existing_triage)
        if existing_triage is not None
        else _load_json_artifact(sample_dir / "triage.json")
    )

    sample_id = _resolve_sample_id(
        sample_dir,
        resolved_existing_triage,
        resolved_oracle,
        resolved_cache_diff,
        resolved_fingerprint,
    )
    rebuilt_triage = build_triage(
        sample_id,
        resolved_oracle,
        resolved_cache_diff,
        resolved_fingerprint,
    )

    payload: Dict[str, Any] = dict(rebuilt_triage)
    payload.update(resolved_existing_triage)

    status_value = payload.get("status")
    status = (
        status_value
        if isinstance(status_value, str) and status_value
        else rebuilt_triage["status"]
    )
    diff_class_value = payload.get("diff_class")
    diff_class = (
        diff_class_value
        if isinstance(diff_class_value, str) and diff_class_value
        else rebuilt_triage["diff_class"]
    )
    filter_labels = _rewrite_filter_labels(
        status=status,
        diff_class=diff_class,
        oracle=resolved_oracle,
        cache_diff=resolved_cache_diff,
        fingerprint=resolved_fingerprint,
    )
    bind9_forwarding_path, unbound_forwarding_path = _forwarding_pair(
        resolved_fingerprint
    )

    payload["filter_labels"] = filter_labels
    payload["cluster_key"] = _build_cluster_key(
        status=status,
        diff_class=diff_class,
        filter_labels=filter_labels,
        bind9_forwarding_path=bind9_forwarding_path,
        unbound_forwarding_path=unbound_forwarding_path,
    )
    payload["needs_manual_review"] = rebuilt_triage["needs_manual_review"]

    for field in TRIAGE_REQUIRED_FIELDS:
        payload.setdefault(field, None)
    return payload


def rewrite_triage_root(root: Path) -> int:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise TriageError(f"follow_diff 根目录不存在或不是目录: {root_path}")

    rewritten = 0
    for sample_dir in sorted(path for path in root_path.iterdir() if path.is_dir()):
        payload = rewrite_triage_payload(sample_dir)
        atomic_write_json(sample_dir / "triage.json", payload)
        rewritten += 1

    sys.stdout.write(
        f"dns-diff: triage rewrite 完成 root={root_path} rewritten={rewritten}\n"
    )
    return 0


__all__ = [
    "TRIAGE_REQUIRED_FIELDS",
    "TriageError",
    "build_triage",
    "rewrite_triage_payload",
    "rewrite_triage_root",
]
