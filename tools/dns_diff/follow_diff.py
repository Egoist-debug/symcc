import hashlib
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .cache_diff import build_cache_diff
from .cache_parser import CacheParseError, parse_cache_dump
from .io import atomic_write_json, load_state_file, save_state_file
from .oracle import ORACLE_FIELDS
from .replay import ReplayError, replay_diff_cache
from .schema import (
    CONTRACT_VERSION,
    build_follow_diff_state_payload,
    build_follow_diff_window_summary_payload,
    build_sample_meta_payload,
    build_state_fingerprint_payload,
    normalize_seed_provenance_payload,
    utc_timestamp,
    validate_follow_diff_state_fields,
    validate_follow_diff_window_summary_fields,
)
from .triage import build_triage

EXIT_USAGE = 2
EXIT_DEADLINE_EXCEEDED = 6
FOLLOW_DIFF_STATE_SCHEMA_VERSION = 1
DEFAULT_FOLLOW_DIFF_INTERVAL_SEC = 60.0
FOLLOW_DIFF_STATE_FILE_NAME = "follow_diff.state.json"
FOLLOW_DIFF_WINDOW_SUMMARY_FILE_NAME = "follow_diff.window.summary.json"
DEFAULT_FOLLOW_DIFF_WORK_DIR_RELATIVE = Path("unbound_experiment") / "work_stateful"
DEFAULT_BIND9_WORK_DIR_RELATIVE = Path("named_experiment") / "work"
DEFAULT_FOLLOW_DIFF_SOURCE_DIR_RELATIVE = Path("afl_out") / "master" / "queue"
FOLLOW_DIFF_OUTPUT_DIR_NAME = "follow_diff"
PRODUCER_SEED_PROVENANCE_FILE_NAME = "producer_seed_provenance.json"
FOLLOW_DIFF_RESOLVER_PAIR = "bind9_vs_unbound"
FOLLOW_DIFF_PRODUCER_PROFILE = "poison-stateful"
FOLLOW_DIFF_INPUT_MODEL = "DST1 transcript"
DEFAULT_SEED_TIMEOUT_SEC = 5
FOLLOW_DIFF_REPEAT_COUNT = 1
FOLLOW_DIFF_TOGGLE_ENV_DEFAULTS: Dict[str, str] = {
    "ENABLE_DST1_MUTATOR": "0",
    "ENABLE_CACHE_DELTA": "1",
    "ENABLE_TRIAGE": "1",
    "ENABLE_SYMCC": "1",
}
FOLLOW_DIFF_TOGGLE_ENV_TO_ABLATION_KEY: Dict[str, str] = {
    "ENABLE_DST1_MUTATOR": "mutator",
    "ENABLE_CACHE_DELTA": "cache-delta",
    "ENABLE_TRIAGE": "triage",
    "ENABLE_SYMCC": "symcc",
}
FOLLOW_DIFF_VARIANT_ENVS: Dict[str, Dict[str, str]] = {
    "full_stack": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
    "afl_only": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "0",
    },
    "no_mutator": {
        "ENABLE_DST1_MUTATOR": "0",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
    "no_cache_delta": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "0",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
}

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

COMPLETED_PREFIX = "completed"
WINDOW_EXIT_REASON_QUIESCENT = "quiescent"
WINDOW_EXIT_REASON_DEADLINE_EXCEEDED = "deadline_exceeded"
WINDOW_IDLE_CONVERGENCE_ROUNDS = 2

BIND9_BEFORE_CACHE_FILE = "bind9.before.cache.txt"
BIND9_AFTER_CACHE_FILE = "bind9.after.cache.txt"
UNBOUND_BEFORE_CACHE_FILE = "unbound.before.cache.txt"
UNBOUND_AFTER_CACHE_FILE = "unbound.after.cache.txt"
CACHE_DIFF_FILE = "cache_diff.json"
TRIAGE_FILE = "triage.json"
CACHE_DETAIL_ALLOWLIST_ENV_KEYS: Tuple[str, ...] = (
    "FOLLOW_DIFF_CACHE_DETAIL_ALLOWLIST",
    "DNS_DIFF_CACHE_DETAIL_ALLOWLIST",
)


class FollowDiffError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class FollowDiffConfig:
    work_dir: Path
    source_dir: Path
    output_root: Path
    seed_provenance: Optional[Dict[str, Any]] = None


@dataclass
class FollowDiffSummary:
    scanned: int = 0
    attempted: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0


@dataclass
class FollowDiffState:
    schema_version: int = FOLLOW_DIFF_STATE_SCHEMA_VERSION
    last_scan_ts: str = ""
    last_queue_event_id: Optional[str] = None
    running_sample_id: Optional[str] = None
    completed_count: int = 0
    failed_count: int = 0
    run_id: Optional[str] = None
    last_exit_reason: Optional[str] = None
    retry_count: int = 0
    last_attempt_ts: Optional[str] = None
    aggregation_key: Optional[Dict[str, Any]] = None
    baseline_compare_key: Optional[Dict[str, Any]] = None

    def to_payload(self) -> Dict[str, Any]:
        return build_follow_diff_state_payload(
            schema_version=self.schema_version,
            last_scan_ts=self.last_scan_ts,
            last_queue_event_id=self.last_queue_event_id,
            running_sample_id=self.running_sample_id,
            completed_count=self.completed_count,
            failed_count=self.failed_count,
            run_id=self.run_id,
            last_exit_reason=self.last_exit_reason,
            retry_count=self.retry_count,
            last_attempt_ts=self.last_attempt_ts,
            aggregation_key=self.aggregation_key,
            baseline_compare_key=self.baseline_compare_key,
        )


@dataclass(frozen=True)
class FollowDiffBatchResult:
    summary: FollowDiffSummary
    matched_sample: bool = False
    seen_sample_ids: Set[str] = field(default_factory=set)
    failed_sample_ids: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class FollowDiffRecoveryAudit:
    status: str = "none"
    sample_id: Optional[str] = None
    detail: Optional[str] = None


def _format_deadline_ts(deadline_epoch_sec: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(deadline_epoch_sec)) + "Z"


def _write_follow_diff_window_summary(
    *,
    config: FollowDiffConfig,
    budget_sec: float,
    deadline_ts: str,
    queue_tail_id: Optional[str],
    state: FollowDiffState,
    exit_reason: str,
    exit_code: int,
    run_id: Optional[str] = None,
    retry_failed: bool = False,
    recovery_audit: Optional[FollowDiffRecoveryAudit] = None,
) -> Path:
    summary_path = config.work_dir / FOLLOW_DIFF_WINDOW_SUMMARY_FILE_NAME
    extra_fields: Dict[str, Any] = {"retry_failed": bool(retry_failed)}
    if run_id:
        extra_fields["run_id"] = run_id
    if recovery_audit is not None:
        extra_fields["recovery_status"] = recovery_audit.status
        if recovery_audit.sample_id:
            extra_fields["recovery_sample_id"] = recovery_audit.sample_id
        if recovery_audit.detail:
            extra_fields["recovery_detail"] = recovery_audit.detail
    payload = build_follow_diff_window_summary_payload(
        budget_sec=budget_sec,
        deadline_ts=deadline_ts,
        queue_tail_id=queue_tail_id,
        exit_reason=exit_reason,
        exit_code=exit_code,
        completed_count=state.completed_count,
        failed_count=state.failed_count,
        last_queue_event_id=state.last_queue_event_id,
        base_payload=extra_fields,
        aggregation_key=state.aggregation_key,
        baseline_compare_key=state.baseline_compare_key,
        seed_provenance=config.seed_provenance,
    )
    errors = validate_follow_diff_window_summary_fields(payload)
    if errors:
        raise FollowDiffError(
            "内部错误：follow-diff-window summary payload 非法: " + "; ".join(errors)
        )
    return atomic_write_json(summary_path, payload)


def _resolve_root_dir() -> Path:
    env_root = os.environ.get("ROOT_DIR")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def default_follow_diff_work_dir(root_dir: Optional[Path] = None) -> Path:
    base_root = _resolve_root_dir() if root_dir is None else Path(root_dir)
    return (
        base_root.expanduser().resolve() / DEFAULT_FOLLOW_DIFF_WORK_DIR_RELATIVE
    ).resolve()


def resolve_follow_diff_work_dir(
    *,
    root_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    env = os.environ if environ is None else environ
    env_work_dir = env.get("WORK_DIR")
    if env_work_dir:
        return Path(env_work_dir).expanduser().resolve()
    return default_follow_diff_work_dir(root_dir)


def default_bind9_work_dir(root_dir: Optional[Path] = None) -> Path:
    base_root = _resolve_root_dir() if root_dir is None else Path(root_dir)
    return (
        base_root.expanduser().resolve() / DEFAULT_BIND9_WORK_DIR_RELATIVE
    ).resolve()


def resolve_bind9_work_dir(
    *,
    root_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    env = os.environ if environ is None else environ
    env_bind9_work_dir = env.get("BIND9_WORK_DIR")
    if env_bind9_work_dir:
        return Path(env_bind9_work_dir).expanduser().resolve()

    env_work_dir = env.get("WORK_DIR")
    if env_work_dir:
        return Path(env_work_dir).expanduser().resolve()

    return default_bind9_work_dir(root_dir)


def default_follow_diff_source_dir(bind9_work_dir: Path) -> Path:
    return (
        Path(bind9_work_dir).expanduser().resolve()
        / DEFAULT_FOLLOW_DIFF_SOURCE_DIR_RELATIVE
    ).resolve()


def resolve_follow_diff_source_dir(
    *,
    root_dir: Optional[Path] = None,
    bind9_work_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    env = os.environ if environ is None else environ
    env_source_dir = env.get("FOLLOW_DIFF_SOURCE_DIR")
    if env_source_dir:
        return Path(env_source_dir).expanduser().resolve()

    resolved_bind9_work_dir = resolve_bind9_work_dir(
        root_dir=root_dir,
        environ=env,
    )
    if bind9_work_dir is not None:
        resolved_bind9_work_dir = Path(bind9_work_dir).expanduser().resolve()
    return default_follow_diff_source_dir(resolved_bind9_work_dir)


def default_follow_diff_output_root(work_dir: Path) -> Path:
    return (
        Path(work_dir).expanduser().resolve() / FOLLOW_DIFF_OUTPUT_DIR_NAME
    ).resolve()


def _collect_config() -> FollowDiffConfig:
    root_dir = _resolve_root_dir()
    work_dir = resolve_follow_diff_work_dir(root_dir=root_dir)
    source_dir = resolve_follow_diff_source_dir(root_dir=root_dir)

    if source_dir.exists() and not source_dir.is_dir():
        raise FollowDiffError(f"FOLLOW_DIFF_SOURCE_DIR 不存在或不是目录: {source_dir}")

    return FollowDiffConfig(
        work_dir=work_dir,
        source_dir=source_dir,
        output_root=default_follow_diff_output_root(work_dir),
        seed_provenance=_load_seed_provenance_sidecar(
            work_dir=work_dir,
            source_dir=source_dir,
        ),
    )


def _iter_seed_provenance_sidecar_candidates(
    *, work_dir: Path, source_dir: Path
) -> Iterable[Path]:
    seen: Set[Path] = set()
    candidate_roots: List[Path] = [work_dir]
    candidate_roots.extend(source_dir.parents[:4])
    for candidate_root in candidate_roots:
        candidate_path = (
            Path(candidate_root).expanduser().resolve()
            / PRODUCER_SEED_PROVENANCE_FILE_NAME
        )
        if candidate_path in seen:
            continue
        seen.add(candidate_path)
        yield candidate_path


def _load_seed_provenance_sidecar(
    *, work_dir: Path, source_dir: Path
) -> Optional[Dict[str, Any]]:
    for candidate_path in _iter_seed_provenance_sidecar_candidates(
        work_dir=work_dir,
        source_dir=source_dir,
    ):
        load_result = load_state_file(candidate_path)
        if load_result.status == "missing":
            continue
        if load_result.downgraded:
            sys.stderr.write(
                "dns-diff: seed_provenance sidecar 读取失败，已忽略 "
                f"path={candidate_path} status={load_result.status} detail={load_result.error}\n"
            )
            continue
        normalized = normalize_seed_provenance_payload(load_result.data)
        if normalized is None:
            sys.stderr.write(
                "dns-diff: seed_provenance sidecar 内容非法，已忽略 "
                f"path={candidate_path}\n"
            )
            continue
        return normalized
    return None


def _iter_queue_entries(source_dir: Path) -> List[Path]:
    if not source_dir.is_dir():
        return []
    return sorted(
        (path for path in source_dir.glob("id:*") if path.is_file()),
        key=lambda p: p.name,
    )


def _compute_sample_digest(queue_file: Path) -> Dict[str, Any]:
    digest = hashlib.sha1()
    size = 0
    with queue_file.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    sample_sha1 = digest.hexdigest()
    return {
        "queue_event_id": queue_file.name,
        "sample_sha1": sample_sha1,
        "sample_size": size,
        "sample_id": f"{queue_file.name}__{sample_sha1[:8]}",
    }


def _compute_file_sha1_and_size(
    sample_file: Path,
) -> Tuple[Optional[str], Optional[int]]:
    if not sample_file.is_file():
        return None, None

    digest = hashlib.sha1()
    size = 0
    with sample_file.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _load_json_object(path: Path) -> Dict[str, Any]:
    return dict(load_state_file(path).data)


def _parse_cache_rows(resolver: str, dump_path: Path) -> List[Tuple[str, ...]]:
    if not dump_path.is_file():
        return []
    try:
        return [
            tuple(record.to_fields())
            for record in parse_cache_dump(resolver, dump_path)
        ]
    except CacheParseError as exc:
        sys.stderr.write(
            f"dns-diff: cache dump 解析失败，按空集降级 {dump_path}: {exc}\n"
        )
        return []


def _normalize_allowlist_tokens(raw: str) -> Set[str]:
    return {
        token.strip() for token in raw.replace("\n", ",").split(",") if token.strip()
    }


def _detail_allowlist_contains(sample_id: str, queue_event_id: Optional[str]) -> bool:
    tokens: Set[str] = set()
    for env_key in CACHE_DETAIL_ALLOWLIST_ENV_KEYS:
        raw = os.environ.get(env_key, "")
        if raw:
            tokens.update(_normalize_allowlist_tokens(raw))
    if sample_id in tokens:
        return True
    return bool(queue_event_id) and queue_event_id in tokens


def _oracle_diff_is_not_same(oracle_payload: Mapping[str, Any]) -> bool:
    if not oracle_payload:
        return False

    bind9_status = oracle_payload.get("bind9.stderr_parse_status")
    unbound_status = oracle_payload.get("unbound.stderr_parse_status")
    if bind9_status == "ok" and unbound_status == "ok":
        for field in ORACLE_FIELDS:
            if oracle_payload.get(f"bind9.{field}") != oracle_payload.get(
                f"unbound.{field}"
            ):
                return True
        return False
    return True


def _cache_detail_triggered(
    sample_id: str,
    *,
    queue_event_id: Optional[str],
    sample_meta: Mapping[str, Any],
    oracle_payload: Mapping[str, Any],
) -> bool:
    afl_tags = sample_meta.get("afl_tags")
    has_cov = isinstance(afl_tags, list) and any(tag == "+cov" for tag in afl_tags)
    return bool(
        has_cov
        or _oracle_diff_is_not_same(oracle_payload)
        or _detail_allowlist_contains(sample_id, queue_event_id)
    )


def _write_cache_diff_artifact(
    *,
    sample_dir: Path,
    sample_id: str,
    queue_event_id: Optional[str],
) -> Path:
    sample_meta = _load_json_object(sample_dir / "sample.meta.json")
    oracle_payload = _load_json_object(sample_dir / "oracle.json")
    triggered = _cache_detail_triggered(
        sample_id,
        queue_event_id=queue_event_id,
        sample_meta=sample_meta,
        oracle_payload=oracle_payload,
    )

    payload = build_cache_diff(
        sample_id,
        _parse_cache_rows("bind9", sample_dir / BIND9_BEFORE_CACHE_FILE),
        _parse_cache_rows("bind9", sample_dir / BIND9_AFTER_CACHE_FILE),
        _parse_cache_rows("unbound", sample_dir / UNBOUND_BEFORE_CACHE_FILE),
        _parse_cache_rows("unbound", sample_dir / UNBOUND_AFTER_CACHE_FILE),
        triggered,
    )
    return atomic_write_json(sample_dir / CACHE_DIFF_FILE, payload)


def _write_triage_artifact(*, sample_dir: Path, sample_id: str) -> Path:
    payload = build_triage(
        sample_id,
        _load_json_object(sample_dir / "oracle.json"),
        _load_json_object(sample_dir / CACHE_DIFF_FILE),
        _load_json_object(sample_dir / "state_fingerprint.json"),
        sample_meta=_load_json_object(sample_dir / "sample.meta.json"),
    )
    return atomic_write_json(sample_dir / TRIAGE_FILE, payload)


def _follow_diff_state_path(config: FollowDiffConfig) -> Path:
    return config.work_dir / FOLLOW_DIFF_STATE_FILE_NAME


def _coerce_optional_text(value: Any) -> Optional[str]:
    if isinstance(value, str) and value:
        return value
    return None


def _coerce_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return ""


def _coerce_non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0


def _coerce_optional_mapping(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, Mapping):
        return dict(value)
    return None


def _parse_positive_int_env(
    env_name: str,
    default: int,
    *,
    environ: Optional[Mapping[str, str]] = None,
) -> int:
    env = os.environ if environ is None else environ
    raw_value = env.get(env_name)
    if raw_value is None or raw_value == "":
        return default

    try:
        parsed = int(raw_value)
    except ValueError as exc:
        raise FollowDiffError(
            f"{env_name} 必须是正整数，当前值: {raw_value!r}"
        ) from exc
    if parsed <= 0:
        raise FollowDiffError(f"{env_name} 必须大于 0，当前值: {raw_value!r}")
    return parsed


def _normalize_budget_sec(budget_sec: float) -> int | float:
    if float(budget_sec).is_integer():
        return int(budget_sec)
    return budget_sec


def _resolve_follow_diff_toggle_env(
    *,
    environ: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    env = os.environ if environ is None else environ
    resolved: Dict[str, str] = {}
    for env_name, default_value in FOLLOW_DIFF_TOGGLE_ENV_DEFAULTS.items():
        resolved[env_name] = "1" if env.get(env_name, default_value) == "1" else "0"
    return resolved


def _build_follow_diff_ablation_status(toggle_env: Mapping[str, str]) -> Dict[str, str]:
    return {
        ablation_key: "on" if toggle_env.get(env_name) == "1" else "off"
        for env_name, ablation_key in FOLLOW_DIFF_TOGGLE_ENV_TO_ABLATION_KEY.items()
    }


def _resolve_follow_diff_variant_name(toggle_env: Mapping[str, str]) -> str:
    normalized_env = {
        env_name: "1" if toggle_env.get(env_name) == "1" else "0"
        for env_name in FOLLOW_DIFF_TOGGLE_ENV_DEFAULTS
    }
    for variant_name, expected_env in FOLLOW_DIFF_VARIANT_ENVS.items():
        if normalized_env == expected_env:
            return variant_name

    custom_parts = [
        f"{FOLLOW_DIFF_TOGGLE_ENV_TO_ABLATION_KEY[env_name]}-"
        f"{'on' if normalized_env[env_name] == '1' else 'off'}"
        for env_name in FOLLOW_DIFF_TOGGLE_ENV_DEFAULTS
    ]
    return "custom-" + "-".join(custom_parts)


def _build_follow_diff_comparability_keys(
    config: FollowDiffConfig,
    *,
    budget_sec: float,
    repeat_count: int = FOLLOW_DIFF_REPEAT_COUNT,
    environ: Optional[Mapping[str, str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    toggle_env = _resolve_follow_diff_toggle_env(environ=environ)
    normalized_budget_sec = _normalize_budget_sec(budget_sec)
    seed_timeout_sec = _parse_positive_int_env(
        "SEED_TIMEOUT_SEC",
        DEFAULT_SEED_TIMEOUT_SEC,
        environ=environ,
    )
    variant_name = _resolve_follow_diff_variant_name(toggle_env)
    ablation_status = _build_follow_diff_ablation_status(toggle_env)

    shared_fields: Dict[str, Any] = {
        "resolver_pair": FOLLOW_DIFF_RESOLVER_PAIR,
        "producer_profile": FOLLOW_DIFF_PRODUCER_PROFILE,
        "input_model": FOLLOW_DIFF_INPUT_MODEL,
        "source_queue_dir": str(config.source_dir),
        "budget_sec": normalized_budget_sec,
        "seed_timeout_sec": seed_timeout_sec,
        "contract_version": CONTRACT_VERSION,
    }
    aggregation_key = {
        **shared_fields,
        "variant_name": variant_name,
        "ablation_status": ablation_status,
    }
    baseline_compare_key = {
        **shared_fields,
        "repeat_count": repeat_count,
    }
    return aggregation_key, baseline_compare_key


def _apply_comparability_keys(
    payload: Dict[str, Any],
    *,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
) -> None:
    if aggregation_key is not None:
        payload["aggregation_key"] = dict(aggregation_key)
    if baseline_compare_key is not None:
        payload["baseline_compare_key"] = dict(baseline_compare_key)


def _new_bounded_run_id() -> str:
    timestamp = utc_timestamp().replace(":", "").replace("-", "")
    return f"follow-diff-window-{timestamp}-{os.getpid()}"


def _load_follow_diff_state(state_path: Path) -> FollowDiffState:
    load_result = load_state_file(state_path)
    if load_result.downgraded and state_path.exists():
        detail = load_result.error or load_result.status
        sys.stderr.write(
            f"dns-diff: follow-diff 状态文件读取降级，已回退默认值 {state_path}: {detail}\n"
        )

    state_data = load_result.data
    return FollowDiffState(
        schema_version=FOLLOW_DIFF_STATE_SCHEMA_VERSION,
        last_scan_ts=_coerce_text(state_data.get("last_scan_ts")),
        last_queue_event_id=_coerce_optional_text(
            state_data.get("last_queue_event_id")
        ),
        running_sample_id=_coerce_optional_text(state_data.get("running_sample_id")),
        completed_count=_coerce_non_negative_int(state_data.get("completed_count")),
        failed_count=_coerce_non_negative_int(state_data.get("failed_count")),
        run_id=_coerce_optional_text(state_data.get("run_id")),
        last_exit_reason=_coerce_optional_text(state_data.get("last_exit_reason")),
        retry_count=_coerce_non_negative_int(state_data.get("retry_count")),
        last_attempt_ts=_coerce_optional_text(state_data.get("last_attempt_ts")),
        aggregation_key=_coerce_optional_mapping(state_data.get("aggregation_key")),
        baseline_compare_key=_coerce_optional_mapping(
            state_data.get("baseline_compare_key")
        ),
    )


def _save_follow_diff_state(state_path: Path, state: FollowDiffState) -> Path:
    payload = state.to_payload()
    errors = validate_follow_diff_state_fields(payload)
    if errors:
        raise FollowDiffError(
            "内部错误：follow-diff 状态文件 payload 非法: " + "; ".join(errors)
        )
    return save_state_file(state_path, payload)


def _resolve_follow_diff_interval_sec() -> float:
    raw_interval = os.environ.get("FOLLOW_DIFF_INTERVAL_SEC")
    if raw_interval is None or raw_interval == "":
        return DEFAULT_FOLLOW_DIFF_INTERVAL_SEC

    try:
        interval_sec = float(raw_interval)
    except ValueError as exc:
        raise FollowDiffError(
            f"FOLLOW_DIFF_INTERVAL_SEC 必须是正数，当前值: {raw_interval!r}"
        ) from exc

    if interval_sec <= 0:
        raise FollowDiffError(
            f"FOLLOW_DIFF_INTERVAL_SEC 必须大于 0，当前值: {raw_interval!r}"
        )
    return interval_sec


def _format_interval_sec(interval_sec: float) -> str:
    if interval_sec.is_integer():
        return str(int(interval_sec))
    return f"{interval_sec:g}"


def _status_is_completed(status: Any) -> bool:
    return isinstance(status, str) and (
        status == STATUS_COMPLETED or status.startswith(COMPLETED_PREFIX)
    )


def _status_is_failed(status: Any) -> bool:
    return isinstance(status, str) and status == STATUS_FAILED


def _is_completed_sample(sample_dir: Path, *, sample_id: str) -> bool:
    sample_bin = sample_dir / "sample.bin"
    if not sample_bin.is_file():
        return False

    triage_data = _load_json_object(sample_dir / "triage.json")
    if _status_is_completed(triage_data.get("status")):
        return True

    meta_data = _load_json_object(sample_dir / "sample.meta.json")
    return meta_data.get("sample_id") == sample_id and _status_is_completed(
        meta_data.get("status")
    )


def _merge_meta_payload(
    *,
    sample_id: str,
    queue_event_id: Optional[str],
    queue_file: Optional[Path],
    sample_dir: Path,
    sample_sha1: Optional[str],
    sample_size: Optional[int],
    status: str,
    base_payload: Optional[Mapping[str, Any]] = None,
    failure: Optional[Mapping[str, Any]] = None,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    base = dict(base_payload or {})
    _apply_comparability_keys(
        base,
        aggregation_key=aggregation_key,
        baseline_compare_key=baseline_compare_key,
    )

    source_resolver: Optional[str] = None
    existing_source_resolver = base.get("source_resolver")
    if isinstance(existing_source_resolver, str) and existing_source_resolver:
        source_resolver = existing_source_resolver

    is_stateful: Optional[bool] = None
    existing_is_stateful = base.get("is_stateful")
    if isinstance(existing_is_stateful, bool):
        is_stateful = existing_is_stateful
    else:
        fuzz_profile = os.environ.get("FUZZ_PROFILE", "").strip().lower()
        if fuzz_profile:
            if "stateful" in fuzz_profile:
                is_stateful = True
            elif "stateless" in fuzz_profile:
                is_stateful = False

    afl_tags: Optional[List[str]] = None
    existing_afl_tags = base.get("afl_tags")
    if isinstance(existing_afl_tags, list) and all(
        isinstance(tag, str) for tag in existing_afl_tags
    ):
        afl_tags = list(existing_afl_tags)
    else:
        parsed_tags = []
        if isinstance(queue_event_id, str) and queue_event_id:
            parsed_tags = [
                part for part in queue_event_id.split(",") if part.startswith("+")
            ]
        if parsed_tags:
            afl_tags = parsed_tags

    if failure is not None:
        base["failure"] = dict(failure)
    elif status != STATUS_FAILED:
        base.pop("failure", None)

    return build_sample_meta_payload(
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        source_queue_file=(str(queue_file) if queue_file is not None else None),
        sample_sha1=sample_sha1,
        sample_size=sample_size,
        status=status,
        source_resolver=source_resolver,
        is_stateful=is_stateful,
        afl_tags=afl_tags,
        first_seen_ts=None,
        seed_provenance=seed_provenance,
        base_payload=base,
        extra_fields={"output_dir": str(sample_dir)},
    )


def _write_state_fingerprint(
    *,
    sample_dir: Path,
    sample_id: str,
    base_payload: Optional[Mapping[str, Any]] = None,
) -> Path:
    payload = build_state_fingerprint_payload(
        sample_id=sample_id,
        base_payload=base_payload,
    )
    return atomic_write_json(sample_dir / "state_fingerprint.json", payload)


def _ensure_sample_contract_artifacts(
    *,
    sample_dir: Path,
    sample_id: str,
    queue_event_id: str,
    queue_file: Path,
    sample_sha1: str,
    sample_size: int,
    status: str,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
) -> None:
    existing_meta = _load_json_object(sample_dir / "sample.meta.json")
    persisted_status = existing_meta.get("status")
    if isinstance(persisted_status, str) and persisted_status:
        status = persisted_status

    _write_sample_meta(
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        queue_file=queue_file,
        sample_sha1=sample_sha1,
        sample_size=sample_size,
        status=status,
        base_payload=existing_meta,
        aggregation_key=aggregation_key,
        baseline_compare_key=baseline_compare_key,
        seed_provenance=seed_provenance,
    )
    _write_state_fingerprint(
        sample_dir=sample_dir,
        sample_id=sample_id,
        base_payload=_load_json_object(sample_dir / "state_fingerprint.json"),
    )
    _write_cache_diff_artifact(
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
    )
    _write_triage_artifact(sample_dir=sample_dir, sample_id=sample_id)


def _write_sample_meta(
    *,
    sample_dir: Path,
    sample_id: str,
    queue_event_id: Optional[str],
    queue_file: Optional[Path],
    sample_sha1: Optional[str],
    sample_size: Optional[int],
    status: str,
    base_payload: Optional[Mapping[str, Any]] = None,
    failure: Optional[Mapping[str, Any]] = None,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
) -> Path:
    payload = _merge_meta_payload(
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        queue_file=queue_file,
        sample_dir=sample_dir,
        sample_sha1=sample_sha1,
        sample_size=sample_size,
        status=status,
        base_payload=base_payload,
        failure=failure,
        aggregation_key=aggregation_key,
        baseline_compare_key=baseline_compare_key,
        seed_provenance=seed_provenance,
    )
    return atomic_write_json(sample_dir / "sample.meta.json", payload)


def _backfill_existing_sample_contracts(
    config: FollowDiffConfig,
    *,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
) -> None:
    if not config.output_root.is_dir():
        return

    for sample_dir in sorted(
        path for path in config.output_root.iterdir() if path.is_dir()
    ):
        sample_id = sample_dir.name
        existing_meta = _load_json_object(sample_dir / "sample.meta.json")
        existing_triage = _load_json_object(sample_dir / "triage.json")

        queue_event_id = existing_meta.get("queue_event_id")
        if not isinstance(queue_event_id, str) or not queue_event_id:
            if "__" in sample_id:
                queue_event_id = sample_id.split("__", 1)[0]
            else:
                queue_event_id = None

        source_queue_file = existing_meta.get("source_queue_file")
        queue_file: Optional[Path] = None
        if isinstance(source_queue_file, str) and source_queue_file:
            queue_file = Path(source_queue_file)

        sample_sha1 = existing_meta.get("sample_sha1")
        sample_size = existing_meta.get("sample_size")
        if not isinstance(sample_sha1, str) or not sample_sha1:
            digest, computed_size = _compute_file_sha1_and_size(
                sample_dir / "sample.bin"
            )
            sample_sha1 = digest
            if not isinstance(sample_size, int) or sample_size < 0:
                sample_size = computed_size
        if not isinstance(sample_size, int) or sample_size < 0:
            _, computed_size = _compute_file_sha1_and_size(sample_dir / "sample.bin")
            sample_size = computed_size

        persisted_status = existing_meta.get("status")
        if isinstance(persisted_status, str) and persisted_status:
            status = persisted_status
        elif _status_is_completed(existing_triage.get("status")):
            status = STATUS_COMPLETED
        else:
            status = STATUS_PENDING

        _write_sample_meta(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
            queue_file=queue_file,
            sample_sha1=sample_sha1,
            sample_size=sample_size,
            status=status,
            base_payload=existing_meta,
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=seed_provenance,
        )
        _write_state_fingerprint(
            sample_dir=sample_dir,
            sample_id=sample_id,
            base_payload=_load_json_object(sample_dir / "state_fingerprint.json"),
        )
        _write_cache_diff_artifact(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
        )
        _write_triage_artifact(sample_dir=sample_dir, sample_id=sample_id)


def _process_one_sample_with_state(
    *,
    queue_file: Path,
    sample_dir: Path,
    sample_id: str,
    queue_event_id: str,
    sample_sha1: str,
    sample_size: int,
    state: FollowDiffState,
    state_path: Path,
    seed_provenance: Optional[Mapping[str, Any]] = None,
    is_retry_attempt: bool = False,
) -> str:
    aggregation_key = state.aggregation_key if state.run_id else None
    baseline_compare_key = state.baseline_compare_key if state.run_id else None

    if _is_completed_sample(sample_dir, sample_id=sample_id):
        _ensure_sample_contract_artifacts(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
            queue_file=queue_file,
            sample_sha1=sample_sha1,
            sample_size=sample_size,
            status=STATUS_COMPLETED,
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=seed_provenance,
        )
        if state.running_sample_id == sample_id:
            state.running_sample_id = None
            _save_follow_diff_state(state_path, state)
        return STATUS_SKIPPED

    state.running_sample_id = sample_id
    state.last_queue_event_id = queue_event_id
    state.last_attempt_ts = utc_timestamp()
    if is_retry_attempt:
        state.retry_count += 1
    _save_follow_diff_state(state_path, state)

    result = _process_one_sample(
        queue_file=queue_file,
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        sample_sha1=sample_sha1,
        sample_size=sample_size,
        aggregation_key=aggregation_key,
        baseline_compare_key=baseline_compare_key,
        seed_provenance=seed_provenance,
    )

    if result == STATUS_COMPLETED:
        state.completed_count += 1
    elif result == STATUS_FAILED:
        state.failed_count += 1

    state.running_sample_id = None
    _save_follow_diff_state(state_path, state)
    return result


def _process_one_sample(
    *,
    queue_file: Path,
    sample_dir: Path,
    sample_id: str,
    queue_event_id: str,
    sample_sha1: str,
    sample_size: int,
    aggregation_key: Optional[Mapping[str, Any]] = None,
    baseline_compare_key: Optional[Mapping[str, Any]] = None,
    seed_provenance: Optional[Mapping[str, Any]] = None,
) -> str:
    if _is_completed_sample(sample_dir, sample_id=sample_id):
        _ensure_sample_contract_artifacts(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
            queue_file=queue_file,
            sample_sha1=sample_sha1,
            sample_size=sample_size,
            status=STATUS_COMPLETED,
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=seed_provenance,
        )
        return STATUS_SKIPPED

    sample_dir.mkdir(parents=True, exist_ok=True)
    existing_meta = _load_json_object(sample_dir / "sample.meta.json")
    _write_state_fingerprint(
        sample_dir=sample_dir,
        sample_id=sample_id,
        base_payload=_load_json_object(sample_dir / "state_fingerprint.json"),
    )
    sample_bin = sample_dir / "sample.bin"
    shutil.copy2(queue_file, sample_bin)

    if sample_size == 0:
        _write_sample_meta(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
            queue_file=queue_file,
            sample_sha1=sample_sha1,
            sample_size=sample_size,
            status=STATUS_FAILED,
            base_payload=existing_meta,
            failure={
                "kind": "empty_sample",
                "message": "样本为空，跳过 replay",
            },
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=seed_provenance,
        )
        _write_cache_diff_artifact(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
        )
        _write_triage_artifact(sample_dir=sample_dir, sample_id=sample_id)
        return STATUS_FAILED

    _write_sample_meta(
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        queue_file=queue_file,
        sample_sha1=sample_sha1,
        sample_size=sample_size,
        status=STATUS_RUNNING,
        base_payload=existing_meta,
        aggregation_key=aggregation_key,
        baseline_compare_key=baseline_compare_key,
        seed_provenance=seed_provenance,
    )

    try:
        replay_diff_cache(str(queue_file), str(sample_dir))
    except ReplayError as exc:
        _write_sample_meta(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
            queue_file=queue_file,
            sample_sha1=sample_sha1,
            sample_size=sample_size,
            status=STATUS_FAILED,
            base_payload=_load_json_object(sample_dir / "sample.meta.json"),
            failure=exc.to_failure_payload(),
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=seed_provenance,
        )
        _write_cache_diff_artifact(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
        )
        _write_triage_artifact(sample_dir=sample_dir, sample_id=sample_id)
        return STATUS_FAILED
    except Exception as exc:
        _write_sample_meta(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
            queue_file=queue_file,
            sample_sha1=sample_sha1,
            sample_size=sample_size,
            status=STATUS_FAILED,
            base_payload=_load_json_object(sample_dir / "sample.meta.json"),
            failure={
                "kind": "unexpected_error",
                "message": str(exc),
                "exception_type": type(exc).__name__,
            },
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=seed_provenance,
        )
        _write_cache_diff_artifact(
            sample_dir=sample_dir,
            sample_id=sample_id,
            queue_event_id=queue_event_id,
        )
        _write_triage_artifact(sample_dir=sample_dir, sample_id=sample_id)
        return STATUS_FAILED

    replay_meta = _load_json_object(sample_dir / "sample.meta.json")
    _write_sample_meta(
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        queue_file=queue_file,
        sample_sha1=sample_sha1,
        sample_size=sample_size,
        status=STATUS_COMPLETED,
        base_payload=replay_meta,
        aggregation_key=aggregation_key,
        baseline_compare_key=baseline_compare_key,
        seed_provenance=seed_provenance,
    )
    _write_cache_diff_artifact(
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
    )
    _write_triage_artifact(sample_dir=sample_dir, sample_id=sample_id)
    return STATUS_COMPLETED


def _consume_queue_entries(
    config: FollowDiffConfig,
    *,
    state: Optional[FollowDiffState] = None,
    state_path: Optional[Path] = None,
    only_sample_id: Optional[str] = None,
    skip_sample_ids: Optional[Iterable[str]] = None,
    max_queue_event_id: Optional[str] = None,
    prior_failed_sample_ids: Optional[Iterable[str]] = None,
) -> FollowDiffBatchResult:
    summary = FollowDiffSummary()
    queue_entries = _iter_queue_entries(config.source_dir)
    if max_queue_event_id is not None:
        queue_entries = [
            queue_file
            for queue_file in queue_entries
            if queue_file.name <= max_queue_event_id
        ]
    summary.scanned = len(queue_entries)

    last_queue_event_id = queue_entries[-1].name if queue_entries else None
    skipped_sample_ids: Set[str] = {
        sample_id for sample_id in (skip_sample_ids or ()) if sample_id
    }
    matched_sample = False
    seen_sample_ids: Set[str] = set()
    failed_sample_ids: Set[str] = set()
    prior_failed_ids: Set[str] = {
        sample_id for sample_id in (prior_failed_sample_ids or ()) if sample_id
    }

    for queue_file in queue_entries:
        try:
            sample_info = _compute_sample_digest(queue_file)
        except OSError as exc:
            sys.stderr.write(
                f"dns-diff: 读取 queue 样本失败，已跳过 {queue_file}: {exc}\n"
            )
            summary.failed += 1
            continue

        sample_id = sample_info["sample_id"]
        if only_sample_id is not None and sample_id != only_sample_id:
            continue

        matched_sample = True
        seen_sample_ids.add(sample_id)
        if sample_id in skipped_sample_ids:
            summary.skipped += 1
            continue

        sample_dir = config.output_root / sample_id
        existing_status: Optional[str] = None
        if sample_dir.is_dir():
            existing_meta = _load_json_object(sample_dir / "sample.meta.json")
            persisted_status = existing_meta.get("status")
            if isinstance(persisted_status, str) and persisted_status:
                existing_status = persisted_status

        is_retry_attempt = sample_id in prior_failed_ids and _status_is_failed(
            existing_status
        )
        if state is not None:
            if state_path is None:
                raise FollowDiffError("内部错误：缺少 follow-diff 状态文件路径")
            result = _process_one_sample_with_state(
                queue_file=queue_file,
                sample_dir=sample_dir,
                sample_id=sample_id,
                queue_event_id=sample_info["queue_event_id"],
                sample_sha1=sample_info["sample_sha1"],
                sample_size=sample_info["sample_size"],
                state=state,
                state_path=state_path,
                seed_provenance=config.seed_provenance,
                is_retry_attempt=is_retry_attempt,
            )
        else:
            result = _process_one_sample(
                queue_file=queue_file,
                sample_dir=sample_dir,
                sample_id=sample_id,
                queue_event_id=sample_info["queue_event_id"],
                sample_sha1=sample_info["sample_sha1"],
                sample_size=sample_info["sample_size"],
                seed_provenance=config.seed_provenance,
            )

        if result == STATUS_SKIPPED:
            summary.skipped += 1
        else:
            summary.attempted += 1
            if result == STATUS_COMPLETED:
                summary.completed += 1
            elif result == STATUS_FAILED:
                summary.failed += 1
                failed_sample_ids.add(sample_id)
                sys.stderr.write(f"dns-diff: 样本处理失败但继续后续样本: {sample_id}\n")

        if only_sample_id is not None:
            break

    if state is not None:
        state.last_scan_ts = utc_timestamp()
        state.last_queue_event_id = last_queue_event_id
        if state_path is None:
            raise FollowDiffError("内部错误：缺少 follow-diff 状态文件路径")
        _save_follow_diff_state(state_path, state)

    return FollowDiffBatchResult(
        summary=summary,
        matched_sample=matched_sample,
        seen_sample_ids=seen_sample_ids,
        failed_sample_ids=failed_sample_ids,
    )


def _write_summary(prefix: str, summary: FollowDiffSummary) -> None:
    sys.stderr.write(
        f"dns-diff: {prefix}，"
        f"扫描 {summary.scanned} 个 queue 样本，"
        f"新处理 {summary.attempted} 个，"
        f"完成 {summary.completed} 个，"
        f"失败 {summary.failed} 个，"
        f"跳过 {summary.skipped} 个\n"
    )


def _recover_running_sample(
    config: FollowDiffConfig,
    *,
    state: FollowDiffState,
    state_path: Path,
    max_queue_event_id: Optional[str] = None,
) -> FollowDiffRecoveryAudit:
    running_sample_id = state.running_sample_id
    if not running_sample_id:
        return FollowDiffRecoveryAudit(status="none")

    sample_dir = config.output_root / running_sample_id
    if _is_completed_sample(sample_dir, sample_id=running_sample_id):
        sys.stderr.write(
            f"dns-diff: 检测到上次运行中的样本已完成，清理状态后继续: {running_sample_id}\n"
        )
        state.running_sample_id = None
        _save_follow_diff_state(state_path, state)
        return FollowDiffRecoveryAudit(
            status="cleared",
            sample_id=running_sample_id,
            detail="already_completed",
        )

    sys.stderr.write(
        f"dns-diff: 检测到未完成样本，启动时先恢复一次: {running_sample_id}\n"
    )
    recovery_result = _consume_queue_entries(
        config,
        state=state,
        state_path=state_path,
        only_sample_id=running_sample_id,
        max_queue_event_id=max_queue_event_id,
    )
    _write_summary("恢复扫描完成", recovery_result.summary)

    if not recovery_result.matched_sample:
        sys.stderr.write(
            f"dns-diff: queue 中未找到待恢复样本，已清理运行中状态: {running_sample_id}\n"
        )
        state.running_sample_id = None
        _save_follow_diff_state(state_path, state)
        return FollowDiffRecoveryAudit(
            status="cleared",
            sample_id=running_sample_id,
            detail="stale_missing",
        )

    if recovery_result.summary.failed > 0:
        sys.stderr.write(
            f"dns-diff: running_sample 恢复失败，保留失败证据并继续流程: {running_sample_id}\n"
        )
        return FollowDiffRecoveryAudit(
            status="recovery_failed",
            sample_id=running_sample_id,
            detail="sample_failed",
        )

    sys.stderr.write(
        f"dns-diff: running_sample 恢复成功，后续本轮不重复处理: {running_sample_id}\n"
    )
    return FollowDiffRecoveryAudit(
        status="recovered",
        sample_id=running_sample_id,
        detail="sample_processed",
    )


def follow_diff() -> int:
    config = _collect_config()
    config.output_root.mkdir(parents=True, exist_ok=True)

    interval_sec = _resolve_follow_diff_interval_sec()
    state_path = _follow_diff_state_path(config)
    state = _load_follow_diff_state(state_path)
    state.run_id = None
    state.aggregation_key = None
    state.baseline_compare_key = None
    _save_follow_diff_state(state_path, state)

    recovery_audit = _recover_running_sample(
        config,
        state=state,
        state_path=state_path,
    )
    recovered_sample_id = recovery_audit.sample_id
    skip_sample_ids: Sequence[str] = (
        (recovered_sample_id,) if recovered_sample_id is not None else ()
    )

    sys.stderr.write(
        "dns-diff: follow-diff 单 worker 轮询启动，"
        f"source={config.source_dir}，interval={_format_interval_sec(interval_sec)}s，"
        f"state={state_path}\n"
    )

    while True:
        batch_result = _consume_queue_entries(
            config,
            state=state,
            state_path=state_path,
            skip_sample_ids=skip_sample_ids,
        )
        _backfill_existing_sample_contracts(
            config,
            seed_provenance=config.seed_provenance,
        )
        _write_summary("follow-diff 扫描完成", batch_result.summary)
        skip_sample_ids = ()
        time.sleep(interval_sec)


def follow_diff_once() -> int:
    config = _collect_config()
    config.output_root.mkdir(parents=True, exist_ok=True)

    state_path = _follow_diff_state_path(config)
    state = _load_follow_diff_state(state_path)
    state.run_id = None
    state.aggregation_key = None
    state.baseline_compare_key = None
    _save_follow_diff_state(state_path, state)

    recovery_audit = _recover_running_sample(
        config,
        state=state,
        state_path=state_path,
    )
    recovered_sample_id = recovery_audit.sample_id
    skip_sample_ids: Sequence[str] = (
        (recovered_sample_id,) if recovered_sample_id is not None else ()
    )

    result = _consume_queue_entries(
        config,
        state=state,
        state_path=state_path,
        skip_sample_ids=skip_sample_ids,
    )
    _backfill_existing_sample_contracts(
        config,
        seed_provenance=config.seed_provenance,
    )
    _write_summary("follow-diff-once 完成", result.summary)
    return 0


def follow_diff_window(
    *,
    budget_sec: float,
    queue_tail_id: Optional[str] = None,
    retry_failed: bool = False,
) -> int:
    if budget_sec <= 0:
        raise FollowDiffError("--budget-sec 必须大于 0")

    config = _collect_config()
    config.output_root.mkdir(parents=True, exist_ok=True)

    interval_sec = _resolve_follow_diff_interval_sec()
    state_path = _follow_diff_state_path(config)
    state = _load_follow_diff_state(state_path)
    bounded_run_id = _new_bounded_run_id()
    aggregation_key, baseline_compare_key = _build_follow_diff_comparability_keys(
        config,
        budget_sec=budget_sec,
    )
    state.run_id = bounded_run_id
    state.retry_count = 0
    state.last_exit_reason = None
    state.aggregation_key = aggregation_key
    state.baseline_compare_key = baseline_compare_key
    _save_follow_diff_state(state_path, state)

    if queue_tail_id is None:
        queue_entries = _iter_queue_entries(config.source_dir)
        queue_tail_id = queue_entries[-1].name if queue_entries else None
    deadline_epoch_sec = time.time() + budget_sec
    deadline_ts = _format_deadline_ts(deadline_epoch_sec)

    recovery_audit = _recover_running_sample(
        config,
        state=state,
        state_path=state_path,
        max_queue_event_id=queue_tail_id,
    )
    skip_sample_ids: Set[str] = set()
    if recovery_audit.sample_id is not None and (
        recovery_audit.status in {"recovered", "cleared"}
        or (recovery_audit.status == "recovery_failed" and not retry_failed)
    ):
        skip_sample_ids.add(recovery_audit.sample_id)
    failed_sample_ids: Set[str] = set()

    idle_rounds = 0
    while True:
        if time.time() >= deadline_epoch_sec:
            state.last_exit_reason = WINDOW_EXIT_REASON_DEADLINE_EXCEEDED
            state.run_id = None
            _save_follow_diff_state(state_path, state)
            _write_follow_diff_window_summary(
                config=config,
                budget_sec=budget_sec,
                deadline_ts=deadline_ts,
                queue_tail_id=queue_tail_id,
                state=state,
                exit_reason=WINDOW_EXIT_REASON_DEADLINE_EXCEEDED,
                exit_code=EXIT_DEADLINE_EXCEEDED,
                run_id=bounded_run_id,
                retry_failed=retry_failed,
                recovery_audit=recovery_audit,
            )
            return EXIT_DEADLINE_EXCEEDED

        batch_result = _consume_queue_entries(
            config,
            state=state,
            state_path=state_path,
            skip_sample_ids=skip_sample_ids,
            max_queue_event_id=queue_tail_id,
            prior_failed_sample_ids=failed_sample_ids,
        )
        _backfill_existing_sample_contracts(
            config,
            aggregation_key=aggregation_key,
            baseline_compare_key=baseline_compare_key,
            seed_provenance=config.seed_provenance,
        )
        _write_summary("follow-diff-window 扫描完成", batch_result.summary)
        failed_sample_ids.update(batch_result.failed_sample_ids)
        if not retry_failed:
            skip_sample_ids.update(batch_result.failed_sample_ids)

        if batch_result.summary.attempted == 0 and state.running_sample_id is None:
            idle_rounds += 1
        else:
            idle_rounds = 0

        reached_frozen_tail = queue_tail_id is None or (
            state.last_queue_event_id == queue_tail_id
        )
        if (
            reached_frozen_tail
            and state.running_sample_id is None
            and idle_rounds >= WINDOW_IDLE_CONVERGENCE_ROUNDS
        ):
            state.last_exit_reason = WINDOW_EXIT_REASON_QUIESCENT
            state.run_id = None
            _save_follow_diff_state(state_path, state)
            _write_follow_diff_window_summary(
                config=config,
                budget_sec=budget_sec,
                deadline_ts=deadline_ts,
                queue_tail_id=queue_tail_id,
                state=state,
                exit_reason=WINDOW_EXIT_REASON_QUIESCENT,
                exit_code=0,
                run_id=bounded_run_id,
                retry_failed=retry_failed,
                recovery_audit=recovery_audit,
            )
            return 0

        remaining_budget = deadline_epoch_sec - time.time()
        if remaining_budget <= 0:
            continue
        time.sleep(min(interval_sec, remaining_budget))


__all__ = [
    "FollowDiffError",
    "default_bind9_work_dir",
    "default_follow_diff_output_root",
    "default_follow_diff_source_dir",
    "default_follow_diff_work_dir",
    "follow_diff",
    "follow_diff_once",
    "follow_diff_window",
    "resolve_bind9_work_dir",
    "resolve_follow_diff_source_dir",
    "resolve_follow_diff_work_dir",
]
