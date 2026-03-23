import hashlib
import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .cache_diff import build_cache_diff
from .cache_parser import CacheParseError, parse_cache_dump
from .io import atomic_write_json, load_state_file, save_state_file
from .oracle import ORACLE_FIELDS
from .replay import ReplayError, replay_diff_cache
from .schema import (
    build_sample_meta_payload,
    build_state_fingerprint_payload,
    utc_timestamp,
)
from .triage import build_triage

EXIT_USAGE = 2
FOLLOW_DIFF_STATE_SCHEMA_VERSION = 1
DEFAULT_FOLLOW_DIFF_INTERVAL_SEC = 60.0
FOLLOW_DIFF_STATE_FILE_NAME = "follow_diff.state.json"

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

COMPLETED_PREFIX = "completed"

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

    def to_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "last_scan_ts": self.last_scan_ts,
            "last_queue_event_id": self.last_queue_event_id,
            "running_sample_id": self.running_sample_id,
            "completed_count": self.completed_count,
            "failed_count": self.failed_count,
        }


@dataclass(frozen=True)
class FollowDiffBatchResult:
    summary: FollowDiffSummary
    matched_sample: bool = False


def _resolve_root_dir() -> Path:
    env_root = os.environ.get("ROOT_DIR")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _collect_config() -> FollowDiffConfig:
    root_dir = _resolve_root_dir()
    work_dir = Path(
        os.environ.get(
            "WORK_DIR", str(root_dir / "unbound_experiment" / "work_stateful")
        )
    ).expanduser()
    source_dir = Path(
        os.environ.get(
            "FOLLOW_DIFF_SOURCE_DIR", str(work_dir / "afl_out" / "master" / "queue")
        )
    ).expanduser()

    if source_dir.exists() and not source_dir.is_dir():
        raise FollowDiffError(f"FOLLOW_DIFF_SOURCE_DIR 不存在或不是目录: {source_dir}")

    return FollowDiffConfig(
        work_dir=work_dir.resolve(),
        source_dir=source_dir.resolve(),
        output_root=(work_dir / "follow_diff").resolve(),
    )


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
    )


def _save_follow_diff_state(state_path: Path, state: FollowDiffState) -> Path:
    return save_state_file(state_path, state.to_payload())


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
) -> Dict[str, Any]:
    base = dict(base_payload or {})

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

    if failure is None:
        base.pop("failure", None)
    else:
        base["failure"] = dict(failure)

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
    )
    return atomic_write_json(sample_dir / "sample.meta.json", payload)


def _backfill_existing_sample_contracts(config: FollowDiffConfig) -> None:
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
        )
        if state.running_sample_id == sample_id:
            state.running_sample_id = None
            _save_follow_diff_state(state_path, state)
        return STATUS_SKIPPED

    state.running_sample_id = sample_id
    state.last_queue_event_id = queue_event_id
    _save_follow_diff_state(state_path, state)

    result = _process_one_sample(
        queue_file=queue_file,
        sample_dir=sample_dir,
        sample_id=sample_id,
        queue_event_id=queue_event_id,
        sample_sha1=sample_sha1,
        sample_size=sample_size,
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
            failure={
                "kind": "replay_error",
                "message": str(exc),
                "exit_code": exc.exit_code,
            },
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
) -> FollowDiffBatchResult:
    summary = FollowDiffSummary()
    queue_entries = _iter_queue_entries(config.source_dir)
    summary.scanned = len(queue_entries)

    last_queue_event_id = queue_entries[-1].name if queue_entries else None
    skipped_sample_ids: Set[str] = {
        sample_id for sample_id in (skip_sample_ids or ()) if sample_id
    }
    matched_sample = False

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
        if sample_id in skipped_sample_ids:
            summary.skipped += 1
            continue

        sample_dir = config.output_root / sample_id
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
            )
        else:
            result = _process_one_sample(
                queue_file=queue_file,
                sample_dir=sample_dir,
                sample_id=sample_id,
                queue_event_id=sample_info["queue_event_id"],
                sample_sha1=sample_info["sample_sha1"],
                sample_size=sample_info["sample_size"],
            )

        if result == STATUS_SKIPPED:
            summary.skipped += 1
        else:
            summary.attempted += 1
            if result == STATUS_COMPLETED:
                summary.completed += 1
            elif result == STATUS_FAILED:
                summary.failed += 1
                sys.stderr.write(f"dns-diff: 样本处理失败但继续后续样本: {sample_id}\n")

        if only_sample_id is not None:
            break

    if state is not None:
        state.last_scan_ts = utc_timestamp()
        state.last_queue_event_id = last_queue_event_id
        if state_path is None:
            raise FollowDiffError("内部错误：缺少 follow-diff 状态文件路径")
        _save_follow_diff_state(state_path, state)

    return FollowDiffBatchResult(summary=summary, matched_sample=matched_sample)


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
) -> Optional[str]:
    running_sample_id = state.running_sample_id
    if not running_sample_id:
        return None

    sample_dir = config.output_root / running_sample_id
    if _is_completed_sample(sample_dir, sample_id=running_sample_id):
        sys.stderr.write(
            f"dns-diff: 检测到上次运行中的样本已完成，清理状态后继续: {running_sample_id}\n"
        )
        state.running_sample_id = None
        _save_follow_diff_state(state_path, state)
        return None

    sys.stderr.write(
        f"dns-diff: 检测到未完成样本，启动时先恢复一次: {running_sample_id}\n"
    )
    recovery_result = _consume_queue_entries(
        config,
        state=state,
        state_path=state_path,
        only_sample_id=running_sample_id,
    )
    _write_summary("恢复扫描完成", recovery_result.summary)

    if not recovery_result.matched_sample:
        sys.stderr.write(
            f"dns-diff: queue 中未找到待恢复样本，已清理运行中状态: {running_sample_id}\n"
        )
        state.running_sample_id = None
        _save_follow_diff_state(state_path, state)
        return None

    return running_sample_id


def follow_diff() -> int:
    config = _collect_config()
    config.output_root.mkdir(parents=True, exist_ok=True)

    interval_sec = _resolve_follow_diff_interval_sec()
    state_path = _follow_diff_state_path(config)
    state = _load_follow_diff_state(state_path)
    _save_follow_diff_state(state_path, state)

    recovered_sample_id = _recover_running_sample(
        config,
        state=state,
        state_path=state_path,
    )
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
        _backfill_existing_sample_contracts(config)
        _write_summary("follow-diff 扫描完成", batch_result.summary)
        skip_sample_ids = ()
        time.sleep(interval_sec)


def follow_diff_once() -> int:
    config = _collect_config()
    config.output_root.mkdir(parents=True, exist_ok=True)

    result = _consume_queue_entries(config)
    _backfill_existing_sample_contracts(config)
    _write_summary("follow-diff-once 完成", result.summary)
    return 0


__all__ = [
    "FollowDiffError",
    "follow_diff",
    "follow_diff_once",
]
