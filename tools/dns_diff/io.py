import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Union

JsonObject = Dict[str, Any]
PathLike = Union[str, os.PathLike[str], Path]


@dataclass(frozen=True)
class JsonLoadResult:
    status: str
    downgraded: bool
    data: JsonObject
    error: Optional[str] = None


def _to_path(path: PathLike) -> Path:
    return path if isinstance(path, Path) else Path(path)


def atomic_write_json(
    path: PathLike,
    payload: Mapping[str, Any],
    *,
    indent: int = 2,
    sort_keys: bool = True,
) -> Path:
    dst = _to_path(path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{dst.name}.", suffix=".tmp", dir=str(dst.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                payload, handle, ensure_ascii=False, indent=indent, sort_keys=sort_keys
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, dst)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return dst


def load_json_with_fallback(
    path: PathLike,
    *,
    fallback_factory: Callable[[], JsonObject] = dict,
) -> JsonLoadResult:
    src = _to_path(path)
    if not src.exists():
        return JsonLoadResult(
            status="missing", downgraded=True, data=fallback_factory()
        )

    try:
        loaded = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return JsonLoadResult(
            status="corrupt_fallback",
            downgraded=True,
            data=fallback_factory(),
            error=f"{exc.msg} (line {exc.lineno}, col {exc.colno})",
        )

    if not isinstance(loaded, dict):
        return JsonLoadResult(
            status="type_mismatch_fallback",
            downgraded=True,
            data=fallback_factory(),
            error=f"expect object, got {type(loaded).__name__}",
        )

    return JsonLoadResult(status="ok", downgraded=False, data=loaded)


def load_state_file(path: PathLike) -> JsonLoadResult:
    return load_json_with_fallback(path, fallback_factory=dict)


def save_state_file(path: PathLike, state: Mapping[str, Any]) -> Path:
    return atomic_write_json(path, state)
