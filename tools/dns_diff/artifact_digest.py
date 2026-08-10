import hashlib
from pathlib import Path
from typing import Any, Dict


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_integrity(path: Path) -> Dict[str, Any]:
    artifact_path = Path(path)
    if not artifact_path.is_file():
        return {"size_bytes": None, "sha256": None}
    return {
        "size_bytes": artifact_path.stat().st_size,
        "sha256": sha256_file(artifact_path),
    }


__all__ = ["file_integrity", "sha256_file"]
