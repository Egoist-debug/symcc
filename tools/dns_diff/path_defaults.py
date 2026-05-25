import json
import os
import subprocess
from pathlib import Path
from typing import Mapping, Optional, Sequence


LEGACY_BIND9_TAG = "v9.20.22"
LEGACY_UNBOUND_TAG = "release-1.24.2"
LEGACY_DNSMASQ_TAG = "v2.92"
LEGACY_SMARTDNS_TAG = "Release47.1"
LEGACY_MARADNS_TAG = "deadwood-3.3.02"
LEGACY_KNOT_RESOLVER_TAG = "v6.2.0"


def _env(environ: Optional[Mapping[str, str]] = None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def _expand_env_path(
    key: str, *, environ: Optional[Mapping[str, str]] = None
) -> Optional[Path]:
    raw_value = _env(environ).get(key, "").strip()
    if not raw_value:
        return None
    return Path(raw_value).expanduser().resolve()


def _resolve_dnslabctl_bin(root_dir: Path) -> Path:
    return (
        Path(
            os.environ.get(
                "DNSLABCTL_BIN",
                str(root_dir / "build" / "linux" / "x86_64" / "release" / "dnslabctl"),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_lock_file(root_dir: Path) -> Path:
    return (root_dir / "experiments" / "resolvers.lock.json").resolve()


def _first_existing(candidates: Sequence[Path]) -> Optional[Path]:
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def _preferred_existing_or_default(candidates: Sequence[Path]) -> Path:
    existing = _first_existing(candidates)
    if existing is not None:
        return existing
    return candidates[0].expanduser().resolve()


def resolve_locked_tag(
    root_dir: Path,
    resolver: str,
    *,
    fallback: str,
    environ: Optional[Mapping[str, str]] = None,
    tag_env_var: Optional[str] = None,
) -> str:
    if tag_env_var:
        raw_value = _env(environ).get(tag_env_var, "").strip()
        if raw_value:
            return raw_value

    dnslabctl = _resolve_dnslabctl_bin(root_dir)
    lock_file = _resolve_lock_file(root_dir)
    if dnslabctl.is_file() and os.access(dnslabctl, os.X_OK) and lock_file.is_file():
        try:
            completed = subprocess.run(
                [
                    str(dnslabctl),
                    "lock-resolved-tag",
                    "--lock-file",
                    str(lock_file),
                    "--resolver",
                    resolver,
                ],
                check=True,
                cwd=root_dir,
                capture_output=True,
                text=True,
            )
            value = completed.stdout.strip()
            if value:
                return value
        except subprocess.SubprocessError:
            pass

    if lock_file.is_file():
        try:
            payload = json.loads(lock_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        for entry in payload.get("resolvers", []):
            if entry.get("resolver") != resolver:
                continue
            value = (entry.get("resolved_tag") or entry.get("desired_tag") or "").strip()
            if value:
                return value

    return fallback


def resolve_bind9_tag(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> str:
    return resolve_locked_tag(
        root_dir,
        "bind9",
        fallback=LEGACY_BIND9_TAG,
        environ=environ,
        tag_env_var="BIND9_TAG",
    )


def resolve_unbound_tag(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> str:
    return resolve_locked_tag(
        root_dir,
        "unbound",
        fallback=LEGACY_UNBOUND_TAG,
        environ=environ,
        tag_env_var="UNBOUND_TAG",
    )


def resolve_dnsmasq_tag(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> str:
    return resolve_locked_tag(
        root_dir,
        "dnsmasq",
        fallback=LEGACY_DNSMASQ_TAG,
        environ=environ,
        tag_env_var="DNSMASQ_TAG",
    )


def resolve_smartdns_tag(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> str:
    return resolve_locked_tag(
        root_dir,
        "smartdns",
        fallback=LEGACY_SMARTDNS_TAG,
        environ=environ,
        tag_env_var="SMARTDNS_TAG",
    )


def resolve_maradns_tag(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> str:
    return resolve_locked_tag(
        root_dir,
        "maradns",
        fallback=LEGACY_MARADNS_TAG,
        environ=environ,
        tag_env_var="MARADNS_TAG",
    )


def resolve_knot_resolver_tag(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> str:
    return resolve_locked_tag(
        root_dir,
        "knot-resolver",
        fallback=LEGACY_KNOT_RESOLVER_TAG,
        environ=environ,
        tag_env_var="KNOT_RESOLVER_TAG",
    )


def resolve_bind9_source_root(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("BIND9_SRC_TREE", environ=environ)
    if env_path is not None:
        return env_path
    bind9_tag = resolve_bind9_tag(root_dir, environ=environ)
    candidates = (
        root_dir / "experiments" / "subjects" / "bind9" / bind9_tag,
        root_dir / "bind-9.18.46",
    )
    return _preferred_existing_or_default(candidates)


def resolve_bind9_afl_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("BIND9_AFL_TREE", environ=environ)
    if env_path is not None:
        return env_path
    bind9_tag = resolve_bind9_tag(root_dir, environ=environ)
    candidates = (
        root_dir
        / "experiments"
        / "subjects"
        / "bind9"
        / f"{bind9_tag}-build"
        / "bind9-afl",
        root_dir / "experiments" / "subjects" / "bind9" / f"{bind9_tag}-afl",
        root_dir / "bind-9.18.46-afl",
    )
    return _preferred_existing_or_default(candidates)


def resolve_bind9_symcc_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("BIND9_SYMCC_TREE", environ=environ)
    if env_path is not None:
        return env_path
    bind9_tag = resolve_bind9_tag(root_dir, environ=environ)
    candidates = (
        root_dir
        / "experiments"
        / "subjects"
        / "bind9"
        / f"{bind9_tag}-build"
        / "bind9-symcc",
        root_dir / "experiments" / "subjects" / "bind9" / f"{bind9_tag}-symcc",
        root_dir / "bind-9.18.46-symcc",
    )
    return _preferred_existing_or_default(candidates)


def resolve_unbound_source_root(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("UNBOUND_SRC_TREE", environ=environ)
    if env_path is not None:
        return env_path
    env_path = _expand_env_path("SRC_TREE", environ=environ)
    if env_path is not None:
        return env_path
    unbound_tag = resolve_unbound_tag(root_dir, environ=environ)
    candidates = (
        root_dir / "experiments" / "subjects" / "unbound" / unbound_tag,
        root_dir / "unbound-1.24.2",
    )
    return _preferred_existing_or_default(candidates)


def resolve_unbound_afl_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("AFL_TREE", environ=environ)
    if env_path is not None:
        return env_path
    unbound_tag = resolve_unbound_tag(root_dir, environ=environ)
    candidates = (
        root_dir
        / "experiments"
        / "subjects"
        / "unbound"
        / f"{unbound_tag}-build"
        / "unbound-afl",
        root_dir / "experiments" / "subjects" / "unbound" / f"{unbound_tag}-afl",
        root_dir / "unbound-1.24.2-afl",
    )
    return _preferred_existing_or_default(candidates)
