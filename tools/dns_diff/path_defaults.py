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
DEFAULT_FOLLOW_DIFF_WORK_DIR_RELATIVE = Path("unbound_experiment") / "work_stateful"
DEFAULT_BIND9_WORK_DIR_RELATIVE = Path("named_experiment") / "work"
DEFAULT_FOLLOW_DIFF_SOURCE_DIR_RELATIVE = (
    Path("afl_out") / "master" / "queue"
)
FOLLOW_DIFF_OUTPUT_DIR_NAME = "follow_diff"


def _env(environ: Optional[Mapping[str, str]] = None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def _expand_env_path(
    key: str, *, environ: Optional[Mapping[str, str]] = None
) -> Optional[Path]:
    raw_value = _env(environ).get(key, "").strip()
    if not raw_value:
        return None
    return Path(raw_value).expanduser().resolve()


def resolve_dnslabctl_bin(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    return (
        Path(
            _env(environ).get(
                "DNSLABCTL_BIN",
                str(root_dir / "build" / "linux" / "x86_64" / "release" / "dnslabctl"),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_lock_file(root_dir: Path) -> Path:
    return (root_dir / "experiments" / "resolvers.lock.json").resolve()


def resolve_root_dir(*, environ: Optional[Mapping[str, str]] = None) -> Path:
    env_path = _expand_env_path("ROOT_DIR", environ=environ)
    if env_path is not None:
        return env_path
    return Path(__file__).resolve().parents[2]


def default_follow_diff_work_dir(root_dir: Path) -> Path:
    return (Path(root_dir).expanduser().resolve() / DEFAULT_FOLLOW_DIFF_WORK_DIR_RELATIVE).resolve()


def resolve_follow_diff_work_dir(
    *,
    root_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    env_path = _expand_env_path("WORK_DIR", environ=environ)
    if env_path is not None:
        return env_path
    effective_root = resolve_root_dir(environ=environ) if root_dir is None else Path(root_dir)
    return default_follow_diff_work_dir(effective_root)


def default_bind9_work_dir(root_dir: Path) -> Path:
    return (Path(root_dir).expanduser().resolve() / DEFAULT_BIND9_WORK_DIR_RELATIVE).resolve()


def resolve_bind9_work_dir(
    *,
    root_dir: Optional[Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Path:
    env_path = _expand_env_path("BIND9_WORK_DIR", environ=environ)
    if env_path is not None:
        return env_path
    env_path = _expand_env_path("WORK_DIR", environ=environ)
    if env_path is not None:
        return env_path
    effective_root = resolve_root_dir(environ=environ) if root_dir is None else Path(root_dir)
    return default_bind9_work_dir(effective_root)


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
    env_path = _expand_env_path("FOLLOW_DIFF_SOURCE_DIR", environ=environ)
    if env_path is not None:
        return env_path
    if bind9_work_dir is not None:
        return default_follow_diff_source_dir(bind9_work_dir)
    return default_follow_diff_source_dir(
        resolve_bind9_work_dir(root_dir=root_dir, environ=environ)
    )


def default_follow_diff_output_root(work_dir: Path) -> Path:
    return (Path(work_dir).expanduser().resolve() / FOLLOW_DIFF_OUTPUT_DIR_NAME).resolve()


def resolve_response_corpus_dir(
    work_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("RESPONSE_CORPUS_DIR", environ=environ)
    if env_path is not None:
        return env_path
    return (Path(work_dir).expanduser().resolve() / "response_corpus").resolve()


def resolve_cache_dump_dir(work_dir: Path) -> Path:
    return (Path(work_dir).expanduser().resolve() / "cache_dumps").resolve()


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

    dnslabctl = resolve_dnslabctl_bin(root_dir, environ=environ)
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


def resolve_dnsmasq_build_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("DNSMASQ_BUILD_TREE", environ=environ)
    if env_path is not None:
        return env_path
    dnsmasq_tag = resolve_dnsmasq_tag(root_dir, environ=environ)
    return (
        root_dir / "experiments" / "subjects" / "dnsmasq" / f"{dnsmasq_tag}-build"
    ).resolve()


def resolve_smartdns_build_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("SMARTDNS_BUILD_TREE", environ=environ)
    if env_path is not None:
        return env_path
    smartdns_tag = resolve_smartdns_tag(root_dir, environ=environ)
    return (
        root_dir
        / "experiments"
        / "subjects"
        / "smartdns"
        / f"{smartdns_tag}-build"
    ).resolve()


def resolve_maradns_build_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("MARADNS_BUILD_TREE", environ=environ)
    if env_path is not None:
        return env_path
    maradns_tag = resolve_maradns_tag(root_dir, environ=environ)
    return (
        root_dir
        / "experiments"
        / "subjects"
        / "maradns"
        / f"{maradns_tag}-build"
    ).resolve()


def resolve_knot_resolver_build_tree(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    env_path = _expand_env_path("KNOT_RESOLVER_BUILD_TREE", environ=environ)
    if env_path is not None:
        return env_path
    knot_resolver_tag = resolve_knot_resolver_tag(root_dir, environ=environ)
    return (
        root_dir
        / "experiments"
        / "subjects"
        / "knot-resolver"
        / f"{knot_resolver_tag}-build"
    ).resolve()


def _first_existing_executable(candidates: Sequence[Path]) -> Optional[Path]:
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


def resolve_dnsmasq_binary(build_root: Path) -> Path:
    return (Path(build_root).expanduser().resolve() / "dnsmasq").resolve()


def resolve_smartdns_binary(build_root: Path) -> Path:
    normalized_build_root = Path(build_root).expanduser().resolve()
    return _first_existing_executable(
        (
            normalized_build_root / "src" / "smartdns",
            normalized_build_root / "smartdns-build" / "src" / "smartdns",
            normalized_build_root / "smartdns",
        )
    ) or (normalized_build_root / "src" / "smartdns")


def resolve_maradns_binary(build_root: Path) -> Path:
    normalized_build_root = Path(build_root).expanduser().resolve()
    return _first_existing_executable(
        (
            normalized_build_root
            / "deadwood-build"
            / "deadwood-github"
            / "src"
            / "Deadwood",
            normalized_build_root / "deadwood-github" / "src" / "Deadwood",
            normalized_build_root / "Deadwood",
        )
    ) or (normalized_build_root / "deadwood-github" / "src" / "Deadwood")


def resolve_knot_resolver_binary(build_root: Path) -> Path:
    return (
        Path(build_root).expanduser().resolve() / "knot-build" / "daemon" / "kresd"
    ).resolve()

def resolve_knot_library_dir(
    root_dir: Path, *, environ: Optional[Mapping[str, str]] = None
) -> Path:
    """knot-resolver 依赖的 libknot 库目录（subjects 内 knot-local/lib，可 env 覆盖）。"""
    env_path = _expand_env_path("KNOT_LIBRARY_DIR", environ=environ)
    if env_path is not None:
        return env_path
    return (
        root_dir / "experiments" / "subjects" / "knot-resolver" / "knot-local" / "lib"
    ).resolve()
