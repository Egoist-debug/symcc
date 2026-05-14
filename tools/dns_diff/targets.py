import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Sequence, Tuple, TypeVar


EXIT_USAGE = 2
EXIT_DEPENDENCY = 3
EXIT_SUBPROCESS = 4


class TargetRegistryError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class ResolverSpec:
    name: str
    aliases: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetSpec:
    name: str
    aliases: Tuple[str, ...] = ()
    fetcher: Optional[Callable[[], int]] = None
    cache_dumper: Optional[Callable[[Optional[str], Optional[str]], int]] = None


RegistrySpec = TypeVar("RegistrySpec", ResolverSpec, TargetSpec)


def _resolve_root_dir() -> Path:
    env_root = os.environ.get("ROOT_DIR")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _resolve_work_dir(root_dir: Path) -> Path:
    return (
        Path(
            os.environ.get(
                "WORK_DIR", str(root_dir / "unbound_experiment" / "work_stateful")
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_response_corpus_dir(work_dir: Path) -> Path:
    return (
        Path(os.environ.get("RESPONSE_CORPUS_DIR", str(work_dir / "response_corpus")))
        .expanduser()
        .resolve()
    )


def _resolve_cache_dump_dir(work_dir: Path) -> Path:
    return (work_dir / "cache_dumps").resolve()


def _resolve_unbound_src_tree(root_dir: Path) -> Path:
    return (
        Path(os.environ.get("SRC_TREE", str(root_dir / "unbound-1.24.2")))
        .expanduser()
        .resolve()
    )


def _resolve_unbound_afl_tree(root_dir: Path) -> Path:
    return (
        Path(os.environ.get("AFL_TREE", str(root_dir / "unbound-1.24.2-afl")))
        .expanduser()
        .resolve()
    )


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


def _resolve_dnsmasq_tag(root_dir: Path) -> str:
    raw = os.environ.get("DNSMASQ_TAG")
    if raw and raw.strip():
        return raw.strip()
    dnslabctl = _resolve_dnslabctl_bin(root_dir)
    if dnslabctl.is_file() and os.access(dnslabctl, os.X_OK):
        try:
            completed = subprocess.run(
                [str(dnslabctl), "lock-resolved-tag", "--resolver", "dnsmasq"],
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
    return "v2.92"


def _resolve_smartdns_tag(root_dir: Path) -> str:
    raw = os.environ.get("SMARTDNS_TAG")
    if raw and raw.strip():
        return raw.strip()
    dnslabctl = _resolve_dnslabctl_bin(root_dir)
    if dnslabctl.is_file() and os.access(dnslabctl, os.X_OK):
        try:
            completed = subprocess.run(
                [str(dnslabctl), "lock-resolved-tag", "--resolver", "smartdns"],
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
    return "Release47.1"


def _resolve_maradns_tag(root_dir: Path) -> str:
    raw = os.environ.get("MARADNS_TAG")
    if raw and raw.strip():
        return raw.strip()
    dnslabctl = _resolve_dnslabctl_bin(root_dir)
    if dnslabctl.is_file() and os.access(dnslabctl, os.X_OK):
        try:
            completed = subprocess.run(
                [str(dnslabctl), "lock-resolved-tag", "--resolver", "maradns"],
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
    return "deadwood-3.3.02"


def _resolve_knot_resolver_tag(root_dir: Path) -> str:
    raw = os.environ.get("KNOT_RESOLVER_TAG")
    if raw and raw.strip():
        return raw.strip()
    dnslabctl = _resolve_dnslabctl_bin(root_dir)
    if dnslabctl.is_file() and os.access(dnslabctl, os.X_OK):
        try:
            completed = subprocess.run(
                [str(dnslabctl), "lock-resolved-tag", "--resolver", "knot-resolver"],
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
    return "v6.2.0"


def _resolve_dnsmasq_src_tree(root_dir: Path) -> Path:
    default_tag = _resolve_dnsmasq_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "DNSMASQ_SRC_TREE",
                str(root_dir / "experiments" / "subjects" / "dnsmasq" / default_tag),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_dnsmasq_build_tree(root_dir: Path) -> Path:
    default_tag = _resolve_dnsmasq_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "DNSMASQ_BUILD_TREE",
                str(root_dir / "experiments" / "subjects" / "dnsmasq" / f"{default_tag}-build"),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_smartdns_src_tree(root_dir: Path) -> Path:
    default_tag = _resolve_smartdns_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "SMARTDNS_SRC_TREE",
                str(root_dir / "experiments" / "subjects" / "smartdns" / default_tag),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_smartdns_build_tree(root_dir: Path) -> Path:
    default_tag = _resolve_smartdns_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "SMARTDNS_BUILD_TREE",
                str(root_dir / "experiments" / "subjects" / "smartdns" / f"{default_tag}-build"),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_maradns_src_tree(root_dir: Path) -> Path:
    default_tag = _resolve_maradns_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "MARADNS_SRC_TREE",
                str(root_dir / "experiments" / "subjects" / "maradns" / default_tag),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_maradns_build_tree(root_dir: Path) -> Path:
    default_tag = _resolve_maradns_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "MARADNS_BUILD_TREE",
                str(root_dir / "experiments" / "subjects" / "maradns" / f"{default_tag}-build"),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_knot_resolver_src_tree(root_dir: Path) -> Path:
    default_tag = _resolve_knot_resolver_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "KNOT_RESOLVER_SRC_TREE",
                str(
                    root_dir
                    / "experiments"
                    / "subjects"
                    / "knot-resolver"
                    / default_tag
                ),
            )
        )
        .expanduser()
        .resolve()
    )


def _resolve_knot_resolver_build_tree(root_dir: Path) -> Path:
    default_tag = _resolve_knot_resolver_tag(root_dir)
    return (
        Path(
            os.environ.get(
                "KNOT_RESOLVER_BUILD_TREE",
                str(
                    root_dir
                    / "experiments"
                    / "subjects"
                    / "knot-resolver"
                    / f"{default_tag}-build"
                ),
            )
        )
        .expanduser()
        .resolve()
    )


def _parse_positive_int(env_key: str, default: int) -> int:
    raw = os.environ.get(env_key)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise TargetRegistryError(
            f"环境变量 {env_key} 必须是正整数，当前值: {raw!r}",
            exit_code=EXIT_USAGE,
        ) from exc
    if value <= 0:
        raise TargetRegistryError(
            f"环境变量 {env_key} 必须大于 0，当前值: {raw!r}",
            exit_code=EXIT_USAGE,
        )
    return value


def _collect_dot_libs(tree_root: Path) -> str:
    if not tree_root.exists():
        raise TargetRegistryError(
            f"依赖树不存在: {tree_root}", exit_code=EXIT_DEPENDENCY
        )
    libs = sorted(
        str(path.resolve()) for path in tree_root.rglob(".libs") if path.is_dir()
    )
    if not libs:
        raise TargetRegistryError(
            f"未找到 {tree_root} 下的 .libs 目录，请先构建",
            exit_code=EXIT_DEPENDENCY,
        )
    return ":".join(libs)


def _normalize_registry_key(kind: str, value: str) -> str:
    normalized = value.strip().lower()
    if normalized:
        return normalized
    raise TargetRegistryError(f"{kind} 不能为空", exit_code=EXIT_USAGE)


def _build_alias_map(
    kind: str, specs: Sequence[RegistrySpec]
) -> Dict[str, RegistrySpec]:
    alias_map: Dict[str, RegistrySpec] = {}
    for spec in specs:
        names = (spec.name, *spec.aliases)
        for raw_name in names:
            normalized = _normalize_registry_key(kind, raw_name)
            existing = alias_map.get(normalized)
            if existing is not None and existing != spec:
                raise RuntimeError(f"重复 {kind} 注册: {normalized}")
            alias_map[normalized] = spec
    return alias_map


def _registered_names(specs: Sequence[ResolverSpec | TargetSpec]) -> Tuple[str, ...]:
    return tuple(sorted(spec.name for spec in specs))


def _unknown_registry_message(kind: str, value: str, *, choices: Sequence[str]) -> str:
    registered = ", ".join(choices)
    return f"未注册 {kind}: {value!r}（已注册: {registered}）"


def _fetch_unbound_target() -> int:
    root_dir = _resolve_root_dir()
    src_tree = _resolve_unbound_src_tree(root_dir)
    clone_dir = (root_dir / src_tree.name).resolve()
    unbound_tag = os.environ.get("UNBOUND_TAG", "release-1.24.2")

    if (src_tree / ".git").is_dir():
        return 0
    if src_tree.exists():
        raise TargetRegistryError(
            f"目标路径已存在但不是 git clone 结果: {src_tree}",
            exit_code=EXIT_DEPENDENCY,
        )

    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                unbound_tag,
                "https://github.com/NLnetLabs/unbound.git",
                clone_dir.name,
            ],
            check=True,
            cwd=root_dir,
        )
    except FileNotFoundError as exc:
        raise TargetRegistryError("缺少命令: git", exit_code=EXIT_DEPENDENCY) from exc
    except subprocess.CalledProcessError as exc:
        raise TargetRegistryError(
            f"git clone 失败: rc={exc.returncode}", exit_code=EXIT_SUBPROCESS
        ) from exc
    return 0


def _run_dnslabctl_command(root_dir: Path, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    dnslabctl = _resolve_dnslabctl_bin(root_dir)
    if not dnslabctl.is_file() or not os.access(dnslabctl, os.X_OK):
        raise TargetRegistryError(
            f"缺少 dnslabctl 可执行文件: {dnslabctl}",
            exit_code=EXIT_DEPENDENCY,
        )
    try:
        return subprocess.run(
            [str(dnslabctl), *args],
            check=False,
            cwd=root_dir,
            capture_output=True,
            text=True,
            env=dict(os.environ),
        )
    except FileNotFoundError as exc:
        raise TargetRegistryError("缺少命令: dnslabctl", exit_code=EXIT_DEPENDENCY) from exc


def _fetch_dnsmasq_target() -> int:
    root_dir = _resolve_root_dir()
    completed = _run_dnslabctl_command(root_dir, ["prepare-subject", "--resolver", "dnsmasq"])
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"dnsmasq prepare-subject 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    return 0


def _fetch_smartdns_target() -> int:
    root_dir = _resolve_root_dir()
    completed = _run_dnslabctl_command(root_dir, ["prepare-subject", "--resolver", "smartdns"])
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"smartdns prepare-subject 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    return 0


def _fetch_maradns_target() -> int:
    root_dir = _resolve_root_dir()
    completed = _run_dnslabctl_command(root_dir, ["prepare-subject", "--resolver", "maradns"])
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"maradns prepare-subject 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    return 0


def _fetch_knot_resolver_target() -> int:
    root_dir = _resolve_root_dir()
    completed = _run_dnslabctl_command(root_dir, ["prepare-subject", "--resolver", "knot-resolver"])
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"knot-resolver prepare-subject 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    return 0


def _dump_maradns_cache(sample: Optional[str], output_path: Optional[str]) -> int:
    root_dir = _resolve_root_dir()
    work_dir = _resolve_work_dir(root_dir)
    cache_dump_dir = _resolve_cache_dump_dir(work_dir)
    build_root = _resolve_maradns_build_tree(root_dir)
    source_root = _resolve_maradns_src_tree(root_dir)
    runtime_root = (work_dir / "maradns_dump_runtime").resolve()

    sample_path: Optional[Path] = None
    base_name = "empty"
    if sample is not None:
        sample_path = Path(sample).expanduser().resolve()
        if not sample_path.is_file():
            raise TargetRegistryError(
                f"样本不存在或不可读: {sample}", exit_code=EXIT_USAGE
            )
        base_name = sample_path.name

    if output_path:
        output_file = Path(output_path).expanduser().resolve()
    else:
        output_file = (cache_dump_dir / f"{base_name}.maradns.cache.txt").resolve()

    cache_dump_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_root.mkdir(parents=True, exist_ok=True)

    binary = build_root / "deadwood-build" / "deadwood-github" / "src" / "Deadwood"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        build_args = [
            "adapter-build",
            "--resolver",
            "maradns",
            "--source-root",
            str(source_root),
            "--build-root",
            str(build_root),
        ]
        completed = _run_dnslabctl_command(root_dir, build_args)
        if completed.returncode != 0:
            raise TargetRegistryError(
                f"maradns adapter-build 失败: rc={completed.returncode}",
                exit_code=EXIT_SUBPROCESS,
            )

    dump_args = [
        "adapter-dump-cache",
        "--resolver",
        "maradns",
        "--source-root",
        str(source_root),
        "--build-root",
        str(build_root),
        "--run-root",
        str(runtime_root),
        "--output-file",
        str(output_file),
    ]
    if sample_path is not None:
        dump_args.extend(["--sample", str(sample_path)])
    completed = _run_dnslabctl_command(root_dir, dump_args)
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"maradns adapter-dump-cache 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    if not output_file.is_file() or output_file.stat().st_size == 0:
        raise TargetRegistryError(
            f"cache dump 为空: {output_file}", exit_code=EXIT_SUBPROCESS
        )
    return 0


def _dump_knot_resolver_cache(sample: Optional[str], output_path: Optional[str]) -> int:
    root_dir = _resolve_root_dir()
    work_dir = _resolve_work_dir(root_dir)
    cache_dump_dir = _resolve_cache_dump_dir(work_dir)
    build_root = _resolve_knot_resolver_build_tree(root_dir)
    source_root = _resolve_knot_resolver_src_tree(root_dir)
    runtime_root = (work_dir / "knot_resolver_dump_runtime").resolve()

    sample_path: Optional[Path] = None
    base_name = "empty"
    if sample is not None:
        sample_path = Path(sample).expanduser().resolve()
        if not sample_path.is_file():
            raise TargetRegistryError(
                f"样本不存在或不可读: {sample}", exit_code=EXIT_USAGE
            )
        base_name = sample_path.name

    if output_path:
        output_file = Path(output_path).expanduser().resolve()
    else:
        output_file = (cache_dump_dir / f"{base_name}.knot-resolver.cache.txt").resolve()

    cache_dump_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_root.mkdir(parents=True, exist_ok=True)

    binary = build_root / "knot-build" / "daemon" / "kresd"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        build_args = [
            "adapter-build",
            "--resolver",
            "knot-resolver",
            "--source-root",
            str(source_root),
            "--build-root",
            str(build_root),
        ]
        completed = _run_dnslabctl_command(root_dir, build_args)
        if completed.returncode != 0:
            raise TargetRegistryError(
                f"knot-resolver adapter-build 失败: rc={completed.returncode}",
                exit_code=EXIT_SUBPROCESS,
            )

    dump_args = [
        "adapter-dump-cache",
        "--resolver",
        "knot-resolver",
        "--source-root",
        str(source_root),
        "--build-root",
        str(build_root),
        "--run-root",
        str(runtime_root),
        "--output-file",
        str(output_file),
    ]
    if sample_path is not None:
        dump_args.extend(["--sample", str(sample_path)])
    completed = _run_dnslabctl_command(root_dir, dump_args)
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"knot-resolver adapter-dump-cache 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    if not output_file.is_file() or output_file.stat().st_size == 0:
        raise TargetRegistryError(
            f"cache dump 为空: {output_file}", exit_code=EXIT_SUBPROCESS
        )
    return 0


def _dump_smartdns_cache(sample: Optional[str], output_path: Optional[str]) -> int:
    root_dir = _resolve_root_dir()
    work_dir = _resolve_work_dir(root_dir)
    cache_dump_dir = _resolve_cache_dump_dir(work_dir)
    build_root = _resolve_smartdns_build_tree(root_dir)
    source_root = _resolve_smartdns_src_tree(root_dir)
    runtime_root = (work_dir / "smartdns_dump_runtime").resolve()

    sample_path: Optional[Path] = None
    base_name = "empty"
    if sample is not None:
        sample_path = Path(sample).expanduser().resolve()
        if not sample_path.is_file():
            raise TargetRegistryError(
                f"样本不存在或不可读: {sample}", exit_code=EXIT_USAGE
            )
        base_name = sample_path.name

    if output_path:
        output_file = Path(output_path).expanduser().resolve()
    else:
        output_file = (cache_dump_dir / f"{base_name}.smartdns.cache.bin").resolve()

    cache_dump_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_root.mkdir(parents=True, exist_ok=True)

    binary = build_root / "src" / "smartdns"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        build_args = [
            "adapter-build",
            "--resolver",
            "smartdns",
            "--source-root",
            str(source_root),
            "--build-root",
            str(build_root),
        ]
        completed = _run_dnslabctl_command(root_dir, build_args)
        if completed.returncode != 0:
            raise TargetRegistryError(
                f"smartdns adapter-build 失败: rc={completed.returncode}",
                exit_code=EXIT_SUBPROCESS,
            )

    dump_args = [
        "adapter-dump-cache",
        "--resolver",
        "smartdns",
        "--source-root",
        str(source_root),
        "--build-root",
        str(build_root),
        "--run-root",
        str(runtime_root),
        "--output-file",
        str(output_file),
    ]
    if sample_path is not None:
        dump_args.extend(["--sample", str(sample_path)])
    completed = _run_dnslabctl_command(root_dir, dump_args)
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"smartdns adapter-dump-cache 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    if not output_file.is_file() or output_file.stat().st_size == 0:
        raise TargetRegistryError(
            f"cache dump 为空: {output_file}", exit_code=EXIT_SUBPROCESS
        )
    return 0


def _dump_unbound_cache(sample: Optional[str], output_path: Optional[str]) -> int:
    root_dir = _resolve_root_dir()
    work_dir = _resolve_work_dir(root_dir)
    cache_dump_dir = _resolve_cache_dump_dir(work_dir)
    response_corpus_dir = _resolve_response_corpus_dir(work_dir)
    unbound_afl_tree = _resolve_unbound_afl_tree(root_dir)
    target = (unbound_afl_tree / ".libs" / "unbound-fuzzme").resolve()
    stderr_path = (work_dir / "unbound_dump_cache.stderr").resolve()
    timeout_sec = _parse_positive_int("SEED_TIMEOUT_SEC", 5)

    if not target.is_file():
        raise TargetRegistryError(
            f"缺少 Unbound AFL 目标或不可执行: {target}",
            exit_code=EXIT_DEPENDENCY,
        )
    if not os.access(target, os.X_OK):
        raise TargetRegistryError(
            f"Unbound AFL 目标不可执行: {target}", exit_code=EXIT_DEPENDENCY
        )

    sample_path: Optional[Path] = None
    base_name = "empty"
    if sample is not None:
        sample_path = Path(sample).expanduser().resolve()
        if not sample_path.is_file():
            raise TargetRegistryError(
                f"样本不存在或不可读: {sample}", exit_code=EXIT_USAGE
            )
        if not response_corpus_dir.is_dir():
            raise TargetRegistryError(
                f"缺少 response 语料目录: {response_corpus_dir}",
                exit_code=EXIT_DEPENDENCY,
            )
        base_name = sample_path.name

    if output_path:
        output_file = Path(output_path).expanduser().resolve()
    else:
        output_file = (cache_dump_dir / f"{base_name}.unbound.cache.txt").resolve()

    work_dir.mkdir(parents=True, exist_ok=True)
    cache_dump_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.unlink(missing_ok=True)
    stderr_path.unlink(missing_ok=True)

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = _collect_dot_libs(unbound_afl_tree)
    env["UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"] = str(output_file)
    env["UNBOUND_RESOLVER_AFL_SYMCC_LOG"] = "1"
    if sample_path is not None:
        env["UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR"] = str(response_corpus_dir)

    command = ["timeout", "-k", "2", str(timeout_sec), str(target)]
    try:
        with stderr_path.open("w", encoding="utf-8") as stderr_handle:
            if sample_path is None:
                completed = subprocess.run(
                    command,
                    check=False,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_handle,
                )
            else:
                with sample_path.open("rb") as sample_handle:
                    completed = subprocess.run(
                        command,
                        check=False,
                        env=env,
                        stdin=sample_handle,
                        stdout=subprocess.DEVNULL,
                        stderr=stderr_handle,
                    )
    except FileNotFoundError as exc:
        missing = exc.filename or command[0]
        raise TargetRegistryError(
            f"缺少命令或目标: {missing}", exit_code=EXIT_DEPENDENCY
        ) from exc

    if completed.returncode in (0, 1):
        pass
    elif completed.returncode in (124, 137):
        raise TargetRegistryError(
            f"dump-cache 超时: rc={completed.returncode}", exit_code=EXIT_SUBPROCESS
        )
    else:
        raise TargetRegistryError(
            f"dump-cache 异常退出: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )

    if not output_file.is_file() or output_file.stat().st_size == 0:
        raise TargetRegistryError(
            f"cache dump 为空，stderr: {stderr_path}", exit_code=EXIT_SUBPROCESS
        )
    return 0


def _dump_dnsmasq_cache(sample: Optional[str], output_path: Optional[str]) -> int:
    root_dir = _resolve_root_dir()
    work_dir = _resolve_work_dir(root_dir)
    cache_dump_dir = _resolve_cache_dump_dir(work_dir)
    build_root = _resolve_dnsmasq_build_tree(root_dir)
    source_root = _resolve_dnsmasq_src_tree(root_dir)
    runtime_root = (work_dir / "dnsmasq_dump_runtime").resolve()

    sample_path: Optional[Path] = None
    base_name = "empty"
    if sample is not None:
        sample_path = Path(sample).expanduser().resolve()
        if not sample_path.is_file():
            raise TargetRegistryError(
                f"样本不存在或不可读: {sample}", exit_code=EXIT_USAGE
            )
        base_name = sample_path.name

    if output_path:
        output_file = Path(output_path).expanduser().resolve()
    else:
        output_file = (cache_dump_dir / f"{base_name}.dnsmasq.cache.txt").resolve()

    cache_dump_dir.mkdir(parents=True, exist_ok=True)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_root.mkdir(parents=True, exist_ok=True)

    binary = build_root / "dnsmasq"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        build_args = [
            "adapter-build",
            "--resolver",
            "dnsmasq",
            "--source-root",
            str(source_root),
            "--build-root",
            str(build_root),
        ]
        completed = _run_dnslabctl_command(root_dir, build_args)
        if completed.returncode != 0:
            raise TargetRegistryError(
                f"dnsmasq adapter-build 失败: rc={completed.returncode}",
                exit_code=EXIT_SUBPROCESS,
            )

    dump_args = [
        "adapter-dump-cache",
        "--resolver",
        "dnsmasq",
        "--source-root",
        str(source_root),
        "--build-root",
        str(build_root),
        "--run-root",
        str(runtime_root),
        "--output-file",
        str(output_file),
    ]
    if sample_path is not None:
        dump_args.extend(["--sample", str(sample_path)])
    completed = _run_dnslabctl_command(root_dir, dump_args)
    if completed.returncode != 0:
        raise TargetRegistryError(
            f"dnsmasq adapter-dump-cache 失败: rc={completed.returncode}",
            exit_code=EXIT_SUBPROCESS,
        )
    if not output_file.is_file() or output_file.stat().st_size == 0:
        raise TargetRegistryError(
            f"cache dump 为空: {output_file}", exit_code=EXIT_SUBPROCESS
        )
    return 0


_RESOLVER_SPECS: Tuple[ResolverSpec, ...] = (
    ResolverSpec(name="bind9", aliases=("named",)),
    ResolverSpec(name="maradns"),
    ResolverSpec(name="smartdns"),
    ResolverSpec(name="knot-resolver", aliases=("kresd",)),
    ResolverSpec(name="unbound"),
    ResolverSpec(name="dnsmasq"),
)

_TARGET_SPECS: Tuple[TargetSpec, ...] = (
    TargetSpec(
        name="dnsmasq",
        aliases=("dnsmasq-replay",),
        fetcher=_fetch_dnsmasq_target,
        cache_dumper=_dump_dnsmasq_cache,
    ),
    TargetSpec(
        name="smartdns",
        aliases=("smartdns-resolver",),
        fetcher=_fetch_smartdns_target,
        cache_dumper=_dump_smartdns_cache,
    ),
    TargetSpec(
        name="maradns",
        aliases=("deadwood",),
        fetcher=_fetch_maradns_target,
        cache_dumper=_dump_maradns_cache,
    ),
    TargetSpec(
        name="knot-resolver",
        aliases=("kresd",),
        fetcher=_fetch_knot_resolver_target,
        cache_dumper=_dump_knot_resolver_cache,
    ),
    TargetSpec(
        name="unbound",
        aliases=("unbound-fuzzme",),
        fetcher=_fetch_unbound_target,
        cache_dumper=_dump_unbound_cache,
    ),
)

_RESOLVER_ALIAS_MAP: Dict[str, ResolverSpec] = _build_alias_map(
    "resolver", _RESOLVER_SPECS
)
_TARGET_ALIAS_MAP: Dict[str, TargetSpec] = _build_alias_map("target", _TARGET_SPECS)


def registered_resolver_names() -> Tuple[str, ...]:
    return _registered_names(_RESOLVER_SPECS)


def registered_target_names() -> Tuple[str, ...]:
    return _registered_names(_TARGET_SPECS)


def resolve_cache_resolver(value: str) -> str:
    normalized = _normalize_registry_key("resolver", value)
    spec = _RESOLVER_ALIAS_MAP.get(normalized)
    if spec is None:
        raise TargetRegistryError(
            _unknown_registry_message(
                "resolver", value, choices=registered_resolver_names()
            ),
            exit_code=EXIT_USAGE,
        )
    return spec.name


def _resolve_target_spec(value: str) -> TargetSpec:
    normalized = _normalize_registry_key("target", value)
    spec = _TARGET_ALIAS_MAP.get(normalized)
    if spec is None:
        raise TargetRegistryError(
            _unknown_registry_message(
                "target", value, choices=registered_target_names()
            ),
            exit_code=EXIT_USAGE,
        )
    return spec


def fetch_target(target: str) -> int:
    spec = _resolve_target_spec(target)
    if spec.fetcher is None:
        raise TargetRegistryError(
            f"target {spec.name!r} 未注册 fetch 行为", exit_code=EXIT_USAGE
        )
    return int(spec.fetcher())


def dump_cache(target: str, sample: Optional[str], output_path: Optional[str]) -> int:
    spec = _resolve_target_spec(target)
    if spec.cache_dumper is None:
        raise TargetRegistryError(
            f"target {spec.name!r} 未注册 dump-cache 行为", exit_code=EXIT_USAGE
        )
    return int(spec.cache_dumper(sample, output_path))
