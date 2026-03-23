import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from .io import atomic_write_json
from .oracle import parse_oracle_summary
from .schema import stamp_with_shared_meta

EXIT_USAGE = 2
EXIT_DEPENDENCY = 3
EXIT_SUBPROCESS = 4
EXIT_ARTIFACT = 5


class ReplayError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class ReplayPaths:
    root_dir: Path
    work_dir: Path
    response_corpus_dir: Path
    output_dir: Path
    sample_src: Path
    sample_bin: Path
    bind9_stderr: Path
    unbound_stderr: Path
    bind9_before_cache: Path
    bind9_after_cache: Path
    unbound_before_cache: Path
    unbound_after_cache: Path
    bind9_runtime_dir: Path
    bind9_named_conf: Path
    bind9_named_conf_template: Path
    bind9_binary: Path
    unbound_binary: Path
    bind9_afl_tree: Path
    unbound_afl_tree: Path


def _resolve_root_dir() -> Path:
    env_root = os.environ.get("ROOT_DIR")
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _parse_positive_int(env_key: str, default: int) -> int:
    raw = os.environ.get(env_key)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ReplayError(
            f"环境变量 {env_key} 必须是正整数，当前值: {raw!r}",
            exit_code=EXIT_USAGE,
        ) from exc
    if value <= 0:
        raise ReplayError(
            f"环境变量 {env_key} 必须大于 0，当前值: {raw!r}",
            exit_code=EXIT_USAGE,
        )
    return value


def _require_file(path: Path, *, message: str, exit_code: int) -> Path:
    if not path.is_file():
        raise ReplayError(message, exit_code=exit_code)
    return path


def _require_dir(path: Path, *, message: str, exit_code: int) -> Path:
    if not path.is_dir():
        raise ReplayError(message, exit_code=exit_code)
    return path


def _require_executable(path: Path, *, message: str) -> Path:
    _require_file(path, message=message, exit_code=EXIT_DEPENDENCY)
    if not os.access(path, os.X_OK):
        raise ReplayError(message, exit_code=EXIT_DEPENDENCY)
    return path


def _collect_paths(sample: str, output_dir: Optional[str]) -> ReplayPaths:
    root_dir = _resolve_root_dir()
    work_dir = Path(
        os.environ.get(
            "WORK_DIR", str(root_dir / "unbound_experiment" / "work_stateful")
        )
    ).expanduser()
    bind9_afl_tree = Path(
        os.environ.get("BIND9_AFL_TREE", str(root_dir / "bind-9.18.46-afl"))
    ).expanduser()
    unbound_afl_tree = Path(
        os.environ.get("AFL_TREE", str(root_dir / "unbound-1.24.2-afl"))
    ).expanduser()

    sample_src = Path(sample).expanduser()
    if not sample_src.is_file():
        raise ReplayError(f"样本不存在或不可读: {sample}", exit_code=EXIT_USAGE)
    sample_src = sample_src.resolve()

    if output_dir:
        out_dir = Path(output_dir).expanduser()
    else:
        out_dir = work_dir / "cache_dumps" / f"{sample_src.name}.replay_diff"
    out_dir = out_dir.resolve()

    response_corpus_dir = (
        Path(os.environ.get("RESPONSE_CORPUS_DIR", str(work_dir / "response_corpus")))
        .expanduser()
        .resolve()
    )
    bind9_named_conf_template = (
        Path(
            os.environ.get(
                "BIND9_NAMED_CONF_TEMPLATE",
                str(root_dir / "named_experiment" / "runtime" / "named.conf"),
            )
        )
        .expanduser()
        .resolve()
    )

    bind9_runtime_dir = out_dir / "bind9_runtime"
    return ReplayPaths(
        root_dir=root_dir,
        work_dir=work_dir.resolve(),
        response_corpus_dir=response_corpus_dir,
        output_dir=out_dir,
        sample_src=sample_src,
        sample_bin=out_dir / "sample.bin",
        bind9_stderr=out_dir / "bind9.stderr",
        unbound_stderr=out_dir / "unbound.stderr",
        bind9_before_cache=out_dir / "bind9.before.cache.txt",
        bind9_after_cache=out_dir / "bind9.after.cache.txt",
        unbound_before_cache=out_dir / "unbound.before.cache.txt",
        unbound_after_cache=out_dir / "unbound.after.cache.txt",
        bind9_runtime_dir=bind9_runtime_dir,
        bind9_named_conf=bind9_runtime_dir / "named.conf",
        bind9_named_conf_template=bind9_named_conf_template,
        bind9_binary=bind9_afl_tree / "bin" / "named" / ".libs" / "named",
        unbound_binary=unbound_afl_tree / ".libs" / "unbound-fuzzme",
        bind9_afl_tree=bind9_afl_tree.resolve(),
        unbound_afl_tree=unbound_afl_tree.resolve(),
    )


def _collect_dot_libs(tree_root: Path) -> str:
    if not tree_root.exists():
        raise ReplayError(f"依赖树不存在: {tree_root}", exit_code=EXIT_DEPENDENCY)
    libs: List[str] = sorted(
        str(path.resolve()) for path in tree_root.rglob(".libs") if path.is_dir()
    )
    if not libs:
        raise ReplayError(
            f"未找到 {tree_root} 下的 .libs 目录，请先构建", exit_code=EXIT_DEPENDENCY
        )
    return ":".join(libs)


def _append_stage_stderr(stderr_path: Path, *, stage: str, payload: bytes) -> None:
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stderr_path.open("ab") as handle:
        handle.write(f"\n===== {stage} =====\n".encode("utf-8"))
        if payload:
            handle.write(payload)
            if not payload.endswith(b"\n"):
                handle.write(b"\n")


def _run_stage(
    *,
    stage: str,
    command: Sequence[str],
    env: Mapping[str, str],
    stdin_file: Optional[Path],
    stderr_path: Path,
    ok_returncodes: Sequence[int],
) -> None:
    stdin_handle = None
    try:
        if stdin_file is None:
            completed = subprocess.run(
                list(command),
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
        else:
            stdin_handle = stdin_file.open("rb")
            completed = subprocess.run(
                list(command),
                env=dict(env),
                stdin=stdin_handle,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
    except FileNotFoundError as exc:
        raise ReplayError(
            f"子进程缺少可执行文件: {exc.filename}", exit_code=EXIT_DEPENDENCY
        ) from exc
    except OSError as exc:
        raise ReplayError(f"子进程执行失败: {exc}", exit_code=EXIT_SUBPROCESS) from exc
    finally:
        if stdin_handle is not None:
            stdin_handle.close()

    _append_stage_stderr(stderr_path, stage=stage, payload=completed.stderr or b"")

    if completed.returncode in ok_returncodes:
        return
    if completed.returncode in (124, 137):
        raise ReplayError(
            f"{stage} 超时，退出码={completed.returncode}", exit_code=EXIT_SUBPROCESS
        )
    raise ReplayError(
        f"{stage} 失败，退出码={completed.returncode}（详见 {stderr_path}）",
        exit_code=EXIT_SUBPROCESS,
    )


def _ensure_nonempty_file(path: Path, *, stage: str) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ReplayError(
            f"{stage} 未生成有效文件: {path}",
            exit_code=EXIT_ARTIFACT,
        )


def _prepare_bind9_conf(paths: ReplayPaths) -> None:
    _require_file(
        paths.bind9_named_conf_template,
        message=f"缺少 BIND9 配置模板: {paths.bind9_named_conf_template}",
        exit_code=EXIT_DEPENDENCY,
    )
    paths.bind9_runtime_dir.mkdir(parents=True, exist_ok=True)
    template_text = paths.bind9_named_conf_template.read_text(encoding="utf-8")
    rendered = template_text.replace(
        "__RUNTIME_STATE_DIR__", str(paths.bind9_runtime_dir)
    )
    paths.bind9_named_conf.write_text(rendered, encoding="utf-8")


def _bind9_env(paths: ReplayPaths, *, ld_library_path: str) -> Dict[str, str]:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = ld_library_path
    env["NAMED_RESOLVER_AFL_SYMCC_TARGET"] = os.environ.get(
        "BIND9_TARGET_ADDR", "127.0.0.1:55301"
    )
    env["NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR"] = str(paths.response_corpus_dir)
    env["NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS"] = os.environ.get(
        "REPLY_TIMEOUT_MS", "50"
    )
    env["NAMED_RESOLVER_AFL_SYMCC_LOG"] = "1"
    return env


def _unbound_env(paths: ReplayPaths, *, ld_library_path: str) -> Dict[str, str]:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = ld_library_path
    env["UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR"] = str(paths.response_corpus_dir)
    env["UNBOUND_RESOLVER_AFL_SYMCC_LOG"] = "1"
    return env


def _sample_sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_stderr_text(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def replay_diff_cache(sample: str, output_dir: Optional[str] = None) -> int:
    paths = _collect_paths(sample, output_dir)
    timeout_sec = _parse_positive_int("SEED_TIMEOUT_SEC", 5)

    _require_executable(
        paths.unbound_binary,
        message=f"缺少 Unbound AFL 目标或不可执行: {paths.unbound_binary}",
    )
    _require_executable(
        paths.bind9_binary,
        message=f"缺少 BIND9 named 目标或不可执行: {paths.bind9_binary}",
    )
    _require_dir(
        paths.response_corpus_dir,
        message=f"缺少 response 语料目录: {paths.response_corpus_dir}",
        exit_code=EXIT_DEPENDENCY,
    )

    unbound_ld = _collect_dot_libs(paths.unbound_afl_tree)
    bind9_ld = _collect_dot_libs(paths.bind9_afl_tree)

    paths.output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(paths.sample_src, paths.sample_bin)

    paths.unbound_stderr.unlink(missing_ok=True)
    paths.bind9_stderr.unlink(missing_ok=True)
    _prepare_bind9_conf(paths)

    unbound_env = _unbound_env(paths, ld_library_path=unbound_ld)
    bind9_env = _bind9_env(paths, ld_library_path=bind9_ld)

    timeout_prefix = ["timeout", "-k", "2", str(timeout_sec)]

    unbound_before_env = dict(unbound_env)
    unbound_before_env["UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"] = str(
        paths.unbound_before_cache
    )
    _run_stage(
        stage="unbound.before",
        command=[*timeout_prefix, str(paths.unbound_binary)],
        env=unbound_before_env,
        stdin_file=None,
        stderr_path=paths.unbound_stderr,
        ok_returncodes=(0, 1),
    )
    _ensure_nonempty_file(paths.unbound_before_cache, stage="unbound.before")

    bind9_before_env = dict(bind9_env)
    bind9_before_env["NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"] = str(
        paths.bind9_before_cache
    )
    _run_stage(
        stage="bind9.before",
        command=[
            *timeout_prefix,
            str(paths.bind9_binary),
            "-g",
            "-c",
            str(paths.bind9_named_conf),
            "-A",
            f"resolver-afl-symcc:{os.environ.get('BIND9_MUTATOR_ADDR', '127.0.0.1:55300')}",
        ],
        env=bind9_before_env,
        stdin_file=None,
        stderr_path=paths.bind9_stderr,
        ok_returncodes=(0,),
    )
    _ensure_nonempty_file(paths.bind9_before_cache, stage="bind9.before")

    unbound_after_env = dict(unbound_env)
    unbound_after_env["UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"] = str(
        paths.unbound_after_cache
    )
    _run_stage(
        stage="unbound.after",
        command=[*timeout_prefix, str(paths.unbound_binary)],
        env=unbound_after_env,
        stdin_file=paths.sample_bin,
        stderr_path=paths.unbound_stderr,
        ok_returncodes=(0, 1),
    )
    _ensure_nonempty_file(paths.unbound_after_cache, stage="unbound.after")

    bind9_after_env = dict(bind9_env)
    bind9_after_env["NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"] = str(
        paths.bind9_after_cache
    )
    _run_stage(
        stage="bind9.after",
        command=[
            *timeout_prefix,
            str(paths.bind9_binary),
            "-g",
            "-c",
            str(paths.bind9_named_conf),
            "-A",
            f"resolver-afl-symcc:{os.environ.get('BIND9_MUTATOR_ADDR', '127.0.0.1:55300')},input={paths.sample_bin}",
        ],
        env=bind9_after_env,
        stdin_file=None,
        stderr_path=paths.bind9_stderr,
        ok_returncodes=(0,),
    )
    _ensure_nonempty_file(paths.bind9_after_cache, stage="bind9.after")

    sample_sha1 = _sample_sha1(paths.sample_bin)
    meta_payload = stamp_with_shared_meta(
        {
            "sample_path": str(paths.sample_src),
            "sample_sha1": sample_sha1,
            "output_dir": str(paths.output_dir),
            "artifacts": {
                "sample_bin": "sample.bin",
                "bind9_stderr": "bind9.stderr",
                "unbound_stderr": "unbound.stderr",
                "bind9_before_cache": "bind9.before.cache.txt",
                "bind9_after_cache": "bind9.after.cache.txt",
                "unbound_before_cache": "unbound.before.cache.txt",
                "unbound_after_cache": "unbound.after.cache.txt",
                "oracle": "oracle.json",
            },
            "oracle_provenance": {
                "mode": "same_replay_after_cache",
                "bind9": {
                    "stderr": "bind9.stderr",
                    "after_cache": "bind9.after.cache.txt",
                    "stage_marker": "===== bind9.after =====",
                },
                "unbound": {
                    "stderr": "unbound.stderr",
                    "after_cache": "unbound.after.cache.txt",
                    "stage_marker": "===== unbound.after =====",
                },
            },
        },
        sample_id=f"{paths.sample_src.name}:{sample_sha1[:12]}",
    )
    atomic_write_json(paths.output_dir / "sample.meta.json", meta_payload)

    bind9_oracle = parse_oracle_summary(_load_stderr_text(paths.bind9_stderr), "bind9")
    unbound_oracle = parse_oracle_summary(
        _load_stderr_text(paths.unbound_stderr), "unbound"
    )
    oracle_payload = dict(bind9_oracle)
    oracle_payload.update(unbound_oracle)
    atomic_write_json(paths.output_dir / "oracle.json", oracle_payload)
    return 0
