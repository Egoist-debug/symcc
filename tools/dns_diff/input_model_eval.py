import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .oracle import parse_oracle_summary

EXIT_USAGE = 2
EXIT_DEPENDENCY = 3
EXIT_SUBPROCESS = 4


class InputModelEvalError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class InputModelSpec:
    name: str
    input_path: Path
    response_dir: Optional[Path]


def _collect_dot_libs(tree_root: Path) -> str:
    libs = sorted(str(path.resolve()) for path in tree_root.rglob(".libs") if path.is_dir())
    if not libs:
        raise InputModelEvalError(
            f"未找到 {tree_root} 下的 .libs 目录，请先构建", exit_code=EXIT_DEPENDENCY
        )
    return ":".join(libs)


def _load_samples(path: Path) -> List[Path]:
    candidate = Path(path).expanduser().resolve()
    if candidate.is_file():
        return [candidate]
    if candidate.is_dir():
        return sorted(sample for sample in candidate.iterdir() if sample.is_file())
    raise InputModelEvalError(f"输入路径不存在或不可读: {path}")


def _render_named_conf(template_path: Path, runtime_dir: Path, output_path: Path) -> None:
    try:
        text = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputModelEvalError(f"读取 named.conf 模板失败 {template_path}: {exc}") from exc
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        text.replace("__RUNTIME_STATE_DIR__", str(runtime_dir)),
        encoding="utf-8",
    )


def _run_single_sample(
    *,
    bind9_tree: Path,
    named_conf_template: Path,
    work_root: Path,
    sample_path: Path,
    response_dir: Optional[Path],
    seed_timeout_sec: int,
    reply_timeout_ms: int,
) -> Dict[str, object]:
    runtime_dir = work_root / "runtime"
    named_conf = runtime_dir / "named.conf"
    cache_dump = work_root / "bind9.cache.txt"
    stderr_path = work_root / "bind9.stderr"
    _render_named_conf(named_conf_template, runtime_dir, named_conf)

    bind9_binary = bind9_tree / "bin" / "named" / ".libs" / "named"
    if not bind9_binary.is_file() or not os.access(bind9_binary, os.X_OK):
        raise InputModelEvalError(
            f"缺少 bind9 可执行文件: {bind9_binary}", exit_code=EXIT_DEPENDENCY
        )

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = _collect_dot_libs(bind9_tree)
    env["NAMED_RESOLVER_AFL_SYMCC_TARGET"] = os.environ.get(
        "BIND9_TARGET_ADDR", "127.0.0.1:55301"
    )
    env["NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS"] = str(reply_timeout_ms)
    env["NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"] = str(cache_dump)
    env["NAMED_RESOLVER_AFL_SYMCC_LOG"] = "1"
    if response_dir is not None:
        env["NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR"] = str(response_dir)
    else:
        env.pop("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR", None)

    command = [
        "timeout",
        "-k",
        "2",
        str(seed_timeout_sec),
        str(bind9_binary),
        "-g",
        "-c",
        str(named_conf),
        "-A",
        f"resolver-afl-symcc:{os.environ.get('BIND9_MUTATOR_ADDR', '127.0.0.1:55300')},input={sample_path}",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=bind9_tree,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise InputModelEvalError(
            f"缺少命令: {exc.filename}", exit_code=EXIT_DEPENDENCY
        ) from exc
    except OSError as exc:
        raise InputModelEvalError(
            f"执行 bind9 输入模型探针失败: {exc}", exit_code=EXIT_SUBPROCESS
        ) from exc

    stderr_path.write_text(completed.stderr, encoding="utf-8")
    oracle = parse_oracle_summary(completed.stderr, "bind9")
    sample_bytes = sample_path.read_bytes()
    meta = {
        "sample_path": str(sample_path.resolve()),
        "sha256": hashlib.sha256(sample_bytes).hexdigest(),
        "byte_length": len(sample_bytes),
        "command": [str(c) for c in command],
        "returncode": completed.returncode,
        "oracle": oracle,
        "stderr_path": str(stderr_path),
        "cache_dump_path": str(cache_dump),
    }
    (work_root / "sample.meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return meta


def _rate(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return numerator / denominator


def _format_rate(value: Optional[float]) -> str:
    if value is None:
        return ""
    return f"{value:.6f}"


def _model_summary(model_name: str, sample_results: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    sample_count = len(sample_results)
    parse_ok = 0
    fetch_started = 0
    response_accepted = 0
    post_check_capable = 0
    second_query_hit = 0
    for item in sample_results:
        oracle = item.get("oracle")
        if not isinstance(oracle, Mapping):
            continue
        if oracle.get("bind9.parse_ok") is True:
            parse_ok += 1
        if oracle.get("bind9.resolver_fetch_started") is True:
            fetch_started += 1
        if oracle.get("bind9.response_accepted") is True:
            response_accepted += 1
        if model_name == "dst1_transcript":
            post_check_capable += 1
            if oracle.get("bind9.second_query_hit") is True:
                second_query_hit += 1
    return {
        "model_name": model_name,
        "sample_count": sample_count,
        "parse_ok_count": parse_ok,
        "parse_accept_rate": _rate(parse_ok, sample_count),
        "resolver_fetch_started_count": fetch_started,
        "recursive_or_cache_path_rate": _rate(fetch_started, sample_count),
        "response_accepted_count": response_accepted,
        "response_accept_rate": _rate(response_accepted, sample_count),
        "post_check_capable_count": post_check_capable,
        "second_query_hit_count": second_query_hit,
        "effective_post_check_rate": _rate(second_query_hit, post_check_capable),
    }


def run_input_model_eval(
    *,
    output_dir: Path,
    bind9_tree: Path,
    named_conf_template: Path,
    dst1_input: Path,
    query_only_input: Path,
    random_input: Path,
    legacy_input: Path,
    legacy_response_dir: Path,
    seed_timeout_sec: int = 5,
    reply_timeout_ms: int = 80,
) -> int:
    resolved_output_dir = Path(output_dir).expanduser().resolve()
    resolved_output_dir.mkdir(parents=True, exist_ok=True)
    bind9_tree = Path(bind9_tree).expanduser().resolve()
    named_conf_template = Path(named_conf_template).expanduser().resolve()
    legacy_response_dir = Path(legacy_response_dir).expanduser().resolve()
    if not legacy_response_dir.is_dir():
        raise InputModelEvalError(
            f"legacy response 目录不存在: {legacy_response_dir}",
            exit_code=EXIT_DEPENDENCY,
        )

    specs = [
        InputModelSpec("dst1_transcript", Path(dst1_input), None),
        InputModelSpec("query_only", Path(query_only_input), None),
        InputModelSpec("random_packet", Path(random_input), None),
        InputModelSpec("legacy_response_tail", Path(legacy_input), legacy_response_dir),
    ]

    summaries: List[Dict[str, object]] = []
    for spec in specs:
        samples = _load_samples(spec.input_path)
        sample_results: List[Dict[str, object]] = []
        model_root = resolved_output_dir / spec.name
        model_root.mkdir(parents=True, exist_ok=True)
        for index, sample in enumerate(samples, start=1):
            sample_root = model_root / f"sample-{index:02d}"
            sample_root.mkdir(parents=True, exist_ok=True)
            result = _run_single_sample(
                bind9_tree=bind9_tree,
                named_conf_template=named_conf_template,
                work_root=sample_root,
                sample_path=sample,
                response_dir=spec.response_dir,
                seed_timeout_sec=seed_timeout_sec,
                reply_timeout_ms=reply_timeout_ms,
            )
            sample_results.append(result)
        summary = _model_summary(spec.name, sample_results)
        summaries.append(summary)
        (model_root / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    summary_path = resolved_output_dir / "summary.tsv"
    header = [
        "model_name",
        "sample_count",
        "parse_ok_count",
        "parse_accept_rate",
        "resolver_fetch_started_count",
        "recursive_or_cache_path_rate",
        "response_accepted_count",
        "response_accept_rate",
        "post_check_capable_count",
        "second_query_hit_count",
        "effective_post_check_rate",
    ]
    lines = ["\t".join(header)]
    for row in summaries:
        lines.append(
            "\t".join(
                [
                    str(row["model_name"]),
                    str(row["sample_count"]),
                    str(row["parse_ok_count"]),
                    _format_rate(row["parse_accept_rate"]),
                    str(row["resolver_fetch_started_count"]),
                    _format_rate(row["recursive_or_cache_path_rate"]),
                    str(row["response_accepted_count"]),
                    _format_rate(row["response_accept_rate"]),
                    str(row["post_check_capable_count"]),
                    str(row["second_query_hit_count"]),
                    _format_rate(row["effective_post_check_rate"]),
                ]
            )
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (resolved_output_dir / "summary.json").write_text(
        json.dumps({"rows": summaries}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


__all__ = ["InputModelEvalError", "run_input_model_eval"]
