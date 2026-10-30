import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from tools.dns_replay_support import parse_transcript

from .oracle import ORACLE_FIELDS, parse_oracle_summary

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


def _byte_identity(data: bytes) -> Dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "byte_length": len(data)}


def _freeze_file(source: Path, snapshot: Path) -> Dict[str, object]:
    try:
        data = source.read_bytes()
        with snapshot.open("xb") as handle:
            handle.write(data)
        snapshot.chmod(0o444)
    except OSError as exc:
        raise InputModelEvalError(f"冻结输入失败 {source}: {exc}") from exc
    return {
        "source_path": str(source.resolve()),
        "snapshot_path": str(snapshot.resolve()),
        **_byte_identity(data),
    }


def _transcript_identity(snapshot: Path) -> Dict[str, object]:
    try:
        query, responses, post = parse_transcript(snapshot)
    except ValueError as exc:
        return {"status": "unverified", "reason": str(exc)}
    return {
        "status": "parsed",
        "client_query": _byte_identity(query),
        "responses": [_byte_identity(response) for response in responses],
        "post_check": _byte_identity(post),
    }


def _input_relation(
    model_name: str, sample: Mapping[str, object], dst1_samples: Sequence[Mapping[str, object]]
) -> Dict[str, object]:
    relation = {
        "status": "unverified",
        "reason": "no_matching_dst1_projection",
        "conversion": "dst1.client_query"
        if model_name == "query_only" else "dst1.client_query+ordered_responses",
        "dst1_snapshot": None,
        "semantic_equivalence_claimed": False,
    }
    if model_name == "random_packet":
        relation.update(status="negative_control", reason="random_not_semantically_equivalent", conversion=None)
        return relation
    if model_name == "dst1_transcript":
        relation.update(
            status="source_transcript" if sample["transcript"]["status"] == "parsed" else "unverified",
            reason="original_dst1_input", conversion=None,
        )
        return relation
    identity = {key: sample[key] for key in ("sha256", "byte_length")}
    responses = [
        {key: response[key] for key in ("sha256", "byte_length")}
        for response in sample["response_snapshots"]
    ]
    candidates = []
    for source in dst1_samples:
        parsed = source["transcript"]
        if parsed.get("status") != "parsed" or parsed["client_query"] != identity:
            continue
        if model_name == "legacy_response_tail" and parsed["responses"] != responses:
            continue
        candidates.append(source["snapshot_path"])
    if len(candidates) == 1:
        relation.update(status="verified", reason="exact_byte_projection", dst1_snapshot=candidates[0])
    elif candidates:
        relation["reason"] = "ambiguous_dst1_match"
    return relation


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
    work_root = work_root.resolve()
    try:
        work_root.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise InputModelEvalError(f"必须使用新的样本运行目录 {work_root}: {exc}") from exc
    snapshot = _freeze_file(sample_path, work_root / "input.bin")
    transcript = _transcript_identity(Path(snapshot["snapshot_path"]))
    response_snapshots = []
    frozen_responses = None
    if response_dir is not None:
        frozen_responses = work_root / "responses"
        frozen_responses.mkdir()
        # 与 BIND tail loader 一致：只选顶层非隐藏普通文件，按文件名字节排序。
        for response in sorted(response_dir.iterdir(), key=lambda path: os.fsencode(path.name)):
            if not response.name.startswith(".") and response.is_file():
                response_snapshots.append(_freeze_file(response, frozen_responses / response.name))
    runtime_dir = work_root / "runtime"
    named_conf = runtime_dir / "named.conf"
    cache_dump = work_root / "bind9.cache.txt"
    stderr_path = work_root / "bind9.stderr"
    stdout_path = work_root / "bind9.stdout"
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
    # direct tail 优先于目录，不能让继承的环境绕过本次冻结的响应。
    for variable in (
        "NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL",
        "NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_SYMBOLIC_SUFFIX",
        "NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_PRESERVE",
    ):
        env.pop(variable, None)
    if frozen_responses is not None:
        env["NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR"] = str(frozen_responses)
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
        f"resolver-afl-symcc:{os.environ.get('BIND9_MUTATOR_ADDR', '127.0.0.1:55300')},input={snapshot['snapshot_path']}",
    ]
    meta = {
        **snapshot,
        "sample_path": snapshot["source_path"],
        "response_source_dir": str(response_dir.resolve()) if response_dir is not None else None,
        "response_snapshot_dir": str(frozen_responses) if frozen_responses is not None else None,
        "response_snapshots": response_snapshots,
        "transcript": transcript,
        "post_check_present": transcript.get("status") == "parsed"
        and transcript["post_check"]["byte_length"] > 0,
        "command": command,
        "execution_status": "prepared",
        "stderr_path": str(stderr_path),
        "stdout_path": str(stdout_path),
        "cache_dump_path": str(cache_dump),
    }
    meta_path = work_root / "sample.meta.json"
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    oracle = parse_oracle_summary(completed.stderr, "bind9")
    meta.update({
        "returncode": completed.returncode,
        "oracle": oracle,
        "execution_status": "failed"
        if completed.returncode != 0 or oracle.get("bind9.timeout") is True
        else "observed" if oracle.get("bind9.stderr_parse_status") == "ok"
        else "missing_observation",
    })
    meta_path.write_text(
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
        return "NA"
    return f"{value:.6f}"


def _model_summary(model_name: str, sample_results: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    sample_count = len(sample_results)
    fields = ("parse_ok", "resolver_fetch_started", "response_accepted", "second_query_hit")
    positives = dict.fromkeys(fields, 0)
    observed = dict.fromkeys(fields, 0)
    post_check_capable = 0
    failed_execution = 0
    missing_observation = 0
    for item in sample_results:
        oracle = item.get("oracle")
        if not isinstance(oracle, Mapping):
            oracle = {}
        capable = item.get("post_check_present") is True and oracle.get("bind9.parse_ok") is True
        post_check_capable += int(capable)
        failed_execution += int(item.get("returncode") != 0 or oracle.get("bind9.timeout") is True)
        missing_observation += int(any(
            not isinstance(oracle.get(f"bind9.{field}"), bool) for field in ORACLE_FIELDS
        ))
        for field in fields:
            if field == "second_query_hit" and not capable:
                continue
            value = oracle.get(f"bind9.{field}")
            if isinstance(value, bool):
                observed[field] += 1
                positives[field] += int(value)
    return {
        "model_name": model_name,
        "sample_count": sample_count,
        "parse_ok_count": positives["parse_ok"],
        "parse_accept_rate": _rate(positives["parse_ok"], observed["parse_ok"]),
        "resolver_fetch_started_count": positives["resolver_fetch_started"],
        "recursive_or_cache_path_rate": _rate(positives["resolver_fetch_started"], observed["resolver_fetch_started"]),
        "response_accepted_count": positives["response_accepted"],
        "response_accept_rate": _rate(positives["response_accepted"], observed["response_accepted"]),
        "post_check_capable_count": post_check_capable,
        "second_query_hit_count": positives["second_query_hit"],
        "effective_post_check_rate": _rate(positives["second_query_hit"], observed["second_query_hit"]),
        **{f"{field}_observed_count": observed[field] for field in fields},
        **{f"{field}_missing_count": (
            post_check_capable if field == "second_query_hit" else sample_count
        ) - observed[field] for field in fields},
        "failed_execution_count": failed_execution,
        "missing_observation_count": missing_observation,
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
    try:
        resolved_output_dir.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise InputModelEvalError(f"必须使用新的输出目录 {resolved_output_dir}: {exc}") from exc
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
    dst1_samples: List[Dict[str, object]] = []
    for spec in specs:
        samples = _load_samples(spec.input_path)
        if not samples:
            raise InputModelEvalError(f"输入目录为空: {spec.input_path}")
        sample_results: List[Dict[str, object]] = []
        model_root = resolved_output_dir / spec.name
        model_root.mkdir(parents=True, exist_ok=True)
        for index, sample in enumerate(samples, start=1):
            sample_root = model_root / f"sample-{index:02d}"
            result = _run_single_sample(
                bind9_tree=bind9_tree,
                named_conf_template=named_conf_template,
                work_root=sample_root,
                sample_path=sample,
                response_dir=spec.response_dir,
                seed_timeout_sec=seed_timeout_sec,
                reply_timeout_ms=reply_timeout_ms,
            )
            result["input_relation"] = _input_relation(spec.name, result, dst1_samples)
            (sample_root / "sample.meta.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            sample_results.append(result)
        if spec.name == "dst1_transcript":
            dst1_samples = sample_results
        summary = _model_summary(spec.name, sample_results)
        summaries.append(summary)
        (model_root / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    summary_path = resolved_output_dir / "summary.tsv"
    header = list(summaries[0])
    lines = ["\t".join(header)]
    for row in summaries:
        lines.append(
            "\t".join(
                [_format_rate(row[column]) if column.endswith("_rate") else str(row[column])
                 for column in header]
            )
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (resolved_output_dir / "summary.json").write_text(
        json.dumps({"rows": summaries}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if any(row["failed_execution_count"] or row["missing_observation_count"] for row in summaries):
        return EXIT_SUBPROCESS
    return 0


__all__ = ["InputModelEvalError", "run_input_model_eval"]
