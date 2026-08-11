import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from .aggregate import CampaignAggregateError, run_campaign_aggregate
from .campaign import CampaignReportError, generate_campaign_report
from .case_study import CaseStudyError, export_case_studies
from .cache_parser import CacheParseError, write_cache_tsv
from .close_loop import CampaignCloseError, run_campaign_close
from .follow_diff import (
    FollowDiffError,
    follow_diff,
    follow_diff_once,
    follow_diff_window,
)
from .input_model_eval import InputModelEvalError, run_input_model_eval
from .matrix import CampaignMatrixError, run_campaign_matrix
from .publication_audit import (
    MINIMUM_PUBLICATION_CASE_STUDIES,
    MINIMUM_PUBLICATION_RUNS,
    PublicationAuditError,
    run_publication_audit,
)
from .report import ReportError, default_follow_diff_root, generate_report
from .replay import ReplayError, replay_diff_cache
from .rq3_snapshot import RQ3SnapshotError, run_rq3_snapshot
from .resolver_backend_matrix_compare import (
    ResolverBackendMatrixCompareError,
    run_resolver_backend_matrix_compare,
)
from .resolver_capability_report import (
    ResolverCapabilityReportError,
    run_resolver_capability_report,
)
from .resolver_matrix_aggregate import (
    ResolverMatrixAggregateError,
    run_resolver_matrix_aggregate,
)
from .targets import (
    TargetRegistryError,
    dump_cache,
    fetch_target,
    registered_resolver_names,
    registered_target_names,
    resolve_cache_resolver,
)
from .triage import TriageError, rewrite_triage_root


class DnslabctlForwardError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        exit_code: int,
        stdout_text: str = "",
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout_text = stdout_text


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_dnslabctl_bin() -> Path:
    explicit = os.environ.get("DNSLABCTL_BIN", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    return (_repo_root() / "build/linux/x86_64/release/dnslabctl").resolve()


def _resolve_cli_backend() -> str:
    raw = os.environ.get("DNS_DIFF_CLI_BACKEND", "").strip().lower()
    if not raw:
        return ""
    if raw in {"python", "dnslabctl"}:
        return raw
    raise RuntimeError(
        f"DNS_DIFF_CLI_BACKEND 只能是 python/dnslabctl，当前值: {raw!r}"
    )


def _use_dnslabctl_backend(*, default: bool = False) -> bool:
    backend = _resolve_cli_backend()
    if not backend:
        return default
    return backend == "dnslabctl"


def _run_dnslabctl(command: Sequence[str]) -> int:
    dnslabctl_bin = _resolve_dnslabctl_bin()
    if not dnslabctl_bin.is_file():
        raise RuntimeError(f"缺少 dnslabctl 可执行文件: {dnslabctl_bin}")

    def _decode_output(raw: bytes) -> str:
        if not raw:
            return ""
        return raw.decode("utf-8", errors="replace")

    completed = subprocess.run(
        [str(dnslabctl_bin), *command],
        cwd=_repo_root(),
        capture_output=True,
        env=dict(os.environ),
        check=False,
    )
    stdout_text = _decode_output(completed.stdout)
    stderr_text = _decode_output(completed.stderr)
    if completed.returncode == 0:
        if stdout_text:
            sys.stdout.write(stdout_text)
        if stderr_text:
            sys.stderr.write(stderr_text)
        return 0

    message = stderr_text.strip() or stdout_text.strip() or (
        f"dnslabctl 返回 {completed.returncode}"
    )
    raise DnslabctlForwardError(
        message,
        exit_code=int(completed.returncode),
        stdout_text=stdout_text,
    )


def _write_forward_failure_stdout(exc: BaseException) -> None:
    stdout_text = getattr(exc, "stdout_text", "")
    if isinstance(stdout_text, str) and stdout_text:
        sys.stdout.write(stdout_text)


def _target_help() -> str:
    registered = ", ".join(registered_target_names())
    return f"目标名（已注册: {registered}；默认: unbound）"


def _resolver_help() -> str:
    registered = ", ".join(registered_resolver_names())
    return f"resolver 类型（已注册: {registered}）"


def _cmd_fetch(args: argparse.Namespace) -> int:
    try:
        return fetch_target(args.target)
    except TargetRegistryError as exc:
        sys.stderr.write(f"dns-diff: fetch 失败: {exc}\n")
        return exc.exit_code


def _cmd_dump_cache(args: argparse.Namespace) -> int:
    try:
        return dump_cache(args.target, args.sample, args.output_file)
    except TargetRegistryError as exc:
        sys.stderr.write(f"dns-diff: dump-cache 失败: {exc}\n")
        return exc.exit_code


def _cmd_follow_diff(_: argparse.Namespace) -> int:
    try:
        return follow_diff()
    except FollowDiffError as exc:
        sys.stderr.write(f"dns-diff: follow-diff 失败: {exc}\n")
        return exc.exit_code


def _cmd_follow_diff_once(_: argparse.Namespace) -> int:
    try:
        if _use_dnslabctl_backend(default=True):
            return _run_dnslabctl(["follow-diff-once"])
        return follow_diff_once()
    except (FollowDiffError, DnslabctlForwardError, RuntimeError) as exc:
        _write_forward_failure_stdout(exc)
        sys.stderr.write(f"dns-diff: follow-diff-once 失败: {exc}\n")
        return getattr(exc, "exit_code", 2)


def _cmd_follow_diff_window(args: argparse.Namespace) -> int:
    try:
        if _use_dnslabctl_backend(default=True):
            command = ["follow-diff-window", "--budget-sec", str(args.budget_sec)]
            if args.retry_failed:
                command.append("--retry-failed")
            if args.queue_tail_id:
                command.extend(["--queue-tail-id", args.queue_tail_id])
            return _run_dnslabctl(command)
        return follow_diff_window(
            budget_sec=args.budget_sec,
            queue_tail_id=args.queue_tail_id,
            retry_failed=bool(args.retry_failed),
        )
    except (FollowDiffError, DnslabctlForwardError, RuntimeError) as exc:
        _write_forward_failure_stdout(exc)
        sys.stderr.write(f"dns-diff: follow-diff-window 失败: {exc}\n")
        return getattr(exc, "exit_code", 2)


def _cmd_input_model_eval(args: argparse.Namespace) -> int:
    try:
        return run_input_model_eval(
            output_dir=Path(args.output_dir),
            bind9_tree=Path(args.bind9_tree),
            named_conf_template=Path(args.named_conf_template),
            dst1_input=Path(args.dst1_input),
            query_only_input=Path(args.query_only_input),
            random_input=Path(args.random_input),
            legacy_input=Path(args.legacy_input),
            legacy_response_dir=Path(args.legacy_response_dir),
            seed_timeout_sec=args.seed_timeout_sec,
            reply_timeout_ms=args.reply_timeout_ms,
        )
    except InputModelEvalError as exc:
        sys.stderr.write(f"dns-diff: input-model-eval 失败: {exc}\n")
        return exc.exit_code


def _cmd_parse_cache(args: argparse.Namespace) -> int:
    try:
        resolver = resolve_cache_resolver(args.resolver)
        write_cache_tsv(resolver, args.dump_file, args.output_file)
        return 0
    except (CacheParseError, TargetRegistryError) as exc:
        sys.stderr.write(f"dns-diff: parse-cache 失败: {exc}\n")
        return exc.exit_code


def _cmd_replay_diff_cache(args: argparse.Namespace) -> int:
    try:
        return replay_diff_cache(args.sample, args.output_dir)
    except ReplayError as exc:
        sys.stderr.write(f"dns-diff: replay-diff-cache 失败: {exc}\n")
        return exc.exit_code


def _cmd_triage(args: argparse.Namespace) -> int:
    if not args.rewrite:
        sys.stderr.write("dns-diff: triage 当前仅实现 --rewrite 离线重写模式\n")
        return 2

    try:
        return rewrite_triage_root(args.root)
    except TriageError as exc:
        sys.stderr.write(f"dns-diff: triage 失败: {exc}\n")
        return exc.exit_code


def _cmd_triage_report(_: argparse.Namespace) -> int:
    root = default_follow_diff_root()
    root.mkdir(parents=True, exist_ok=True)
    try:
        rewrite_code = rewrite_triage_root(root)
        if rewrite_code != 0:
            return rewrite_code
        return generate_report(root)
    except TriageError as exc:
        sys.stderr.write(f"dns-diff: triage-report triage 阶段失败: {exc}\n")
        return exc.exit_code
    except ReportError as exc:
        sys.stderr.write(f"dns-diff: triage-report report 阶段失败: {exc}\n")
        return exc.exit_code


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        if _use_dnslabctl_backend(default=True):
            command = ["report", "--root", str(args.root)]
            if args.high_value_manifest:
                command.extend(
                    ["--high-value-manifest", str(args.high_value_manifest)]
                )
            return _run_dnslabctl(command)
        return generate_report(args.root)
    except (ReportError, DnslabctlForwardError, RuntimeError) as exc:
        _write_forward_failure_stdout(exc)
        sys.stderr.write(f"dns-diff: report 失败: {exc}\n")
        return getattr(exc, "exit_code", 2)


def _cmd_rq3_snapshot(args: argparse.Namespace) -> int:
    try:
        return run_rq3_snapshot(
            resolver_variant_summary_tsv=Path(args.resolver_variant_summary_tsv),
            output_dir=Path(args.output_dir),
        )
    except RQ3SnapshotError as exc:
        sys.stderr.write(f"dns-diff: rq3-snapshot 失败: {exc}\n")
        return exc.exit_code


def _cmd_campaign_report(args: argparse.Namespace) -> int:
    root = Path(args.root) if args.root else default_follow_diff_root()
    try:
        if _use_dnslabctl_backend(default=True):
            command = ["campaign-report", "--root", str(root)]
            if args.output_dir:
                command.extend(["--output-dir", str(args.output_dir)])
            return _run_dnslabctl(command)
        if args.output_dir:
            raise RuntimeError("Python backend 暂不支持 --output-dir")
        return generate_campaign_report(root, is_custom_root=bool(args.root))
    except (ReportError, DnslabctlForwardError, RuntimeError) as exc:
        _write_forward_failure_stdout(exc)
        sys.stderr.write(f"dns-diff: campaign-report 失败: {exc}\n")
        return getattr(exc, "exit_code", 2)
    except CampaignReportError as exc:
        sys.stderr.write(f"dns-diff: campaign-report 失败: {exc}\n")
        return exc.exit_code


def _cmd_case_study_export(args: argparse.Namespace) -> int:
    try:
        if _use_dnslabctl_backend(default=True):
            command = [
                "case-study-export",
                "--root",
                str(args.root),
                "--campaign-report-dir",
                str(args.campaign_report_dir),
            ]
            if args.top_n != 5:
                command.extend(["--top-n", str(args.top_n)])
            return _run_dnslabctl(command)
        return export_case_studies(
            Path(args.root),
            Path(args.campaign_report_dir),
            top_n=args.top_n,
        )
    except (CaseStudyError, DnslabctlForwardError, RuntimeError) as exc:
        _write_forward_failure_stdout(exc)
        sys.stderr.write(f"dns-diff: case-study-export 失败: {exc}\n")
        return getattr(exc, "exit_code", 2)


def _cmd_campaign_close(args: argparse.Namespace) -> int:
    try:
        if _use_dnslabctl_backend(default=True):
            return _run_dnslabctl(
                ["campaign-close", "--budget-sec", str(args.budget_sec)]
            )
        return run_campaign_close(budget_sec=args.budget_sec)
    except (CampaignCloseError, DnslabctlForwardError, RuntimeError) as exc:
        _write_forward_failure_stdout(exc)
        sys.stderr.write(f"dns-diff: campaign-close 失败: {exc}\n")
        return getattr(exc, "exit_code", 2)


def _cmd_campaign_aggregate(args: argparse.Namespace) -> int:
    try:
        return run_campaign_aggregate(
            reports_root=Path(args.reports_root),
            output_dir=Path(args.output_dir) if args.output_dir else None,
        )
    except CampaignAggregateError as exc:
        sys.stderr.write(f"dns-diff: campaign-aggregate 失败: {exc}\n")
        return exc.exit_code


def _cmd_campaign_matrix(args: argparse.Namespace) -> int:
    try:
        return run_campaign_matrix(
            matrix_file=Path(args.matrix_file),
            budget_sec=args.budget_sec,
            repeat=args.repeat,
            work_root=Path(args.work_root),
        )
    except CampaignMatrixError as exc:
        sys.stderr.write(f"dns-diff: campaign-matrix 失败: {exc}\n")
        return exc.exit_code


def _cmd_resolver_matrix_aggregate(args: argparse.Namespace) -> int:
    try:
        return run_resolver_matrix_aggregate(
            matrix_roots=[Path(path) for path in args.matrix_root],
            output_dir=Path(args.output_dir) if args.output_dir else None,
        )
    except ResolverMatrixAggregateError as exc:
        sys.stderr.write(f"dns-diff: resolver-matrix-aggregate 失败: {exc}\n")
        return exc.exit_code


def _cmd_resolver_capability_report(args: argparse.Namespace) -> int:
    try:
        return run_resolver_capability_report(
            replay_matrix_dir=Path(args.replay_matrix_dir),
            matrix_batch_dir=Path(args.matrix_batch_dir),
            output_dir=Path(args.output_dir) if args.output_dir else None,
        )
    except ResolverCapabilityReportError as exc:
        sys.stderr.write(f"dns-diff: resolver-capability-report 失败: {exc}\n")
        return exc.exit_code


def _cmd_resolver_backend_matrix_compare(args: argparse.Namespace) -> int:
    try:
        return run_resolver_backend_matrix_compare(
            baseline_batch_dir=Path(args.baseline_batch_dir),
            candidate_batch_dir=Path(args.candidate_batch_dir),
            baseline_label=args.baseline_label,
            candidate_label=args.candidate_label,
            output_dir=Path(args.output_dir) if args.output_dir else None,
        )
    except ResolverBackendMatrixCompareError as exc:
        sys.stderr.write(f"dns-diff: resolver-backend-matrix-compare 失败: {exc}\n")
        return exc.exit_code


def _cmd_publication_audit(args: argparse.Namespace) -> int:
    try:
        return run_publication_audit(
            matrix_roots=[Path(path) for path in args.matrix_root],
            output_dir=Path(args.output_dir) if args.output_dir else None,
            minimum_runs=args.minimum_runs,
            minimum_case_studies=args.minimum_case_studies,
        )
    except PublicationAuditError as exc:
        sys.stderr.write(f"dns-diff: publication-audit 失败: {exc}\n")
        return exc.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.dns_diff.cli",
        description=(
            "dns-diff Python 真入口；target/resolver 选择统一走 registry，"
            "thin wrapper 只做兼容转发与环境注入。"
            "默认优先由 dnslabctl 处理 follow-diff-once/window、report、"
            "campaign-report、case-study-export、campaign-close。"
            "设置 DNS_DIFF_CLI_BACKEND=python/dnslabctl 可显式覆盖。"
        ),
    )
    if hasattr(parser, "suggest_on_error"):
        setattr(parser, "suggest_on_error", True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch = subparsers.add_parser("fetch", help="拉取实验目标源码树")
    fetch.add_argument("--target", default="unbound", help=_target_help())
    fetch.set_defaults(handler=_cmd_fetch)

    dump_cache_parser = subparsers.add_parser(
        "dump-cache", help="直接调用目标并导出 cache dump"
    )
    dump_cache_parser.add_argument("--target", default="unbound", help=_target_help())
    dump_cache_parser.add_argument("sample", nargs="?", help="可选输入样本路径")
    dump_cache_parser.add_argument("output_file", nargs="?", help="可选输出文件路径")
    dump_cache_parser.set_defaults(handler=_cmd_dump_cache)

    follow_diff = subparsers.add_parser("follow-diff", help="跟随 queue 进行差分消费")
    follow_diff.set_defaults(handler=_cmd_follow_diff)

    follow_diff_once = subparsers.add_parser(
        "follow-diff-once", help="执行一次 queue 差分消费"
    )
    follow_diff_once.set_defaults(handler=_cmd_follow_diff_once)

    follow_diff_window = subparsers.add_parser(
        "follow-diff-window",
        help="有界消费 queue，冻结启动 tail 并在预算内收敛退出",
    )
    follow_diff_window.add_argument(
        "--budget-sec",
        type=float,
        required=True,
        help="bounded 消费预算秒数（>0）",
    )
    follow_diff_window.add_argument(
        "--retry-failed",
        action="store_true",
        help="显式允许在同一 bounded run 内重试 failed 样本（默认关闭）",
    )
    follow_diff_window.add_argument(
        "--queue-tail-id",
        help="可选冻结 tail queue id；默认在启动时自动探测",
    )
    follow_diff_window.set_defaults(handler=_cmd_follow_diff_window)

    input_model_eval = subparsers.add_parser(
        "input-model-eval",
        help="对比 DST1/query-only/random/legacy-response-tail 的输入有效性指标",
    )
    input_model_eval.add_argument("--output-dir", required=True, help="输出目录")
    input_model_eval.add_argument(
        "--bind9-tree",
        required=True,
        help="bind9 AFL 构建树，需包含 bin/named/.libs/named",
    )
    input_model_eval.add_argument(
        "--named-conf-template",
        required=True,
        help="named.conf 模板路径",
    )
    input_model_eval.add_argument("--dst1-input", required=True, help="DST1 transcript 文件或目录")
    input_model_eval.add_argument("--query-only-input", required=True, help="query-only 文件或目录")
    input_model_eval.add_argument("--random-input", required=True, help="random packet 文件或目录")
    input_model_eval.add_argument("--legacy-input", required=True, help="legacy-response-tail 使用的 query 文件或目录")
    input_model_eval.add_argument(
        "--legacy-response-dir",
        required=True,
        help="legacy-response-tail 使用的 response 目录",
    )
    input_model_eval.add_argument(
        "--seed-timeout-sec",
        type=int,
        default=5,
        help="单样本运行超时秒数",
    )
    input_model_eval.add_argument(
        "--reply-timeout-ms",
        type=int,
        default=80,
        help="reply timeout 毫秒数",
    )
    input_model_eval.set_defaults(handler=_cmd_input_model_eval)

    parse_cache = subparsers.add_parser("parse-cache", help="解析 resolver cache dump")
    parse_cache.add_argument("resolver", help=_resolver_help())
    parse_cache.add_argument("dump_file", help="cache dump 文件路径")
    parse_cache.add_argument("output_file", nargs="?", help="可选输出文件路径")
    parse_cache.set_defaults(handler=_cmd_parse_cache)

    replay_diff_cache = subparsers.add_parser(
        "replay-diff-cache", help="执行 paired replay/cache 对比"
    )
    replay_diff_cache.add_argument("sample", help="输入样本路径")
    replay_diff_cache.add_argument("output_dir", nargs="?", help="可选输出目录")
    replay_diff_cache.set_defaults(handler=_cmd_replay_diff_cache)

    triage = subparsers.add_parser("triage", help="离线重写 triage 标签与 cluster key")
    triage.add_argument("--root", required=True, help="follow_diff 根目录")
    triage.add_argument(
        "--rewrite",
        action="store_true",
        help="扫描根目录并重写 triage.json 的 filter_labels 与 cluster_key",
    )
    triage.set_defaults(handler=_cmd_triage)

    triage_report = subparsers.add_parser("triage-report", help="汇总 triage 结果")
    triage_report.set_defaults(handler=_cmd_triage_report)

    report = subparsers.add_parser("report", help="离线汇总 triage 报告产物")
    report.add_argument("--root", required=True, help="follow_diff 根目录")
    report.add_argument(
        "--high-value-manifest",
        help="可选高价值样本文本清单输出路径",
    )
    report.set_defaults(handler=_cmd_report)

    rq3_snapshot = subparsers.add_parser(
        "rq3-snapshot",
        help="从 resolver_variant_summary.tsv 导出 RQ3 Hybrid 增益快照",
    )
    rq3_snapshot.add_argument(
        "--resolver-variant-summary-tsv",
        required=True,
        help="resolver_variant_summary.tsv 路径",
    )
    rq3_snapshot.add_argument(
        "--output-dir",
        required=True,
        help="输出目录",
    )
    rq3_snapshot.set_defaults(handler=_cmd_rq3_snapshot)

    campaign_report = subparsers.add_parser(
        "campaign-report", help="汇总 campaign 指标"
    )
    campaign_report.add_argument("--root", help="可选 follow_diff 根目录")
    campaign_report.add_argument(
        "--output-dir",
        help="可选输出根目录；dnslabctl backend 下写入 <output-dir>/<timestamp>/",
    )
    campaign_report.set_defaults(handler=_cmd_campaign_report)

    case_study_export = subparsers.add_parser(
        "case-study-export",
        help="导出 case study 与 manual truth 附属证据包",
    )
    case_study_export.add_argument("--root", required=True, help="follow_diff 根目录")
    case_study_export.add_argument(
        "--campaign-report-dir",
        required=True,
        help="campaign report 目录；默认输出写入 <campaign-report-dir>/case_studies",
    )
    case_study_export.add_argument(
        "--top-n",
        type=int,
        default=5,
        help="最多导出前 N 个候选（固定上限 5，默认 5）",
    )
    case_study_export.set_defaults(handler=_cmd_case_study_export)

    campaign_close = subparsers.add_parser(
        "campaign-close",
        help="单进程闭环执行 follow-diff-window -> triage-report -> campaign-report",
    )
    campaign_close.add_argument(
        "--budget-sec",
        type=float,
        required=True,
        help="全链路闭环预算秒数（>0），由 campaign-close 统一持有 deadline",
    )
    campaign_close.set_defaults(handler=_cmd_campaign_close)

    campaign_aggregate = subparsers.add_parser(
        "campaign-aggregate",
        help="多轮 campaign 报告聚合与方差统计",
    )
    campaign_aggregate.add_argument(
        "--reports-root",
        required=True,
        help="campaign_reports 根目录（仅读取 */summary.json）",
    )
    campaign_aggregate.add_argument(
        "--output-dir",
        help="可选输出根目录；实际写入 <output-dir>/campaign_aggregates/<ts>/",
    )
    campaign_aggregate.set_defaults(handler=_cmd_campaign_aggregate)

    campaign_matrix = subparsers.add_parser(
        "campaign-matrix",
        help="固定 poison-stateful baseline/ablation 矩阵 runner",
    )
    campaign_matrix.add_argument(
        "--matrix-file",
        required=True,
        help="矩阵配置 JSON（固定 4 变体 poison-stateful 合约）",
    )
    campaign_matrix.add_argument(
        "--budget-sec",
        type=float,
        required=True,
        help="单 run campaign-close 预算秒数（>0）",
    )
    campaign_matrix.add_argument(
        "--repeat",
        type=int,
        required=True,
        help="每个 variant 串行重复次数（>0）",
    )
    campaign_matrix.add_argument(
        "--work-root",
        required=True,
        help="矩阵工作根目录；输出写入 matrix_runs/ 与 _summary/",
    )
    campaign_matrix.set_defaults(handler=_cmd_campaign_matrix)

    resolver_matrix_aggregate = subparsers.add_parser(
        "resolver-matrix-aggregate",
        help="汇总多个 resolver campaign-matrix 输出为统一对比表",
    )
    resolver_matrix_aggregate.add_argument(
        "--matrix-root",
        action="append",
        required=True,
        help="单个 resolver 的 campaign-matrix work root，可重复传入",
    )
    resolver_matrix_aggregate.add_argument(
        "--output-dir",
        help="可选输出目录；默认写入首个 matrix-root 同级 resolver_matrix_aggregates/<ts>/",
    )
    resolver_matrix_aggregate.set_defaults(handler=_cmd_resolver_matrix_aggregate)

    resolver_capability_report = subparsers.add_parser(
        "resolver-capability-report",
        help="合并真实 replay 能力矩阵与 campaign-matrix 结果为 resolver 总表",
    )
    resolver_capability_report.add_argument(
        "--replay-matrix-dir",
        required=True,
        help="真实 replay 能力矩阵目录，需包含 matrix.tsv",
    )
    resolver_capability_report.add_argument(
        "--matrix-batch-dir",
        required=True,
        help="真实 multi-resolver campaign matrix 目录，需包含 matrix_run_status.tsv 和 _resolver_summary/",
    )
    resolver_capability_report.add_argument(
        "--output-dir",
        help="可选输出目录；默认写入 <matrix-batch-dir>/_resolver_capability/",
    )
    resolver_capability_report.set_defaults(handler=_cmd_resolver_capability_report)

    resolver_backend_matrix_compare = subparsers.add_parser(
        "resolver-backend-matrix-compare",
        help="比较 Python backend 与 dnslabctl backend 的 resolver matrix 结果",
    )
    resolver_backend_matrix_compare.add_argument(
        "--baseline-batch-dir",
        required=True,
        help="基线 batch 目录，例如 Python backend 的真实 batch",
    )
    resolver_backend_matrix_compare.add_argument(
        "--candidate-batch-dir",
        required=True,
        help="候选 batch 目录，例如 dnslabctl backend 的真实 batch",
    )
    resolver_backend_matrix_compare.add_argument(
        "--baseline-label",
        required=True,
        help="基线标签，例如 python",
    )
    resolver_backend_matrix_compare.add_argument(
        "--candidate-label",
        required=True,
        help="候选标签，例如 dnslabctl",
    )
    resolver_backend_matrix_compare.add_argument(
        "--output-dir",
        help="可选输出目录；默认写入 <candidate-batch-dir>/_backend_compare/",
    )
    resolver_backend_matrix_compare.set_defaults(
        handler=_cmd_resolver_backend_matrix_compare
    )

    publication_audit = subparsers.add_parser(
        "publication-audit",
        help="审计矩阵统计、可比性、证据哈希与 case study 是否达到论文引用门槛",
    )
    publication_audit.add_argument(
        "--matrix-root",
        action="append",
        required=True,
        help="campaign-matrix 工作根目录，可重复传入",
    )
    publication_audit.add_argument(
        "--output-dir",
        help="可选输出目录；默认写入首个 matrix-root 同级 publication_audits/<ts>/",
    )
    publication_audit.add_argument(
        "--minimum-runs",
        type=int,
        default=MINIMUM_PUBLICATION_RUNS,
        help=(
            "每个变体最低独立重复次数；只能提高，"
            f"论文硬门槛为 {MINIMUM_PUBLICATION_RUNS}"
        ),
    )
    publication_audit.add_argument(
        "--minimum-case-studies",
        type=int,
        default=MINIMUM_PUBLICATION_CASE_STUDIES,
        help=(
            "每个矩阵最低完整且已裁决 case study 总数；只能提高，"
            f"论文硬门槛为 {MINIMUM_PUBLICATION_CASE_STUDIES}"
        ),
    )
    publication_audit.set_defaults(handler=_cmd_publication_audit)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
