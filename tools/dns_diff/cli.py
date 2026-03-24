import argparse
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from .campaign import generate_campaign_report
from .cache_parser import CacheParseError, write_cache_tsv
from .close_loop import CampaignCloseError, run_campaign_close
from .follow_diff import (
    FollowDiffError,
    follow_diff,
    follow_diff_once,
    follow_diff_window,
)
from .report import ReportError, default_follow_diff_root, generate_report
from .replay import ReplayError, replay_diff_cache
from .triage import TriageError, rewrite_triage_root


def _fail_unimplemented(command: str) -> int:
    sys.stderr.write(
        f"dns-diff: 子命令 {command!r} 尚未实现（本任务仅提供基础 CLI 框架）\n"
    )
    return 2


def _cmd_follow_diff(_: argparse.Namespace) -> int:
    try:
        return follow_diff()
    except FollowDiffError as exc:
        sys.stderr.write(f"dns-diff: follow-diff 失败: {exc}\n")
        return exc.exit_code


def _cmd_follow_diff_once(_: argparse.Namespace) -> int:
    try:
        return follow_diff_once()
    except FollowDiffError as exc:
        sys.stderr.write(f"dns-diff: follow-diff-once 失败: {exc}\n")
        return exc.exit_code


def _cmd_follow_diff_window(args: argparse.Namespace) -> int:
    try:
        return follow_diff_window(
            budget_sec=args.budget_sec,
            retry_failed=bool(args.retry_failed),
        )
    except FollowDiffError as exc:
        sys.stderr.write(f"dns-diff: follow-diff-window 失败: {exc}\n")
        return exc.exit_code


def _cmd_parse_cache(args: argparse.Namespace) -> int:
    try:
        write_cache_tsv(args.resolver, args.dump_file, args.output_file)
        return 0
    except CacheParseError as exc:
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
        return generate_report(args.root)
    except ReportError as exc:
        sys.stderr.write(f"dns-diff: report 失败: {exc}\n")
        return exc.exit_code


def _cmd_campaign_report(args: argparse.Namespace) -> int:
    root = Path(args.root) if args.root else default_follow_diff_root()
    return generate_campaign_report(root, is_custom_root=bool(args.root))


def _cmd_campaign_close(args: argparse.Namespace) -> int:
    try:
        return run_campaign_close(budget_sec=args.budget_sec)
    except CampaignCloseError as exc:
        sys.stderr.write(f"dns-diff: campaign-close 失败: {exc}\n")
        return exc.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.dns_diff.cli",
        description=(
            "dns-diff Python 真入口；thin wrapper 仅转发 parse-cache、"
            "replay-diff-cache、follow-diff、follow-diff-once、follow-diff-window、triage-report、"
            "campaign-report、campaign-close，triage/report/close-loop 仅通过 Python CLI 直调。"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

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
    follow_diff_window.set_defaults(handler=_cmd_follow_diff_window)

    parse_cache = subparsers.add_parser("parse-cache", help="解析 resolver cache dump")
    parse_cache.add_argument("resolver", help="resolver 类型，例如 unbound 或 bind9")
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
    report.set_defaults(handler=_cmd_report)

    campaign_report = subparsers.add_parser(
        "campaign-report", help="汇总 campaign 指标"
    )
    campaign_report.add_argument("--root", help="可选 follow_diff 根目录")
    campaign_report.set_defaults(handler=_cmd_campaign_report)

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

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
