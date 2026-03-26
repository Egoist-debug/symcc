import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .campaign import generate_campaign_report
from .follow_diff import (
    EXIT_DEADLINE_EXCEEDED,
    FollowDiffError,
    follow_diff_window,
    resolve_follow_diff_source_dir,
    resolve_follow_diff_work_dir,
)
from .io import atomic_write_json, load_json_with_fallback
from .report import (
    ReportError,
    collect_report_snapshot,
    default_follow_diff_root,
    generate_report,
    resolve_high_value_manifest_path,
    resolve_semantic_frontier_manifest_path,
)
from .schema import utc_timestamp
from .triage import TriageError, rewrite_triage_root

EXIT_USAGE = 2
EXIT_PHASE_FAILED = 1
CAMPAIGN_CLOSE_SUMMARY_FILE_NAME = "campaign_close.summary.json"

PHASE_FOLLOW_DIFF_WINDOW = "follow-diff-window"
PHASE_TRIAGE_REPORT = "triage-report"
PHASE_CAMPAIGN_REPORT = "campaign-report"


class CampaignCloseError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _format_deadline_ts(deadline_epoch_sec: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(deadline_epoch_sec)) + "Z"


def _resolve_queue_tail_id() -> Optional[str]:
    source_dir = resolve_follow_diff_source_dir()
    if not source_dir.is_dir():
        return None
    queue_entries = sorted(
        (path for path in source_dir.glob("id:*") if path.is_file()),
        key=lambda path: path.name,
    )
    if not queue_entries:
        return None
    return queue_entries[-1].name


def _normalize_exit_code(code: int) -> int:
    return EXIT_PHASE_FAILED if code == 124 else code


def _phase_defaults() -> Dict[str, Any]:
    return {
        "status": "not_started",
        "started_at": "",
        "finished_at": "",
        "duration_sec": 0.0,
        "exit_reason": "not_started",
        "exit_code": 0,
    }


def _mark_phase_started(phases: Dict[str, Dict[str, Any]], phase_name: str) -> float:
    started_epoch = time.time()
    phase_payload = phases[phase_name]
    phase_payload["status"] = "running"
    phase_payload["started_at"] = utc_timestamp()
    return started_epoch


def _mark_phase_finished(
    phases: Dict[str, Dict[str, Any]],
    phase_name: str,
    *,
    started_epoch: float,
    status: str,
    exit_reason: str,
    exit_code: int,
    message: Optional[str] = None,
) -> None:
    phase_payload = phases[phase_name]
    phase_payload["status"] = status
    phase_payload["finished_at"] = utc_timestamp()
    phase_payload["duration_sec"] = round(max(0.0, time.time() - started_epoch), 6)
    phase_payload["exit_reason"] = exit_reason
    phase_payload["exit_code"] = int(exit_code)
    if message:
        phase_payload["message"] = message


def _write_close_summary(work_dir: Path, summary_payload: Mapping[str, Any]) -> Path:
    return atomic_write_json(
        work_dir / CAMPAIGN_CLOSE_SUMMARY_FILE_NAME, summary_payload
    )


def _build_phase_context(*, run_metadata: Mapping[str, Any]) -> Dict[str, Any]:
    state_payload = run_metadata.get("state")
    if not isinstance(state_payload, Mapping):
        state_payload = {}
    window_payload = run_metadata.get("window_summary")
    if not isinstance(window_payload, Mapping):
        window_payload = {}

    return {
        "follow_diff_state": {
            "run_id": state_payload.get("run_id"),
            "last_exit_reason": state_payload.get("last_exit_reason"),
            "retry_count": state_payload.get("retry_count"),
            "last_attempt_ts": state_payload.get("last_attempt_ts"),
            "last_queue_event_id": state_payload.get("last_queue_event_id"),
        },
        "follow_diff_window_summary": {
            "run_id": window_payload.get("run_id"),
            "exit_reason": window_payload.get("exit_reason"),
            "exit_code": window_payload.get("exit_code"),
            "queue_tail_id": window_payload.get("queue_tail_id"),
            "last_queue_event_id": window_payload.get("last_queue_event_id"),
            "seed_provenance": window_payload.get("seed_provenance")
            if isinstance(window_payload.get("seed_provenance"), Mapping)
            else None,
        },
    }


def _collect_semantic_frontier_lifecycle(
    follow_root: Path,
    *,
    work_dir: Path,
) -> Dict[str, Any]:
    text_manifest_path = resolve_high_value_manifest_path(
        follow_root, work_dir=work_dir
    )
    semantic_manifest_path = resolve_semantic_frontier_manifest_path(
        follow_root,
        work_dir=work_dir,
    )
    load_result = load_json_with_fallback(semantic_manifest_path)
    payload = load_result.data
    entries = payload.get("entries")
    generated_at = payload.get("generated_at")

    return {
        "text_manifest_path": str(text_manifest_path),
        "text_manifest_exists": text_manifest_path.is_file(),
        "sidecar_path": str(semantic_manifest_path),
        "sidecar_exists": semantic_manifest_path.is_file(),
        "sidecar_status": load_result.status,
        "generated_at": generated_at
        if isinstance(generated_at, str) and generated_at
        else None,
        "entry_count": len(entries) if isinstance(entries, list) else 0,
        "error": load_result.error,
    }


def _write_close_summary_with_context(
    work_dir: Path,
    follow_root: Path,
    summary_payload: Mapping[str, Any],
) -> Path:
    snapshot = collect_report_snapshot(
        follow_root,
        work_dir=work_dir,
        require_root=False,
    )
    enriched_summary = dict(summary_payload)
    enriched_summary["run_id"] = snapshot["run_id"]
    enriched_summary["metric_denominators"] = snapshot["metric_denominators"]
    enriched_summary["comparability"] = snapshot["comparability"]
    enriched_summary["seed_provenance"] = snapshot["seed_provenance"]
    phase_context = _build_phase_context(run_metadata=snapshot["run_metadata"])
    phase_context["semantic_frontier_manifest"] = _collect_semantic_frontier_lifecycle(
        follow_root,
        work_dir=work_dir,
    )
    enriched_summary["phase_context"] = phase_context
    return _write_close_summary(work_dir, enriched_summary)


def _build_summary_base(
    *,
    budget_sec: float,
    deadline_ts: str,
    queue_tail_id: Optional[str],
    phases: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    return {
        "budget_sec": budget_sec,
        "deadline_ts": deadline_ts,
        "queue_tail_id": queue_tail_id,
        "status": "failed",
        "exit_reason": "phase_failed",
        "exit_code": EXIT_PHASE_FAILED,
        "phases": dict(phases),
    }


def _remaining_budget_sec(deadline_epoch_sec: float) -> float:
    return deadline_epoch_sec - time.time()


def _require_remaining_budget(
    *,
    phases: Dict[str, Dict[str, Any]],
    phase_name: str,
    deadline_epoch_sec: float,
) -> Optional[Dict[str, Any]]:
    remaining = _remaining_budget_sec(deadline_epoch_sec)
    if remaining > 0:
        return None

    started_epoch = _mark_phase_started(phases, phase_name)
    _mark_phase_finished(
        phases,
        phase_name,
        started_epoch=started_epoch,
        status="failed",
        exit_reason="deadline_exceeded",
        exit_code=EXIT_DEADLINE_EXCEEDED,
        message="全局 deadline 已耗尽，阶段未启动",
    )
    return {
        "failed_phase": phase_name,
        "exit_reason": "deadline_exceeded",
        "exit_code": EXIT_DEADLINE_EXCEEDED,
    }


def _validate_triage_report_artifacts(follow_root: Path) -> None:
    required_files = [
        follow_root / "cluster_summary.tsv",
        follow_root / "status_summary.tsv",
        follow_root / "triage_report.md",
        resolve_high_value_manifest_path(follow_root),
    ]
    missing_paths = [path for path in required_files if not path.is_file()]
    if missing_paths:
        formatted_missing = ", ".join(str(path) for path in missing_paths)
        raise CampaignCloseError(
            f"triage-report 产物缺失: {formatted_missing}",
            exit_code=EXIT_PHASE_FAILED,
        )


def _validate_campaign_report_artifacts(work_dir: Path) -> None:
    report_base = work_dir / "campaign_reports"
    if not report_base.is_dir():
        raise CampaignCloseError(
            f"campaign-report 产物目录不存在: {report_base}",
            exit_code=EXIT_PHASE_FAILED,
        )

    report_dirs = sorted(path for path in report_base.iterdir() if path.is_dir())
    if not report_dirs:
        raise CampaignCloseError(
            f"campaign-report 未生成目录: {report_base}",
            exit_code=EXIT_PHASE_FAILED,
        )

    latest_report_dir = report_dirs[-1]
    required_files = [
        latest_report_dir / "summary.json",
        latest_report_dir / "ablation_matrix.tsv",
        latest_report_dir / "cluster_counts.tsv",
        latest_report_dir / "repro_rate.tsv",
    ]
    missing_paths = [path for path in required_files if not path.is_file()]
    if missing_paths:
        formatted_missing = ", ".join(str(path) for path in missing_paths)
        raise CampaignCloseError(
            f"campaign-report 产物缺失: {formatted_missing}",
            exit_code=EXIT_PHASE_FAILED,
        )


def run_campaign_close(*, budget_sec: float) -> int:
    if budget_sec <= 0:
        raise CampaignCloseError("--budget-sec 必须大于 0")

    work_dir = resolve_follow_diff_work_dir()
    follow_root = default_follow_diff_root(work_dir=work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    follow_root.mkdir(parents=True, exist_ok=True)

    queue_tail_id = _resolve_queue_tail_id()
    deadline_epoch_sec = time.time() + budget_sec
    deadline_ts = _format_deadline_ts(deadline_epoch_sec)

    phases: Dict[str, Dict[str, Any]] = {
        PHASE_FOLLOW_DIFF_WINDOW: _phase_defaults(),
        PHASE_TRIAGE_REPORT: _phase_defaults(),
        PHASE_CAMPAIGN_REPORT: _phase_defaults(),
    }
    summary = _build_summary_base(
        budget_sec=budget_sec,
        deadline_ts=deadline_ts,
        queue_tail_id=queue_tail_id,
        phases=phases,
    )

    for phase_name in (
        PHASE_FOLLOW_DIFF_WINDOW,
        PHASE_TRIAGE_REPORT,
        PHASE_CAMPAIGN_REPORT,
    ):
        deadline_failure = _require_remaining_budget(
            phases=phases,
            phase_name=phase_name,
            deadline_epoch_sec=deadline_epoch_sec,
        )
        if deadline_failure is not None:
            summary.update(
                {
                    "status": "failed",
                    "failed_phase": deadline_failure["failed_phase"],
                    "exit_reason": deadline_failure["exit_reason"],
                    "exit_code": deadline_failure["exit_code"],
                }
            )
            _write_close_summary_with_context(work_dir, follow_root, summary)
            return int(summary["exit_code"])

        started_epoch = _mark_phase_started(phases, phase_name)
        if phase_name == PHASE_FOLLOW_DIFF_WINDOW:
            remaining_budget = _remaining_budget_sec(deadline_epoch_sec)
            try:
                phase_exit_code = follow_diff_window(
                    budget_sec=remaining_budget,
                    queue_tail_id=queue_tail_id,
                )
            except FollowDiffError as exc:
                phase_exit_code = exc.exit_code
                phase_message = str(exc)
            except Exception as exc:
                phase_exit_code = EXIT_PHASE_FAILED
                phase_message = str(exc)
            else:
                phase_message = None

            phase_exit_code = _normalize_exit_code(int(phase_exit_code))
            if phase_exit_code != 0:
                phase_exit_reason = (
                    "deadline_exceeded"
                    if phase_exit_code == EXIT_DEADLINE_EXCEEDED
                    else "phase_failed"
                )
                _mark_phase_finished(
                    phases,
                    PHASE_FOLLOW_DIFF_WINDOW,
                    started_epoch=started_epoch,
                    status="failed",
                    exit_reason=phase_exit_reason,
                    exit_code=phase_exit_code,
                    message=phase_message,
                )
                summary.update(
                    {
                        "status": "failed",
                        "failed_phase": PHASE_FOLLOW_DIFF_WINDOW,
                        "exit_reason": phase_exit_reason,
                        "exit_code": phase_exit_code,
                    }
                )
                _write_close_summary_with_context(work_dir, follow_root, summary)
                return int(summary["exit_code"])

            _mark_phase_finished(
                phases,
                PHASE_FOLLOW_DIFF_WINDOW,
                started_epoch=started_epoch,
                status="success",
                exit_reason="success",
                exit_code=0,
            )
            continue

        if phase_name == PHASE_TRIAGE_REPORT:
            try:
                rewrite_exit_code = rewrite_triage_root(follow_root)
                rewrite_exit_code = _normalize_exit_code(int(rewrite_exit_code))
                if rewrite_exit_code != 0:
                    raise CampaignCloseError(
                        f"triage rewrite 返回非零退出码: {rewrite_exit_code}",
                        exit_code=rewrite_exit_code,
                    )

                report_exit_code = generate_report(follow_root)
                report_exit_code = _normalize_exit_code(int(report_exit_code))
                if report_exit_code != 0:
                    raise CampaignCloseError(
                        f"triage report 返回非零退出码: {report_exit_code}",
                        exit_code=report_exit_code,
                    )

                _validate_triage_report_artifacts(follow_root)
            except (CampaignCloseError, TriageError, ReportError) as exc:
                phase_exit_code = _normalize_exit_code(getattr(exc, "exit_code", 1))
                _mark_phase_finished(
                    phases,
                    PHASE_TRIAGE_REPORT,
                    started_epoch=started_epoch,
                    status="failed",
                    exit_reason="phase_failed",
                    exit_code=phase_exit_code,
                    message=str(exc),
                )
                summary.update(
                    {
                        "status": "failed",
                        "failed_phase": PHASE_TRIAGE_REPORT,
                        "exit_reason": "phase_failed",
                        "exit_code": phase_exit_code,
                    }
                )
                _write_close_summary_with_context(work_dir, follow_root, summary)
                return int(summary["exit_code"])
            except Exception as exc:
                _mark_phase_finished(
                    phases,
                    PHASE_TRIAGE_REPORT,
                    started_epoch=started_epoch,
                    status="failed",
                    exit_reason="phase_failed",
                    exit_code=EXIT_PHASE_FAILED,
                    message=str(exc),
                )
                summary.update(
                    {
                        "status": "failed",
                        "failed_phase": PHASE_TRIAGE_REPORT,
                        "exit_reason": "phase_failed",
                        "exit_code": EXIT_PHASE_FAILED,
                    }
                )
                _write_close_summary_with_context(work_dir, follow_root, summary)
                return int(summary["exit_code"])

            _mark_phase_finished(
                phases,
                PHASE_TRIAGE_REPORT,
                started_epoch=started_epoch,
                status="success",
                exit_reason="success",
                exit_code=0,
            )
            continue

        try:
            campaign_exit_code = generate_campaign_report(follow_root)
            campaign_exit_code = _normalize_exit_code(int(campaign_exit_code))
            if campaign_exit_code != 0:
                raise CampaignCloseError(
                    f"campaign report 返回非零退出码: {campaign_exit_code}",
                    exit_code=campaign_exit_code,
                )

            _validate_campaign_report_artifacts(work_dir)
        except CampaignCloseError as exc:
            phase_exit_code = _normalize_exit_code(exc.exit_code)
            _mark_phase_finished(
                phases,
                PHASE_CAMPAIGN_REPORT,
                started_epoch=started_epoch,
                status="failed",
                exit_reason="phase_failed",
                exit_code=phase_exit_code,
                message=str(exc),
            )
            summary.update(
                {
                    "status": "failed",
                    "failed_phase": PHASE_CAMPAIGN_REPORT,
                    "exit_reason": "phase_failed",
                    "exit_code": phase_exit_code,
                }
            )
            _write_close_summary_with_context(work_dir, follow_root, summary)
            return int(summary["exit_code"])
        except Exception as exc:
            _mark_phase_finished(
                phases,
                PHASE_CAMPAIGN_REPORT,
                started_epoch=started_epoch,
                status="failed",
                exit_reason="phase_failed",
                exit_code=EXIT_PHASE_FAILED,
                message=str(exc),
            )
            summary.update(
                {
                    "status": "failed",
                    "failed_phase": PHASE_CAMPAIGN_REPORT,
                    "exit_reason": "phase_failed",
                    "exit_code": EXIT_PHASE_FAILED,
                }
            )
            _write_close_summary_with_context(work_dir, follow_root, summary)
            return int(summary["exit_code"])

        _mark_phase_finished(
            phases,
            PHASE_CAMPAIGN_REPORT,
            started_epoch=started_epoch,
            status="success",
            exit_reason="success",
            exit_code=0,
        )

    summary.update(
        {
            "status": "success",
            "exit_reason": "success",
            "exit_code": 0,
        }
    )
    summary.pop("failed_phase", None)
    _write_close_summary_with_context(work_dir, follow_root, summary)
    return 0


__all__ = ["CampaignCloseError", "run_campaign_close"]
