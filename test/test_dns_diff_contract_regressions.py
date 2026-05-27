import json
import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.close_loop import CampaignCloseError, _write_close_summary_with_context
from tools.dns_diff.follow_diff import FollowDiffError, _load_follow_diff_state
from tools.dns_diff.report import (
    default_follow_diff_root,
    resolve_semantic_frontier_manifest_path,
)


class DnsDiffContractRegressionsTest(unittest.TestCase):
    def test_load_follow_diff_state_missing_file_returns_default_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state = _load_follow_diff_state(Path(tmpdir) / "follow_diff.state.json")
            self.assertEqual("", state.last_scan_ts)
            self.assertEqual(0, state.completed_count)
            self.assertEqual(0, state.failed_count)
            self.assertIsNone(state.run_id)

    def test_load_follow_diff_state_rejects_corrupt_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "follow_diff.state.json"
            state_path.write_text("{broken", encoding="utf-8")

            with self.assertRaises(FollowDiffError) as exc_ctx:
                _load_follow_diff_state(state_path)

            self.assertIn("follow-diff 状态文件无效", str(exc_ctx.exception))
            self.assertIn(str(state_path.resolve()), str(exc_ctx.exception))

    def test_load_follow_diff_state_rejects_non_object_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "follow_diff.state.json"
            state_path.write_text("[]", encoding="utf-8")

            with self.assertRaises(FollowDiffError) as exc_ctx:
                _load_follow_diff_state(state_path)

            self.assertIn("follow-diff 状态文件无效", str(exc_ctx.exception))
            self.assertIn("JSON 顶层类型无效", str(exc_ctx.exception))

    def test_load_follow_diff_state_rejects_existing_file_missing_required_fields(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "follow_diff.state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "last_scan_ts": "",
                        "completed_count": 0,
                        "failed_count": 0,
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(FollowDiffError) as exc_ctx:
                _load_follow_diff_state(state_path)

            self.assertIn("follow-diff 状态文件无效", str(exc_ctx.exception))
            self.assertIn("字段校验失败", str(exc_ctx.exception))

    def test_write_close_summary_with_context_allows_missing_semantic_frontier_sidecar(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = Path(tmpdir)
            follow_root = default_follow_diff_root(work_dir=work_dir)
            follow_root.mkdir(parents=True, exist_ok=True)

            summary_path = _write_close_summary_with_context(
                work_dir,
                follow_root,
                {
                    "status": "failed",
                    "exit_reason": "phase_failed",
                    "exit_code": 1,
                    "phases": {},
                },
            )

            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            manifest = ((payload.get("phase_context") or {}).get("semantic_frontier_manifest")) or {}
            self.assertEqual("missing", manifest.get("sidecar_status"))
            self.assertFalse(manifest.get("sidecar_exists"))
            self.assertEqual(0, manifest.get("entry_count"))

    def test_write_close_summary_with_context_rejects_corrupt_semantic_frontier_sidecar(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = Path(tmpdir)
            follow_root = default_follow_diff_root(work_dir=work_dir)
            follow_root.mkdir(parents=True, exist_ok=True)

            sidecar_path = resolve_semantic_frontier_manifest_path(
                follow_root,
                work_dir=work_dir,
            )
            sidecar_path.write_text("{broken", encoding="utf-8")

            with self.assertRaises(CampaignCloseError) as exc_ctx:
                _write_close_summary_with_context(
                    work_dir,
                    follow_root,
                    {
                        "status": "success",
                        "exit_reason": "success",
                        "exit_code": 0,
                        "phases": {},
                    },
                )

            self.assertIn("semantic frontier sidecar 无效", str(exc_ctx.exception))
            self.assertIn(str(sidecar_path.resolve()), str(exc_ctx.exception))


if __name__ == "__main__":
    unittest.main()
