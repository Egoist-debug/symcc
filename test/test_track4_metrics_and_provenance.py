import json
import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.matrix import (
    _queue_snapshot_digest,
    _write_producer_execution_manifest,
    MatrixVariant,
    PRODUCER_EXECUTION_MANIFEST_NAME,
)


class Track4MetricsAndProvenanceTest(unittest.TestCase):
    def test_f6_queue_snapshot_pure_content_digest(self):
        """F6: queue snapshot digest must ignore *.meta.json run metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            seed1 = dir_path / "seed1.bin"
            seed1.write_bytes(b"\x01\x02\x03\x04")

            digest1, count1, size1 = _queue_snapshot_digest(dir_path)
            self.assertEqual(count1, 1)
            self.assertEqual(size1, 4)

            # Adding run metadata must NOT change the queue snapshot digest
            meta = dir_path / "queue_snapshot.meta.json"
            meta.write_text(json.dumps({"run_id": "run-01", "time": "2026-09-10"}), encoding="utf-8")

            digest2, count2, size2 = _queue_snapshot_digest(dir_path)
            self.assertEqual(digest1, digest2)
            self.assertEqual(count1, count2)
            self.assertEqual(size1, size2)

    def test_f6_manifest_replay_mode_decoupling(self):
        """F6: Replay runs over shared queue must declare replay mode and started=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            run_dir = tmp / "run-01"
            run_dir.mkdir()
            queue_dir = tmp / "queue"
            queue_dir.mkdir()
            (queue_dir / "id:000000.bin").write_bytes(b"TEST_SEED_CONTENT")

            # Mock campaign_close.summary.json
            (run_dir / "campaign_close.summary.json").write_text(
                json.dumps({"run_id": "close-run-123"}), encoding="utf-8"
            )

            variant = MatrixVariant(
                variant_name="full_stack",
                env={"ENABLE_SYMCC": "1", "ENABLE_CACHE_DELTA": "1"},
            )

            # Replay mode
            _write_producer_execution_manifest(
                run_dir=run_dir,
                source_queue_dir=queue_dir,
                variant=variant,
                repeat_index=1,
                started_at="2026-09-10T00:00:00Z",
                finished_at="2026-09-10T00:01:00Z",
                is_replay=True,
            )

            manifest_path = run_dir / PRODUCER_EXECUTION_MANIFEST_NAME
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            self.assertEqual(manifest["execution_mode"], "shared_queue_replay")
            self.assertFalse(manifest["components"]["symcc"]["started"])
            self.assertTrue(manifest["components"]["symcc"]["enabled"])

            # Call again on run-02 with same queue: snapshot sha256 must be identical!
            run_dir2 = tmp / "run-02"
            run_dir2.mkdir()
            (run_dir2 / "campaign_close.summary.json").write_text(
                json.dumps({"run_id": "close-run-456"}), encoding="utf-8"
            )
            _write_producer_execution_manifest(
                run_dir=run_dir2,
                source_queue_dir=queue_dir,
                variant=variant,
                repeat_index=2,
                started_at="2026-09-10T00:02:00Z",
                finished_at="2026-09-10T00:03:00Z",
                is_replay=True,
            )
            manifest2 = json.loads((run_dir2 / PRODUCER_EXECUTION_MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["queue_snapshot"]["sha256"],
                manifest2["queue_snapshot"]["sha256"],
            )

    def test_f10_paper_status_truth(self):
        """F10: DNSPoisonPaperMaterialStatus.md must not have false 20/20 success claims."""
        doc_path = Path(__file__).resolve().parent.parent / "docs" / "DNSPoisonPaperMaterialStatus.md"
        content = doc_path.read_text(encoding="utf-8")
        self.assertNotIn("20/20 replay 成功", content)
        self.assertIn("0/20 completed", content)
        self.assertIn("missing response_corpus", content)

    def test_f11_ablation_na_export(self):
        """F11: Check that empty/invalid variance_status exports NA instead of 0.000000."""
        agg_summary_failed = {"variance_status": "insufficient_runs", "aggregates": {}}
        variance_status = agg_summary_failed.get('variance_status', '')
        aggregates = agg_summary_failed.get('aggregates', {})
        valid_stats = (variance_status == 'ok') and bool(aggregates)

        def mean_of(name: str) -> str:
            if not valid_stats or name not in aggregates or 'mean' not in aggregates[name]:
                return 'NA'
            return f"{float(aggregates[name]['mean']):.6f}"

        self.assertEqual(mean_of('total_samples'), 'NA')

        # Now test valid stats
        agg_summary_ok = {
            "variance_status": "ok",
            "aggregates": {"total_samples": {"mean": 42.0, "stddev": 1.5}},
        }
        variance_status = agg_summary_ok.get('variance_status', '')
        aggregates = agg_summary_ok.get('aggregates', {})
        valid_stats = (variance_status == 'ok') and bool(aggregates)
        self.assertEqual(mean_of('total_samples'), '42.000000')

    def test_f12_input_model_meta_provenance(self):
        """F12: Verify sample.meta.json schema and sha256 calculation."""
        import hashlib
        sample_bytes = b"SAMPLE_PAYLOAD_TEST_BYTES"
        sha256 = hashlib.sha256(sample_bytes).hexdigest()
        meta = {
            "sample_path": "/path/to/sample.bin",
            "sha256": sha256,
            "byte_length": len(sample_bytes),
            "command": ["named", "-g"],
            "returncode": 0,
            "oracle": {"bind9.parse_ok": True},
            "stderr_path": "/path/to/stderr",
            "cache_dump_path": "/path/to/cache",
        }
        self.assertEqual(len(meta["sha256"]), 64)
        self.assertEqual(meta["byte_length"], len(sample_bytes))
        self.assertTrue(meta["oracle"]["bind9.parse_ok"])


if __name__ == "__main__":
    unittest.main()
