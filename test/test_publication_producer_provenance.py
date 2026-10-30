import json
import tempfile
import unittest
from pathlib import Path

from tools.dns_diff import matrix, publication_audit


class PublicationProducerProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = matrix.EXPECTED_VARIANT_ENVS["full_stack"]
        self.identities = {
            "producer_run_ids": set(),
            "random_seeds": set(),
        }

    def make_manifest(self, index=1):
        run_dir = self.root / f"run-{index:02d}"
        queue_dir = run_dir / "queue_snapshot"
        queue_dir.mkdir(parents=True)
        (queue_dir / "seed.bin").write_bytes(b"same payload")
        (queue_dir / "queue_snapshot.meta.json").write_text(
            json.dumps({"run": index}), encoding="utf-8"
        )
        digest, count, size = matrix._queue_snapshot_digest(queue_dir)
        # 这是离线合同 fixture，不代表执行过 producer。
        manifest = {
            "contract_name": matrix.PRODUCER_EXECUTION_CONTRACT_NAME,
            "contract_version": 1,
            "execution_mode": "independent_producer_generation",
            "status": "success",
            "exit_code": 0,
            "variant_name": "full_stack",
            "repeat_index": index,
            "producer_run_id": f"producer-{index}",
            "random_seed": index,
            "run_dir": str(run_dir),
            "started_at": f"2026-10-30T00:{index:02d}:00Z",
            "finished_at": f"2026-10-30T00:{index:02d}:30Z",
            "toggles": dict(self.env),
            "components": {
                "afl_master": {
                    "enabled": True,
                    "started": True,
                    "pid": 100,
                    "command_summary": f"afl-fuzz -M master -s {index}",
                },
                "afl_secondary": {
                    "enabled": False,
                    "started": False,
                    "pid": None,
                    "command_summary": None,
                },
                "symcc": {
                    "enabled": True,
                    "started": True,
                    "pid": 101,
                    "command_summary": "symcc_fuzzing_helper -a master",
                },
            },
            "queue_snapshot": {
                "algorithm": matrix.QUEUE_SNAPSHOT_DIGEST_ALGORITHM,
                "path": str(queue_dir),
                "sha256": digest,
                "snapshot_id": digest,
                "file_count": count,
                "size_bytes": size,
            },
        }
        return run_dir, manifest

    def audit(self, run_dir, manifest):
        path = run_dir / matrix.PRODUCER_EXECUTION_MANIFEST_NAME
        path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        before = path.read_bytes()
        issues = []
        publication_audit._audit_producer_execution_manifest(
            run={},
            expected_run_dir=run_dir,
            variant_name="full_stack",
            repeat_index=int(run_dir.name.split("-")[1]),
            expected_env=self.env,
            matrix_root=self.root,
            scope=run_dir.name,
            issues=issues,
            **self.identities,
        )
        self.assertEqual(path.read_bytes(), before, "审计不能改写历史 manifest")
        return {issue["code"] for issue in issues}

    def test_same_payload_and_snapshot_id_allow_independent_runs(self):
        first_dir, first = self.make_manifest(1)
        second_dir, second = self.make_manifest(2)
        self.assertEqual(first["queue_snapshot"]["sha256"], second["queue_snapshot"]["sha256"])
        self.assertEqual(self.audit(first_dir, first), set())
        self.assertEqual(self.audit(second_dir, second), set())

    def test_missing_unknown_and_replay_modes_are_not_generation(self):
        run_dir, manifest = self.make_manifest()
        for mode in (None, "", "unknown", "shared_queue_replay"):
            with self.subTest(mode=mode):
                if mode is None:
                    manifest.pop("execution_mode", None)
                else:
                    manifest["execution_mode"] = mode
                manifest["components"]["symcc"]["started"] = mode != "shared_queue_replay"
                self.identities = {key: set() for key in self.identities}
                self.assertIn("invalid_producer_execution_mode", self.audit(run_dir, manifest))

    def test_missing_and_contradictory_execution_evidence(self):
        cases = [
            (("producer_run_id",), None, "missing_producer_run_id"),
            (("random_seed",), None, "missing_producer_random_seed"),
            (("run_dir",), str(self.root), "producer_run_directory_mismatch"),
            (("started_at",), None, "incomplete_producer_execution_manifest"),
            (("started_at",), "not-a-time", "invalid_producer_execution_time"),
            (("started_at",), "2026-10-30T00:01:00", "invalid_producer_execution_time"),
            (("finished_at",), "2026-10-29T00:01:00Z", "invalid_producer_execution_time"),
            (("status",), "failed", "invalid_producer_execution_state"),
            (("exit_code",), False, "invalid_producer_execution_state"),
            (("repeat_index",), True, "invalid_producer_execution_state"),
            (("toggles", "ENABLE_SYMCC"), "0", "producer_toggle_mismatch"),
            (("components", "symcc", "started"), False, "producer_symcc_state_mismatch"),
            (("components", "afl_master"), None, "producer_component_state_mismatch"),
            (("components", "afl_master", "started"), False, "producer_component_state_mismatch"),
            (("components", "afl_master", "pid"), None, "incomplete_producer_component_evidence"),
            (("components", "symcc", "command_summary"), "", "incomplete_producer_component_evidence"),
            (("components", "afl_secondary", "started"), True, "producer_component_state_mismatch"),
        ]
        for index, (keys, value, expected) in enumerate(cases, start=1):
            with self.subTest(keys=keys, value=value):
                run_dir, manifest = self.make_manifest(index)
                target = manifest
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                self.assertIn(expected, self.audit(run_dir, manifest))

    def test_run_and_seed_reuse_are_still_rejected(self):
        first_dir, first = self.make_manifest(1)
        second_dir, second = self.make_manifest(2)
        self.assertEqual(self.audit(first_dir, first), set())
        second["producer_run_id"] = first["producer_run_id"]
        second["random_seed"] = first["random_seed"]
        codes = self.audit(second_dir, second)
        self.assertIn("duplicate_producer_run_id", codes)
        self.assertIn("duplicate_producer_random_seed", codes)

    def test_legacy_v1_remains_readable_but_ineligible(self):
        run_dir, manifest = self.make_manifest()
        manifest["queue_snapshot"]["algorithm"] = "sha256-relative-path-size-content-v1"
        self.assertIn("invalid_queue_snapshot_algorithm", self.audit(run_dir, manifest))

    def test_v2_digest_tracks_payload_not_metadata(self):
        run_dir, manifest = self.make_manifest()
        queue = Path(manifest["queue_snapshot"]["path"])
        self.assertEqual(matrix.QUEUE_SNAPSHOT_DIGEST_ALGORITHM, "sha256-relative-path-size-content-v2")
        self.assertEqual(publication_audit.QUEUE_SNAPSHOT_DIGEST_ALGORITHM, matrix.QUEUE_SNAPSHOT_DIGEST_ALGORITHM)
        before = matrix._queue_snapshot_digest(queue)
        (queue / "seed.bin.meta.json").write_text('{"extra": true}', encoding="utf-8")
        (queue / "queue_snapshot.meta.json").write_text('{"run": "changed"}', encoding="utf-8")
        self.assertEqual(matrix._queue_snapshot_digest(queue), before)
        self.assertEqual(publication_audit._queue_snapshot_digest(queue), before)
        self.assertEqual(self.audit(run_dir, manifest), set())
        (queue / "seed.bin").write_bytes(b"edit payload")
        self.assertNotEqual(matrix._queue_snapshot_digest(queue)[0], before[0])
        self.assertIn("queue_snapshot_integrity_mismatch", self.audit(run_dir, manifest))
        changed = matrix._queue_snapshot_digest(queue)
        (queue / "seed.bin").rename(queue / "renamed.bin")
        self.assertNotEqual(matrix._queue_snapshot_digest(queue)[0], changed[0])
        self.assertEqual(matrix._queue_snapshot_digest(queue), publication_audit._queue_snapshot_digest(queue))

    def test_snapshot_escape_and_symlink_remain_invalid(self):
        run_dir, manifest = self.make_manifest()
        manifest["queue_snapshot"]["path"] = str(self.root)
        self.assertIn("queue_snapshot_path_escape", self.audit(run_dir, manifest))
        manifest["queue_snapshot"]["path"] = str(run_dir / "queue_snapshot")
        (run_dir / "queue_snapshot" / "link.meta.json").symlink_to(run_dir / "missing")
        self.assertIn("invalid_queue_snapshot_directory", self.audit(run_dir, manifest))

    def test_matrix_cannot_claim_generation_or_invent_seed(self):
        run_dir = self.root / "run-01"
        run_dir.mkdir()
        (run_dir / "campaign_close.summary.json").write_text(
            '{"run_id": "replay-1"}', encoding="utf-8"
        )
        source = self.root / "source"
        source.mkdir()
        (source / "seed").write_bytes(b"payload")
        kwargs = {
            "run_dir": run_dir,
            "source_queue_dir": source,
            "variant": matrix.MatrixVariant("full_stack", self.env),
            "repeat_index": 1,
            "started_at": "2026-10-30T00:00:00Z",
            "finished_at": "2026-10-30T00:00:01Z",
        }
        with self.assertRaises(TypeError):
            matrix._write_producer_execution_manifest(**kwargs, is_replay=False)
        matrix._write_producer_execution_manifest(**kwargs)
        manifest = json.loads((run_dir / matrix.PRODUCER_EXECUTION_MANIFEST_NAME).read_text())
        self.assertEqual(manifest["execution_mode"], "shared_queue_replay")
        self.assertFalse(manifest["components"]["symcc"]["started"])
        self.assertIsNone(manifest["random_seed"])
        self.assertIn("invalid_producer_execution_mode", self.audit(run_dir, manifest))
        manifest["execution_mode"] = "independent_producer_generation"
        manifest["components"]["symcc"]["started"] = True
        codes = self.audit(run_dir, manifest)
        self.assertIn("producer_component_state_mismatch", codes)
        self.assertIn("incomplete_producer_component_evidence", codes)

    def test_matrix_missing_metric_is_na_not_zero(self):
        self.assertEqual(matrix._format_metric_value(None), "NA")
        self.assertEqual(matrix._format_metric_value(0), "0.000000")


if __name__ == "__main__":
    unittest.main()
