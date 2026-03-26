import unittest

from tools.dns_diff.schema import (
    SAMPLE_META_REQUIRED_FIELDS,
    STATE_FINGERPRINT_REQUIRED_FIELDS,
    build_sample_meta_payload,
    build_seed_provenance_payload,
    build_state_fingerprint_payload,
    validate_sample_meta_fields,
    validate_seed_provenance_fields,
)


class DnsDiffSchemaTest(unittest.TestCase):
    def test_build_sample_meta_payload_has_required_fields(self) -> None:
        payload = build_sample_meta_payload(
            sample_id="id:000001__deadbeef",
            queue_event_id="id:000001",
            source_queue_file="/tmp/queue/id:000001",
            sample_sha1="deadbeef",
            sample_size=4,
            status="completed",
            source_resolver="unbound",
            is_stateful=True,
            afl_tags=["+cov"],
        )
        for field in SAMPLE_META_REQUIRED_FIELDS:
            self.assertIn(field, payload)
        self.assertEqual("completed", payload["status"])

    def test_build_state_fingerprint_payload_fills_missing_required(self) -> None:
        payload = build_state_fingerprint_payload(
            sample_id="id:000001__deadbeef",
            overrides={"bind9.forwarding_path": "iterative"},
        )
        for field in STATE_FINGERPRINT_REQUIRED_FIELDS:
            self.assertIn(field, payload)
        self.assertEqual("iterative", payload["bind9.forwarding_path"])
        self.assertIsNone(payload["unbound.forwarding_path"])

    def test_validate_sample_meta_fields_rejects_unknown_status(self) -> None:
        payload = build_sample_meta_payload(
            sample_id="id:000001__deadbeef",
            queue_event_id="id:000001",
            source_queue_file="/tmp/queue/id:000001",
            sample_sha1="deadbeef",
            sample_size=4,
            status="not-a-valid-status",
            source_resolver="unbound",
            is_stateful=False,
            afl_tags=[],
        )
        errors = validate_sample_meta_fields(payload)
        self.assertTrue(any("status 必须是" in error for error in errors))

    def test_build_sample_meta_payload_preserves_seed_provenance(self) -> None:
        seed_provenance = build_seed_provenance_payload(
            cold_start=False,
            seed_source_dir="/tmp/named-work/stable_transcript_corpus",
            seed_materialization_method="reused_filtered_corpus",
            seed_snapshot_id="a" * 40,
            regen_seeds=False,
            refilter_queries=False,
            stable_input_dir="/tmp/named-work/stable_transcript_corpus",
            recorded_at="2026-03-26T00:00:00Z",
        )
        payload = build_sample_meta_payload(
            sample_id="id:000001__deadbeef",
            queue_event_id="id:000001",
            source_queue_file="/tmp/queue/id:000001",
            sample_sha1="deadbeef",
            sample_size=4,
            status="completed",
            source_resolver="unbound",
            is_stateful=True,
            afl_tags=["+cov"],
            seed_provenance=seed_provenance,
        )
        self.assertEqual(seed_provenance, payload.get("seed_provenance"))

    def test_validate_seed_provenance_fields_rejects_invalid_boolean(self) -> None:
        errors = validate_seed_provenance_fields(
            {
                "cold_start": "no",
                "seed_source_dir": "/tmp/source",
                "seed_materialization_method": "reused_filtered_corpus",
                "seed_snapshot_id": "a" * 40,
                "regen_seeds": False,
                "refilter_queries": False,
                "stable_input_dir": "/tmp/stable",
                "recorded_at": "2026-03-26T00:00:00Z",
            }
        )
        self.assertTrue(any("cold_start 必须是布尔值" in error for error in errors))

    def test_validate_sample_meta_fields_rejects_invalid_seed_provenance(self) -> None:
        payload = build_sample_meta_payload(
            sample_id="id:000001__deadbeef",
            queue_event_id="id:000001",
            source_queue_file="/tmp/queue/id:000001",
            sample_sha1="deadbeef",
            sample_size=4,
            status="completed",
            source_resolver="unbound",
            is_stateful=False,
            afl_tags=[],
        )
        payload["seed_provenance"] = {
            "cold_start": False,
            "seed_source_dir": "/tmp/source",
            "seed_materialization_method": "reused_filtered_corpus",
            "seed_snapshot_id": "a" * 40,
            "regen_seeds": False,
            "refilter_queries": False,
            "stable_input_dir": "/tmp/stable",
            "recorded_at": "not-a-timestamp",
        }
        errors = validate_sample_meta_fields(payload)
        self.assertTrue(
            any(
                "seed_provenance.recorded_at 必须是 ISO-8601 时间戳" in error
                for error in errors
            )
        )


if __name__ == "__main__":
    unittest.main()
