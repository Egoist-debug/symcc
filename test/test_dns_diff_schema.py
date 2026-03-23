import unittest

from tools.dns_diff.schema import (
    SAMPLE_META_REQUIRED_FIELDS,
    STATE_FINGERPRINT_REQUIRED_FIELDS,
    build_sample_meta_payload,
    build_state_fingerprint_payload,
    validate_sample_meta_fields,
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


if __name__ == "__main__":
    unittest.main()
