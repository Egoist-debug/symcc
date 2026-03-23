import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.triage import build_triage, rewrite_triage_payload


class DnsDiffTriageTest(unittest.TestCase):
    def test_build_triage_oracle_missing(self) -> None:
        oracle = {
            "bind9.stderr_parse_status": None,
            "unbound.stderr_parse_status": None,
        }
        cache_diff = {
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
        }
        fingerprint = {}

        payload = build_triage("sample-1", oracle, cache_diff, fingerprint)
        self.assertEqual("failed_replay", payload["status"])
        self.assertEqual("replay_incomplete", payload["diff_class"])
        self.assertIn("oracle_missing", payload["filter_labels"])
        self.assertTrue(payload["needs_manual_review"])

    def test_build_triage_oracle_diff(self) -> None:
        oracle = {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": False,
            "bind9.resolver_fetch_started": True,
            "unbound.resolver_fetch_started": True,
            "bind9.response_accepted": True,
            "unbound.response_accepted": True,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
            "bind9.timeout": False,
            "unbound.timeout": False,
        }
        cache_diff = {
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
        }
        payload = build_triage("sample-2", oracle, cache_diff, {})
        self.assertEqual("completed_oracle_diff", payload["status"])
        self.assertEqual("oracle_diff", payload["diff_class"])
        self.assertIn("oracle_diff", payload["filter_labels"])

    def test_rewrite_triage_payload_marks_partial_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_dir = Path(tmpdir) / "id:000001__deadbeef"
            sample_dir.mkdir(parents=True, exist_ok=True)

            payload = rewrite_triage_payload(
                sample_dir,
                oracle={
                    "bind9.stderr_parse_status": "ok",
                    "unbound.stderr_parse_status": "ok",
                    "bind9.parse_ok": True,
                    "unbound.parse_ok": True,
                    "bind9.resolver_fetch_started": True,
                    "unbound.resolver_fetch_started": True,
                    "bind9.response_accepted": True,
                    "unbound.response_accepted": True,
                    "bind9.second_query_hit": False,
                    "unbound.second_query_hit": False,
                    "bind9.cache_entry_created": False,
                    "unbound.cache_entry_created": False,
                    "bind9.timeout": False,
                    "unbound.timeout": False,
                },
                cache_diff={
                    "cache_delta_triggered": False,
                    "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
                    "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
                },
                fingerprint={
                    "bind9.forwarding_path": "iterative",
                    "unbound.forwarding_path": None,
                },
                existing_triage={
                    "sample_id": "id:000001__deadbeef",
                    "status": "completed_no_diff",
                    "diff_class": "no_diff",
                },
            )
            self.assertIn("partial_fingerprint", payload["filter_labels"])
            self.assertIn("forwarding_path_seen", payload["filter_labels"])
            self.assertEqual("completed_no_diff", payload["status"])


if __name__ == "__main__":
    unittest.main()
