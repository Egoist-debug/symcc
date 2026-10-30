import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.cache_diff import build_cache_diff
from tools.dns_diff.cache_parser import parse_cache_dump
from tools.dns_diff.follow_diff import _parse_cache_rows
from tools.dns_diff.triage import build_triage


class DnsDiffCacheDiffTest(unittest.TestCase):
    def test_shared_dump_semantics(self) -> None:
        root = Path(__file__).parent / "fixtures" / "cache_semantics"
        for line in (root / "cases.tsv").read_text().splitlines():
            case, lb, la, resolver, rb, ra, expected = line.split("\t")

            def rows(name, filename):
                return [] if filename == "-" else parse_cache_dump(name, root / filename)

            for triggered in (False, True):
                with self.subTest(case=case, triggered=triggered):
                    payload = build_cache_diff(
                        case, rows("bind9", lb), rows("bind9", la),
                        rows(resolver, rb), rows(resolver, ra), triggered,
                        secondary_resolver=resolver,
                    )
                    self.assertEqual(
                        "incomparable" if expected == "cache_comparison_incomplete" else "comparable",
                        payload["cache_comparison_status"],
                    )
                    oracle = {}
                    for name in ("bind9", "unbound"):
                        oracle[f"{name}.stderr_parse_status"] = "ok"
                        oracle[f"{name}.timeout"] = False
                    triage = build_triage(case, oracle, payload, {})
                    self.assertEqual(expected, triage["diff_class"])
                    self.assertEqual(expected == "cache_diff_interesting", triage["case_study_candidate"])
                    self.assertEqual(
                        "unknown" if expected == "cache_comparison_incomplete" else "included",
                        triage["analysis_state"],
                    )
                    if la == "bind.cache":
                        self.assertEqual("300", payload["bind9"]["observations_after"][0]["ttl"])
                    if ra.startswith("smartdns"):
                        self.assertEqual("0", payload["unbound"]["observations_after"][0]["ttl"])
                        self.assertEqual("smartdns", payload["unbound"]["observations_after"][0]["resolver"])
                    if case == "metadata-before-delta":
                        self.assertTrue(payload["unbound"]["has_cache_diff"])
                        self.assertEqual([], payload["unbound"]["semantic_delta"])
                    if case.startswith("initial-mismatch"):
                        self.assertEqual("initial_state_mismatch", payload["cache_comparison_reason"])
                        self.assertFalse(payload["diff_detected"])
                        self.assertEqual([], payload["resolver_diffs"])
                        self.assertEqual([], payload["bind9"]["semantic_delta"])
                        self.assertEqual(case.endswith("same-final"), bool(payload["unbound"]["semantic_delta"]))

    def test_legacy_cache_evidence_is_unknown(self) -> None:
        oracle = {f"{r}.stderr_parse_status": "ok" for r in ("bind9", "unbound")}
        triage = build_triage("legacy", oracle, {"bind9": {"has_cache_diff": True}}, {})
        self.assertEqual("unknown", triage["analysis_state"])
        self.assertFalse(triage["case_study_candidate"])

    def test_partial_comparison_contract_is_unknown(self) -> None:
        oracle = {f"{r}.stderr_parse_status": "ok" for r in ("bind9", "unbound")}
        rows = [("bind9", "_", "example.com.", "A", "A", "RRSET",
                 "rrset", "60", "192.0.2.1", "class=IN")]
        for field in ("cache_comparison_version", "cache_comparison_status"):
            with self.subTest(field=field):
                cache = build_cache_diff("legacy", [], rows, [], [], True)
                del cache[field]
                triage = build_triage("legacy", oracle, cache, {})
                self.assertEqual("unknown", triage["analysis_state"])
                self.assertFalse(triage["case_study_candidate"])

    def test_missing_snapshot_is_not_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = _parse_cache_rows("bind9", Path(directory) / "missing.cache")
            corrupt = Path(directory) / "corrupt.cache"
            corrupt.write_bytes(b"truncated")
            self.assertIsNone(_parse_cache_rows("smartdns", corrupt))
            empty = Path(directory) / "empty.cache"
            empty.write_bytes(b"")
            self.assertIsNone(_parse_cache_rows("bind9", empty))
            empty.write_text("; Cache dump of view '_default'\n")
            self.assertEqual([], _parse_cache_rows("bind9", empty))
        self.assertIsNone(rows)
        payload = build_cache_diff("missing", rows, [], [], [], True)
        self.assertEqual("unknown", payload["cache_comparison_status"])
        self.assertFalse(payload["diff_detected"])

    def test_ttl_only_change_is_not_structural_diff(self) -> None:
        before = [
            (
                "bind9",
                "_default",
                "example.com.",
                "A",
                "A",
                "RRSET",
                "rrset",
                "300",
                "1.2.3.4",
                "class=IN",
            )
        ]
        after = [
            (
                "bind9",
                "_default",
                "example.com.",
                "A",
                "A",
                "RRSET",
                "rrset",
                "299",
                "1.2.3.4",
                "class=IN",
            )
        ]
        payload = build_cache_diff("sample-1", before, after, [], [], triggered=True)
        self.assertFalse(payload["bind9"]["has_cache_diff"])
        self.assertEqual(0, payload["bind9"]["interesting_delta_count"])
        self.assertEqual([], payload["bind9"]["delta_items"])

    def test_triggered_diff_has_delta_items(self) -> None:
        bind_before = []
        bind_after = [
            (
                "bind9",
                "_default",
                "example.com.",
                "A",
                "A",
                "RRSET",
                "rrset",
                "300",
                "1.2.3.4",
                "class=IN",
            )
        ]
        payload = build_cache_diff(
            "sample-2",
            bind_before,
            bind_after,
            [],
            [],
            triggered=True,
        )
        self.assertTrue(payload["cache_delta_triggered"])
        self.assertTrue(payload["bind9"]["has_cache_diff"])
        self.assertEqual(1, payload["bind9"]["interesting_delta_count"])
        self.assertEqual("added", payload["bind9"]["delta_items"][0]["kind"])


if __name__ == "__main__":
    unittest.main()
