import unittest

from tools.dns_diff.cache_diff import build_cache_diff


class DnsDiffCacheDiffTest(unittest.TestCase):
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
