import json
import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.io import atomic_write_json, load_json_with_fallback


class DnsDiffIoTest(unittest.TestCase):
    def test_load_json_with_fallback_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = Path(tmpdir) / "missing.json"
            result = load_json_with_fallback(missing_path)
            self.assertTrue(result.downgraded)
            self.assertEqual("missing", result.status)
            self.assertEqual({}, result.data)

    def test_load_json_with_fallback_corrupt_and_type_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            corrupt_path = Path(tmpdir) / "corrupt.json"
            corrupt_path.write_text("{broken", encoding="utf-8")
            corrupt = load_json_with_fallback(corrupt_path)
            self.assertTrue(corrupt.downgraded)
            self.assertEqual("corrupt_fallback", corrupt.status)
            self.assertEqual({}, corrupt.data)

            mismatch_path = Path(tmpdir) / "mismatch.json"
            mismatch_path.write_text("[]", encoding="utf-8")
            mismatch = load_json_with_fallback(mismatch_path)
            self.assertTrue(mismatch.downgraded)
            self.assertEqual("type_mismatch_fallback", mismatch.status)
            self.assertEqual({}, mismatch.data)

    def test_atomic_write_json_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "state.json"
            payload = {"key": "值", "count": 3}
            atomic_write_json(output_path, payload)
            text = output_path.read_text(encoding="utf-8")
            self.assertTrue(text.endswith("\n"))
            self.assertEqual(payload, json.loads(text))


if __name__ == "__main__":
    unittest.main()
