import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.rq3_snapshot import RQ3SnapshotError, run_rq3_snapshot


class RQ3SnapshotTest(unittest.TestCase):
    def test_legacy_single_run_and_missing_cells_are_normalized_only_in_new_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "legacy.tsv"
            header = ["variant_name", "run_count", "variance_status", "total_samples_mean",
                      "total_samples_sample_stddev", "total_samples_ci95_lower",
                      "total_samples_ci95_upper"]
            data = io.StringIO()
            writer = csv.writer(data, delimiter="\t")
            writer.writerow(header)
            writer.writerows([
                ["full_stack", 1, "insufficient_runs", 0, 0, 0, 0],
                ["afl_only", 1, "ok", 8, 0, 8, 8],
                ["no_mutator", 2, "ok", 8, 2, 1, 15],
                ["no_cache_delta", 2, "ok", "", "nan", "bad", "inf"],
                ["full_stack", "", "", 0, 0, 0, 0],
                ["afl_only", 2, "insufficient_runs", 0, 0, 0, 0],
            ])
            source.write_text(data.getvalue())
            original = source.read_bytes()
            self.assertEqual(run_rq3_snapshot(resolver_variant_summary_tsv=source,
                                             output_dir=root / "out"), 0)
            payload = json.loads((root / "out/rq3_hybrid_snapshot.json").read_text())
            rows = list(csv.DictReader((root / "out/rq3_hybrid_snapshot.tsv").read_text().splitlines(), delimiter="\t"))
            self.assertEqual(rows, payload["rows"])
            self.assertEqual(source.read_bytes(), original)
            for index in (0, 1, 4, 5):
                for column in header[3:]:
                    self.assertEqual(rows[index][column], "NA")
            self.assertEqual(rows[2]["total_samples_mean"], "8")
            self.assertEqual(rows[2]["total_samples_sample_stddev"], "2")
            self.assertEqual(rows[2]["total_samples_ci95_lower"], "1")
            for column in header[3:]:
                self.assertEqual(rows[3][column], "NA")
            self.assertEqual(rows[2]["cluster_count_mean"], "NA")
            self.assertEqual(rows[1]["variance_status"], "insufficient_runs")
            self.assertEqual(rows[4]["variance_status"], "unknown")
            self.assertEqual(rows[4]["run_count"], "NA")

    def test_short_row_and_source_output_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "rq3_hybrid_snapshot.tsv"
            original = "variant_name\trun_count\tvariance_status\nfull_stack\n"
            source.write_text(original)
            self.assertEqual(run_rq3_snapshot(
                resolver_variant_summary_tsv=source, output_dir=root / "out",
            ), 0)
            payload = json.loads((root / "out/rq3_hybrid_snapshot.json").read_text())
            self.assertEqual(payload["rows"][0]["run_count"], "NA")
            with self.assertRaises(RQ3SnapshotError):
                run_rq3_snapshot(resolver_variant_summary_tsv=source, output_dir=root)
            self.assertEqual(source.read_text(), original)


if __name__ == "__main__":
    unittest.main()
