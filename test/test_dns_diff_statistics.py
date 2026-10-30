import csv
import json
import math
import tempfile
import unittest
from pathlib import Path

from tools.dns_diff import matrix
from tools.dns_diff.aggregate import (
    CampaignAggregateError, METRIC_NAMES, _extract_metrics,
    _write_variance_tsv, run_campaign_aggregate,
)
from tools.dns_diff.statistics import StatisticsError, compute_metric_statistics


def valid_summary():
    return {
        "total_samples": 2, "needs_review_count": 0, "cluster_count": 0,
        "repro_rate": 0.5, "oracle_audit_candidate_count": 0, "semantic_diff_count": 0,
        "metric_denominators": {"analysis_state": {"included": 2, "excluded": 0, "unknown": 0}},
        "comparability": {"aggregation_key": {"variant_name": "test"}},
    }


class StatisticsMissingValueTest(unittest.TestCase):
    def test_single_run_has_no_sample_inference_and_tsv_uses_na(self):
        stats = compute_metric_statistics([7.0])
        self.assertEqual(stats["mean"], 7)
        self.assertEqual(stats["stddev"], 0)
        for field in ("sample_stddev", "standard_error", "ci95_lower", "ci95_upper"):
            self.assertIsNone(stats[field])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_variance_tsv(root, variance_status="ok", aggregates={"total_samples": stats})
            row = next(csv.DictReader((root / "variance.tsv").read_text().splitlines(), delimiter="\t"))
            self.assertEqual(row["ci95_lower"], "NA")
            self.assertEqual(row["sample_stddev"], "NA")

    def test_multi_run_and_invalid_stat_inputs(self):
        stats = compute_metric_statistics([10.0, 20.0])
        self.assertEqual(stats["mean"], 15)
        self.assertAlmostEqual(stats["sample_stddev"], math.sqrt(50))
        self.assertAlmostEqual(stats["ci95_lower"], -48.53)
        for values in ([], [None], [True], ["bad"], [math.nan], [math.inf]):
            with self.subTest(values=values), self.assertRaises(StatisticsError):
                compute_metric_statistics(values)

    def test_missing_and_invalid_metrics_are_unknown_not_zero(self):
        self.assertTrue(all(math.isnan(v) for v in _extract_metrics({}).values()))
        for invalid in (None, True, -1, "bad", math.inf, math.nan, 0.5):
            payload = valid_summary()
            payload["cluster_count"] = invalid
            with self.subTest(invalid=invalid):
                self.assertTrue(math.isnan(_extract_metrics(payload)["cluster_count"]))
        for invalid in (None, True, -0.1, 1.1, "bad", math.inf):
            payload = valid_summary()
            payload["repro_rate"] = invalid
            with self.subTest(rate=invalid):
                self.assertTrue(math.isnan(_extract_metrics(payload)["repro_rate"]))
        self.assertEqual(_extract_metrics(valid_summary())["cluster_count"], 0)

    def test_public_aggregate_rejects_missing_metrics_and_preserves_sources(self):
        for missing in ("repro_rate", "cluster_count", "metric_denominators"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                reports = root / "reports"
                original = {}
                for index in range(2):
                    path = reports / str(index) / "summary.json"
                    path.parent.mkdir(parents=True)
                    payload = valid_summary()
                    if index == 0:
                        payload.pop(missing)
                    path.write_text(json.dumps(payload))
                    original[path] = path.read_bytes()
                with self.assertRaises(CampaignAggregateError):
                    run_campaign_aggregate(reports, root / "out")
                out = next((root / "out/campaign_aggregates").iterdir())
                summary = json.loads((out / "summary.json").read_text())
                self.assertEqual(summary["variance_status"], "missing_metrics")
                self.assertEqual(summary["aggregates"], {})
                rows = list(csv.DictReader((out / "run_matrix.tsv").read_text().splitlines(), delimiter="\t"))
                field = "included_samples" if missing == "metric_denominators" else missing
                self.assertEqual(rows[0][field], "NA")
                self.assertIn(field, summary["missing_metrics"]["0"])
                for path, data in original.items():
                    self.assertEqual(path.read_bytes(), data)

    def test_matrix_missing_metrics_and_nullable_statistics_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            aggregates = {}
            for name, env in matrix.EXPECTED_VARIANT_ENVS.items():
                records = []
                for index in range(2):
                    summary = valid_summary()
                    if name == "afl_only":
                        summary.pop("repro_rate")
                    records.append(matrix.MatrixRunRecord(
                        name, index, root / str(index), root, root / "summary.json",
                        root / "close.json", summary,
                    ))
                aggregate = matrix._aggregate_variant(matrix.MatrixVariant(name, env), records)
                aggregates[name] = aggregate
            self.assertEqual(aggregates["afl_only"].variance_status, "missing_metrics")
            self.assertEqual(aggregates["afl_only"].aggregates, {})
            self.assertEqual(aggregates["full_stack"].variance_status, "ok")
            # 同时覆盖旧统计字典缺字段，以及共享统计显式 None。
            aggregates["no_mutator"].aggregates["total_samples"] = {"mean": 7.0}
            aggregates["no_cache_delta"].aggregates["total_samples"] = compute_metric_statistics([7.0])
            matrix._write_variant_summary_tsv(root, aggregates)
            rows = list(csv.DictReader((root / "variant_summary.tsv").read_text().splitlines(), delimiter="\t"))
            self.assertEqual(rows[0]["total_samples_mean"], "2.000000")
            self.assertEqual(rows[0]["total_samples_ci95_lower"], "2.000000")
            for index in (1, 2, 3):
                self.assertEqual(rows[index]["total_samples_sample_stddev"], "NA")
                self.assertEqual(rows[index]["total_samples_ci95_lower"], "NA")

    def test_matrix_delta_does_not_invent_missing_mean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            aggregates = {}
            for name, env in matrix.EXPECTED_VARIANT_ENVS.items():
                aggregates[name] = matrix.VariantAggregate(
                    name, env, (), 2, "ok", {}, {"shared": "key"}, "ok",
                    {"total_samples": {"mean": 2.0}},
                )
            aggregates["afl_only"].aggregates["total_samples"] = {}
            aggregates["no_mutator"].aggregates["total_samples"] = {"mean": None}
            matrix._write_delta_vs_baseline_tsv(
                root, baseline=aggregates["full_stack"], aggregates_by_variant=aggregates,
            )
            rows = list(csv.DictReader((root / "delta_vs_baseline.tsv").read_text().splitlines(), delimiter="\t"))
            totals = [row for row in rows if row["metric"] == "total_samples"]
            for row in totals[:2]:
                self.assertEqual(row["variant_mean"], "NA")
                self.assertEqual(row["delta"], "NA")
            self.assertEqual(totals[2]["delta"], "0.000000")


if __name__ == "__main__":
    unittest.main()
