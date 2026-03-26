#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

python3 - "$ROOT_DIR" <<'PY'
import json
import os
import pathlib
import tempfile
from contextlib import contextmanager

from tools.dns_diff import matrix as matrix_module
from tools.dns_diff.cli import main as cli_main


ROOT_DIR = pathlib.Path(os.environ["PYTHONPATH"].split(":", 1)[0]).resolve()
DEFAULT_MATRIX_FILE = (
    ROOT_DIR / "tools" / "dns_diff" / "config" / "poison_stateful_longbudget_matrix.json"
)
EXPECTED_ENV = {
    "full_stack": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
    "afl_only": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "0",
    },
    "no_mutator": {
        "ENABLE_DST1_MUTATOR": "0",
        "ENABLE_CACHE_DELTA": "1",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
    "no_cache_delta": {
        "ENABLE_DST1_MUTATOR": "1",
        "ENABLE_CACHE_DELTA": "0",
        "ENABLE_TRIAGE": "1",
        "ENABLE_SYMCC": "1",
    },
}
VARIANT_ORDER = ["full_stack", "afl_only", "no_mutator", "no_cache_delta"]


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ASSERT FAIL: {message}")


def detect_variant(env: dict[str, str]) -> str:
    for variant_name, expected in EXPECTED_ENV.items():
        if all(env.get(key) == value for key, value in expected.items()):
            return variant_name
    raise SystemExit(f"ASSERT FAIL: 无法从 env 识别变体: {env!r}")


def repeat_index_from_work_dir(work_dir: pathlib.Path) -> int:
    return int(work_dir.name.split("-", 1)[1])


def write_summary(report_dir: pathlib.Path, payload: dict) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def base_summary(total_samples: int, cluster_count: int, repro_rate: float) -> dict:
    included = max(total_samples - 3, 0)
    return {
        "total_samples": total_samples,
        "needs_review_count": 2,
        "cluster_count": cluster_count,
        "repro_rate": repro_rate,
        "oracle_audit_candidate_count": 5,
        "semantic_counts": {
            "no_diff": max(total_samples - 2, 0),
            "cache_diff_interesting": 2,
        },
        "metric_denominators": {
            "analysis_state": {
                "included": included,
                "excluded": 1,
                "unknown": 2,
            }
        },
    }


def expected_source_queue_dir(work_root: pathlib.Path) -> str:
    return str((work_root / "afl_out" / "master" / "queue").resolve())


def expected_aggregation_key(
    *,
    work_root: pathlib.Path,
    variant_name: str,
    budget_sec: int,
) -> dict:
    env = EXPECTED_ENV[variant_name]
    return {
        "resolver_pair": "bind9_vs_unbound",
        "producer_profile": "poison-stateful",
        "input_model": "DST1 transcript",
        "source_queue_dir": expected_source_queue_dir(work_root),
        "budget_sec": budget_sec,
        "seed_timeout_sec": 1,
        "variant_name": variant_name,
        "ablation_status": {
            "mutator": "on" if env["ENABLE_DST1_MUTATOR"] == "1" else "off",
            "cache-delta": "on" if env["ENABLE_CACHE_DELTA"] == "1" else "off",
            "triage": "on" if env["ENABLE_TRIAGE"] == "1" else "off",
            "symcc": "on" if env["ENABLE_SYMCC"] == "1" else "off",
        },
        "contract_version": 1,
    }


def expected_baseline_compare_key(
    *, work_root: pathlib.Path, budget_sec: int, repeat_count: int
) -> dict:
    return {
        "resolver_pair": "bind9_vs_unbound",
        "producer_profile": "poison-stateful",
        "input_model": "DST1 transcript",
        "source_queue_dir": expected_source_queue_dir(work_root),
        "budget_sec": budget_sec,
        "seed_timeout_sec": 1,
        "repeat_count": repeat_count,
        "contract_version": 1,
    }


@contextmanager
def patched_close(fake_close):
    original = matrix_module.run_campaign_close
    matrix_module.run_campaign_close = fake_close
    try:
        yield
    finally:
        matrix_module.run_campaign_close = original


def run_comparable_scenario() -> None:
    with tempfile.TemporaryDirectory(prefix="symcc-campaign-matrix-ok.") as tmp:
        work_root = pathlib.Path(tmp)
        queue_dir = work_root / "afl_out" / "master" / "queue"
        queue_dir.mkdir(parents=True, exist_ok=True)
        invocation_log = work_root / "invocations.log"

        totals = {
            "full_stack": [100, 110],
            "afl_only": [80, 90],
            "no_mutator": [95, 100],
            "no_cache_delta": [92, 96],
        }
        clusters = {
            "full_stack": [20, 22],
            "afl_only": [15, 18],
            "no_mutator": [18, 19],
            "no_cache_delta": [17, 18],
        }
        repro_rates = {
            "full_stack": [0.6, 0.7],
            "afl_only": [0.4, 0.5],
            "no_mutator": [0.55, 0.58],
            "no_cache_delta": [0.52, 0.54],
        }

        def fake_close(*, budget_sec: float) -> int:
            env = dict(os.environ)
            variant_name = detect_variant(env)
            work_dir = pathlib.Path(env["WORK_DIR"])
            repeat_index = repeat_index_from_work_dir(work_dir)
            with invocation_log.open("a", encoding="utf-8") as handle:
                handle.write(f"{variant_name}\trun-{repeat_index:02d}\n")

            summary = base_summary(
                totals[variant_name][repeat_index - 1],
                clusters[variant_name][repeat_index - 1],
                repro_rates[variant_name][repeat_index - 1],
            )
            summary["comparability"] = {
                "status": "comparable",
                "reason": "ok",
                "aggregation_key": expected_aggregation_key(
                    work_root=work_root,
                    variant_name=variant_name,
                    budget_sec=5,
                ),
                "baseline_compare_key": expected_baseline_compare_key(
                    work_root=work_root,
                    budget_sec=5,
                    repeat_count=2,
                ),
            }
            report_dir = work_dir / "campaign_reports" / f"report-{repeat_index:02d}"
            write_summary(report_dir, summary)
            (work_dir / "campaign_close.summary.json").write_text(
                json.dumps({"status": "success"}, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            return 0

        with patched_close(fake_close):
            exit_code = cli_main(
                [
                    "campaign-matrix",
                    "--matrix-file",
                    str(DEFAULT_MATRIX_FILE),
                    "--budget-sec",
                    "5",
                    "--repeat",
                    "2",
                    "--work-root",
                    str(work_root),
                ]
            )
        assert_true(exit_code == 0, f"可比场景 exit_code={exit_code!r} != 0")

        summary_root = work_root / "_summary"
        manifest_path = summary_root / "matrix_manifest.json"
        variant_summary_path = summary_root / "variant_summary.tsv"
        delta_path = summary_root / "delta_vs_baseline.tsv"
        comparability_path = summary_root / "comparability.tsv"
        for path in (manifest_path, variant_summary_path, delta_path, comparability_path):
            assert_true(path.is_file(), f"缺少输出文件 {path}")

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert_true(
            manifest.get("baseline_variant_name") == "full_stack",
            f"manifest baseline_variant_name 非预期: {manifest.get('baseline_variant_name')!r}",
        )
        assert_true(
            manifest.get("matrix_internal_baseline_variant") == "full_stack",
            "manifest 未显式标记 matrix_internal_baseline_variant=full_stack",
        )
        variants = manifest.get("variants")
        assert_true(isinstance(variants, list) and len(variants) == 4, "manifest 变体数非法")
        assert_true(
            [item.get("variant_name") for item in variants] == VARIANT_ORDER,
            f"manifest 变体顺序非法: {variants!r}",
        )
        for item in variants:
            variant_name = item["variant_name"]
            assert_true(item.get("repeat_count") == 2, f"{variant_name} repeat_count 非 2")
            assert_true(item.get("env") == EXPECTED_ENV[variant_name], f"{variant_name} env 非预期")
            runs = item.get("runs")
            assert_true(isinstance(runs, list) and len(runs) == 2, f"{variant_name} runs 非 2 条")

        invocation_lines = invocation_log.read_text(encoding="utf-8").splitlines()
        expected_invocation_lines = [
            "full_stack\trun-01",
            "full_stack\trun-02",
            "afl_only\trun-01",
            "afl_only\trun-02",
            "no_mutator\trun-01",
            "no_mutator\trun-02",
            "no_cache_delta\trun-01",
            "no_cache_delta\trun-02",
        ]
        assert_true(
            invocation_lines == expected_invocation_lines,
            f"串行执行顺序非法: {invocation_lines!r}",
        )

        variant_summary_lines = variant_summary_path.read_text(encoding="utf-8").splitlines()
        assert_true(any("full_stack" in line for line in variant_summary_lines), "variant_summary 缺少 full_stack")
        assert_true(any("afl_only" in line for line in variant_summary_lines), "variant_summary 缺少 afl_only")

        comparability_lines = comparability_path.read_text(encoding="utf-8").splitlines()
        assert_true(
            any("full_stack\t2\tok\tbaseline\tbaseline" in line for line in comparability_lines),
            "comparability 缺少 full_stack baseline 行",
        )
        assert_true(
            any("afl_only\t2\tok\tok\tok\tsymcc" in line for line in comparability_lines),
            "comparability 缺少 afl_only baseline-delta=ok 行",
        )

        delta_lines = delta_path.read_text(encoding="utf-8").splitlines()
        assert_true(
            delta_lines[0]
            == "baseline_variant\tvariant_name\tmetric\tstatus\treason\ttoggle_diff_field\tbaseline_mean\tvariant_mean\tdelta\tbaseline_variant_scope",
            f"delta_vs_baseline 表头非预期: {delta_lines[0]!r}",
        )
        assert_true(
            all(line.endswith("\tmatrix_internal") for line in delta_lines[1:]),
            "delta_vs_baseline 数据行未显式标记 matrix_internal baseline",
        )
        expected_total_delta = "full_stack\tafl_only\ttotal_samples\tok\tok\tsymcc\t105.000000\t85.000000\t-20.000000\tmatrix_internal"
        assert_true(
            expected_total_delta in delta_lines,
            f"delta_vs_baseline 缺少预期 total_samples delta 行: {expected_total_delta}",
        )
        expected_cache_delta = "full_stack\tno_cache_delta\tcluster_count\tok\tok\tcache-delta\t21.000000\t17.500000\t-3.500000\tmatrix_internal"
        assert_true(
            expected_cache_delta in delta_lines,
            f"delta_vs_baseline 缺少预期 cluster_count delta 行: {expected_cache_delta}",
        )


def run_non_comparable_scenario() -> None:
    with tempfile.TemporaryDirectory(prefix="symcc-campaign-matrix-nc.") as tmp:
        work_root = pathlib.Path(tmp)
        queue_dir = work_root / "afl_out" / "master" / "queue"
        queue_dir.mkdir(parents=True, exist_ok=True)

        def fake_close(*, budget_sec: float) -> int:
            env = dict(os.environ)
            variant_name = detect_variant(env)
            work_dir = pathlib.Path(env["WORK_DIR"])
            repeat_index = repeat_index_from_work_dir(work_dir)
            summary = base_summary(50 + repeat_index, 10 + repeat_index, 0.5)

            baseline_key = expected_baseline_compare_key(
                work_root=work_root,
                budget_sec=5,
                repeat_count=2,
            )
            if variant_name == "afl_only":
                baseline_key = dict(baseline_key)
                baseline_key["source_queue_dir"] = "/tmp/non-comparable-queue"

            summary["comparability"] = {
                "status": "comparable",
                "reason": "ok",
                "aggregation_key": expected_aggregation_key(
                    work_root=work_root,
                    variant_name=variant_name,
                    budget_sec=5,
                ),
                "baseline_compare_key": baseline_key,
            }
            report_dir = work_dir / "campaign_reports" / f"report-{repeat_index:02d}"
            write_summary(report_dir, summary)
            (work_dir / "campaign_close.summary.json").write_text(
                json.dumps({"status": "success"}, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            return 0

        with patched_close(fake_close):
            exit_code = cli_main(
                [
                    "campaign-matrix",
                    "--matrix-file",
                    str(DEFAULT_MATRIX_FILE),
                    "--budget-sec",
                    "5",
                    "--repeat",
                    "2",
                    "--work-root",
                    str(work_root),
                ]
            )
        assert_true(exit_code == 0, f"non-comparable 场景 exit_code={exit_code!r} != 0")

        summary_root = work_root / "_summary"
        delta_lines = (summary_root / "delta_vs_baseline.tsv").read_text(
            encoding="utf-8"
        ).splitlines()
        comparability_lines = (summary_root / "comparability.tsv").read_text(
            encoding="utf-8"
        ).splitlines()

        expected_status_line = (
            "full_stack\tafl_only\ttotal_samples\tnon-comparable\tbaseline_compare_key_mismatch\tsymcc\t\t\t\tmatrix_internal"
        )
        assert_true(
            expected_status_line in delta_lines,
            "delta_vs_baseline 未正确标记 afl_only non-comparable",
        )
        assert_true(
            any(
                "afl_only\t2\tok\tnon-comparable\tbaseline_compare_key_mismatch\tsymcc"
                in line
                for line in comparability_lines
            ),
            "comparability 未正确标记 afl_only baseline_compare_key mismatch",
        )


def run_missing_comparability_scenario() -> None:
    with tempfile.TemporaryDirectory(prefix="symcc-campaign-matrix-missing-meta.") as tmp:
        work_root = pathlib.Path(tmp)
        queue_dir = work_root / "afl_out" / "master" / "queue"
        queue_dir.mkdir(parents=True, exist_ok=True)

        def fake_close(*, budget_sec: float) -> int:
            env = dict(os.environ)
            variant_name = detect_variant(env)
            work_dir = pathlib.Path(env["WORK_DIR"])
            repeat_index = repeat_index_from_work_dir(work_dir)
            summary = base_summary(70 + repeat_index, 12 + repeat_index, 0.45)

            if variant_name != "afl_only":
                summary["comparability"] = {
                    "status": "comparable",
                    "reason": "ok",
                    "aggregation_key": expected_aggregation_key(
                        work_root=work_root,
                        variant_name=variant_name,
                        budget_sec=5,
                    ),
                    "baseline_compare_key": expected_baseline_compare_key(
                        work_root=work_root,
                        budget_sec=5,
                        repeat_count=2,
                    ),
                }

            report_dir = work_dir / "campaign_reports" / f"report-{repeat_index:02d}"
            write_summary(report_dir, summary)
            (work_dir / "campaign_close.summary.json").write_text(
                json.dumps({"status": "success"}, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            return 0

        with patched_close(fake_close):
            exit_code = cli_main(
                [
                    "campaign-matrix",
                    "--matrix-file",
                    str(DEFAULT_MATRIX_FILE),
                    "--budget-sec",
                    "5",
                    "--repeat",
                    "2",
                    "--work-root",
                    str(work_root),
                ]
            )
        assert_true(exit_code == 0, f"missing comparability 场景 exit_code={exit_code!r} != 0")

        summary_root = work_root / "_summary"
        delta_lines = (summary_root / "delta_vs_baseline.tsv").read_text(
            encoding="utf-8"
        ).splitlines()
        comparability_lines = (summary_root / "comparability.tsv").read_text(
            encoding="utf-8"
        ).splitlines()

        expected_missing_delta_line = (
            "full_stack\tafl_only\ttotal_samples\tnon-comparable\tmissing_comparability_metadata\tsymcc\t\t\t\tmatrix_internal"
        )
        assert_true(
            expected_missing_delta_line in delta_lines,
            "缺 comparability 时 delta_vs_baseline 未标记 non-comparable/missing_comparability_metadata",
        )
        assert_true(
            any(
                "afl_only\t2\tmissing_comparability_metadata\tnon-comparable\tmissing_comparability_metadata\tsymcc"
                in line
                for line in comparability_lines
            ),
            "comparability 未标记 afl_only missing_comparability_metadata",
        )


run_comparable_scenario()
run_non_comparable_scenario()
run_missing_comparability_scenario()
print("PASS: campaign matrix regression test passed")
PY
