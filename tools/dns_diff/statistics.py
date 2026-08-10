import math
from typing import Any, Dict, Sequence

CONFIDENCE_LEVEL = 0.95
CONFIDENCE_INTERVAL_METHOD = "student_t_df_le_30_normal_asymptotic"
SAMPLE_STDDEV_DENOMINATOR = "n-1"
LEGACY_STDDEV_SEMANTICS = "population"


class StatisticsError(ValueError):
    pass


# 双侧 95% Student-t 临界值；自由度超过 30 时使用正态近似。
_T_CRITICAL_95 = (
    0.0,
    12.706,
    4.303,
    3.182,
    2.776,
    2.571,
    2.447,
    2.365,
    2.306,
    2.262,
    2.228,
    2.201,
    2.179,
    2.160,
    2.145,
    2.131,
    2.120,
    2.110,
    2.101,
    2.093,
    2.086,
    2.080,
    2.074,
    2.069,
    2.064,
    2.060,
    2.056,
    2.052,
    2.048,
    2.045,
    2.042,
)


def _student_t_critical_95(degrees_of_freedom: int) -> float:
    if degrees_of_freedom < 1:
        raise StatisticsError("Student-t 自由度必须大于等于 1")
    if degrees_of_freedom < len(_T_CRITICAL_95):
        return _T_CRITICAL_95[degrees_of_freedom]
    return 1.96


def compute_metric_statistics(values: Sequence[float]) -> Dict[str, float]:
    if not values:
        raise StatisticsError("统计指标不能为空")
    if any(not math.isfinite(value) for value in values):
        raise StatisticsError("统计指标必须全部为有限数值")

    count = len(values)
    mean = sum(values) / count
    squared_deviations = sum((value - mean) ** 2 for value in values)
    population_stddev = math.sqrt(squared_deviations / count)

    if count == 1:
        sample_stddev = 0.0
        standard_error = 0.0
        ci95_lower = mean
        ci95_upper = mean
    else:
        sample_stddev = math.sqrt(squared_deviations / (count - 1))
        standard_error = sample_stddev / math.sqrt(count)
        margin = _student_t_critical_95(count - 1) * standard_error
        ci95_lower = mean - margin
        ci95_upper = mean + margin

    return {
        "count": float(count),
        "mean": mean,
        "min": min(values),
        "max": max(values),
        # 保留历史 population stddev 语义，避免既有结果表静默漂移。
        "stddev": population_stddev,
        "sample_stddev": sample_stddev,
        "standard_error": standard_error,
        "ci95_lower": ci95_lower,
        "ci95_upper": ci95_upper,
    }


def statistics_contract() -> Dict[str, Any]:
    return {
        "confidence_level": CONFIDENCE_LEVEL,
        "confidence_interval_method": CONFIDENCE_INTERVAL_METHOD,
        "sample_stddev_denominator": SAMPLE_STDDEV_DENOMINATOR,
        "legacy_stddev_semantics": LEGACY_STDDEV_SEMANTICS,
    }


__all__ = [
    "CONFIDENCE_INTERVAL_METHOD",
    "CONFIDENCE_LEVEL",
    "LEGACY_STDDEV_SEMANTICS",
    "SAMPLE_STDDEV_DENOMINATOR",
    "StatisticsError",
    "compute_metric_statistics",
    "statistics_contract",
]
