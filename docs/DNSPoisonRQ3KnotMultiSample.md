# DNS Poison RQ3 knot-resolver 多样本消融结果

## 文档目的

本文档记录当前 `knot-resolver` 上已经完成的 RQ3 多样本消融主表。它回答的是第三个局部问题：在 `queue_limit=8`、`repeat=5`、`budget_sec=120` 的真实批次里，`knot-resolver` 上的四个 Hybrid 变体是否已经拉开结果差异。

## 当前真实批次

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260529_094512/knot`
- 当前已完成并可直接引用的变体：
  - `full_stack`
  - `afl_only`
  - `no_mutator`
  - `no_cache_delta`
- repo 内正式表：
  - [RQ3KnotVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3KnotVariantSummary.tsv)

## 主表结论

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |

## 当前可直接写入论文的表述

> 在 `knot-resolver` 上，`full_stack / afl_only / no_mutator / no_cache_delta` 四个变体都完成了 `repeat=5` 的稳定重复，并且在当前 `queue_limit=8`、`budget_sec=120` 的样本池上全部收敛到 `no_diff`。这说明 `knot-resolver` 当前不仅是 RQ5 的稳定负对照，在 RQ3 的变体消融里也保持了稳定负对照属性。

## 当前意义

这轮结果把 RQ3 当前的保守结论补成了三条真实路径：

- `dnsmasq` 与 `maradns` 的四个变体都稳定落为 `oracle_diff`
- `knot-resolver` 的四个变体都稳定落为 `no_diff`
- 当前稳定 transcript 主表里，还看不出 `SYMCC / mutator / cache-delta` 改变主导语义分布

## 结论边界

当前仍不能写成以下强结论：

- `SYMCC` 在所有 resolver 上都没有作用
- `DST1 mutator` 在当前系统中没有价值
- `cache-delta` 对任何真实场景都不重要

当前更稳妥的结论是：

- 在当前 `knot-resolver + queue_limit=8 + repeat=5 + budget_sec=120` 批次里，四个变体语义结果一致
- RQ3 的增益验证还需要补“无 high-value gate”对照，并扩大预算
