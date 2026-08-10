# DNS Poison RQ3 maradns 多样本消融结果

## 文档目的

本文档记录当前 `maradns` 上已经完成的 RQ3 多样本消融主表。它回答的是第二个局部问题：在 `queue_limit=8`、`repeat=5`、`budget_sec=120` 的真实批次里，`maradns` 上的四个 Hybrid 变体是否已经拉开结果差异。

## 当前真实批次

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260529_094512/maradns`
- 当前已完成并可直接引用的变体：
  - `full_stack`
  - `afl_only`
  - `no_mutator`
  - `no_cache_delta`
- repo 内正式表：
  - [RQ3MaradnsVariantSummary.tsv](./RQ3MaradnsVariantSummary.tsv)

## 主表结论

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |

## 当前可直接写入论文的表述

> 在 `maradns` 上，`full_stack / afl_only / no_mutator / no_cache_delta` 四个变体同样完成了 `repeat=5` 的稳定重复，并且在当前 `queue_limit=8`、`budget_sec=120` 的样本池上都收敛到相同的 `oracle_diff` 语义结果。这说明 RQ3 当前观测到的“变体差异不显著”并不是 `dnsmasq` 单一路径的偶然现象，至少在 `maradns` 上也成立。

## 当前意义

这轮结果强化了 RQ3 当前的保守结论：

- 现在已经有五个 resolver (`dnsmasq`、`maradns`、`knot-resolver`、`unbound`、`smartdns`) 在相同主表口径下显示“四个变体结果一致”
- 当前样本池下，还看不出 `SYMCC / mutator / cache-delta` 的稳定增益
- 补 gate 对照和长期预算的收益高于继续重复相同中等预算配置

## 结论边界

当前仍不能写成以下强结论：

- `SYMCC` 在所有 resolver 上都没有作用
- `DST1 mutator` 在当前系统中没有价值
- `cache-delta` 不影响语义结果

当前更稳妥的结论是：

- 在当前 `maradns + queue_limit=8 + repeat=5 + budget_sec=120` 批次里，四个变体语义结果一致
- RQ3 的增益验证仍然需要 gate 对照或更长预算
