# DNS Poison RQ3 dnsmasq 多样本消融结果

## 文档目的

本文档记录当前 `dnsmasq` 上已经完成的 RQ3 多样本消融主表。它回答的是一个局部问题：在 `queue_limit=8`、`repeat=5`、`budget_sec=120` 的真实批次里，四个 Hybrid 变体是否已经拉开结果差异。

## 当前真实批次

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260529_094512/dnsmasq`
- 当前已完成并可直接引用的变体：
  - `full_stack`
  - `afl_only`
  - `no_mutator`
  - `no_cache_delta`
- repo 内正式表：
  - [RQ3DnsmasqVariantSummary.tsv](./RQ3DnsmasqVariantSummary.tsv)

## 主表结论

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |

## 当前可直接写入论文的表述

> 在 `dnsmasq` 上，`full_stack / afl_only / no_mutator / no_cache_delta` 四个变体均完成了 `repeat=5` 的稳定重复，并且在当前 `queue_limit=8`、`budget_sec=120` 的样本池上都收敛到相同的 `oracle_diff` 语义结果。也就是说，在这轮真实批次里，关闭 `SYMCC`、关闭 `DST1 mutator` 或关闭 `cache-delta` 尚未改变 `dnsmasq` 的主导语义分布，当前样本池还看不出明显的 hybrid 增益。

## 当前意义

这轮结果已经从单样本 smoke 推进到多样本消融，但它更适合支持以下表述：

- 当前 `dnsmasq` 批次里，四个变体结果没有拉开差距
- `queue_limit=8`、`budget_sec=120` 样本池下，Hybrid 组件的边际收益还没被稳定观测到
- 后续需要补“无 high-value gate”对照或提升到长期预算，再判断增益

## 结论边界

当前不应写成以下强结论：

- `SYMCC` 没有作用
- `DST1 mutator` 没有增益
- `cache-delta` 没有价值

当前更稳妥的结论是：

- 在当前 `dnsmasq + queue_limit=8 + repeat=5 + budget_sec=120` 批次里，四个变体语义结果一致
- RQ3 还需要 gate 对照与长期预算来验证是否存在稳定增益

## 下一步

1. 在当前 `dnsmasq / maradns / knot-resolver / unbound / smartdns` 主表之上补“无 high-value gate”对照
2. 将预算提升到 `600s+`，观察四个变体是否开始分化
3. 将当前结果和 `RQ5` 主表一起写成论文正文里的“工程闭环 + 变体无显著差异”双重结论
