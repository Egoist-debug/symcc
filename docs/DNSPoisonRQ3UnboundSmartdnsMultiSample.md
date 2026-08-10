# DNS Poison RQ3 unbound/smartdns 多样本消融结果

## 文档目的

本文档记录 `unbound` 与 `smartdns` 在 RQ3 多样本消融中的补跑结果，并判断这批数据作为论文数据是否足够、是否合理。它补齐此前 RQ3 只覆盖 `dnsmasq / maradns / knot-resolver` 的空白，使当前 `queue_limit=8`、`repeat=5`、`budget_sec=120` 口径覆盖 5 个 secondary resolver。

## 当前真实批次

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260603_121445`
- 当前完成的 resolver：
  - `unbound`
  - `smartdns`
- 当前完成的变体：
  - `full_stack`
  - `afl_only`
  - `no_mutator`
  - `no_cache_delta`
- repo 内正式表：
  - [RQ3UnboundVariantSummary.tsv](./RQ3UnboundVariantSummary.tsv)
  - [RQ3SmartdnsVariantSummary.tsv](./RQ3SmartdnsVariantSummary.tsv)
- 原始汇总表：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260603_121445/resolver_variant_summary.tsv`
  - `experiments/results/real_rq3_multi_resolver_ablation/20260603_121445/resolver_variant_summary.json`

## 主表结论

### unbound

| variant_name | run_count | variance_status | total_samples_mean | unknown_samples_mean | cluster_count_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 8.0}` |

### smartdns

| variant_name | run_count | variance_status | total_samples_mean | unknown_samples_mean | cluster_count_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `8.000000` | `8.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |

## 当前可直接写入论文的表述

> 在 `unbound` 与 `smartdns` 上，`full_stack / afl_only / no_mutator / no_cache_delta` 四个变体均完成了 `repeat=5` 的稳定重复，且 `variance_status=ok`、`unknown_samples_mean=0`。`unbound` 的四个变体全部收敛到 `oracle_and_cache_diff`，`smartdns` 的四个变体全部收敛到 `6` 个 `oracle_diff` 加 `2` 个 `oracle_and_cache_diff` 的相同混合分布。这说明此前 RQ5 中已经观测到的 `unbound / smartdns` 语义类别，在 RQ3 变体消融口径下同样稳定复现；同时，在当前 `queue_limit=8`、`budget_sec=120` 的样本池里，四个 hybrid 变体仍未拉开可观测差距。

## 论文数据充分性判断

这批数据足够支撑 RQ3 的保守论文结论：

- 每个 resolver/variant 都有 `repeat=5`，满足当前仓库对 paper-facing 主表的最低重复次数口径。
- 每行均为 `variance_status=ok`，说明 5 次重复之间没有出现当前 aggregate 规则判定的异常方差。
- `unknown_samples_mean=0`，说明本批次没有依赖 `runtime_or_parse_failure` 或 parse incomplete 类别来支撑结论。
- `total_samples_mean=8`，与此前 `dnsmasq / maradns / knot-resolver` 的 `queue_limit=8` RQ3 主表口径一致。
- `unbound` 与 `smartdns` 的结果和 RQ5 full_stack 主表中的语义分布一致，具备跨实验口径复现性。

但这批数据不足以支撑“Hybrid 组件显著增益”的强结论：

- 四个变体在同一 resolver 内完全同分布，不能证明 `SYMCC`、`DST1 mutator` 或 `cache-delta` 单独带来了更高 oracle 命中。
- 当前脚本的四个变体仍未覆盖计划中明确提到的“无 high-value gate”对照。
- `budget_sec=120` 是中等预算，不能替代长期 fuzzing 预算下的增益评估。
- 样本来自稳定 transcript corpus 的前 8 个样本，更适合支撑 paired replay 和多 resolver 语义稳定性，不适合外推到全语料空间。

## 合理性判断

当前结果是合理的，原因如下：

- `unbound` 的四个变体全部为 `oracle_and_cache_diff`，和多 resolver full_stack 主表中 `unbound` 的稳定语义一致。
- `smartdns` 的四个变体全部为 `6` 个 `oracle_diff` 与 `2` 个 `oracle_and_cache_diff`，和多 resolver full_stack 主表中的混合分布一致。
- 两个 resolver 均从早期 `runtime_or_parse_failure` 风险收敛到 `unknown_samples_mean=0`，说明 `budget_sec=120` 与当前 replay 路径足以支撑有效 oracle 证据。
- 同一 resolver 内四个变体结果一致，与此前 `dnsmasq / maradns / knot-resolver` 的 RQ3 消融趋势一致：当前稳定样本池更像是在测量 resolver 语义差异，而不是测量 hybrid 组件差异。

## 当前结论边界

当前可以写：

- RQ3 在 `queue_limit=8`、`repeat=5`、`budget_sec=120` 口径下已覆盖 5 个 secondary resolver。
- 5 个 resolver 的四个变体均未在当前稳定样本池中拉开主导语义分布差异。
- `unbound` 与 `smartdns` 的 RQ3 补跑强化了 RQ5 中的 resolver 语义分类结论。

当前不应写：

- `SYMCC` 没有价值。
- `DST1 mutator` 没有价值。
- `cache-delta` 没有价值。
- RQ3 已经证明 hybrid 组件存在显著增益。

## 下一步

1. 补“无 high-value gate”对照，使 RQ3 与计划中的消融项完全对齐。
2. 将预算提升到 `600s+`，检查长期 fuzzing 下四个变体是否开始分化。
3. 在论文正文中把 RQ3 写成“当前真实 paired replay 批次下的保守消融结果”，而不是写成 hybrid 组件增益证明。
