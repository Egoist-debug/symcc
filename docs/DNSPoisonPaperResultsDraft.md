# DNS Poison 论文结果草稿

## 当前研究主线

本文当前最稳的主线是：`BIND9` 作为单一 producer，`DST1 transcript` 作为统一输入模型，通过同步 replay/triage 将同一批样本投递给多个 secondary resolver，并以结构化 `oracle / cache diff / triage / campaign report` 作为论文证据链。

当前已经具备 3 类可直接写入正文的结果：

1. RQ1 输入模型可接入性
2. RQ3 `dnsmasq` 多样本消融
3. RQ5 多 resolver 多样本 full_stack 主表

## RQ1 输入模型可接入性

当前正式表：

- [RQ1InputModelMultiSample.tsv](/home/egoist/codex/symcc/docs/RQ1InputModelMultiSample.tsv)

当前口径：

- `sample_count = 16`
- `dst1_transcript` 取 `stable_transcript_corpus`
- `query_only / legacy_response_tail` 取 `query_corpus`
- `random_packet` 随机生成

当前结果：

| model_name | sample_count | parse_accept_rate | recursive_or_cache_path_rate | response_accept_rate | effective_post_check_rate |
| --- | --- | --- | --- | --- | --- |
| `dst1_transcript` | `16` | `1.000000` | `0.000000` | `0.000000` | `0.000000` |
| `query_only` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |
| `random_packet` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |
| `legacy_response_tail` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |

当前可直接写入正文的表述：

> 在当前 producer 接口与稳定 transcript 样本集下，`DST1 transcript` 在 `16/16` 个样本上均能被 BIND9 输入侧稳定解析；对照的裸 `query-only`、随机包和当前 `legacy_response_tail` 对照集均未进入同一解析路径。这说明论文主输入模型在当前真实语料上具备稳定的可接入性优势。

当前边界：

- 这张表更偏“输入是否可被当前 producer 接口接受”
- 它还没有证明 post-check 语义优势
- 它还没有覆盖更长预算下的漏洞触达能力

## RQ3 dnsmasq 多样本消融

当前正式表：

- [RQ3DnsmasqVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3DnsmasqVariantSummary.tsv)

当前批次：

- `experiments/results/real_rq3_multi_resolver_ablation/20260522_083406/dnsmasq`
- `queue_limit = 2`
- `repeat = 5`
- `budget_sec = 12`

当前结果：

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |
| `afl_only` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |
| `no_mutator` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |
| `no_cache_delta` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |

当前可直接写入正文的表述：

> 在 `dnsmasq` 上，`full_stack / afl_only / no_mutator / no_cache_delta` 四个变体均完成了 `repeat=5` 的稳定重复，并且在当前 `queue_limit=2` 的样本池上都收敛到相同的 `oracle_diff` 语义结果。当前样本池下，关闭 `SYMCC`、关闭 `DST1 mutator` 或关闭 `cache-delta` 尚未改变 `dnsmasq` 的主导语义分布。

当前边界：

- 当前不能把这一结果写成“Hybrid 组件无效”
- 当前只能写成“这轮真实批次还未观测到显著变体差异”
- `knot-resolver` 的同构消融尚未补齐

## RQ3 maradns 多样本消融

当前正式表：

- [RQ3MaradnsVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3MaradnsVariantSummary.tsv)

当前批次：

- `experiments/results/real_rq3_multi_resolver_ablation/20260522_084931/maradns`
- `queue_limit = 2`
- `repeat = 5`
- `budget_sec = 12`

当前结果：

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |
| `afl_only` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |
| `no_mutator` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |
| `no_cache_delta` | `5` | `ok` | `2.000000` | `2.000000` | `2.000000` | `2.000000` | `{"oracle_diff": 2.0}` |

当前可直接写入正文的表述：

> `maradns` 上的四个变体也都完成了 `repeat=5`，并且和 `dnsmasq` 一样在当前样本池下全部收敛到 `oracle_diff`。这说明当前 RQ3 的保守结论已经跨越两个不同 resolver：在小样本稳定 transcript 批次下，四个 hybrid 变体尚未拉开可观测差距。

## RQ5 多 resolver 多样本主表

当前正式表：

- [RQ5FullStackMultiSampleSummary.tsv](/home/egoist/codex/symcc/docs/RQ5FullStackMultiSampleSummary.tsv)

当前批次：

- `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442`
- `queue_limit = 2`
- `repeat = 5`
- `budget_sec = 12`

当前结果：

| resolver | resolver_pair | run_count | variance_status | total_samples_mean | unknown_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `bind9_vs_unbound` | `5` | `ok` | `2.0` | `2.0` | `0.0` | `0.0` | `{"runtime_or_parse_failure": 2.0}` |
| `dnsmasq` | `bind9_vs_dnsmasq` | `5` | `ok` | `2.0` | `0.0` | `2.0` | `2.0` | `{"oracle_diff": 2.0}` |
| `smartdns` | `bind9_vs_smartdns` | `5` | `ok` | `2.0` | `2.0` | `0.0` | `0.0` | `{"runtime_or_parse_failure": 2.0}` |
| `maradns` | `bind9_vs_maradns` | `5` | `ok` | `2.0` | `0.0` | `2.0` | `2.0` | `{"oracle_diff": 2.0}` |
| `knot-resolver` | `bind9_vs_knot-resolver` | `5` | `ok` | `2.0` | `0.0` | `0.0` | `0.0` | `{"no_diff": 2.0}` |

当前可直接写入正文的表述：

> 在 `full_stack` 主线、`queue_limit=2`、`repeat=5`、`budget_sec=12` 的真实批次中，5 个 secondary resolver 全部完成了稳定重复，`variance_status` 均为 `ok`。其中，`bind9_vs_dnsmasq` 与 `bind9_vs_maradns` 在所有重复中都稳定落为 `oracle_diff`，`bind9_vs_knot-resolver` 在同一批样本上持续表现为 `no_diff`，而 `bind9_vs_unbound` 与 `bind9_vs_smartdns` 当前仍主要落在保守的失败标签上。这说明当前稳定 transcript 子集已经能够把不同 resolver 分化成至少三类结果。

## RQ5 failure refinement

当前正式表：

- [RQ5FailureRefinement.tsv](/home/egoist/codex/symcc/docs/RQ5FailureRefinement.tsv)

当前结果：

| resolver | total_samples | completed_samples | bind9_parse_ok_samples | secondary_parse_ok_samples | semantic_outcome | diff_class | interpretation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `10` | `10` | `10` | `10` | `runtime_or_parse_failure` | `oracle_parse_incomplete` | 样本已完成 replay，当前只是 oracle 证据不完整 |
| `smartdns` | `10` | `10` | `10` | `10` | `runtime_or_parse_failure` | `oracle_parse_incomplete` | 样本已完成 replay，当前只是 oracle 证据不完整 |

当前可直接写入正文的表述：

> 在当前多样本批次中，`unbound` 和 `smartdns` 的代表性样本均完成 replay，且 `bind9` 与 secondary 的 `parse_ok` 都为真。当前 `runtime_or_parse_failure` 更适合被保守地解释为 `oracle_parse_incomplete`，而不是目标未运行或目标崩溃。

## 当前最有价值的 case study

当前人工 case study 索引：

- `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/index.tsv`

当前 4 个代表性 case：

1. `case-01-dnsmasq`：稳定 `oracle_diff`
2. `case-02-maradns`：secondary 运行异常但 triage 仍收敛到 `oracle_diff`
3. `case-03-knot`：稳定 `no_diff` 负对照
4. `case-04-unbound`：`oracle_parse_incomplete` 代表性样本

## 当前可以稳定声称的结论

1. `DST1 transcript` 在当前 producer 接口上具备稳定可接入性
2. 多 resolver full_stack 主线已经从 smoke 推进到 `repeat=5` 的真实多样本批次
3. `dnsmasq / maradns / knot-resolver / unbound / smartdns` 已出现可区分的三类结果
4. `dnsmasq` 的四个 RQ3 变体在当前小样本池下还未拉开差距

## 当前仍应保守处理的结论

1. 不能写“RQ1 已证明 DST1 的 post-check 优势”
2. 不能写“RQ3 已证明 Hybrid 组件有显著增益”
3. 不能写“`runtime_or_parse_failure` 等于真实运行崩溃”
4. 不能写“现有结果已经达到长期预算终稿级统计”

## 当前最自然的后续路线

1. 保持 `full_stack only`，把 `queue_limit` 从 `2` 提到 `4/8`
2. 补完 `maradns / knot-resolver` 的同构消融
3. 将当前结果浓缩成论文正文里的 3 张主表和 1 张 failure refinement 表
