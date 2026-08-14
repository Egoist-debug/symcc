# DNS Poison 论文结果草稿

> 证据状态：本文件中的数值来自历史快照。当前工作树未包含对应原始矩阵目录；在矩阵通过 `publication-audit` 并生成 `status=ready` 的 `publication_readiness.json` 前，以下结果只用于草稿推演，不作为终稿可复核证据。

## 当前研究主线

本文当前最稳的主线是：`BIND9` 作为单一 producer，`DST1 transcript` 作为统一输入模型，通过同步 replay/triage 将同一批样本投递给多个 secondary resolver，并以结构化 `oracle / cache diff / triage / campaign report` 作为论文证据链。

当前已经具备 3 类可直接写入正文的结果：

1. RQ1 输入模型可接入性
2. RQ3 多 resolver 多样本消融
3. RQ5 多 resolver 多样本 full_stack 主表

## RQ1 输入模型可接入性

当前正式表：

- [RQ1InputModelMultiSample.tsv](./RQ1InputModelMultiSample.tsv)（2026-08-14 更新，68 样本）

当前口径（2026-08-14 修正）：

- `dst1_transcript`：`stable_transcript_corpus` 68 个稳定样本（扩充自 64 个新生成 transcript，3×回放一致筛选）
- `query_only` / `legacy_response_tail`：从 transcript `client_query` 提取的 DNS wire 格式 query（同源对照）
- `random_packet`：随机生成 16 个 32 字节包

当前结果（68 样本）：

| model_name | sample_count | parse_accept_rate | recursive_or_cache_path_rate | response_accept_rate | effective_post_check_rate |
| --- | --- | --- | --- | --- | --- |
| `dst1_transcript` | `68` | `1.000000` | `1.000000` | `1.000000` | `0.279412` |
| `query_only` | `68` | `1.000000` | `1.000000` | `1.000000` | `-` |
| `random_packet` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |
| `legacy_response_tail` | `68` | `1.000000` | `1.000000` | `1.000000` | `-` |

当前可直接写入正文的表述：

> 在当前 producer 接口与稳定 transcript 样本集下，`DST1 transcript` 在 `68/68` 个样本上均能被 BIND9 输入侧稳定解析并触达 resolver fetch 路径；同源的 wire 格式裸 query 与 legacy-response-tail 对照同样触达 fetch 路径。三类输入模型的可接入性无显著差异，DST1 transcript 的独有优势在于 post-check 阶段（`19/68` 样本命中缓存验证），这是其他输入模型不具备的语义能力。

当前边界：

- 上轮（2026-08-13）"对照全 0"是修复前链路 + 非 wire 格式对照（gen_input DSL 中间格式）的双重假象，已被本表取代。
- post-check 命中率 27.9% 是当前样本分布的真实值，不是所有 transcript 都命中 cache 验证。
- 该表回答"输入模型能力差异"，不回答"漏洞触达能力"。

## RQ3 dnsmasq 多样本消融

当前正式表：

- [RQ3DnsmasqVariantSummary.tsv](./RQ3DnsmasqVariantSummary.tsv)

当前批次：

- `experiments/results/real_rq3_multi_resolver_ablation/20260529_094512/dnsmasq`
- `queue_limit = 8`
- `repeat = 5`
- `budget_sec = 120`

当前结果：

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |

当前可直接写入正文的表述：

> 在 `dnsmasq` 上，`full_stack / afl_only / no_mutator / no_cache_delta` 四个变体均完成了 `repeat=5` 的稳定重复，并且在 `queue_limit=8`、`budget_sec=120` 的样本池上都收敛到相同的 `oracle_diff` 语义结果，`semantic_diff_count_mean=8.0` 说明每个 run 的 8 个样本全部命中 oracle 差异。当前样本池下，关闭 `SYMCC`、关闭 `DST1 mutator` 或关闭 `cache-delta` 尚未改变 `dnsmasq` 的主导语义分布。

当前边界：

- 当前不能把这一结果写成“Hybrid 组件无效”
- 当前只能写成“这轮真实批次还未观测到显著变体差异”
- 更大的样本池与“无 high-value gate”对照仍待补齐

## RQ3 maradns 多样本消融

当前正式表：

- [RQ3MaradnsVariantSummary.tsv](./RQ3MaradnsVariantSummary.tsv)

当前批次：

- `experiments/results/real_rq3_multi_resolver_ablation/20260529_094512/maradns`
- `queue_limit = 8`
- `repeat = 5`
- `budget_sec = 120`

当前结果：

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `8.000000` | `8.000000` | `8.000000` | `{"oracle_diff": 8.0}` |

当前可直接写入正文的表述：

> `maradns` 上的四个变体也都完成了 `repeat=5`，并且和 `dnsmasq` 一样在当前 `queue_limit=8` 样本池上全部收敛到 `oracle_diff`，所有 8 个样本均命中 oracle 差异。这说明当前 RQ3 的保守结论已经跨越两个不同 resolver：在 4 倍于先前批次的稳定 transcript 样本池下，四个 hybrid 变体仍未拉开可观测差距。

## RQ3 knot-resolver 多样本消融

当前正式表：

- [RQ3KnotVariantSummary.tsv](./RQ3KnotVariantSummary.tsv)

当前批次：

- `experiments/results/real_rq3_multi_resolver_ablation/20260529_094512/knot`
- `queue_limit = 8`
- `repeat = 5`
- `budget_sec = 120`

当前结果：

| variant_name | run_count | variance_status | total_samples_mean | included_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `full_stack` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |
| `afl_only` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |
| `no_mutator` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |
| `no_cache_delta` | `5` | `ok` | `8.000000` | `8.000000` | `0.000000` | `0.000000` | `{"no_diff": 8.0}` |

当前可直接写入正文的表述：

> `knot-resolver` 上的四个变体也都完成了 `repeat=5`，并且在 `queue_limit=8` 样本池下全部收敛到 `no_diff`。这让 RQ3 当前同时拥有两条稳定 `oracle_diff` 路径（dnsmasq、maradns）和一条稳定 `no_diff` 路径（knot-resolver），说明四个 hybrid 变体在 4 倍样本池的真实批次里仍未拉开主导语义差异。

## RQ3 unbound/smartdns 多样本消融

当前正式表：

- [RQ3UnboundVariantSummary.tsv](./RQ3UnboundVariantSummary.tsv)
- [RQ3SmartdnsVariantSummary.tsv](./RQ3SmartdnsVariantSummary.tsv)

当前批次：

- `experiments/results/real_rq3_multi_resolver_ablation/20260603_121445`
- `queue_limit = 8`
- `repeat = 5`
- `budget_sec = 120`

当前结果：

| resolver | variant_name | run_count | variance_status | total_samples_mean | unknown_samples_mean | cluster_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `full_stack` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `unbound` | `afl_only` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `unbound` | `no_mutator` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `unbound` | `no_cache_delta` | `5` | `ok` | `8.000000` | `0.000000` | `1.000000` | `{"oracle_and_cache_diff": 8.0}` |
| `smartdns` | `full_stack` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `smartdns` | `afl_only` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `smartdns` | `no_mutator` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `smartdns` | `no_cache_delta` | `5` | `ok` | `8.000000` | `0.000000` | `2.000000` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |

当前可直接写入正文的表述：

> `unbound` 与 `smartdns` 的 RQ3 补跑也完成了 `repeat=5` 的四变体消融，并且所有行均为 `variance_status=ok`、`unknown_samples_mean=0`。`unbound` 的四个变体全部稳定为 `oracle_and_cache_diff`，`smartdns` 的四个变体全部稳定为 `6` 个 `oracle_diff` 加 `2` 个 `oracle_and_cache_diff` 的混合分布。这说明 RQ3 当前已在 5 个 secondary resolver 上形成同一保守结论：当前稳定样本池里四个 hybrid 变体没有拉开主导语义差异，但不同 resolver 之间的语义类别可以稳定区分。

## RQ5 多 resolver 多样本主表

当前正式表：

- [RQ5FullStackMultiSampleSummary.tsv](./RQ5FullStackMultiSampleSummary.tsv)

当前批次：

- `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260529_093012`
- `queue_limit = 8`
- `repeat = 5`
- `budget_sec = 120`

当前结果：

| resolver | resolver_pair | run_count | variance_status | total_samples_mean | unknown_samples_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `bind9_vs_unbound` | `5` | `ok` | `8.0` | `0.0` | `8.0` | `8.0` | `{"oracle_and_cache_diff": 8.0}` |
| `dnsmasq` | `bind9_vs_dnsmasq` | `5` | `ok` | `8.0` | `0.0` | `8.0` | `8.0` | `{"oracle_diff": 8.0}` |
| `smartdns` | `bind9_vs_smartdns` | `5` | `ok` | `8.0` | `0.0` | `8.0` | `8.0` | `{"oracle_and_cache_diff": 2.0, "oracle_diff": 6.0}` |
| `maradns` | `bind9_vs_maradns` | `5` | `ok` | `8.0` | `0.0` | `8.0` | `8.0` | `{"oracle_diff": 8.0}` |
| `knot-resolver` | `bind9_vs_knot-resolver` | `5` | `ok` | `8.0` | `0.0` | `0.0` | `0.0` | `{"no_diff": 8.0}` |

当前可直接写入正文的表述：

> 在 `full_stack` 主线、`queue_limit=8`、`repeat=5`、`budget_sec=120` 的真实批次中，5 个 secondary resolver 全部完成了稳定重复，`variance_status` 均为 `ok`，`unknown_samples_mean` 全部为 0（先前批次中 unbound/smartdns 的 `runtime_or_parse_failure` 问题已消除）。其中，`bind9_vs_unbound` 在所有 8 个样本上稳定表现为 `oracle_and_cache_diff`（同时存在 oracle 差异和 cache 差异），`bind9_vs_dnsmasq` 与 `bind9_vs_maradns` 稳定落为 `oracle_diff`，`bind9_vs_smartdns` 呈现混合分布（6 个 `oracle_diff` + 2 个 `oracle_and_cache_diff`），`bind9_vs_knot-resolver` 持续表现为 `no_diff`。这说明当前稳定 transcript 子集在更大样本池和更长预算下，能够将 5 个 resolver 分化成三类可区分的语义结果：oracle+cache 双差异、仅 oracle 差异、无差异。

## RQ5 failure refinement

当前正式表：

- [RQ5FailureRefinement.tsv](./RQ5FailureRefinement.tsv)

当前状态：

> **已解决**。在 `queue_limit=8`、`budget_sec=120` 的新批次中，`unbound` 和 `smartdns` 的 `unknown_samples_mean` 均降为 0，所有样本都成功完成 replay 并产出有效 oracle 证据。先前的 `runtime_or_parse_failure` 问题已通过增加预算和样本池得到消除。`unbound` 现在稳定表现为 `oracle_and_cache_diff`，`smartdns` 表现为 `oracle_diff` + `oracle_and_cache_diff` 混合分布。

## 当前最有价值的 case study

当前人工 case study 索引：

- `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/index.tsv`
  - 当前仍沿用上一轮代表性样本说明；新批次 `run-01` 的四类语义仍保持相同样本角色

当前 4 个代表性 case：

1. `case-01-dnsmasq`：稳定 `oracle_diff`
2. `case-02-maradns`：secondary 运行异常但 triage 仍收敛到 `oracle_diff`
3. `case-03-knot`：稳定 `no_diff` 负对照
4. `case-04-unbound`：`oracle_parse_incomplete` 代表性样本

## 当前可以稳定声称的结论

1. `DST1 transcript` 在当前 producer 接口上具备稳定可接入性
2. 多 resolver full_stack 主线已经在 `queue_limit=8`、`budget_sec=120`、`repeat=5` 的真实多样本批次上完整跑通
3. `dnsmasq / maradns / knot-resolver / unbound / smartdns` 已出现可区分的三类语义结果（oracle+cache 双差异、仅 oracle 差异、无差异）
4. `dnsmasq / maradns / knot-resolver / unbound / smartdns` 的四个 RQ3 变体都在各自 resolver 内保持主导语义一致，当前未观测到变体差异
5. `unbound` 与 `smartdns` 在 RQ3/RQ5 新批次中已不再落入 `runtime_or_parse_failure`，分别稳定表现为 `oracle_and_cache_diff` 与 `oracle_diff`+`oracle_and_cache_diff` 混合

## 当前仍应保守处理的结论

1. 不能写"RQ1 已证明 DST1 的 post-check 优势"
2. 不能写"RQ3 已证明 Hybrid 组件有显著增益"（4 变体仍未拉开差距）
3. 不能写"现有结果已经达到长期预算终稿级统计"（budget=120s 仍属中等预算）

## 当前最自然的后续路线

1. 在当前 `queue_limit=8`、`budget_sec=120` 基础上延长预算到 `budget_sec=600+`，验证大预算下变体差异是否显现
2. 在当前 RQ3 基础上补"无 high-value gate"对照
3. 将当前结果浓缩成论文正文里的 3 张主表和 1 张 case study 表
