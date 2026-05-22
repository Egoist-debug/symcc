# DNS Poison 论文材料状态

## 更新时间

- `2026-05-22`

## 本轮新增真实产物

### RQ1 多样本输入模型对照

- 运行结果目录：
  - `experiments/results/rq1_input_model_multi_sample_20260522_071746/out`
- repo 内落盘表：
  - [RQ1InputModelMultiSample.tsv](/home/egoist/codex/symcc/docs/RQ1InputModelMultiSample.tsv)
- 运行口径：
  - `dst1_transcript`：取 `named_experiment/work/stable_transcript_corpus` 前 `16` 个稳定样本
  - `query_only`：取 `named_experiment/work/query_corpus` 前 `16` 个裸 query
  - `random_packet`：随机生成 `16` 个 `32` 字节包
  - `legacy_response_tail`：取 `named_experiment/work/query_corpus` 前 `16` 个 query，并复用 `named_experiment/work/response_corpus`

当前表格结论：

| model_name | sample_count | parse_accept_rate | recursive_or_cache_path_rate | response_accept_rate | effective_post_check_rate |
| --- | --- | --- | --- | --- | --- |
| `dst1_transcript` | `16` | `1.000000` | `0.000000` | `0.000000` | `0.000000` |
| `query_only` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |
| `random_packet` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |
| `legacy_response_tail` | `16` | `0.000000` | `0.000000` | `0.000000` | `-` |

当前可直接写入论文的保守表述：

> 在当前 producer 接口与稳定 transcript 样本集下，`DST1 transcript` 在 `16/16` 个样本上均能被 BIND9 输入侧稳定解析；对照的裸 `query-only`、随机包和当前 `legacy_response_tail` 对照集均未进入同一解析路径。这说明论文主输入模型在当前真实语料上具备稳定的“可接入性”优势。

当前解释边界：

- 这张表回答的是“当前 producer 接口是否接受该类输入”，不是“它们在相同语义条件下的漏洞触达能力”。
- `query_only` 与 `legacy_response_tail` 当前直接取自 `query_corpus`，它们和 `2026-05-14` 单样本探针的手工构造 query 不同，因此不能把两张表混写为同一实验。
- `DST1 transcript` 当前仍未触发 `resolver_fetch_started / response_accepted / second_query_hit`，说明这批稳定样本更偏“可解析性”验证，不足以单独支撑 post-check 增益结论。

## 当前可复用的 multi-resolver 证据基底

### 完整 smoke 级 batch

- 目录：
  - `experiments/results/real_campaign_matrix_batch_dnslabctl/20260520_102330`
  - `experiments/results/real_campaign_matrix_batch_dnslabctl/20260520_103202`
  - `experiments/results/real_campaign_matrix_batch_dnslabctl/20260520_103638`
- 共同特征：
  - `5` 个 secondary resolver 全部 `pass`
  - `repeat=2`
  - 每个 resolver 队列仅 `1` 个样本
  - `resolver_variant_summary.tsv` 显示 `run_count=2`

这批结果当前适合支持的论文口径：

- 多 resolver 工程链路已经闭环
- `bind9_vs_unbound/dnsmasq/smartdns/maradns/knot-resolver` 的统一 matrix 入口已经真实跑通
- 当前差异类型分布仍明显偏向 `unbound`

### 当前可直接引用的 RQ5 语义分布表

- repo 内表：
  - [RQ5ResolverSemanticDistribution.tsv](/home/egoist/codex/symcc/docs/RQ5ResolverSemanticDistribution.tsv)

当前表格结论：

| resolver | resolver_pair | full_stack_oracle_audit_candidate_count_mean | full_stack_semantic_diff_count_mean | full_stack_semantic_counts_json |
| --- | --- | --- | --- | --- |
| `dnsmasq` | `bind9_vs_dnsmasq` | `0.000000` | `0.000000` | `{"runtime_or_parse_failure": 1.0}` |
| `knot-resolver` | `bind9_vs_knot-resolver` | `0.000000` | `0.000000` | `{"runtime_or_parse_failure": 1.0}` |
| `maradns` | `bind9_vs_maradns` | `0.000000` | `0.000000` | `{"runtime_or_parse_failure": 1.0}` |
| `smartdns` | `bind9_vs_smartdns` | `0.000000` | `0.000000` | `{"runtime_or_parse_failure": 1.0}` |
| `unbound` | `bind9_vs_unbound` | `1.000000` | `1.000000` | `{"oracle_and_cache_diff": 1.0}` |

当前可直接写入论文的保守表述：

> 在当前 smoke 级 multi-resolver batch 中，`bind9_vs_unbound` 是唯一稳定产生 `oracle_and_cache_diff` 的路径；`dnsmasq/smartdns/maradns/knot-resolver` 当前主要表现为 `runtime_or_parse_failure`。这说明统一差分框架已经具备跨 resolver 的可比能力，但强语义差异仍集中在 `unbound` 路径。

### `repeat=5` 多样本 full_stack 主表

- 批次目录：
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442`
- repo 内正式表：
  - [RQ5FullStackMultiSampleSummary.tsv](/home/egoist/codex/symcc/docs/RQ5FullStackMultiSampleSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ5MultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ5MultiSample.md)
- 人工 case study：
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/index.tsv`

这轮主表的关键结论：

| resolver | run_count | variance_status | semantic_counts_mean_json |
| --- | --- | --- | --- |
| `unbound` | `5` | `ok` | `{"runtime_or_parse_failure": 2.0}` |
| `dnsmasq` | `5` | `ok` | `{"oracle_diff": 2.0}` |
| `smartdns` | `5` | `ok` | `{"runtime_or_parse_failure": 2.0}` |
| `maradns` | `5` | `ok` | `{"oracle_diff": 2.0}` |
| `knot-resolver` | `5` | `ok` | `{"no_diff": 2.0}` |

这意味着：

- `dnsmasq` 与 `maradns` 已经在小批量多样本设置下稳定落为 `oracle_diff`
- `knot-resolver` 已经提供了稳定 `no_diff` 负对照
- `unbound` 与 `smartdns` 当前仍主要体现为 `runtime_or_parse_failure`
- `unbound / smartdns` 的代表性样本当前仍是 `sample.meta.status=completed` 且 `parse_ok=true`，因此这一标签更像保守的 `oracle_parse_incomplete`，还不是明确的运行崩溃

因此，当前论文材料已经从“5 个 resolver 能跑”推进到“5 个 resolver 在多样本重复下出现可区分的三类结论”。

## 当前不应直接写入论文终稿的说法

- “RQ1 已经完成正式输入模型对照实验”
- “RQ3 已经证明 `SYMCC / mutator / cache-delta` 带来显著增益”
- “RQ4 已经完成状态指纹降噪定量评估”
- “RQ5 已达到多样本、长预算、`repeat>=5` 的终稿级统计”

## 本轮额外观察

### `2026-05-21` partial batch

- 目录：
  - `experiments/results/real_campaign_matrix_batch_dnslabctl/20260521_092218`
- 现象：
  - `unbound/dnsmasq/knot` 为 `pass`
  - `smartdns/maradns` 为 `fail`
  - `campaign_close.summary.json` 显示失败原因为 `follow-diff-window` 的 `deadline_exceeded`

这说明：

- 当预算收窄到 `3s` 时，`smartdns/maradns` 已经开始出现闭环时间不足
- 当前参数对不同 resolver 的鲁棒性不一致，不能把这轮 partial batch 当成论文主表

### `2026-05-22` 大队列探索

- 目录：
  - `experiments/results/real_campaign_matrix_batch_dnslabctl/20260522_071145`
- 现象：
  - 将 `QUEUE_LIMIT` 提升到 `32` 后，`unbound/full_stack/run-01` 在单轮 `campaign-close` 内持续消费多样本，整轮矩阵预计进入小时级
  - 本轮人工中断，未形成完整 batch

这说明：

- “全 resolver + 4 变体 + 大队列”当前仍需要分层调度
- 下一轮适合先缩到 `full_stack only` 或 `QUEUE_LIMIT<=8`，再把 `repeat` 提到 `5`

## 当前判断

当前仓库已经拥有一组可以直接服务论文草稿的材料：

1. 一张新的 RQ1 多样本输入可接入性表
2. 一张 `queue_limit=2`、`repeat=5` 的 RQ5 多样本 full_stack 主表
3. 一组 `5 resolver` 全部 `pass` 的真实 smoke batch
4. 一张明确显示 `dnsmasq / maradns / knot-resolver / unbound / smartdns` 已开始分化的 RQ5 结果说明
5. 一组 `4` 个端到端人工 case study

当前仓库距离“整份论文实验完成”还差三步：

1. 把 `queue_limit` 从 `2` 继续抬到 `4` 或 `8`
2. 在当前多样本主表之上补 `afl_only / no_mutator / no_cache_delta`，完成 RQ3 对照
3. 把 `runtime_or_parse_failure` 再细分成更可发表的真值类别

### dnsmasq 多样本 RQ3 消融结果

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260522_083406/dnsmasq`
- repo 内正式表：
  - [RQ3DnsmasqVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3DnsmasqVariantSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ3DnsmasqMultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ3DnsmasqMultiSample.md)

当前可直接写入论文的保守结论：

- `dnsmasq` 上的 `full_stack / afl_only / no_mutator / no_cache_delta` 四个变体都完成了 `repeat=5`
- 当前 `queue_limit=2` 的样本池下，四个变体都收敛到相同的 `oracle_diff`
- 这表示当前批次还看不出明确的 hybrid 增益，后续需要继续扩大样本池再做判断

当前结论边界：

- 这不是对 `SYMCC / mutator / cache-delta` 价值的否定
- 这只是对当前 `dnsmasq + queue_limit=2` 批次的真实观测
- 后续若样本池扩大，结果可能发生变化

### maradns 多样本 RQ3 消融结果

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260522_084931/maradns`
- repo 内正式表：
  - [RQ3MaradnsVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3MaradnsVariantSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ3MaradnsMultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ3MaradnsMultiSample.md)

这说明：

- `maradns` 现在也已经在 `full_stack / afl_only / no_mutator / no_cache_delta` 四个变体上全部完成 `repeat=5`
- 四个变体同样都收敛到 `oracle_diff`
- 当前“变体差异不显著”的 RQ3 结论已经不再局限于 `dnsmasq` 单一路径

### RQ5 failure refinement

- 汇总表：
  - [RQ5FailureRefinement.tsv](/home/egoist/codex/symcc/docs/RQ5FailureRefinement.tsv)
- 结果说明：
  - [DNSPoisonRQ5FailureRefinement.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ5FailureRefinement.md)

当前可直接写入论文的保守结论：

- `unbound` 与 `smartdns` 的代表性样本都已完成 replay
- 当前 `runtime_or_parse_failure` 更接近 `oracle_parse_incomplete`
- 这比“运行崩溃”更准确，也更适合论文里的失败标签分层
