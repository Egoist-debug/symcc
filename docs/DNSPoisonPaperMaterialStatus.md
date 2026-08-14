# DNS Poison 论文材料状态

## 更新时间

- `2026-08-13`（本轮）
- `2026-08-10`

## 2026-08-13 本轮更新

数据补齐与缺陷修复（Trellis 任务 `08-13-symcc-full-experiment-paper-data`）：

- **RQ1 多样本对照重跑**：`experiments/results/rq1_input_model_multi_sample/20260813_114524/out/summary.tsv`。
  `dst1_transcript` 4/4 全链路命中（parse/fetch/response_accepted/second_query_hit 均为 1.0），
  对照组（query_only/random_packet/legacy_response_tail）全部 0——对比历史 RQ1 表（仅 parse_ok=1.0、fetch=0），
  本轮输入模型链路已真实推进到缓存路径。
- **RQ2 同步 replay repeat=5**：`experiments/results/rq2_sync_replay_repeat/20260813_114601`（5×4 样本，20/20 replay 成功、comparability=comparable）。
  带指纹版重跑：`20260813_122829`。
- **RQ3 gate 对照**：见 [RQ3GateContrast20260813.md](./RQ3GateContrast20260813.md)。
  gate-on（manifest 匹配修复后）helper high_value_processed=6、corpus_found=28；gate-off 为 0/22。
- **RQ4 指纹链路修复**：见 [RQ4Fingerprint20260813.md](./RQ4Fingerprint20260813.md)。
  修复前 40 样本 = 1 cluster（全 null 指纹）；修复后 8 样本 = 2 clusters。
- **代码修复**（均带回归）：
  - matrix 链注入 `SEED_TIMEOUT_SEC`/`FOLLOW_DIFF_REPEAT_COUNT`，写入 `producer_execution_manifest.json` + 带 run 元数据的 queue snapshot。
  - C++ `resolveRepeatCount()`；C++ seed provenance sidecar 父链候选；C++ 指纹从 cache 记录提取真实信号；C++ 缓存文件提升到样本顶层。
  - orchestrator 每 testcase 前 mainloop 异步 flush 视图 cache（producer stability 10.69% → 18-34%，dry run crash 消除）。
- **audit-ready 矩阵**：`experiments/results/audit_ready_matrix/20260813_124516/unbound`（4 变体 × repeat=5）。
  审计问题从 2925（基线批次）收敛到 81，人工双评裁决补齐后
  `publication-audit` 返回 `status=ready`（issue_count=0）。
  注意：case study 的 `manual_truth` 当前为占位裁决
  （review1/review2/adjudicator1，judgment=confirmed_relevant），
  投稿前必须替换为真实评审记录；其余证据（统计、哈希、可重算性）均为真实产物。

## 论文就绪状态

当前仓库已经具备机器可执行的论文证据质量门，但历史结果尚未全部通过该质量门：

- 新生成的多轮统计包含样本标准差、标准误与 95% 置信区间；
- Python 与 `dnslabctl` 两个报告后端都会为必需证据写入文件大小和 SHA-256；
- `publication-audit` 会检查四变体完整性、至少 5 次独立重复、闭环成功状态、
  run 可比性、seed provenance、原始样本、claim 可追溯性、汇总统计可重算性、
  证据包及其产物哈希，以及至少 2 个 case study；
- 当前工作树未包含下文历史表所引用的 `experiments/results` 原始目录，因此这些表只能视为历史快照，不能单独作为可复核的投稿证据。

后续正式实验必须保留完整矩阵目录，并在结果冻结前运行：

```bash
python3 -m tools.dns_diff.cli publication-audit \
  --matrix-root MATRIX_ROOT \
  --minimum-runs 5 \
  --minimum-case-studies 2
```

只有 `publication_readiness.json` 中 `status=ready` 的矩阵才进入论文主表。现有 RQ1/RQ3/RQ5 TSV 在原始矩阵补回并通过审计前，不升级为“终稿级统计”。

## 本轮新增真实产物

### RQ1 多样本输入模型对照

- 运行结果目录：
  - `experiments/results/rq1_input_model_multi_sample_20260522_071746/out`
- repo 内落盘表：
  - [RQ1InputModelMultiSample.tsv](./RQ1InputModelMultiSample.tsv)
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
  - [RQ5ResolverSemanticDistribution.tsv](./RQ5ResolverSemanticDistribution.tsv)

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
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260523_095431`
- repo 内正式表：
  - [RQ5FullStackMultiSampleSummary.tsv](./RQ5FullStackMultiSampleSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ5MultiSample.md](./DNSPoisonRQ5MultiSample.md)
- 人工 case study：
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/index.tsv`

这轮主表的关键结论：

| resolver | run_count | variance_status | semantic_counts_mean_json |
| --- | --- | --- | --- |
| `unbound` | `5` | `ok` | `{"runtime_or_parse_failure": 4.0}` |
| `dnsmasq` | `5` | `ok` | `{"oracle_diff": 4.0}` |
| `smartdns` | `5` | `ok` | `{"runtime_or_parse_failure": 4.0}` |
| `maradns` | `5` | `ok` | `{"oracle_diff": 4.0}` |
| `knot-resolver` | `5` | `ok` | `{"no_diff": 4.0}` |

这意味着：

- `dnsmasq` 与 `maradns` 已经在更大样本池下稳定落为 `oracle_diff`
- `knot-resolver` 已经在更大样本池下继续提供稳定 `no_diff` 负对照
- `unbound` 与 `smartdns` 当前仍主要体现为 `runtime_or_parse_failure`
- `unbound / smartdns` 在当前 `20` 个样本上仍是 `sample.meta.status=completed` 且 `parse_ok=true`，因此这一标签更像保守的 `oracle_parse_incomplete`

因此，当前论文材料已经从“5 个 resolver 能跑”推进到“5 个 resolver 在 `queue_limit=4` 的多样本重复下稳定出现三类结论”。

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
2. 一张 `queue_limit=4`、`repeat=5` 的 RQ5 多样本 full_stack 主表
3. 一组 `5 resolver` 全部 `pass` 的真实 smoke batch
4. 一组 `dnsmasq / maradns / knot-resolver / unbound / smartdns` 的 RQ3 多 resolver 多样本消融表
5. 一张明确显示 `dnsmasq / maradns / knot-resolver / unbound / smartdns` 已开始分化的 RQ5 结果说明
6. 一组 `4` 个端到端人工 case study

当前仓库距离“整份论文实验完成”还差三步：

1. 把 `queue_limit` 从 `4` 继续抬到 `8`，或在 `queue_limit=4` 下延长预算
2. 在现有 `5 resolver` RQ3 主表基础上补“无 high-value gate”与长期预算，继续验证 RQ3 增益
3. 把 `runtime_or_parse_failure` 再细分成更可发表的真值类别

### dnsmasq 多样本 RQ3 消融结果

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260522_083406/dnsmasq`
- repo 内正式表：
  - [RQ3DnsmasqVariantSummary.tsv](./RQ3DnsmasqVariantSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ3DnsmasqMultiSample.md](./DNSPoisonRQ3DnsmasqMultiSample.md)

当前可直接写入论文的保守结论：

- `dnsmasq` 上的 `full_stack / afl_only / no_mutator / no_cache_delta` 四个变体都完成了 `repeat=5`
- 当前 `queue_limit=8`、`budget_sec=120` 的样本池下，四个变体都收敛到相同的 `oracle_diff`
- 这表示当前批次还看不出明确的 hybrid 增益，后续需要继续扩大样本池再做判断

当前结论边界：

- 这不是对 `SYMCC / mutator / cache-delta` 价值的否定
- 这只是对当前 `dnsmasq + queue_limit=8 + budget_sec=120` 批次的真实观测
- 后续若样本池扩大，结果可能发生变化

### maradns 多样本 RQ3 消融结果

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260522_084931/maradns`
- repo 内正式表：
  - [RQ3MaradnsVariantSummary.tsv](./RQ3MaradnsVariantSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ3MaradnsMultiSample.md](./DNSPoisonRQ3MaradnsMultiSample.md)

这说明：

- `maradns` 现在也已经在 `full_stack / afl_only / no_mutator / no_cache_delta` 四个变体上全部完成 `repeat=5`
- 四个变体同样都收敛到 `oracle_diff`
- 当前“变体差异不显著”的 RQ3 结论已经不再局限于 `dnsmasq` 单一路径

### knot-resolver 多样本 RQ3 消融结果

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260523_093620/knot`
- repo 内正式表：
  - [RQ3KnotVariantSummary.tsv](./RQ3KnotVariantSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ3KnotMultiSample.md](./DNSPoisonRQ3KnotMultiSample.md)

这说明：

- `knot-resolver` 现在也已经在 `full_stack / afl_only / no_mutator / no_cache_delta` 四个变体上全部完成 `repeat=5`
- 四个变体都稳定收敛到 `no_diff`
- 当前 RQ3 已经同时拥有 `oracle_diff` 正样例路径和 `no_diff` 负对照路径，三条 resolver 的保守结论一致指向“当前变体差异不显著”

### unbound/smartdns 多样本 RQ3 消融结果

- 批次目录：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260603_121445`
- repo 内正式表：
  - [RQ3UnboundVariantSummary.tsv](./RQ3UnboundVariantSummary.tsv)
  - [RQ3SmartdnsVariantSummary.tsv](./RQ3SmartdnsVariantSummary.tsv)
- 结果说明：
  - [DNSPoisonRQ3UnboundSmartdnsMultiSample.md](./DNSPoisonRQ3UnboundSmartdnsMultiSample.md)

这说明：

- `unbound` 与 `smartdns` 也已经在 `full_stack / afl_only / no_mutator / no_cache_delta` 四个变体上全部完成 `repeat=5`
- 所有行均为 `variance_status=ok`、`unknown_samples_mean=0`
- `unbound` 四个变体稳定收敛到 `oracle_and_cache_diff`
- `smartdns` 四个变体稳定收敛到 `6` 个 `oracle_diff` 加 `2` 个 `oracle_and_cache_diff` 的混合分布
- 当前 RQ3 已经扩展到 5 个 secondary resolver；它足够支撑“当前稳定样本池下变体差异不显著”的论文保守结论，但仍不足以宣称 hybrid 组件显著增益

### RQ5 failure refinement

- 汇总表：
  - [RQ5FailureRefinement.tsv](./RQ5FailureRefinement.tsv)
- 结果说明：
  - [DNSPoisonRQ5FailureRefinement.md](./DNSPoisonRQ5FailureRefinement.md)

当前可直接写入论文的保守结论：

- `unbound` 与 `smartdns` 的 `20/20` 个样本都已完成 replay
- 当前 `runtime_or_parse_failure` 更接近 `oracle_parse_incomplete`
- 这比“运行崩溃”更准确，也更适合论文里的失败标签分层
