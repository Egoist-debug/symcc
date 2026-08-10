# RQ5 章节草稿

## 研究问题

RQ5 关注所提出的 `transcript-guided hybrid fuzzing + single-producer multi-resolver replay/triage` 工作流，是否能够在多个 DNS resolver 上稳定复用，而不是只对 `bind9_vs_unbound` 这一条路径成立。

本文当前版本将 RQ5 收敛为 4 个可观测维度：

1. adapter 成本
2. 构建成功率
3. cache 可观测性
4. 差异类型分布

## 实验设置

当前真实快照基于如下固定设置：

- producer 固定为 `bind9`
- secondary resolver 包括 `unbound`、`dnsmasq`、`smartdns`、`maradns`、`knot-resolver`
- 输入采用统一 `DST1 transcript`
- 每个 resolver 的 `campaign-matrix` 采用 `budget-sec=5`、`repeat=2`
- 当前真实 batch 目录为 `/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657`

当前章节对应的 repo 内正式表为：

- [RQ5ResolverAdapterCost.tsv](./RQ5ResolverAdapterCost.tsv)
- [RQ5ResolverBuildReplayMatrix.tsv](./RQ5ResolverBuildReplayMatrix.tsv)
- [RQ5ResolverSemanticDistribution.tsv](./RQ5ResolverSemanticDistribution.tsv)

## 当前结果

### Adapter 成本

当前工程实现把 adapter 成本分成 3 档：

- `low`：`dnsmasq`、`smartdns`
- `medium`：`maradns`、`knot-resolver`
- `high`：`unbound`

这里的成本是工程代理口径，而不是最终人工标注的代码行级成本。当前代理规则是：

- `python_harness` 记为 `low`
- `python_harness_with_preload_shim` 与 `python_harness_with_selfcontained_runtime` 记为 `medium`
- `native_orchestrator` 记为 `high`

这一结果说明，多 resolver 泛化在工程上已经不再是“全都需要深度原生改造”的问题。除 `unbound` 外，其余 4 个 resolver 都可以通过较薄的 harness 层接入统一 replay/triage 主线。

### 构建与 replay 可用性

当前 5 个 secondary resolver 的真实 `build/replay/campaign-matrix` 状态均为 `pass`。这意味着：

- resolver 源码冻结路径可用
- resolver 可在当前工作流下完成真实 `adapter-build`
- resolver 能生成可比较的 replay 产物
- resolver 能在 `campaign-matrix` 中完成真实 full-stack 闭环

从工程可移植性角度，这一结果已经足以支撑“框架具备多 resolver 泛化能力”这一中间结论。

### Cache 可观测性

当前 5 个 secondary resolver 的 `cache_observable_status` 全部为 `observable`。这说明统一 cache 证据链已经具备：

- before/after cache dump
- oracle 输出
- triage/report 聚合产物

因此，RQ5 里的“cache 可观测性”这一维已经从设计要求变成了真实已验证能力。

### 差异类型分布

当前真实 `full_stack_semantic_counts_json` 显示：

- `unbound`：`{"oracle_and_cache_diff": 1.0}`
- `dnsmasq`：`{"runtime_or_parse_failure": 1.0}`
- `smartdns`：`{"runtime_or_parse_failure": 1.0}`
- `maradns`：`{"runtime_or_parse_failure": 1.0}`
- `knot-resolver`：`{"runtime_or_parse_failure": 1.0}`

这一结果的含义不是“其它 resolver 不支持该框架”，而是当前单样本真实快照下，只有 `bind9_vs_unbound` 观察到了更强的 `oracle_and_cache_diff`。其它 4 个 resolver 当前更多体现为：

- 接入成功
- 证据链可落
- 当前样本下尚未形成更细粒度语义分布

因此，当前 RQ5 结果更适合被表述为“多 resolver 工程闭环已经成立，语义差异强度在当前样本池下存在明显不均衡”。

## 可直接使用的结果表述

可用于论文正文的保守表述：

> 我们在 `bind9` 作为单一 producer 的设置下，对 `unbound`、`dnsmasq`、`smartdns`、`maradns` 与 `knot-resolver` 完成了统一 `campaign-matrix` 真实运行。实验结果表明，5 个 secondary resolver 均能完成真实 build、paired replay 与 matrix 闭环，说明该工作流在工程层面具备可移植性。进一步地，所有 resolver 均已具备 cache 证据可观测性，但在当前单样本快照下，仅 `bind9_vs_unbound` 产生了 `oracle_and_cache_diff`，其余 resolver 主要表现为 `runtime_or_parse_failure`。这说明当前系统已经具备跨 resolver 的统一比较能力，而差异类型分布仍需在更大样本池和更长预算下继续展开。

可用于计划书/中期检查的表述：

> RQ5 当前已经从“是否可接入”推进到“是否可真实批跑”。我们已获得 5 个 secondary resolver 的真实 `build/replay/campaign-matrix` 通过结果，并形成了 repo 内快照表与 capability 总表。下一阶段重点不再是打通工程链路，而是扩大样本池、提高重复次数，并把当前 smoke 级快照升级为论文终稿级统计结果。

## 当前结论边界

当前可以稳定声称：

- 多 resolver 工程闭环已经成立
- 5 个 secondary resolver 都具备真实 build/replay/matrix 能力
- cache 可观测性已经在真实链路上统一成立

当前不应直接声称：

- 所有 resolver 都已经表现出同等强度的缓存语义差异
- 当前差异类型分布已经稳定
- 当前 adapter 成本已经完成最终量化

## 下一步

当前章节草稿之后，最自然的扩展方向是：

1. 将 `repeat=2` 提升为 `repeat=5`
2. 将真实 queue 从单样本扩展到多样本
3. 从 `resolver_semantic_distribution.tsv` 继续派生论文图表
4. 按真实样本挑选 2 到 5 个 case study，支撑更强语义结论
