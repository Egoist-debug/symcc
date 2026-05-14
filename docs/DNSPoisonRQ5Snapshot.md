# DNS Poison RQ5 真实快照

## 文档目的

本文档记录 `docs/DNSPoisonFuzzingPlan.md` 中 RQ5“多 resolver 泛化”的当前真实执行结果，给出可复用的证据路径、运行命令、能力总表与当前边界。

当前快照时间：

- `2026-05-14`

当前快照定位：

- **真实工程快照**
- **可复现实验入口**
- **RQ5 早期证据**
- **论文正文草稿入口**

当前快照边界：

- 已完成 `bind9_vs_unbound/dnsmasq/smartdns/maradns/knot-resolver` 的真实 `campaign-matrix`
- 已完成真实 replay/build 能力矩阵与统一 capability 总表
- 当前矩阵仍是 **单样本、`repeat=2`、`budget-sec=5`** 的最小真实验证，不是论文终稿统计规模

## 当前证据入口

真实 replay 能力矩阵：

- 目录：`/home/ubuntu/tmp/real_resolver_replay_matrix/20260514_073433`
- 表格：`/home/ubuntu/tmp/real_resolver_replay_matrix/20260514_073433/matrix.tsv`
- 清单：`/home/ubuntu/tmp/real_resolver_replay_matrix/20260514_073433/manifest.json`

真实 multi-resolver campaign matrix：

- 目录：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657`
- resolver 状态表：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/matrix_run_status.tsv`
- full-stack 对比表：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_summary/resolver_full_stack.tsv`
- variant 全表：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_summary/resolver_variant_summary.tsv`

真实 `follow_diff -> dnslabctl sync-replay` 后端探针：

- 目录：`/home/ubuntu/tmp/follow-diff-dnslabctl-real.WGbbQE`
- 状态表：`/home/ubuntu/tmp/follow-diff-dnslabctl-real.WGbbQE/result.tsv`
- 当前 5 个 secondary resolver 的 `meta_status/triage_status` 均为 `completed/completed_oracle_diff`

Python backend vs `dnslabctl` backend 真实对照：

- 目录：`/home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501/_backend_compare`
- TSV：`/home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501/_backend_compare/resolver_backend_compare.tsv`
- JSON：`/home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501/_backend_compare/resolver_backend_compare.json`

resolver capability 总表：

- TSV：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability/resolver_capability_summary.tsv`
- JSON：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability/resolver_capability_summary.json`

RQ5 正式派生表：

- repo 内快照：
  - `docs/RQ5ResolverAdapterCost.tsv`
  - `docs/RQ5ResolverBuildReplayMatrix.tsv`
  - `docs/RQ5ResolverSemanticDistribution.tsv`
- 原始真实产物：
  - `/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability/resolver_adapter_cost.tsv`
  - `/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability/resolver_build_replay_matrix.tsv`
  - `/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability/resolver_semantic_distribution.tsv`

论文正文草稿：

- `docs/DNSPoisonRQ5PaperSectionDraft.md`

backend 对照快照：

- `docs/RQ5ResolverBackendCompare.tsv`
- `docs/DNSPoisonRQ5BackendCompare.md`

## 当前运行命令

真实 replay 能力矩阵：

```bash
bash test/test_real_resolver_replay_matrix.sh
```

真实 multi-resolver campaign matrix：

```bash
bash test/test_real_campaign_matrix_multi_resolver.sh
```

真实 multi-resolver `dnslabctl` backend campaign matrix：

```bash
bash test/test_real_campaign_matrix_multi_resolver_dnslabctl.sh
```

resolver capability 总表：

```bash
python3 -m tools.dns_diff.cli resolver-capability-report \
  --replay-matrix-dir /home/ubuntu/tmp/real_resolver_replay_matrix/20260514_073433 \
  --matrix-batch-dir /home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657 \
  --output-dir /home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability
```

Python backend vs `dnslabctl` backend 对照：

```bash
python3 -m tools.dns_diff.cli resolver-backend-matrix-compare \
  --baseline-batch-dir /home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657 \
  --candidate-batch-dir /home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501 \
  --baseline-label python \
  --candidate-label dnslabctl \
  --output-dir /home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501/_backend_compare
```

该命令会生成：

- `_resolver_capability/resolver_capability_summary.tsv`
- `_resolver_capability/resolver_capability_summary.json`
- `_resolver_capability/resolver_adapter_cost.tsv`
- `_resolver_capability/resolver_build_replay_matrix.tsv`
- `_resolver_capability/resolver_semantic_distribution.tsv`

## RQ5 当前总表

表头解释：

- `integration_mode`：当前 resolver 接入方式
- `adapter_cost_proxy`：当前接入复杂度代理值，不是精确 LOC
- `build_real_status`：真实 `adapter-build` 结果
- `replay_real_status`：真实 `adapter-replay` 或等价 replay smoke 结果
- `matrix_status`：真实 `campaign-matrix` 结果
- `cache_observable_status`：当前是否能在真实链路中导出 cache 证据
- `full_stack_semantic_counts_json`：当前 `full_stack` 真实快照下的差异类型分布

| resolver | resolver_pair | integration_mode | adapter_cost_proxy | build_real_status | replay_real_status | matrix_status | cache_observable_status | full_stack_run_count | full_stack_variance_status | full_stack_semantic_counts_json |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `bind9_vs_unbound` | `native_orchestrator` | `high` | `pass` | `pass` | `pass` | `observable` | `2` | `ok` | `{"oracle_and_cache_diff": 1.0}` |
| `dnsmasq` | `bind9_vs_dnsmasq` | `python_harness` | `low` | `pass` | `pass` | `pass` | `observable` | `2` | `ok` | `{"runtime_or_parse_failure": 1.0}` |
| `smartdns` | `bind9_vs_smartdns` | `python_harness` | `low` | `pass` | `pass` | `pass` | `observable` | `2` | `ok` | `{"runtime_or_parse_failure": 1.0}` |
| `maradns` | `bind9_vs_maradns` | `python_harness_with_preload_shim` | `medium` | `pass` | `pass` | `pass` | `observable` | `2` | `ok` | `{"runtime_or_parse_failure": 1.0}` |
| `knot-resolver` | `bind9_vs_knot-resolver` | `python_harness_with_selfcontained_runtime` | `medium` | `pass` | `pass` | `pass` | `observable` | `2` | `ok` | `{"runtime_or_parse_failure": 1.0}` |

## 当前结论

### 1. RQ5 的真实接入目标已全部跑通

当前 5 个 secondary resolver 都具备：

- 真实 build 信号
- 真实 replay 信号
- 真实 `campaign-matrix` 信号
- 真实 capability 汇总信号

这意味着“多 resolver 泛化”这一问题已经从“设计目标”推进到了“真实可运行系统能力”。

### 1.1 当前可直接引用的正式表

当前最适合直接写入论文或计划书附录的 3 张表是：

1. `docs/RQ5ResolverAdapterCost.tsv`
2. `docs/RQ5ResolverBuildReplayMatrix.tsv`
3. `docs/RQ5ResolverSemanticDistribution.tsv`

### 2. 当前 adapter 成本呈现出 3 档结构

- `low`：`dnsmasq`、`smartdns`
- `medium`：`maradns`、`knot-resolver`
- `high`：`unbound`

当前这是一种**工程代理口径**：

- `python_harness` 记为 `low`
- `python_harness_with_preload_shim` / `python_harness_with_selfcontained_runtime` 记为 `medium`
- `native_orchestrator` 记为 `high`

这个口径适合当前阶段的工程比较，后续若要写入论文正文，建议再补一版更严格的量化口径，例如：

- 适配文件数
- 适配增量代码行数
- 首次跑通耗时

### 3. 当前 cache 可观测性已经形成统一 `observable`

当前 5 个 secondary resolver 在真实链路中都已经能稳定产出 cache 证据，说明 RQ5 中“cache 可观测性”这一列已经具备真实支撑，不再只是设计假设。

### 4. 当前差异类型分布仍然偏“最小样本快照”

当前 `full_stack_semantic_counts_json` 反映的是：

- `unbound`：`{"oracle_and_cache_diff": 1.0}`
- 其余 4 个 resolver：`{"runtime_or_parse_failure": 1.0}`

这说明当前单一样本的语义区分力主要集中在 `bind9_vs_unbound`，其它 resolver 在这份样本上更多体现为“可运行但未形成强差异证据”。

这个结果对论文是有价值的，因为它清楚说明了：

- RQ5 的工程可移植性已经成立
- RQ5 的“差异类型分布”仍然需要更大样本池支撑

### 5. `dnslabctl` 后端当前已具备真实对照证据

当前真实对照表显示：

- `python backend` 与 `dnslabctl backend` 都已在 5 个 secondary resolver 上完成真实 `campaign-matrix`
- 5 个 resolver 的 `matrix_status`、`run_count` 与 `variance_status` 在当前快照中保持一致

当前单样本快照下，`dnslabctl backend` 在 `dnsmasq/smartdns/maradns/knot-resolver` 上比 `python backend` 产生了更强的 `oracle_and_cache_diff` 或 `oracle_diff` 语义分类，这说明该后端已经不只是“可运行替代路径”，而是会影响真实语义结果分布。

## 当前局限

### 局限 1：样本规模过小

当前真实矩阵只使用了 1 个 transcript 样本，虽然每个 variant 做了 `repeat=2`，但仍不足以形成论文级统计显著性。

### 局限 2：预算仍是 smoke 级

当前 `budget-sec=5` 只够证明：

- 流程能跑
- 证据能落
- 对比表能生成

它不够支持论文中的长期运行结论。

### 局限 3：差异类型分布还没有扩展开

当前除 `unbound` 外，其它 resolver 的 `full_stack_semantic_counts_json` 都是 `runtime_or_parse_failure`，这说明当前队列样本对这些 resolver 还没有产生更细粒度的语义分布。

## 下一步建议

### 优先级 1：扩展真实 queue

目标：

- 给 5 个 secondary resolver 提供同一批更大的真实 transcript 队列

直接效果：

- `full_stack_semantic_counts_json` 不再只反映单样本
- `oracle_audit_candidate_count_mean`、`semantic_diff_count_mean` 才有论文意义

### 优先级 2：把 `repeat` 提升到 `5`

目标：

- 对齐 `docs/DNSPoisonFuzzingPlan.md` 中“每个配置至少 5 次独立重复”的要求

### 优先级 3：补论文口径表

建议从当前总表继续派生 3 张正式表：

1. `resolver_adapter_cost.tsv`
2. `resolver_build_replay_matrix.tsv`
3. `resolver_semantic_distribution.tsv`

## 当前结论边界

当前可以稳定陈述的内容：

- 5 个 secondary resolver 的真实 `build/replay/campaign-matrix` 已全部跑通
- 当前系统已经具备真实 RQ5 对比能力
- 当前单样本快照下，`bind9_vs_unbound` 产生了 `oracle_and_cache_diff`
- 其它 4 个 resolver 当前更多体现为“已接通、可运行、可出证据”

当前不应直接陈述的内容：

- “所有 resolver 都已经观察到同等强度的缓存语义差异”
- “当前 RQ5 差异类型分布已经充分稳定”
- “当前 adapter 成本已经完成最终量化”
- “当前 `dnslabctl backend` 已可无条件替代 Python backend 成为默认路径”
