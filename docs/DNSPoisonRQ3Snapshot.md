# DNS Poison RQ3 真实快照

## 文档目的

本文档记录 `docs/DNSPoisonFuzzingPlan.md` 中 `RQ3 Hybrid 增益` 的当前真实最小快照，说明当前变体矩阵已经具备哪些真实证据，以及它还缺什么。

对应快照时间：

- `2026-05-14`

repo 内快照表：

- [RQ3HybridSnapshot.tsv](/home/ubuntu/codex/symcc/docs/RQ3HybridSnapshot.tsv)

原始真实产物：

- `/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_summary/resolver_variant_summary.tsv`

## 当前覆盖的变体

当前真实快照覆盖 4 个变体：

1. `full_stack`
2. `afl_only`
3. `no_mutator`
4. `no_cache_delta`

当前快照中：

- `afl_only` 等价于关闭 `SYMCC`
- `no_mutator` 等价于关闭 `DST1 mutator`
- `no_cache_delta` 等价于关闭 `cache-delta`

这说明当前 RQ3 快照已经具备真实“部分消融矩阵”，但还没有覆盖计划中提到的“无 high-value gate”这一项。

## 当前结果

### 1. 变体矩阵本身已真实跑通

当前 5 个 resolver 上的 4 个变体全部满足：

- `run_count = 2`
- `variance_status = ok`

因此，当前系统已经不是“只能跑一条 full_stack 主线”，而是能在真实 resolver 上跑通最小 Hybrid/ablation 变体矩阵。

### 2. 当前快照下，`unbound` 仍然是唯一显著语义差异来源

在 `bind9_vs_unbound` 上：

- `oracle_audit_candidate_count_mean = 1`
- `semantic_diff_count_mean = 1`

在其余 4 个 resolver 上：

- `oracle_audit_candidate_count_mean = 0`
- `semantic_diff_count_mean = 0`

这说明当前单样本真实快照里，真正能把 Hybrid 变体结果“拉到语义差异层”的仍是 `unbound` 路径。其它 resolver 当前主要体现为“矩阵能跑、但信号还没展开”。

### 3. 当前变体之间还没有拉出可见统计差距

对当前所有 resolver 而言，`total_samples_mean / needs_review_count_mean / cluster_count_mean` 都保持一致。这说明：

- 当前样本池过小
- 当前预算过短
- 当前变体矩阵更多证明“工程可运行”，还不能证明“方法增益已显著可测”

## 当前结论边界

当前可以稳定声称：

- RQ3 的最小真实变体矩阵已经成立
- `full_stack / afl_only / no_mutator / no_cache_delta` 已可在 5 个 resolver 上真实运行
- 当前真实快照中，`bind9_vs_unbound` 仍然是主要语义差异来源

当前不应直接声称：

- `SYMCC` 或 `DST1 mutator` 在当前快照中已经带来了显著增益
- 当前 4 个变体足以完整代表计划中的所有 Hybrid 组件
- 当前 RQ3 已达到论文终稿级统计说服力

## 下一步建议

1. 把 `repeat=2` 提升到 `repeat=5`
2. 扩大 queue，不再只用单样本
3. 增加 `no_high_value_gate` 变体
4. 在 `resolver_backend_compare` 之外，再做一张 `RQ3 delta` 正式表
