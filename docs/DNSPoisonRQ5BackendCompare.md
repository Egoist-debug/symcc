# DNS Poison RQ5 Backend 对照

## 文档目的

本文档记录 `python backend` 与 `dnslabctl backend` 在当前真实 RQ5 快照中的对照结果，回答两个问题：

1. `dnslabctl backend` 是否已经具备真实工程可运行性
2. `dnslabctl backend` 是否已经开始影响真实语义结果分布

对应快照时间：

- `2026-05-14`

repo 内对照表：

- [RQ5ResolverBackendCompare.tsv](/home/ubuntu/codex/symcc/docs/RQ5ResolverBackendCompare.tsv)

原始真实产物：

- `/home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501/_backend_compare/resolver_backend_compare.tsv`

## 当前对照结论

### 1. 两条后端都已经完成真实 multi-resolver batch

当前 5 个 secondary resolver 在 `python backend` 与 `dnslabctl backend` 下都满足：

- `matrix_status=pass`
- `run_count=2`
- `variance_status=ok`

这说明 `dnslabctl backend` 已经不再只是探针或 fake smoke，而是已经具备真实 `campaign-matrix` 运行能力。

### 2. `dnslabctl backend` 已经开始改变语义结果分布

当前单样本真实快照下：

- `dnsmasq`：`runtime_or_parse_failure -> oracle_and_cache_diff`
- `smartdns`：`runtime_or_parse_failure -> oracle_and_cache_diff`
- `maradns`：`runtime_or_parse_failure -> oracle_and_cache_diff`
- `knot-resolver`：`runtime_or_parse_failure -> oracle_diff`
- `unbound`：两条后端都为 `oracle_and_cache_diff`

这说明 `dnslabctl backend` 不是单纯“把 Python orchestrator 翻译成 C++ 命令封装”，它已经影响了真实样本在 resolver 上被归类的方式。

## 当前意义

当前可以稳定陈述：

- `dnslabctl backend` 已具备真实 batch 可运行性
- `dnslabctl backend` 已具备和 `python backend` 直接对照的工程基础
- 当前值得继续推进“默认后端切换”或“至少在更多路径上优先使用 C++ replay 后端”

当前仍不宜直接陈述：

- `dnslabctl backend` 已全面优于 `python backend`
- `dnslabctl backend` 的更强语义信号已经等价于更高的真实漏洞发现能力

## 下一步建议

1. 用更大样本池重复这张对照表
2. 抽样人工复核 `oracle_and_cache_diff` 与 `oracle_diff`
3. 若对照结果继续稳定，再考虑把 `DNS_DIFF_REPLAY_BACKEND=dnslabctl` 提升为默认路径
