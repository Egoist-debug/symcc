# DNS Poison RQ5 多样本 full_stack 结果

## 文档目的

本文档记录 `docs/DNSPoisonFuzzingPlan.md` 中 RQ5“多 resolver 泛化”在当前 repo 内最新一轮多样本真实结果，重点回答两个问题：

1. 当队列从单样本扩到稳定小批量时，`full_stack` 主线是否仍然稳定可重复
2. 不同 resolver 的语义结果是否已经开始分化出可写入论文的主表

## 当前真实批次

- 批次目录：
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260523_095431`
- 运行口径：
  - `resolver = unbound / dnsmasq / smartdns / maradns / knot-resolver`
  - `variant = full_stack only`
  - `queue_limit = 4`
  - `repeat = 5`
  - `budget_sec = 12`
- repo 内正式表：
  - [RQ5FullStackMultiSampleSummary.tsv](./RQ5FullStackMultiSampleSummary.tsv)
- 人工 case study 索引：
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/index.tsv`
  - 当前仍沿用上一轮代表性样本说明；新批次 `run-01` 的四类语义仍保持相同样本角色

## 主表结论

| resolver | resolver_pair | run_count | variance_status | total_samples_mean | unknown_samples_mean | needs_review_count_mean | oracle_audit_candidate_count_mean | semantic_diff_count_mean | semantic_counts_mean_json |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `bind9_vs_unbound` | `5` | `ok` | `4.0` | `4.0` | `4.0` | `0.0` | `0.0` | `{"runtime_or_parse_failure": 4.0}` |
| `dnsmasq` | `bind9_vs_dnsmasq` | `5` | `ok` | `4.0` | `0.0` | `4.0` | `4.0` | `4.0` | `{"oracle_diff": 4.0}` |
| `smartdns` | `bind9_vs_smartdns` | `5` | `ok` | `4.0` | `4.0` | `4.0` | `0.0` | `0.0` | `{"runtime_or_parse_failure": 4.0}` |
| `maradns` | `bind9_vs_maradns` | `5` | `ok` | `4.0` | `0.0` | `4.0` | `4.0` | `4.0` | `{"oracle_diff": 4.0}` |
| `knot-resolver` | `bind9_vs_knot-resolver` | `5` | `ok` | `4.0` | `0.0` | `0.0` | `0.0` | `0.0` | `{"no_diff": 4.0}` |

## 当前可直接写入论文的表述

> 在 `full_stack` 主线、`queue_limit=4`、`repeat=5`、`budget_sec=12` 的真实批次中，5 个 secondary resolver 全部完成了稳定重复，`variance_status` 均为 `ok`。其中，`bind9_vs_dnsmasq` 与 `bind9_vs_maradns` 在所有重复中都稳定落为 `oracle_diff`，而 `bind9_vs_knot-resolver` 在同一批样本上持续表现为 `no_diff`。相对地，`bind9_vs_unbound` 与 `bind9_vs_smartdns` 当前仍主要表现为 `runtime_or_parse_failure`，说明当前稳定 transcript 子集在更大样本池下仍然保持了同样的三类分化。

## 当前意义

这轮结果已经强于此前的单样本 smoke 快照，原因有三点：

1. 每个 resolver 都完成了 `repeat=5` 的真实重复
2. 每次运行都消费了 `4` 个稳定 transcript，而不是单个 `matrix-seed`
3. `dnsmasq / maradns / knot-resolver` 已经拉出了三类不同结论：`oracle_diff / oracle_diff / no_diff`

这说明当前论文材料已经不再只有“工程闭环能跑”，而是开始具备“不同 resolver 语义分化可被主表稳定捕捉”的证据。

## 结论边界

当前仍应保持以下边界：

- 这轮仍是“小批量稳定样本”实验，不是大队列长期预算实验
- `queue_limit=4` 仍然只是“小规模多样本下结果稳定”，还不能替代 `1h/6h/24h` 主实验
- `unbound / smartdns` 的 `runtime_or_parse_failure` 需要继续拆成更细的原因，当前不宜直接上升为漏洞结论
- `smartdns` 的 `cluster_count_mean` 已升到 `2.0`，说明更大样本池里失败轨迹开始分叉，但主导语义标签还没变化

当前已确认的一点是：

- `unbound / smartdns` 的代表性样本在 `sample.meta.status` 上仍为 `completed`
- `bind9.parse_ok` 与 secondary `parse_ok` 当前都为 `true`
- 这说明当前标签更接近 `oracle_parse_incomplete` 这一层的保守分类，而不是“目标根本没有跑起来”

## 当前最有价值的 4 个 case study

- `case-01-dnsmasq`：稳定 `oracle_diff` 正例
- `case-02-maradns`：secondary 运行失败但 triage 仍收敛到 `oracle_diff`
- `case-03-knot`：稳定 `no_diff` 负对照
- `case-04-unbound`：`runtime_or_parse_failure` 代表性样本

这些案例已经落在：

- `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/`

## 下一步

当前最自然的强化方向有两条：

1. 保持 `full_stack only`，把 `queue_limit` 从 `4` 提到 `8` 或延长 `budget_sec`
2. 在现有 `dnsmasq / maradns / knot-resolver` 结果之上追加“无 high-value gate”对照，补强 RQ3
