# DNS Poison 计划完成度审计

## 审计目的

本文档对应 `docs/DNSPoisonFuzzingPlan.md`，把当前仓库状态按“已完成 / 部分完成 / 未完成”做一次计划级审计，并给出证据路径与未完成原因。

审计时间：

- `2026-05-14`

审计结论：

- **计划未完成**
- **RQ5 已形成真实工程闭环与正式快照**
- **RQ1/RQ2/RQ3/RQ4 仍未达到论文终稿要求**
- **Python 主链仍承担大量复杂逻辑，C++ 主体化目标未完成**

## 目标拆解

当前目标可拆为 4 类交付物：

1. 实现计划落地
2. RQ1-RQ5 实验链落地
3. 论文证据与验收契约落地
4. 计划文档可直接引用的正式表与快照

## 一、实现计划审计

| 计划项 | 状态 | 证据 | 当前边界 |
| --- | --- | --- | --- |
| `dnslab_core` 作为 C++ 主体模块存在 | `部分完成` | [dnslab_core/xmake.lua](/home/ubuntu/codex/symcc/dnslab_core/xmake.lua), [dnslab_core/src/main.cpp](/home/ubuntu/codex/symcc/dnslab_core/src/main.cpp), [dnslab_core/src/concrete_adapters.cpp](/home/ubuntu/codex/symcc/dnslab_core/src/concrete_adapters.cpp) | 已覆盖 transcript、adapter、sync-replay、batch-sync-replay、evidence-bundle；`follow-diff/replay/matrix/campaign` 仍主要在 Python |
| 复用 `gen_input` 与 `DST1Mutator`，固定统一 transcript 输入模型 | `部分完成` | [gen_input/include/DST1Transcript.h](/home/ubuntu/codex/symcc/gen_input/include/DST1Transcript.h), [gen_input/src/afl_dst1_mutator.cpp](/home/ubuntu/codex/symcc/gen_input/src/afl_dst1_mutator.cpp), [test/test_dns_diff_replay_unbound_smoke.sh](/home/ubuntu/codex/symcc/test/test_dns_diff_replay_unbound_smoke.sh) | 10 字节头协议已在真实链路可用；仍存在旧样本/旧 fake transcript 兼容层，仓库还未完全清理旧格式依赖 |
| 将 `schema.py` 证据契约迁移为 C++ 数据结构 | `部分完成` | [dnslab_core/include/dnslab_core/evidence_contract.hpp](/home/ubuntu/codex/symcc/dnslab_core/include/dnslab_core/evidence_contract.hpp), [dnslab_core/src/evidence_contract.cpp](/home/ubuntu/codex/symcc/dnslab_core/src/evidence_contract.cpp), [dnslab_core/include/dnslab_core/reporting.hpp](/home/ubuntu/codex/symcc/dnslab_core/include/dnslab_core/reporting.hpp) | C++ 已有契约结构；真实主链仍由 Python 侧 `schema.py / report.py / campaign.py` 驱动 |
| 泛化为 `ResolverAdapter` 接口 | `已完成` | [dnslab_core/include/dnslab_core/resolver_adapter.hpp](/home/ubuntu/codex/symcc/dnslab_core/include/dnslab_core/resolver_adapter.hpp), [dnslab_core/include/dnslab_core/concrete_adapters.hpp](/home/ubuntu/codex/symcc/dnslab_core/include/dnslab_core/concrete_adapters.hpp) | 已覆盖 `bind9/unbound/dnsmasq/smartdns/maradns/knot-resolver` |
| 六个 resolver 按 tag 冻结并可准备源码树 | `已完成` | [experiments/resolvers.lock.json](/home/ubuntu/codex/symcc/experiments/resolvers.lock.json), `experiments/subjects/*`, `dnslabctl prepare-subject(s)` 路径 | 当前 freeze 证据已齐 |
| `BIND9` 作为 producer，其他 resolver 作为 replay target | `已完成` | [tools/dns_diff/config/poison_stateful_longbudget_matrix.json](/home/ubuntu/codex/symcc/tools/dns_diff/config/poison_stateful_longbudget_matrix.json), [tools/dns_diff/config/poison_stateful_dnsmasq_matrix.json](/home/ubuntu/codex/symcc/tools/dns_diff/config/poison_stateful_dnsmasq_matrix.json), [tools/dns_diff/config/poison_stateful_smartdns_matrix.json](/home/ubuntu/codex/symcc/tools/dns_diff/config/poison_stateful_smartdns_matrix.json), [tools/dns_diff/config/poison_stateful_maradns_matrix.json](/home/ubuntu/codex/symcc/tools/dns_diff/config/poison_stateful_maradns_matrix.json), [tools/dns_diff/config/poison_stateful_knot_matrix.json](/home/ubuntu/codex/symcc/tools/dns_diff/config/poison_stateful_knot_matrix.json) | 真实 batch 已按 `bind9_vs_<resolver>` 跑通 |
| Python 只保留聚合/制图，复杂逻辑进入 C++ | `未完成` | Python 主链仍集中在 [tools/dns_diff/follow_diff.py](/home/ubuntu/codex/symcc/tools/dns_diff/follow_diff.py), [tools/dns_diff/replay.py](/home/ubuntu/codex/symcc/tools/dns_diff/replay.py), [tools/dns_diff/matrix.py](/home/ubuntu/codex/symcc/tools/dns_diff/matrix.py), [tools/dns_diff/campaign.py](/home/ubuntu/codex/symcc/tools/dns_diff/campaign.py) | 当前最主要未完成项之一 |
| `follow_diff` 开始具备 `dnslabctl sync-replay` 后端 | `部分完成` | [tools/dns_diff/follow_diff.py](/home/ubuntu/codex/symcc/tools/dns_diff/follow_diff.py), [test/test_follow_diff_dnslabctl_backend_knot_smoke.sh](/home/ubuntu/codex/symcc/test/test_follow_diff_dnslabctl_backend_knot_smoke.sh), [test/test_follow_diff_dnslabctl_backend_dnsmasq_smoke.sh](/home/ubuntu/codex/symcc/test/test_follow_diff_dnslabctl_backend_dnsmasq_smoke.sh), [test/test_follow_diff_dnslabctl_backend_smartdns_smoke.sh](/home/ubuntu/codex/symcc/test/test_follow_diff_dnslabctl_backend_smartdns_smoke.sh), [test/test_follow_diff_dnslabctl_backend_maradns_smoke.sh](/home/ubuntu/codex/symcc/test/test_follow_diff_dnslabctl_backend_maradns_smoke.sh), 真实 5 resolver 探针结果 `/home/ubuntu/tmp/follow-diff-dnslabctl-real.WGbbQE/result.tsv`，真实多 resolver backend 对照 `/home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/20260514_082501/_backend_compare/resolver_backend_compare.tsv` | 当前仍是受控开关 `DNS_DIFF_REPLAY_BACKEND=dnslabctl`，尚未成为默认路径；但 `unbound/dnsmasq/smartdns/maradns/knot-resolver` 的真实 `follow-diff-once` 探针都已达到 `sample.meta.status=completed` 且 `triage.status=completed_oracle_diff`，并且真实 multi-resolver batch 已与 Python backend 做完一轮统一对照 |
| `git ls-remote --tags` 驱动 lock 文件生成 | `已完成` | `dnslabctl lock-generate`, [experiments/resolvers.lock.json](/home/ubuntu/codex/symcc/experiments/resolvers.lock.json) | 当前 lock 文件已可复用 |

## 二、实验设计审计

### RQ1 输入有效性

状态：

- `部分完成`

证据：

- [DNSPoisonRQ1Snapshot.md](/home/ubuntu/codex/symcc/docs/DNSPoisonRQ1Snapshot.md)
- [RQ1InputModelSnapshot.tsv](/home/ubuntu/codex/symcc/docs/RQ1InputModelSnapshot.tsv)
- 真实产物：`/home/ubuntu/tmp/rq1_input_model_snapshot/20260514_084505/out/summary.tsv`

边界：

- 已有 `DST1 transcript / query-only / random packet / legacy-response-tail` 的真实最小快照
- 当前只覆盖单样本/模型，仍不满足论文终稿级输入模型对照实验

### RQ2 同步差分有效性

状态：

- `部分完成`

证据：

- [dnslab_core/src/main.cpp](/home/ubuntu/codex/symcc/dnslab_core/src/main.cpp) 的 `sync-replay / batch-sync-replay`
- [test/test_dnslabctl_sync_replay_secondary_knot.sh](/home/ubuntu/codex/symcc/test/test_dnslabctl_sync_replay_secondary_knot.sh)
- [test/test_real_campaign_matrix_multi_resolver.sh](/home/ubuntu/codex/symcc/test/test_real_campaign_matrix_multi_resolver.sh)

边界：

- 同步 paired replay 主线已跑通
- 还没有看到“单一 producer 同步 replay”对“各 resolver 独立 fuzz”的正式统计对照

### RQ3 Hybrid 增益

状态：

- `部分完成（3 个 resolver 的 repeat=5 多样本消融已完成，长期预算与 gate 对照未完成）`

证据：

- [DNSPoisonRQ3DnsmasqMultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ3DnsmasqMultiSample.md)
- [RQ3DnsmasqVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3DnsmasqVariantSummary.tsv)
- [DNSPoisonRQ3MaradnsMultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ3MaradnsMultiSample.md)
- [RQ3MaradnsVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3MaradnsVariantSummary.tsv)
- [DNSPoisonRQ3KnotMultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ3KnotMultiSample.md)
- [RQ3KnotVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3KnotVariantSummary.tsv)
- 原始统计表：
  - `experiments/results/real_rq3_multi_resolver_ablation/20260522_083406/resolver_variant_summary.tsv`
  - `experiments/results/real_rq3_multi_resolver_ablation/20260523_093620/resolver_variant_summary.tsv`

边界：

- `dnsmasq / maradns / knot-resolver` 已完成 `queue_limit=2`、`repeat=5`、`budget-sec=12` 的真实多样本消融
- 当前覆盖 `full_stack / afl_only / no_mutator / no_cache_delta`
- 仍未覆盖“无 high-value gate”，也还没达到计划要求的更大样本池和长期预算

### RQ4 状态指纹降噪

状态：

- `部分完成`

证据：

- `state_fingerprint.json` 已在真实 `follow_diff` 目录中落盘：
  - `/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/unbound/matrix_runs/full_stack/run-01/follow_diff/id:000001,orig:matrix-seed__8c387461/state_fingerprint.json`
- `triage.json`、`cluster_summary.tsv`、`status_summary.tsv` 已存在

边界：

- 工程路径存在
- 还没有看到“无过滤 / 启发式 / fingerprint 聚类 / 人工真值”的正式对比结果

### RQ5 多 resolver 泛化

状态：

- `部分完成（工程闭环与 queue_limit=4 主表已完成，长期预算统计未完成）`

核心证据：

- [RQ5FullStackMultiSampleSummary.tsv](/home/egoist/codex/symcc/docs/RQ5FullStackMultiSampleSummary.tsv)
- [DNSPoisonRQ5MultiSample.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ5MultiSample.md)
- [RQ5FailureRefinement.tsv](/home/egoist/codex/symcc/docs/RQ5FailureRefinement.tsv)
- [DNSPoisonRQ5FailureRefinement.md](/home/egoist/codex/symcc/docs/DNSPoisonRQ5FailureRefinement.md)
- 当前正式批次：
  - `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260523_095431`

当前已完成的 RQ5 能力：

- 5 个 secondary resolver 已在 `queue_limit=4`、`repeat=5`、`budget-sec=12` 的 `full_stack` 主线上全部完成稳定重复
- 统一 `full-stack` 主表、failure refinement 表与人工 case study 索引都已生成
- `dnsmasq / maradns / knot-resolver / unbound / smartdns` 已在当前样本池上形成可区分的三类结果

当前未完成的 RQ5 部分：

- `queue_limit=4` 与 `budget-sec=12` 仍偏保守，还没有更大队列与更长预算的主表
- `unbound / smartdns` 当前仍主要落在保守失败标签，需要继续细分失败真值
- `adapter 成本` 仍是工程代理口径，不是最终量化

## 三、论文证据与验收审计

| 验收项 | 状态 | 证据 | 当前边界 |
| --- | --- | --- | --- |
| 固定预算实验 | `部分完成` | `queue_limit=4`、`budget-sec=12` 的正式主表已落盘；批次见 `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260523_095431` | 还没有 `1h/6h/24h` 三档 |
| 每个配置至少 5 次重复 | `部分完成` | [RQ5FullStackMultiSampleSummary.tsv](/home/egoist/codex/symcc/docs/RQ5FullStackMultiSampleSummary.tsv)、[RQ3DnsmasqVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3DnsmasqVariantSummary.tsv)、[RQ3MaradnsVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3MaradnsVariantSummary.tsv)、[RQ3KnotVariantSummary.tsv](/home/egoist/codex/symcc/docs/RQ3KnotVariantSummary.tsv) | RQ1/RQ2/RQ4 仍未达到同口径重复次数 |
| 每个 run 生成 `evidence_bundle.json/summary.json/oracle_audit.tsv/failure_taxonomy.tsv/cluster.tsv/case_studies/index.tsv` | `部分完成` | 真实 `campaign_reports/...` 已有 `summary.json/ablation_matrix.tsv/cluster_counts.tsv/repro_rate.tsv/oracle_audit.tsv/oracle_reliability.json/failure_taxonomy.tsv/exclusion_summary.tsv/evidence_bundle.json` | 真实 batch 目前没有看到 `cluster.tsv` 与 `case_studies/index.tsv` 的统一落盘 |
| 至少 2 到 5 个端到端 case study | `已完成` | `experiments/results/real_full_stack_multi_resolver_dnslabctl/20260522_073442/manual_case_studies/index.tsv` | 当前已有 `4` 个代表性 case；当前 queue_limit=4 主表仍可补同批次案例说明 |
| 失败样本明确分类 | `部分完成` | `failure_taxonomy.tsv`、`resolver_semantic_distribution.tsv` 已存在 | 论文级 failure taxonomy 仍需更大样本 |

## 四、当前最重要的已完成成果

1. 六个 resolver 的 `ResolverAdapter` 工程接口已经齐备。
2. `bind9_vs_unbound/dnsmasq/smartdns/maradns/knot-resolver` 的真实 `campaign-matrix` 已全部跑通。
3. 真实 `replay` 能力矩阵与 `resolver capability summary` 已形成固定产物。
4. RQ5 已经从“设计目标”推进到“真实可运行、可汇总、可引用”的工程闭环。

## 五、当前未完成的最高优先级缺口

1. **Python 主链仍然过重**
   - 这直接对应主计划“复杂逻辑全部进入 C++”仍未完成。
   - 虽然 `dnslabctl backend` 已完成真实 backend 对照，但默认主链仍是 Python。
2. **RQ1/RQ2/RQ4 缺少正式对照实验结果**
   - 当前主要正式证据集中在 RQ3/RQ5。
3. **RQ5 仍缺更大队列与更长预算，RQ3 仍缺 gate 对照**
   - `queue_limit=4`、`budget_sec=12` 仍偏保守，`no_high_value_gate` 还未纳入正式表。
4. **当前 queue_limit=4 主表仍缺同批次人工 case study 说明**
   - 现有 `4` 个代表性案例来自上一轮主表，当前可继续补齐同批次说明。

## 六、建议的下一步

### 路线 A：补论文口径结论与图表

适合当前阶段：

- 直接把 `docs/RQ5Resolver*.tsv` 变成论文图表和文字结论
- 让当前真实结果进入可投稿草稿

### 路线 B：扩展真实样本池

适合继续强化实验：

- 扩大 queue
- 把 `repeat` 提高到 `5`
- 重新生成 `resolver_semantic_distribution.tsv`

### 路线 C：继续把 Python 主链下沉到 C++

适合继续兑现实现计划：

- 优先迁 `replay.py`
- 再迁 `follow_diff.py`
- 最后迁 `matrix.py / campaign.py`

## 当前判断

当前仓库状态足以支撑以下表述：

- “RQ5 的真实工程闭环已经成立”
- “5 个 secondary resolver 的真实 build/replay/campaign-matrix 已全部跑通”
- “当前已有 repo 内正式 RQ5 快照表”

当前仓库状态还不足以支撑以下表述：

- “整份 `DNSPoisonFuzzingPlan` 已完成”
- “Python 主链已被 C++ 主体完全替代”
- “RQ1-RQ5 全部具备论文终稿级统计结果”
