 # DNS 多解析器同步差分测试论文实现与实验计划

  ## 摘要

  论文主线选择开题报告方法二“单一变异源与多解析器同步差分重放”，把方法一“多层级输入模型与局部符号化生成”作为输入建模与增强模块。研究点收敛为：面向 DNS 缓存语义缺陷的 transcript-guided hybrid fuzzing 与多解析器
  同步 replay/triage 框架。

  当前仓库已经具备可复用基础：DST1 transcript、gen_input、AFL++ custom mutator、BIND9/Unbound patch 布局、tools/dns_diff 的 replay/oracle/cache diff/triage/campaign 证据链。后续重构目标是把 Python 差分原型下沉
  为 C++ 主体框架，Python/Bash 只保留短脚本入口，每个脚本控制在 100 行以内。

  ## 实现计划

  - 新增 C++ 主体模块 dnslab_core，由 xmake 统一维护，负责 transcript 解析、样本身份、resolver adapter 调度、oracle 提取、cache fingerprint、差异聚类与证据 bundle 生成。
  - 复用 gen_input/include 与 DST1Mutator，把 DST1 transcript 固定为论文主输入模型，支持“query -> forged response -> post-check query”的完整交互序列。
  - 将现有 tools/dns_diff/schema.py 的证据契约迁移为 C++ 数据结构，保留字段语义：analysis_state、aggregation_key、baseline_compare_key、seed_provenance、failure。
  - 将现有 BIND9/Unbound patch 机制泛化为 ResolverAdapter 接口：prepare_source、apply_patch、build、run_sample、dump_cache、flush_cache、parse_oracle、collect_logs。
  - 六个 resolver 全部按 tag 冻结源码：BIND9、Unbound、MaraDNS、dnsmasq、SmartDNS、Knot Resolver；源码修改统一通过 git diff > patch/<purpose>/<resolver>/<tag>.patch 保存。
  - BIND9 继续作为 producer，其他 resolver 作为同步 replay target；后续可增加 Unbound producer 消融，但正式主线固定单 producer，降低状态失配。
  - Python 只保留报告聚合和图表生成脚本，Bash 只保留环境启动与批量运行包装；复杂逻辑全部进入 C++。
  - tag 冻结由实现阶段的 git ls-remote --tags 自动生成 experiments/resolvers.lock.json，本轮网页核对到的候选包括 BIND9 v9.20.22/v9.18.48、Unbound release-1.24.2、SmartDNS Release47.1、Knot Resolver v6.2.0；
    dnsmasq 指定仓库 imp/dnsmasq 显示较旧 tag，实验前需要按用户给定仓库真实 tag 冻结。

  ## 实验设计

  - RQ1 输入有效性：比较 DST1 transcript、query-only、随机 DNS packet、legacy response-tail，指标为解析接受率、进入递归/cache 路径比例、有效 post-check 比例。
  - RQ2 同步差分有效性：比较“单一 producer 同步 replay”和“各 resolver 独立 fuzz”，指标为可比较样本比例、replay 成功率、差异噪声率、人工审计成本。
  - RQ3 Hybrid 增益：比较 full stack、AFL-only、无 SymCC 回流、无 high-value gate，指标为新路径、有效候选、oracle 命中、单位时间高价值样本数。
  - RQ4 状态指纹降噪：比较无过滤、启发式过滤、fingerprint 聚类、人工审计后真值，指标为假阳性率、cluster 数、每个真值 case 的定位成本。
  - RQ5 多 resolver 泛化：比较 BIND9/Unbound/MaraDNS/dnsmasq/SmartDNS/Knot Resolver，报告 adapter 成本、构建成功率、cache 可观测性、差异类型分布。

  ## 当前 RQ1 实证快照

  - 当前真实 RQ1 最小快照已经落盘到 [DNSPoisonRQ1Snapshot.md](./DNSPoisonRQ1Snapshot.md)。
  - 当前 repo 内 RQ1 正式表：`docs/RQ1InputModelSnapshot.tsv`
  - 当前原始真实产物：`/home/ubuntu/tmp/rq1_input_model_snapshot/20260514_084505/out/summary.tsv`
  - 当前快照只覆盖单样本/模型的最小验证，还不能替代正式大样本输入模型对照实验。

  ## 当前 RQ5 实证快照

  - 当前真实 RQ5 快照已经落盘到 [DNSPoisonRQ5Snapshot.md](./DNSPoisonRQ5Snapshot.md)。
  - 当前真实 multi-resolver batch 目录：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657`
  - 当前真实 capability 总表：`/home/ubuntu/tmp/real_campaign_matrix_batch/20260514_072657/_resolver_capability/resolver_capability_summary.tsv`
  - 当前 repo 内 RQ5 正式表：`docs/RQ5ResolverAdapterCost.tsv`、`docs/RQ5ResolverBuildReplayMatrix.tsv`、`docs/RQ5ResolverSemanticDistribution.tsv`
  - 当前 5 个 secondary resolver 的真实 `build/replay/campaign-matrix` 都已经通过，说明“多 resolver 泛化”的工程闭环已经成立。
  - 当前快照仍是单样本、`repeat=2`、`budget-sec=5` 的最小真实验证，后续还需要扩大 queue、提高 repeat 并补论文口径表。

  ## 论文证据与验收

  - 每次正式实验使用固定预算，例如 1h/6h/24h 三档；每个配置至少 5 次独立重复，报告均值、方差、最小值、最大值。
  - 每个 run 生成 evidence_bundle.json、summary.json、oracle_audit.tsv、failure_taxonomy.tsv、cluster.tsv、case_studies/index.tsv。
  - 至少完成 2 到 5 个端到端 case study，每个 case 包含原始 transcript、resolver 日志、before/after cache dump、oracle、人工结论和一键 replay 命令。
  - 失败样本必须分类为 transcript 解析失败、构建/依赖失败、harness 失败、timeout/crash、目标行为差异，论文结果只统计 included 样本。
  - 投稿目标按 CCF-C 优先落地，CCF-B 需要补强大规模重复实验、更多 resolver 支持、真值 case 和与 ResolverFuzz/BGF-DR/AFLNet/StateAFL 的系统对比。

  ## 默认假设

  - 论文核心贡献为“DNS 状态语义差分测试框架”，漏洞发现案例作为实证支撑。
  - 正式实现以 C++17 为主体，继续使用 xmake，保留现有 gen_input 与 SymCC 构建体系。
  - resolver 源码默认放入 experiments/subjects/<resolver>/<tag>，所有本地改动以 patch 保存，实验产物放入 experiments/runs/<timestamp>。
  - 实现阶段遇到 cache dump 接口、resolver 运行模式、patch 粒度、实验预算等模糊点时，先提问再继续实现。
