# DNS Poison 论文优化关键五件事

## 文档目的

本文档把当前研究原型继续推进为可投稿论文时，最关键的 5 件补强事项固定下来，避免后续优化只停留在对话结论里。

适用范围：

- `poison-stateful` transcript fuzzing 主线
- `campaign-close` 差分闭环
- bind9 / unbound replay、triage 与 cache 相关代理信号

配套背景文档：

- [DNSPoisonFuzzingPlan.md](./DNSPoisonFuzzingPlan.md)
- [DNSPoisonFuzzingChecklist.md](./DNSPoisonFuzzingChecklist.md)

## 当前研究定位

目前最稳妥的论文定位不是“已证明跨 resolver 的 cache poisoning 语义差异”，而是：

> 一种面向 DNS poison-stateful 场景的 transcript-guided hybrid fuzzing 与 campaign-close replay / triage 工作流。

换句话说，现阶段更像“候选样本生成、筛选、归因与闭环复现框架”，而不是“已经完成强语义判真的漏洞发现系统”。

## 为什么必须补这 5 件事

当前系统已经具备以下基础：

1. `DST1 transcript` 统一输入模型。
2. AFL++ 与 SymCC 在 transcript 空间协同探索。
3. `campaign-close` 闭环执行 `follow-diff-window -> triage-report -> campaign-report`。
4. 能输出 `oracle.json`、`cache_diff.json`、`triage.json` 与活动级 summary。

但当前仍然存在明显边界：

- `second_query_hit`、`cache_entry_created` 仍是代理信号，不是最终漏洞证明。
- 部分 replay 失败会污染结果解释，尤其是 `unbound.after`。
- 单次短时 run 只能证明流程可运行，不能证明稳定性与统计显著性。
- 没有基线 / 消融，就无法证明方法本身的收益。
- 没有少量人工确认的真值样本，就无法把 proxy signal 升级为研究结论。

因此，后续优化优先级应固定为下面 5 项。

---

## 关键事项 1：做 Oracle 审计

### 目标

回答一个核心问题：当前代理信号到底有多可信。

重点对象：

- `response_accepted`
- `second_query_hit`
- `cache_entry_created`

### 为什么重要

如果不先做 Oracle 审计，论文里最多只能说“筛出了高价值候选样本”，不能说“这些信号对应真实的缓存语义变化”或“对应真实漏洞现象”。

### 建议产出

1. 一份抽样审计表：
   - 样本 ID
   - oracle 命中情况
   - 人工复核结果
   - 最终判断（真阳性 / 假阳性 / 无法判定）
2. 每个 oracle 指标或组合指标的经验可信度说明。
3. 一份“哪些信号只能作为弱代理、哪些组合更强”的总结。

### 最低完成标准

- 至少对一批有代表性的样本做人工复核。
- 能明确写出 `cache_entry_created` 与“真实缓存被污染”之间仍然差多少。
- 能给出假阳性主要来源，而不是只报命中率。

---

## 关键事项 2：做 Failure Taxonomy

### 目标

把 replay 阶段的失败样本系统拆清楚，尤其是 `unbound.after` 的失败，不再把所有失败都混在一起解释。

### 为什么重要

如果失败池不干净，审稿人会优先怀疑 harness / replay 伪影，而不是相信观察到的是 resolver 的真实语义差异。

失败证据路径约定：`sample.meta.json.failure` 表示 `sample.meta.json` 内嵌 `failure` 对象的 JSON 路径，不是独立文件。

publication-facing 引用约定：`campaign_reports/<timestamp>/evidence_bundle.json` 是 `publication_evidence_bundle` 合约文件，后续文稿中的 claim 应先引用 bundle，再由 bundle 回溯到 `summary.json`、`oracle_audit.tsv`、`oracle_reliability.json`、`failure_taxonomy.tsv`、`exclusion_summary.tsv` 与 `case_studies/index.tsv` 的路径、字段路径和再生成命令。

### 建议分类

至少拆成以下类别：

1. transcript 解析失败
2. replay 环境或工件缺失
3. harness / orchestrator 兼容性问题
4. 目标程序崩溃 / timeout
5. 真正值得追踪的行为差异

### 建议产出

1. 失败分类统计表。
2. 每个大类对应的代表样本与证据路径。
3. 一个“哪些失败应剔除，哪些失败值得作为研究现象保留”的规则说明。

### 最低完成标准

- 对失败样本有稳定、可复核的分类口径。
- 能把“环境问题”和“目标差异”分开。
- 论文中可以单独报告失败池，而不是把它们混进发现结果。

---

## 关键事项 3：做多轮独立实验与方差统计

### 目标

证明当前方法不是“一次演示跑通”，而是可以重复得到相近行为分布的实验流程。

### 为什么重要

单次 30 分钟或单次 1 小时 campaign 只能证明流程能跑，不足以支撑研究结论。

### 建议实验组织

1. 固定正式闭环命令：`campaign-close --budget-sec 3600`。
2. 在相同设置下做多次独立重复。
3. 统计至少以下指标：
   - 总样本数
   - completed / failed 数量
   - needs review 数量
   - cluster 数量
   - replay 成功率
   - oracle 命中率
4. 报告均值、最小值、最大值和方差范围。

### 建议产出

1. 多次 run 的总表。
2. 一份趋势图或对比图。
3. 对“不稳定项”的解释，例如 queue 波动、失败率波动、cluster 漂移。

### 最低完成标准

- 至少有多轮相同 protocol 的独立实验。
- 能说明结果不是一次性偶然现象。
- 能指出哪些指标稳定，哪些指标尚不稳定。

---

## 关键事项 4：做基线与消融

### 目标

回答“为什么必须是这套方法组合”这个问题，而不是让评审觉得只是把已有组件拼接在一起。

### 为什么重要

没有基线和消融，评审无法判断收益来自：

- transcript 输入模型
- SymCC 补洞
- post-check 机制
- campaign-close 闭环
- triage / cache-diff 规则

### 建议优先基线

至少选 1 到 2 组最关键对照：

1. **仅 AFL++，无 SymCC**
2. **无 post-check query**
3. **无 campaign-close，只看 producer 结果**
4. **query-only / legacy response-tail 对比 transcript 模式**

### 建议产出

1. 对照实验表：每组配置、预算、输出指标。
2. 消融结论：哪一部分对候选质量、覆盖、复现率提升最大。
3. 明确指出“复杂度增加是否换来了实质收益”。

### 最低完成标准

- 至少有一个能够清楚说明“方法增益”的基线。
- 至少有一个能够清楚说明“关键模块作用”的消融。

---

## 关键事项 5：做少量端到端真值样本

### 目标

从高价值候选样本中，挑出少量案例做深度人工复核，建立从 proxy signal 到真实语义现象的闭环证据。

### 为什么重要

这一步是把“工程上有用的启发式”升级为“学术上可 defend 的研究证据”的关键。

### 建议样本要求

每个样本至少要满足：

1. 证据完整，可回放。
2. 能排除明显 harness / replay 伪影。
3. 能说明 bind9 与 unbound 的行为差异，或说明缓存状态确实发生了有意义变化。
4. 最终结论可人工复核，而不是完全依赖 summary 字段。

### 建议产出

1. 2 到 5 个高质量 case study。
2. 每个 case 的执行路径、oracle、cache diff、人工结论。
3. 一份“为什么这些样本能代表论文主张”的说明。

### 最低完成标准

- 至少拿出少量样本做端到端人工验证。
- 能区分“候选异常”与“真实语义差异”。

---

## 推荐执行顺序

建议按下面顺序推进，而不是并行撒网：

1. **Oracle 审计**
2. **Failure Taxonomy**
3. **多轮独立实验与方差统计**
4. **基线与消融**
5. **端到端真值样本**

原因：

- 前两项先解决“结果能不能信”的问题；
- 第三项解决“结果稳不稳定”的问题；
- 第四项解决“方法有没有增益”的问题；
- 第五项解决“能不能把研究主张升级”的问题。

## 当前阶段不应过度主张的内容

在完成上述 5 项之前，不建议把项目写成以下表述：

1. 已证明跨 resolver 的统一语义差异。
2. 已证明真实 cache poisoning 成功。
3. `cache_entry_created` 可直接等价为漏洞成立。
4. 单次 30 分钟或 1 小时 run 已足以支撑稳定研究结论。
5. 当前系统已经具备论文级 differential truth。
6. `included / excluded / unknown` 已经等价于人工真值标签。

这里需要再明确一次：`response_accepted`、`second_query_hit`、`cache_entry_created`、`oracle_diff` 都只是 proxy signal。它们可以帮助筛样本、定优先级、做归因，但不能直接替代端到端人工复核，也不能直接写成缓存投毒已证明。

## 可升级的论文定位

### 当前最稳定位

- workshop / tool paper
- 工程型研究原型
- transcript-guided DNS stateful testing 工作流论文

### 完成 5 项后的可升级方向

- 更强的实证安全论文
- 面向 DNS resolver 差分测试的方法论文
- 强调 proxy-oracle 可信度与 case study 的系统论文

## 一句话结论

当前项目已经具备论文雏形，但要从“有意思的工程”升级到“有说服力的研究贡献”，关键不在于继续堆功能，而在于补上这 5 件事所代表的证据链。
