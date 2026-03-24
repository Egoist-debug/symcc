# DNS Resolver 缓存投毒 Differential Fuzzing 计划

## 摘要

本项目的目标是建立一条面向多个 DNS resolver 的缓存投毒差异模糊测试主线。

当前计划不再把重点放在“分别把 BIND9 和 Unbound 各自跑一个长期 campaign”，而是转向：

1. 用统一输入模型生成高价值样本。
2. 用单一 producer 产生样本，保证样本在多个 resolver 之间一一对应。
3. 对同一样本同步执行多 resolver replay、oracle 提取和 cache dump。
4. 以差异样本、cache 指纹和后续复核作为主发现信号。
5. 把“候选差异样本”和“漏洞证据”严格区分。

配套执行清单见：

- [DNSPoisonFuzzingChecklist.md](./DNSPoisonFuzzingChecklist.md)

## 目标重述

### 总目标

构建一个面向多个 DNS resolver 的缓存投毒 differential fuzzing 框架，用统一输入、统一比较口径和统一复核流程来发现可疑缓存投毒行为。

### 具体目标

1. 不只覆盖 DNS 报文解析，而是覆盖缓存相关的状态演化过程。
2. 让 AFL++、SymCC 与 `gen_input` 在同一条实验链路上协同工作。
3. 保证同一样本可以被多个 resolver 以同口径重放。
4. 用缓存相关行为差异而不是单一 crash 作为主要发现信号。
5. 把 cache dump、post-check 和复现脚本纳入统一证据链。

### 当前目标 resolver

- 第一主线：BIND9
- 第二目标：Unbound
- 后续可扩展到更多 resolver，但当前不预设第三个实现

## 论文结论整理

本节总结以下两篇论文中与本项目最相关的方法信息：

- [ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities with Query-Response Fuzzing](../paper/Zhang%20%E7%AD%89%20-%202024%20-%20ResolverFuzz%20Automated%20Discovery%20of%20DNS%20Resolver%20Vulnerabilities%20with%20Query-Response%20Fuzzing-081906.pdf)
- [BGF-DR: bidirectional greybox fuzzing for DNS resolver vulnerability discovery](../paper/Ying%20%E7%AD%89%20-%202026%20-%20BGF-DR%20bidirectional%20greybox%20fuzzing%20for%20DNS%20resolver%20vulnerability%20discovery-509466.pdf)

### ResolverFuzz 的核心做法

- 把 resolver fuzzing 建模为 `client-query + ns-response` 的成对输入，而不是单向单包输入。
- 基于 CVE 分析，优先聚焦短消息序列，认为大量 resolver bug 可以由极短的 query-response 序列触发。
- 查询和响应都采用语法生成，再叠加字节级变异，提高输入被 resolver 接受的概率。
- 采用黑盒执行方式，不依赖深入源码重写。
- 通过 differential testing 比较多个 resolver 的行为差异，以此发现非 crash 语义 bug。
- 通过 cache dump、抓包和行为观测来辅助判断缓存相关漏洞，而不是只看崩溃。
- 对大量差异做聚类和 triage，减少人工筛查成本。
- 将 nameserver 侧本地化，避免真实网络环境干扰 fuzz 结果。

### BGF-DR 的核心做法

- 同时对 client-query 和 nameserver-response 做双向变异。
- 使用 branch coverage 和 state coverage 的联合反馈，而不是只看代码覆盖。
- 把 resolver 的状态空间探索作为核心目标，强调缓存、重试、转发、递归等内部状态。
- 继续使用 differential testing 发现语义 bug。
- 在差分结果上叠加启发式过滤，剔除已知 benign 差异。
- 再对剩余差异做 fingerprint 聚类，按根因组织样本。
- 目标不是找 crash 为主，而是找 cache poisoning、资源消耗和错误响应等语义漏洞。

### BGF-DR 如何解决多被测程序的样本一致性问题

BGF-DR 不是让每个 resolver 各自运行独立 fuzzer、各自变异种子，然后再比较最终结果。它采用的是中央生成与统一分发模式：

- Generator 负责统一生成和变异测试样本。
- Scheduler 从 Generator 取样本后，把同一个测试样本分发给对应的测试单元。
- 每个测试单元包含同构的 client、nameserver 和 resolver 运行环境。
- 为了保证比较有意义，论文明确要求所有 resolver 接收到的是逻辑等价的输入。
- 每轮测试结束后，resolver 会通过 flush cache 或重启来复位，确保下一轮独立。
- 差分阶段虽然会使用多个线程并以不同 resolver 作为 golden standard 做比较，但比较对象始终是同一个测试样本在不同 resolver 上的执行结果。

换句话说，BGF-DR 解决“多被测程序种子变异失配”问题的方式，不是同步多个 fuzzer 的种子库，而是从一开始就避免多套独立变异器并存，改用“单一 Generator 变异一次，再把同一样本 fan-out 给多个 resolver”。

### 对本项目的直接启发

1. 样本必须双向建模。
2. 短 query-response 序列优先，长 transcript 后置。
3. 差分必须基于同一样本，而不是两个独立 campaign 的最终状态。
4. cache 相关证据必须进入自动化流程，不能只靠人工抽查。
5. 需要在 branch coverage 之外引入轻量状态指纹。
6. 差异结果必须先过滤、再聚类、最后人工复核。

## 当前仓库状态

### 当前主链（以仓库实现为准）

1. **BIND9 是 producer**：`named_experiment/run_named_afl_symcc.sh` 负责 producer 侧 fuzz/corpus/work 产物。
2. **Unbound shell 是 thin wrapper**：`unbound_experiment/run_unbound_afl_symcc.sh` 仅做路由、环境注入与路径检查；对 `follow-diff-window` / `campaign-close` 这类闭环路径，不再持有 shell 侧 timeout owner。
3. **Python CLI 是 dns-diff 真入口**：`python3 -m tools.dns_diff.cli` 承载差分主流程，核心命令为：
   - `follow-diff`
   - `follow-diff-once`
   - `follow-diff-window`
   - `replay-diff-cache`
   - `parse-cache`
   - `triage-report`
   - `campaign-report`
   - `campaign-close`
4. **默认 source queue**：`named_experiment/work/afl_out/master/queue`。
5. **默认 follow_diff root**：`unbound_experiment/work_stateful/follow_diff`。

### 样本身份与目录契约

- `sample_id = <queue_event_id>__<sha1前8位>`。
- 每个 `sample_id` 对应 follow_diff 下一个样本目录，承载 replay、cache、triage 与失败证据。

### 当前证据与正式闭环口径

1. replay/follow_diff 负责单样本证据目录。
2. `triage-report` 负责重写 triage 并生成 report 四件套。
3. `campaign-report` 负责生成活动级统计产物，但它只是正式闭环的第三阶段，不单独承担结论口径。
4. 严格 1 小时正式闭环命令固定为 `python3 -m tools.dns_diff.cli campaign-close --budget-sec 3600`，或等价 wrapper 转发命令 `./unbound_experiment/run_unbound_afl_symcc.sh campaign-close --budget-sec 3600`。
5. 正式 deadline owner 固定在 Python `campaign-close`，summary 固定写入 `WORK_DIR/campaign_close.summary.json`，不是 wrapper 的 `DNS_DIFF_CLI_TIMEOUT_SEC`，也不是外层 shell `timeout`。
6. 只有 `follow-diff-window -> triage-report -> campaign-report` 三阶段全部成功，且 `campaign_close.summary.json` 显示 `status=success` 时，才算闭环成功。
7. `follow-diff` / `follow-diff-once` 仍保留为手工观察、局部检查、队列巡检入口，不作为 task 5 或正式实验结论命令。

### 已淘汰且不得回潮的旧表述

- 不再把双独立长期 campaign 作为主线解释。
- 不再把旧 `diff-test` 表述为主入口或主流程。
- 不再把 `cache_entry_created` 当作漏洞成立的强语义证明。
- 不再把 shell timeout、`DNS_DIFF_CLI_TIMEOUT_SEC` 或 `campaign-report` 单独写成闭环 owner。
- 在本次修复完全完成前，历史 run 的正式口径仍是“当次 run 不可行”，不是“只需继续放大时间预算即可”。

## 判定原则

本项目的核心判定逻辑是：

- 同一样本在不同 resolver 上应尽量产生同口径、可比较的结果。
- 一旦出现稳定的 oracle 差异或 cache 差异，就将该样本视为候选异常样本。
- 候选异常样本需要进入 replay、归因和强语义复核流程。
- 差异本身不直接等价于漏洞成立。

换句话说，本项目的主发现信号不是“是否 crash”，而是“同一样本是否导致 resolver 在缓存相关行为上出现不一致”。

## 统一输入模型

### 输入层级

建议把输入明确分成三层：

#### 1. query corpus

用于：

- 起量
- parser 路径探索
- 生成 response 骨架

#### 2. response corpus

用于：

- 构造合法或近合法的上游响应
- 覆盖 authority、additional、glue、compression 等高约束区域
- 作为缓存投毒导向的上游注入素材

#### 3. transcript corpus

用于：

- 表达一次完整的缓存投毒实验交互
- 统一描述 query、多个 response 与 post-check
- 作为跨 resolver replay 的直接输入格式

### 默认策略

- 第一优先：短 query-response 序列
- 第二优先：单 query + 单 response + 单 post-check
- 更长 transcript 仅在短序列筛出高价值样本后再投入主精力

### `gen_input` 的职责边界

1. 生成高质量 DNS query 和 response 语料。
2. 维护 response 内部字段耦合关系。
3. 对 authority、additional、glue 等高价值区域做结构化放大。
4. 生成 transcript 原材料，而不直接承担漏洞定性。

## AFL++、SymCC 与 `gen_input` 的分工

### AFL++

职责：

- 作为唯一在线主变异器提供主吞吐
- 维护主语料池
- 作为 producer 产生新样本
- 通过 custom mutator 在不破坏 transcript 结构的前提下扩展输入空间

### SymCC

职责：

- 补 AFL++ 很难命中的强约束路径
- 只对 producer 队列中的高价值样本做局部符号探索
- 重点突破事务匹配、RR 计数、压缩指针、section 耦合和少量 flag 约束
- 只把“覆盖新增或语义新增”的样本回流到 producer 队列

### `gen_input`

职责：

- 生成结构化种子
- 为 query、response 和 transcript 提供语法感知输入
- 作为多 resolver 共享输入的上游生成器

## 完整实现方案

### 主链执行（Python-first）

1. `named_experiment` producer 产生样本并写入 source queue。
2. 正式闭环使用 `campaign-close --budget-sec 3600` 启动全局 deadline，并在启动时冻结 queue tail。
3. `campaign-close` 在预算内执行 `follow-diff-window`，消费冻结窗口中的样本并落单样本证据目录。
4. `campaign-close` 随后执行 `triage-report`，重写 triage 并生成 report 四件套。
5. `campaign-close` 最后执行 `campaign-report`，生成活动级统计产物与 summary。

> 说明 1：shell 仅是薄包装。dns-diff 的正式闭环入口固定为 `python3 -m tools.dns_diff.cli campaign-close --budget-sec 3600`，wrapper 只做等价转发。
>
> 说明 2：`follow-diff` / `follow-diff-once` 继续保留，用于手工观察、局部检查和队列巡检，不作为正式结论入口。

### 默认路径与身份规则

- 默认 source queue：`named_experiment/work/afl_out/master/queue`。
- 默认 follow_diff root：`unbound_experiment/work_stateful/follow_diff`。
- 默认状态文件：`unbound_experiment/work_stateful/follow_diff.state.json`。
- 样本身份：`sample_id = <queue_event_id>__<sha1前8位>`。

### 单样本证据目录（必须可复核）

对每个 `sample_id`，至少包含：

- `sample.bin`
- `sample.meta.json`
- `oracle.json`
- `cache_diff.json`
- `state_fingerprint.json`
- `triage.json`
- resolver 侧 stderr / cache 工件（按 replay 实际阶段落盘）

### replay 失败证据（必须保留）

当 replay 失败时，主证据链固定为：

- `sample.meta.json.failure`
- 对应阶段 `*.stderr`
- `triage.json`

要求：失败不吞样本，样本目录必须保留可定位的失败上下文。

### 严格 1 小时闭环判定（Frozen）

- 正式命令：`python3 -m tools.dns_diff.cli campaign-close --budget-sec 3600`
- 等价 wrapper：`./unbound_experiment/run_unbound_afl_symcc.sh campaign-close --budget-sec 3600`
- deadline owner：Python `campaign-close`
- summary 路径：`WORK_DIR/campaign_close.summary.json`
- 成功条件：`follow-diff-window`、`triage-report`、`campaign-report` 三阶段全部成功，且 `campaign_close.summary.json` 的 `status` 为 `success`
- 正式结论读取口径：task 5 与正式实验结论统一看 `campaign_close.summary.json` 和进程 exit code
- 非正式辅助口径：`follow-diff`、`follow-diff-once`、`follow-diff-window` 的过程输出可用于观察和定位，但不单独定义闭环成功

### 报告闭环产物（report 四件套）

`triage-report` 后 follow_diff 根目录应包含：

- `cluster_summary.tsv`
- `status_summary.tsv`
- `triage_report.md`
- `high_value_samples.txt`

### 活动闭环产物（campaign 四件套）

`campaign-report` 输出目录应包含：

- `summary.json`
- `ablation_matrix.tsv`
- `cluster_counts.tsv`
- `repro_rate.tsv`

### 正式闭环 summary 产物

`campaign-close` 固定写入 `WORK_DIR/campaign_close.summary.json`，至少用于回答以下问题：

- 本次闭环的 `budget_sec` 与 `deadline_ts`
- 冻结的 `queue_tail_id`
- 闭环总 `status`、`exit_reason`、`exit_code`
- 三阶段 `follow-diff-window` / `triage-report` / `campaign-report` 的 phase summary

## 验收标准

### 功能验收

1. `campaign-close --budget-sec 3600` 能作为严格 1 小时正式闭环入口运行。
2. `follow-diff-window` 能在冻结 queue tail 的前提下消费 source queue，并稳定生成 `sample_id` 目录。
3. `follow-diff` / `follow-diff-once` 仅作为观察和巡检入口保留，不承担正式结论口径。
2. 失败样本目录仍保留 `sample.meta.json.failure` + `*.stderr` + `triage.json`。
4. 闭环成功必须体现为 `follow-diff-window -> triage-report -> campaign-report` 三阶段全部成功，且 `campaign_close.summary.json` 显示 success。

### 产物验收

1. follow_diff 根目录可稳定生成 report 四件套。
2. campaign 报告目录可稳定生成 campaign 四件套。
3. `WORK_DIR/campaign_close.summary.json` 可稳定生成，且能作为正式结论 summary。
4. 所有路径与默认值解释与当前仓库实现一致（以 Python CLI helper 逻辑为准）。

## 范围护栏（本轮冻结）

1. 不恢复旧 `diff-test` 主线叙事或入口定位。
2. 不把 `run/start/stop/status` 写回 unbound wrapper 主线命令面。
3. 不引入第三个 resolver。
4. 不扩展为通用 benchmark 平台。
5. 不在本文件添加长期研究路线扩张表述。
