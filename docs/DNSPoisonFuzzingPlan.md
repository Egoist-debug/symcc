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

### 已具备的基础能力

- BIND9 已具备 `poison-stateful` transcript 主实验线。
- `gen_input` 已支持 `dns`、`dns-poison-response`、`dns-stateful-transcript`。
- Unbound 已接入第二 resolver 的工程入口，并能消费 `DST1` transcript。
- `unbound_experiment/run_unbound_afl_symcc.sh` 已具备：
  - `diff-test`
  - `dump-cache`
  - `parse-cache`
  - `replay-diff-cache`
- 当前已经具备两阶段 cache 证据链的第一版落地能力。

### 当前的主要问题

1. BIND9 与 Unbound 仍然主要是“各自跑、再离线比较”，而不是“同一样本同步驱动多个 resolver”。
2. `diff-test` 仍偏离线辅助工具，还不是主实验链路。
3. 还没有真正的共享样本 queue follower。
4. 还没有轻量状态覆盖或状态指纹。
5. 差异结果还缺少启发式过滤与聚类。
6. AFL++ 对 transcript 仍缺少专门的结构化 custom mutator。
7. SymCC helper 目前仍主要按 coverage 选种，和 cache / differential 目标耦合不够。

### 已明确淘汰的旧思路

以下思路不再作为主线目标：

- 让 BIND9 和 Unbound 各自独立运行长期 AFL campaign，然后直接比较最终 cache。
- 把 Unbound 长期定位为 parser-lite 辅助目标。
- 继续把 `diff-test` 仅当作一次性人工检查脚本。
- 把 `cache_entry_created` 当作强语义缓存污染证明。

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

### 设计原则

1. 在线只有一个主变异器，即 AFL++ producer。
2. SymCC 不维护独立种子主线，只服务于 producer 队列。
3. 多 resolver 不共享状态模型，只共享样本。
4. branch / state feedback 用于本地引导变异，oracle / cache diff 用于跨 resolver 比较。
5. 所有高成本分析都放在 AFL++ 主路径之外的 sidecar 流程中。

### 方案总览

完整链路拆成五层：

1. `gen_input` 生成结构化初始种子。
2. AFL++ producer 以 BIND9 为唯一在线 target 进行主变异。
3. SymCC helper 从 producer 队列中挑选高价值样本做局部符号探索。
4. `follow-diff` follower 把同一样本 fan-out 到 BIND9 与 Unbound 做成对 replay。
5. sidecar 对 replay 结果做 oracle、cache、状态指纹、过滤、聚类和复核。

### AFL++ 主变异方案

#### 角色定位

- BIND9 `poison-stateful` 目标作为唯一在线 AFL++ target。
- Unbound 不参与在线 AFL++ 反馈，只参与同样本 replay。

#### 输入格式

- 主输入格式固定为 `DST1` transcript。
- transcript 的三个核心部分为：
  - `client_query`
  - `upstream_response_seq`
  - `post_check_query`

#### 变异方式

推荐采用 `custom mutator + AFL++ 原生变异` 的组合：

1. custom mutator 先做结构保持：
   - 保持 `DST1` 包装头和长度字段一致
   - 保持 section 计数、偏移和最小字段约束
   - 在 query / response / post-check 三段上做定向字段变异
2. AFL++ 原生 bit/byte havoc 作为补充：
   - 只在 custom mutator 输出的结构化样本之上继续扩散

#### custom mutator 的重点字段

- Query 侧：
  - `QNAME`
  - `QTYPE`
  - `RD/TC/CD` 等 flags
- Response 侧：
  - `AA/RA/RCODE`
  - `ANCOUNT/NSCOUNT/ARCOUNT`
  - authority / additional 中的 `NS/CNAME/SOA/A/AAAA`
  - glue 相关 name / type / rdata
- Transcript 侧：
  - response 数量
  - post-check query 的目标 name / type

#### 在线反馈

AFL++ 在线反馈只使用单 target 的稳定信号：

- branch coverage
- 少量轻量状态指纹映射成伪边或附加反馈

不直接把以下结果并入 AFL++ 主反馈：

- 多 resolver oracle diff
- cache diff
- 聚类结果

### SymCC 融合方案

#### 角色定位

- SymCC 不替代 AFL++。
- SymCC 是 producer 的“局部约束突破器”。

#### 样本来源

SymCC 只消费 producer 队列中的样本，优先级如下：

1. `+cov` 样本
2. `favored` 样本
3. differential sidecar 标记为新 fingerprint 的样本
4. 命中高价值 oracle 的样本

#### 分段符号化

SymCC 不应符号化整个 transcript，而应采用分段符号化：

- 保持具体值：
  - `DST1` 头部
  - 大部分 `client_query`
  - `post_check_query`
- 重点符号化：
  - response 的 authority / additional
  - RR type / class / ttl / rdata 中的强约束字段
  - 少量 query / response flags
  - 事务匹配相关字段

#### 样本准入规则

SymCC 生成的新样本应通过两级门控：

1. 覆盖价值：
   - `afl-showmap` 判断是否带来新的边
2. 语义价值：
   - replay 后是否带来新的 oracle diff
   - replay 后是否带来新的 cache fingerprint
   - replay 后是否带来新的状态指纹

只有满足其一的样本才进入高价值样本池。

### 状态反馈与跨 resolver 比较解耦

#### 本地状态反馈

BGF-DR 的启发是：

- 每个 resolver 维护自己的状态模型
- 状态模型不要求跨 resolver 一致

因此本项目的设计应是：

- BIND9 记录自己的轻量状态指纹
- Unbound 记录自己的轻量状态指纹
- 两者只用于各自 replay 的摘要和附加分析

#### 跨 resolver 比较对象

跨 resolver 只比较统一行为结果：

- oracle
- cache fingerprint
- 日志摘要
- 流量摘要
- 差异 fingerprint

不直接比较：

- 内部状态名
- branch coverage 数值
- state coverage 数值

### Follow-Diff 方案

新增一个主入口，例如 `follow-diff`，职责如下：

1. 监听 producer queue 中的新样本。
2. 对样本生成唯一结果目录。
3. 执行：
   - BIND9 replay
   - Unbound replay
   - BIND9 dump-cache before/after
   - Unbound dump-cache before/after
4. 统一提取：
   - oracle
   - cache fingerprint
   - 状态指纹
5. 产出：
   - 差异类型
   - 过滤标签
   - cluster id

### 结果目录设计

建议按单样本落盘：

- `sample.bin`
- `bind9.stderr`
- `unbound.stderr`
- `bind9.before.cache.txt`
- `bind9.after.cache.txt`
- `unbound.before.cache.txt`
- `unbound.after.cache.txt`
- `bind9.norm.tsv`
- `unbound.norm.tsv`
- `oracle.json`
- `cache_diff.json`
- `state_fingerprint.json`
- `triage.json`

### 过滤与聚类方案

#### 过滤

优先过滤以下 benign 差异：

- TTL 波动
- transaction id / 随机字段
- `_bind` 等非目标 view 的差异
- 仅格式差异、无 cache 变化、无 post-check 变化的样本

#### 聚类

cluster 指纹至少包含：

- resolver pair
- qname
- qtype
- rcode
- cache section
- cache type
- 是否写入 negative cache
- 是否 post-check hit
- 是否存在 authority / additional / glue 相关变化

## 目标架构

### A. 样本生产层

当前建议：

- 由 BIND9 `poison-stateful` 主线继续承担 producer 角色
- 由 AFL++ 和 SymCC helper 共同向同一个队列回流样本

### B. 样本同步层

新增目标：

- 建立 queue follower
- 监听 producer queue 中的新样本
- 保证每个样本都能被 BIND9 与 Unbound 同步 replay

### C. resolver adapter 层

每个 resolver 都应暴露统一能力：

- replay 样本
- 导出 cache dump
- 提取 oracle
- 输出统一日志

### D. 差分与 triage 层

对同一样本自动生成：

- BIND9 oracle
- Unbound oracle
- BIND9 cache fingerprint
- Unbound cache fingerprint
- 差异类型
- fingerprint / cluster id

## oracle 与状态指纹

### 基础 oracle

所有 resolver 最终都应输出统一字段：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `second_query_hit`
- `cache_entry_created`
- `timeout`

### 轻量状态指纹

在 BGF-DR 的启发下，建议增加轻量状态指纹，而不是等待完整 state coverage。

优先补充的状态维度：

- 是否进入 forwarding path
- 是否触发 retry / retransmission
- 是否写入 `MSG` cache
- 是否写入 `RRSET` cache
- 是否写入 negative cache
- 是否只写入 `SERVFAIL` / `BADCACHE`
- query type / rcode / section 摘要

### 文档与实验记录中的使用约束

1. `response_accepted` 只能表述为“伪造响应进入接受路径”。
2. `second_query_hit` 只能表述为“post-check 未再次触发新的上游抓取”。
3. `cache_entry_created` 当前仍主要是代理信号。
4. `cache dump` 只能证明“缓存中出现了什么”，不能单独证明漏洞成立。

## 两阶段缓存证据链

为避免在 fuzz 主线上引入过多 resolver 内部改动，同时又提升缓存投毒候选样本的证据强度，后续缓存分析按两阶段推进：

### 阶段一：离线 cache dump 观测

- fuzz 主线保持简洁，不在在线执行路径中塞入整套 cache 解析逻辑
- campaign 后或单样本 replay 后导出 cache dump
- dump 结果承担“缓存中出现了什么”的证据职责

### 阶段二：候选样本单样本 replay + 前后对比

- 对高价值差异样本在干净实例里逐个 replay
- replay 前后分别导出 cache dump
- 结合 post-check 结果分析 cache 是否被样本真正影响

## 统一实验流程

### 当前推荐主链

1. 生成 query corpus。
2. 基于 query corpus 生成或扩展 response corpus。
3. 用 response corpus 组装 transcript corpus。
4. 用 BIND9 producer 运行长期 campaign。
5. 由 follower 监听 producer queue 中的新样本。
6. 对同一样本同步执行 BIND9 与 Unbound replay。
7. 提取 oracle、cache dump 和状态指纹。
8. 先过滤差异，再聚类，再做强语义复核。

### 当前脚本分工

#### BIND9 主线

- `named_experiment/run_named_afl_symcc.sh`

当前定位：

- producer
- 长期 campaign 承载者
- 样本主队列维护者

#### Unbound 与差分辅助线

- `unbound_experiment/run_unbound_afl_symcc.sh`

当前定位：

- 第二 resolver adapter
- cache dump 与 replay 差分辅助线
- 后续 queue follower 的落点

## 论文驱动后的计划调整

### 计划调整 1：放弃“双独立 campaign 直接比较”

原因：

- 样本很快会分叉
- cache 结果失去一一对应关系
- 差异解释力不足

替代方案：

- 单 producer 或中央 Generator
- 同一样本 fan-out 到多个 resolver
- 禁止让多个 resolver 各自维护独立变异主线后再直接比较最终 cache

### 计划调整 2：把 `diff-test` 升级为 queue 跟随式差分

原因：

- 论文中的主发现信号是“同一样本的多实现差异”
- 当前 `diff-test` 偏离线，不足以支撑长期实验

替代方案：

- 新增 `follow-diff` 或同等模式
- 持续消费 producer queue 的新样本

### 计划调整 3：短序列优先，长 transcript 后置

原因：

- 论文表明大量 bug 可以用短 query-response 序列触发
- 当前 stateful 长链路稳定性偏低

替代方案：

- 先把短序列做成主吞吐
- 再让更长 transcript 承担深状态复核

### 计划调整 4：增加过滤与聚类

原因：

- 差异数量会快速膨胀
- 全量人工查看不可扩展

替代方案：

- 先做启发式规则过滤
- 再做 fingerprint 聚类

## 分阶段计划

### 第一阶段：建立共享样本 differential 基线

目标：

- 不再让两个 resolver 各跑各的
- 让 BIND9 producer 与 Unbound follower 基于同一样本工作

交付物：

- queue follower
- 同样本双 resolver replay 脚本
- 成对输出目录结构

完成标准：

- 新样本能自动在 BIND9 与 Unbound 上成对 replay
- 每个样本都能产出成对 oracle 与 cache dump

### 第二阶段：统一 cache / oracle / 指纹输出

目标：

- 把当前离散结果收敛成结构化差分结果

交付物：

- 统一 oracle 键集合
- 统一 cache fingerprint
- 统一结果文件格式

完成标准：

- 差异样本能稳定落盘并可直接复查
- TTL、格式噪声和 benign 差异得到初步抑制

### 第三阶段：过滤、聚类与 triage

目标：

- 降低人工分析成本

交付物：

- 启发式过滤规则
- fingerprint 聚类策略
- 差异样本 triage 模板

完成标准：

- 新样本能自动标出差异类别
- 分析人员优先看到 root-cause cluster，而不是海量原始样本

### 第四阶段：强语义复核与漏洞确认

目标：

- 把行为差异转换成漏洞证据

交付物：

- 候选样本复现脚本
- cache 前后对比记录
- 最终漏洞确认记录

完成标准：

- 至少一类高价值差异样本能被稳定复现
- 能明确区分“实现差异”和“疑似缓存投毒漏洞”

## 验收标准

### 功能验收

1. BIND9 `poison-stateful` 主线可长期稳定运行。
2. 同一样本可被 BIND9 与 Unbound 同步 replay。
3. cache dump、oracle 和状态指纹能统一落盘。
4. 差异样本能进入过滤、聚类和复核流程。

### 指标验收

- 长时间运行中仍能看到 `new edges` 增长
- 差异样本数量非零
- 差异样本中能区分低层解析差异与缓存相关差异
- cache 结果比较不再受 TTL 等纯噪声主导

### 研究验收

本项目达到阶段性成功时，应满足以下条件：

1. 已经形成“同样本、多 resolver、统一 oracle、统一 cache 指纹、自动比较”的基本闭环。
2. 已能稳定输出缓存相关候选差异样本。
3. 已建立从差异样本到强语义复核的工作流。

## 当前优先级

按当前状态，建议优先级固定为：

1. 为 `DST1` transcript 增加 AFL++ custom mutator。
2. 建立单 producer + 双 resolver replay 主线。
3. 把 SymCC 收敛成“高价值样本的局部符号探索器”。
4. 统一 cache / oracle / 指纹输出。
5. 引入启发式过滤与 fingerprint 聚类。
6. 再去扩展更多 resolver。
7. 最后再补更强的内部状态观测与论文级统计。

## 不应再混淆的几点

1. 当前项目的主目标是多 resolver differential fuzzing，不是单 BIND9 深测本身。
2. 当前主线不应是“双独立 campaign 对比最终结果”，而应是“同一样本同步重放”。
3. 当前 `cache_entry_created` 仍主要是代理信号，不是强证明。
4. 当前 cache dump 是证据链的一部分，不是漏洞定性本身。
5. 只有在统一输入与统一比较口径都成立后，resolver 之间的差异才有较强解释力。
