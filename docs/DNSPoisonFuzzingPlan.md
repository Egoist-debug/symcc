# DNS Resolver 缓存投毒 Differential Fuzzing 计划

## 摘要

本项目的当前目标，不再是单独把某一个 resolver 跑通，而是建立一条面向多个 DNS resolver 的缓存投毒差异模糊测试主线。

核心思路如下：

1. 对多个 resolver 输入同一批种子。
2. 结合 AFL++、SymCC 与 `gen_input` 生成和放大高价值输入。
3. 统一抽取缓存相关 oracle。
4. 通过 resolver 之间的行为差异筛出可疑样本。
5. 对差异样本再做强语义复核，判断其是否对应真实缓存投毒漏洞。

当前仓库已经具备这条主线的一部分基础能力，但整体状态仍处于“单 BIND9 深测 + 第二 resolver 接入中 + 差分骨架已出现”的阶段，尚未形成完整的多 resolver stateful differential 实验闭环。

配套执行清单见：

- [DNSPoisonFuzzingChecklist.md](./DNSPoisonFuzzingChecklist.md)

## 目标重述

### 总目标

构建一个面向多个 DNS resolver 的缓存投毒 differential fuzzing 框架，用统一输入、统一 oracle 和统一筛选逻辑来发现可疑缓存投毒行为。

### 具体目标

1. 不只覆盖 DNS 报文解析，而是覆盖缓存投毒相关的状态演化过程。
2. 让 AFL++、SymCC 和 `gen_input` 在同一条实验链路上协同工作。
3. 对多个 resolver 使用同一批 query、response 或 transcript 语料。
4. 用缓存相关 oracle 差异而不是单一崩溃作为主要发现信号。
5. 将“差异样本”与“漏洞证据”明确区分，避免过早下结论。

### 当前目标 resolver

- 第一主线：BIND9
- 第二目标：Unbound
- 后续可扩展到更多 resolver，但当前文档不预设第三个实现

## 判定原则

本项目的核心判定逻辑是：

- 同一输入在不同 resolver 上应尽量产生同口径、可比较的结果。
- 一旦出现稳定的 oracle 差异，就将该样本视为候选异常样本。
- 候选异常样本需要进入复现、归因和强语义复核流程。
- 差异本身不直接等价于漏洞成立。

换句话说，本项目的主发现信号不是“是否 crash”，而是“同样的输入是否导致 resolver 在缓存相关行为上出现不一致”。

## 当前仓库状态

### 已落地能力

#### 1. BIND9 的 stateful 主线已经存在

当前 BIND9 已经具备 `poison-stateful` 实验线，核心能力包括：

- `client_query -> upstream_response_seq -> post_check_query` 的 transcript 驱动方式
- `named_experiment/run_named_afl_symcc.sh` 的 build、gen-seeds、filter-seeds、prepare、start、status、stop 流程
- AFL++ persistent 模式 + SymCC helper 的协同执行
- 稳定语料筛选与实验运行脚本

这意味着 BIND9 已经不只是 parser fuzz，而是能承载“缓存影响路径”的主实验线。

#### 2. `gen_input` 已具备 DNS response 和 transcript 生成能力

当前 `gen_input` 已支持以下格式能力：

- `dns`
- `dns-response`
- `dns-poison-response`
- `dns-stateful-transcript`

其中与本项目最直接相关的是：

- `dns-poison-response`：生成面向缓存投毒场景的 response 种子
- `dns-stateful-transcript`：生成状态化 transcript 语料

此外，`--hybrid --preserve 20` 已经可用。这里的含义需要明确：

- 默认保留前 20 字节前缀
- 之后的 response 区域交给 SymCC 辅助探索
- 重点放在 authority、additional、glue 和更深的 payload 结构

因此，`gen_input` 在当前项目中的定位不是“附属工具”，而是 response 生成链路的核心组成部分。

#### 3. Unbound 已经接入第二 resolver 的工程入口

当前 `unbound_experiment/run_unbound_afl_symcc.sh` 已具备以下基础能力：

- 获取与构建 Unbound 本地源码树
- 构建 AFL 版本与 SymCC 版本目标
- 生成 query corpus
- 做 smoke 验证
- 做 response tail 探索并回灌 `response_corpus`

这说明第二 resolver 的编译链、输入链和基础实验脚本已经出现，不再是纯计划状态。

#### 4. 差分测试脚本骨架已经存在

`unbound_experiment/run_unbound_afl_symcc.sh` 中已经包含 `diff-test`，其核心逻辑是：

- 取同一批种子
- 分别喂给 Unbound 与 BIND9
- 提取 oracle
- 比较两边输出
- 保存差异样本与详情

这非常接近项目最终目标，但当前仍属于“骨架已在、主线未成”的状态。

### 部分落地、但还不完整的能力

#### 1. 多 resolver 差分已经出现，但还不是 stateful 主线

当前差分测试更多是：

- BIND9 system-mode
- Unbound parser-lite 或最小入口
- 基于 query 与 response 语料的外部比较

它还不是完整的“同一 transcript 同时驱动多个 resolver”的统一 stateful differential 主线。

#### 2. oracle 已经能比较，但语义层级还不统一

当前仓库中，BIND9 侧较稳定的 oracle 包括：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `second_query_hit`
- `cache_entry_created`
- `timeout`

Unbound 侧当前更稳定的主要是：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`

这意味着跨 resolver 的 oracle 对齐仍未完成。

#### 3. `cache_entry_created` 仍是代理信号

当前 BIND9 线里的 `cache_entry_created` 仍然主要来自：

- post-check 阶段没有再次观察到新的上游交互

它当前更适合作为：

- 语料筛选信号
- 差异比较信号
- 值得复核的缓存影响路径信号

而不应直接写成“缓存投毒已被严格证明”。

### 尚未完成的关键缺口

1. Unbound 还没有接入完整的 stateful transcript 执行模型。
2. 多 resolver 还没有完全共享同一种 transcript 语义。
3. 统一 oracle 结果格式还没有在所有 resolver 上补齐。
4. 差异样本还没有形成稳定的聚类、复现与归因流程。
5. 还没有强语义缓存证明机制来确认真正的 poison success。

## 实验总架构

### 总体分层

建议把实验主线拆成三层：

#### A. 单 resolver 基线层

目标是先把单个 resolver 的输入模型、稳定性、oracle 与样本回流打稳。

当前主承担者：

- BIND9 poison-stateful 主线

#### B. 多 resolver 可比层

目标是让多个 resolver 在同一批语料上输出同口径结果。

核心要求：

- 输入模型一致
- oracle 字段一致
- 日志与结果结构一致

当前推进状态：

- 已有 BIND9 与 Unbound 的双目标骨架
- 但还未完全对齐到 stateful transcript 级别

#### C. 差异判定与复核层

目标是从行为差异中筛出可疑样本，并将其送入更强的验证流程。

核心输出：

- 差异样本集
- 差异详情
- 可复现脚本
- 最终漏洞判定结果

## 统一输入模型

### 输入层级

建议把输入明确分成三层：

#### 1. query corpus

用于：

- 快速起量
- parser 路径探索
- 生成 response 骨架
- 供第二 resolver 早期 smoke 与 parser-lite 使用

#### 2. response corpus

用于：

- 构造合法或近合法的上游响应
- 覆盖 authority、additional、glue、compression 等高约束区域
- 作为缓存投毒导向的上游注入素材

其生成策略应保持为：

- `gen_input` 负责结构化生成
- AFL++ 负责后续字节级扩散
- SymCC 负责突破强约束字段

#### 3. transcript corpus

用于：

- 表达一次完整的缓存投毒实验交互
- 统一描述 query、多个 response 与 post-check
- 承载真正的 stateful differential 主线

### 默认 profile

#### `parser-lite`

适用场景：

- 第二 resolver 接入初期
- 构建链路和输入链路验证
- 快速 smoke

#### `poison-stateful`

适用场景：

- 缓存投毒主实验
- 多响应竞争
- post-check 命中验证
- 长时间 campaign

### `gen_input` 的职责边界

在当前项目中，`gen_input` 的职责建议固定为：

1. 负责生成高质量 DNS query 和 response 语料。
2. 负责维护 response 内部字段耦合关系。
3. 负责对 authority、additional、glue 等高价值区域做结构化放大。
4. 负责生成 transcript 原材料，而不是直接承担最终漏洞判定。

需要强调的是，当前 hybrid 模式的默认策略应表述为：

- 保留前 20 字节前缀
- 将其后的 response 区域作为主要探索对象

不要把它表述成“只探索最后 20 字节”。

## AFL++、SymCC 与 `gen_input` 的分工

### AFL++

职责：

- 提供主吞吐
- 拉高覆盖
- 维护主语料池
- 长时间运行 campaign

默认模式：

- 对单 resolver 主线优先使用 persistent mode
- 无法稳定 reset 的 resolver 可临时降级到 forkserver

### SymCC

职责：

- 补 AFL++ 很难命中的强约束路径
- 重点突破事务匹配、RR 计数、压缩指针、authority/additional 合法性
- 生成高价值样本并回流 AFL++ 语料库

不建议做的事：

- 对整个 transcript 做无差别全量符号化

### `gen_input`

职责：

- 负责语法感知和格式感知生成
- 为 response 与 transcript 提供高质量 seed
- 作为多 resolver 共享输入的上游生成器

## Resolver 角色规划

### BIND9

当前角色：

- 第一条完整 stateful 基线
- oracle 设计的先行者
- `poison-stateful` 主实验线承载者

短期目标：

- 收紧 oracle 语义
- 区分 `second_query_hit` 与 `cache_entry_created`
- 为后续跨 resolver 对齐提供参照口径

### Unbound

当前角色：

- 第二 resolver 接入对象
- parser-lite 与差分骨架承载者
- BIND9 之外的第一个横向对照目标

短期目标：

- 从 parser-lite 过渡到最小可比 oracle
- 接入更贴近真实递归路径的执行方式
- 为后续 transcript 级别对齐做准备

### 后续其他 resolver

只有在以下条件满足后，才建议接入第三个 resolver：

1. BIND9 与 Unbound 已完成同口径 oracle 对齐。
2. 差异样本已有稳定复现流程。
3. transcript 主线已经可跨实现复用。

## oracle 设计

### 统一输出目标

所有 resolver 最终都应输出统一字段：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `second_query_hit`
- `cache_entry_created`
- `cache_entry_updated`
- `bailiwick_rejected`
- `mismatch_rejected`
- `timeout`
- `crash`
- `hang`
- `nondeterministic_state_detected`

### 语义分层

建议把 oracle 分成四层来理解：

#### L0. 输入被成功解析

- `parse_ok`

#### L1. resolver 确实进入了上游取数路径

- `resolver_fetch_started`

#### L2. 伪造响应进入了接受判定路径

- `response_accepted`

#### L3. 出现了可能影响缓存的后续行为

- `second_query_hit`
- `cache_entry_created`
- `cache_entry_updated`

#### L4. 强语义缓存证明

这一层当前仍未落地，后续可通过：

- 更强日志钩子
- cache dump
- resolver 内部状态观测

来补齐。

### 当前文档中的使用约束

在当前阶段，文档和实验记录中应遵守以下约束：

1. `response_accepted` 只能表述为“伪造响应进入接受路径”。
2. `second_query_hit` 只能表述为“post-check 未再次触发上游抓取”。
3. `cache_entry_created` 当前默认仍视为代理信号，不直接等价于“缓存已被污染”。

## 统一实验流程

### 当前推荐主链

1. 生成 query corpus。
2. 基于 query corpus 生成或扩展 response corpus。
3. 用 response corpus 组装 transcript corpus。
4. 在单 resolver 上先做稳定性筛选。
5. 将同一批稳定样本输入多个 resolver。
6. 提取统一 oracle。
7. 对差异样本做保存、分类和复现。
8. 对高价值差异样本做强语义复核。

### 当前脚本分工

#### BIND9 主线

- `named_experiment/run_named_afl_symcc.sh`

负责：

- build
- gen-seeds
- filter-seeds
- prepare
- start
- run
- status
- stop

#### Unbound 与差分辅助线

- `unbound_experiment/run_unbound_afl_symcc.sh`

当前负责：

- fetch
- build
- gen-seeds
- explore-response
- filter-seeds
- smoke
- diff-test

需要注意的是：

- 当前 `diff-test` 已经能比较同一批种子在 BIND9 和 Unbound 上的 oracle 差异
- 但它还不是完整 transcript differential 主线的终态

## 分阶段计划

### 第一阶段：稳固单 BIND9 基线

目标：

- 保持 `poison-stateful` 可稳定运行
- 稳定 query、response、transcript 三层语料链路
- 收紧当前 oracle 语义

交付物：

- 稳定的 BIND9 campaign
- 明确的稳定性筛选规则
- 文档化的 oracle 边界说明

完成标准：

- `prepare` 与 `start` 可稳定执行
- `response_accepted` 与 `second_query_hit` 能稳定出现
- `cache_entry_created` 的代理语义被明确记录

### 第二阶段：补齐 Unbound 的可比能力

目标：

- 让 Unbound 不再只停留在 parser-lite
- 逐步补齐与 BIND9 同口径的 oracle
- 把第二 resolver 从“工程接入”推进到“行为对比”

交付物：

- 更完整的 Unbound oracle 输出
- 至少一种贴近真实 resolver 路径的执行模式
- 可与 BIND9 共享的语料输入方式

完成标准：

- `diff-test` 不再只比较低层 parser 行为
- Unbound 至少能稳定产出 `second_query_hit` 或同等语义字段

### 第三阶段：建立多 resolver differential 主线

目标：

- 将“同一批种子输入多个 resolver”升级为主实验流程
- 优先推进 transcript 级别的跨 resolver 对齐

交付物：

- 统一 oracle 结果文件格式
- 差异样本目录结构
- 差异详情与复现脚本

完成标准：

- 同一批语料能稳定重放到 BIND9 与 Unbound
- 差异样本能够自动落盘
- 差异统计能够用于长期实验记录

### 第四阶段：强语义复核与漏洞确认

目标：

- 把“行为差异”转换成“漏洞证据”

交付物：

- 更强的 cache 观测手段
- 差异样本归因记录
- 最终漏洞确认结论

完成标准：

- 至少一类差异样本能被强语义方法确认
- 实验记录中能够明确区分“候选样本”和“已确认漏洞”

## 验收标准

### 功能验收

1. BIND9 `poison-stateful` 主线可长期稳定运行。
2. `gen_input` 能稳定生成对缓存投毒有意义的 response 种子。
3. Unbound 能作为第二 resolver 参与同口径行为比较。
4. `diff-test` 或其后继流程能自动筛出跨 resolver 差异样本。
5. 差异样本能进入复现与复核流程。

### 指标验收

- `stability` 保持在可接受区间
- `timeout ratio` 不持续恶化
- 长时间运行中仍能看到 `new edges` 增长
- 至少存在非零的差异样本数量
- 差异样本中能区分低层解析差异与缓存相关差异

### 研究验收

本项目达到阶段性成功时，应满足以下条件：

1. 已经形成“同种子、多 resolver、统一 oracle、自动比较”的基本闭环。
2. 已能稳定输出缓存相关候选差异样本。
3. 已建立从差异样本到强语义复核的工作流。

## 当前优先级排序

按当前仓库状态，建议优先级固定为：

1. 收紧 BIND9 oracle 语义。
2. 补齐 Unbound 的可比 oracle。
3. 把现有 `diff-test` 从辅助脚本升级成正式实验链路。
4. 再去扩展更多 resolver。
5. 最后再补强语义缓存证明与论文级统计流程。

## 不应再混淆的几点

1. 当前项目的主目标是多 resolver differential fuzzing，不是单 BIND9 深测本身。
2. 当前 `gen_input --hybrid --preserve 20` 的重点是保留前 20 字节前缀后继续探索，不是“只看末尾 20 字节”。
3. 当前 `cache_entry_created` 仍主要是代理信号，不是强证明。
4. 当前差分能力已经出现，但尚未完成 transcript 级统一。
5. 只有在统一 oracle 与统一输入都成立后，resolver 之间的差异才有较强解释力。
