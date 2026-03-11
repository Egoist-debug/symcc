# DNS Resolver 缓存投毒联合模糊测试方案

## 摘要

本方案面向具有状态的 DNS resolver，目标不是只覆盖单包解析，而是覆盖缓存投毒所依赖的多步状态演化过程。整体采用“两层实验线、统一输入模型”的设计：

- 主线使用状态化 transcript harness，统一接入多个 DNS resolver。
- 补线保留当前 BIND9 `resolver-afl-symcc` 系统态方案，作为真实 daemon 行为验证。
- AFL++ 负责高吞吐率覆盖增长与常规指标采集。
- SymCC 负责突破事务匹配、缓存写入等强约束。
- `gen_input` 负责对上游 `response` 包进行结构化变异，重点探索 authority、additional、glue 和响应尾部区域。

## 目标与范围

### 目标

1. 覆盖缓存投毒相关的有状态逻辑，而不仅仅是 DNS 报文解析。
2. 支持多个 resolver 的统一实验与横向对比。
3. 同时兼顾 AFL++ 的执行效率与 SymCC 的约束突破能力。
4. 将 `gen_input` 集成到响应包生成与变异链路中，提升复杂响应路径可达性。

### 研究重点

- query 与 response 的事务匹配关系
- 伪造响应的接受条件
- cache entry 的创建、更新与二次命中
- bailiwick、glue、authority/additional 相关安全边界
- timeout、重试、竞争响应等状态相关行为

## 总体架构

### 主线：状态化 transcript harness

主线使用统一的 transcript 输入模型，每个测试用例描述一次有界状态交互，而不是单个 DNS 包。

每个测试用例至少包含以下逻辑步骤：

1. `client_query`
   - 客户端向 resolver 发起查询。
2. `upstream_response_seq`
   - 注入一到多个上游响应，可用于模拟合法响应、伪造响应和竞争响应。
3. `post_check_query`
   - 再次发起查询，用于验证缓存是否被污染以及命中行为是否异常。
4. `oracle`
   - 记录本轮是否发生缓存写入、错误接受、异常命中、崩溃或超时。

### 补线：BIND9 system-mode

保留当前 BIND9 `named` 主流程内建 orchestrator 的方案，作为真实 daemon 级网络行为验证路径：

- 保留真实 socket、事件循环、timeout 与重试语义。
- 用于验证 ACL、view、peer 地址、调度行为等 harness 可能弱化的路径。
- 不作为多 resolver 主基线，而作为 BIND9 深测与结果校验的对照组。

## 统一输入模型

### transcript 格式

默认每个测试用例由以下部分组成：

- 文件头
  - 版本号
  - profile 类型
  - 传输类型
  - step 数量
  - 标志位
- step 数组
  - `step_type`
  - `ordering_or_delay`
  - `packet_length`
  - `packet_bytes`
- 可选元数据
  - 是否允许多响应竞争
  - 是否允许乱序响应
  - 是否启用 TCP fallback

### 默认 profile

#### `parser-lite`

仅包含：

- 一个 query
- 一个 response

用于：

- 快速起量
- parser 与基础事务路径探索
- 生成初始高质量 corpus

#### `poison-stateful`

默认主 profile，包含：

- 一个 query
- 多个 response
- 一次 post-check query

用于：

- 缓存投毒主实验
- 竞争响应与错误接受场景
- cache 污染验证

## AFL++ 集成方案

### 执行模式

默认使用：

- `persistent mode`
- 共享内存输入

约束如下：

- 单个 `__AFL_LOOP` 对应一个完整 transcript。
- AFL 迭代之间必须完全重置 resolver 状态。
- 若某 resolver 无法稳定 reset，则降级为 forkserver 模式。

### AFL++ 指标

需要持续采集并纳入实验记录的指标包括：

- `execs/sec`
- `stability`
- `map density`
- `count coverage`
- `corpus size`
- `unique crashes`
- `unique hangs`
- `favored paths`
- `timeout ratio`
- `new edges over time`

### 领域指标

除 AFL++ 常规指标外，还必须增加缓存投毒相关领域指标：

- `accepted_forged_responses`
- `cache_entry_created`
- `cache_entry_updated`
- `poison_success`
- `unexpected_second_query_hit`
- `bailiwick_violation_accepted`
- `mismatch_but_accepted`

## SymCC 集成方案

### 角色定位

SymCC 不承担全量状态空间搜索，而是作为 AFL++ 的补洞器，用于突破 AFL++ 难以满足的强约束路径。

### 默认符号化范围

默认只将以下字段或区域符号化：

- response 头部中的事务匹配关键字段
- authority 与 additional 中的结构性字段
- glue、referral、CNAME 等高约束部分
- 少量 query 头字段

不默认将整个 transcript 全量符号化，以避免路径爆炸和求解开销失控。

### 重点求解目标

- QID 与事务匹配约束
- RR count 与长度场一致性
- DNS name compression 约束
- authority/additional 中的结构合法性
- cache 写入前的接受条件
- 二次查询命中的前置约束

### 与 AFL++ 协同

- SymCC 运行在与 AFL++ 相同的 transcript 模型上。
- SymCC 生成的高价值样本必须回流 AFL++ 语料库。
- 对 stateful profile，SymCC 重点服务于深状态样本生成，而不是替代 AFL++ 常规变异。

## gen_input 集成方案

### 职责

`gen_input` 主要负责 response 包的结构化生成与变异。

重点包括：

- 合法或近合法 DNS response 生成
- authority / additional / glue 区域的结构化探索
- 自动维护长度、压缩与字段耦合关系
- 生成适合 AFL++ 继续字节级变异的高质量响应种子

### 默认变异分工

- query：以 AFL++ 变异为主
- response header 与 question mirror：由约束保持器维护
- response tail：由 `gen_input` 重点探索
- 深层约束突破：由 SymCC 补充

### 需要新增的格式能力

建议新增以下格式模式：

- `dns-poison-response`
- `dns-stateful-transcript`

并支持以下能力：

- 多响应竞争组生成
- 二次查询验证场景生成
- response tail 冻结与局部探索

## adapter 设计

### 公共逻辑接口

所有 resolver adapter 统一实现以下逻辑接口：

- `init_context(profile, options)`
- `run_client_query(packet, transport)`
- `run_upstream_response(packet, metadata)`
- `run_post_check(packet)`
- `collect_oracle()`
- `reset_context()`

### 主线 adapter 的最低能力要求

每个 resolver adapter 至少必须具备：

- 初始化最小运行上下文
- 注入一条 client query
- 注入一到多个 upstream responses
- 观测 cache 结果或等价的命中结果
- 在一次 AFL 迭代后清理状态

### BIND9 适配策略

对 BIND9 采用双线策略：

1. 保留当前 `named` system-mode 方案。
2. 额外实现一个 BIND9 stateful harness adapter，作为主线的一部分。

该 adapter 的目标不是只调用纯 parser，而是尽量靠近现有 resolver 请求与响应处理主链，以减少语义遗漏。

## oracle 设计

所有实验线统一输出以下结果：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `cache_entry_created`
- `cache_entry_updated`
- `second_query_hit`
- `bailiwick_rejected`
- `mismatch_rejected`
- `crash`
- `hang`
- `timeout`
- `nondeterministic_state_detected`

这些 oracle 同时用于：

- 实验成功判定
- 语料优先级判断
- 论文统计与结果对比

## 测试与验收

### 功能验收

1. `parser-lite` 模式下，AFL++ 可稳定运行，`stability` 不低于现有 BIND9 持久模式基线。
2. `poison-stateful` 模式下，单个测试用例能够完成 query、多个 response 注入与 post-check query。
3. SymCC 能生成 AFL++ 难以直接命中的深状态样本，并被 AFL++ 成功回收利用。
4. `gen_input` 能稳定生成复杂但结构合法的 response 种子。
5. BIND9 system-mode 与主线 harness 对同一 poisoning transcript 的接受/拒绝结论基本一致。

### 场景测试

必须覆盖以下典型场景：

- 正常 query + 正常 response
- QID 不匹配 response
- 源地址或端口不匹配 response
- authority/additional 携带恶意 glue
- referral / CNAME / NXDOMAIN / negative cache
- 多响应竞争，合法响应与伪造响应顺序互换
- 二次查询命中验证
- name compression 与长度场异常
- timeout、重试、空响应、截断响应
- persistent 模式下状态泄漏检测

### AFL++ 指标门槛

默认验收门槛如下：

- `execs/sec` 显著高于真网络 system-mode
- `stability >= 90%`
- `timeout ratio` 可控且不持续上升
- 首轮 24 小时内 `new edges` 持续增长
- `poison-stateful` lane 能产出非零的 `response_accepted` 与 `cache_entry_created`
- 至少一类 oracle 能区分“解析成功但拒绝缓存”与“真正缓存污染成功”

## 实施顺序

### 第一阶段

- 固化 transcript 输入模型
- 建立公共 oracle 结果格式
- 为 BIND9 增加 transcript 支持
- 打通 AFL++ persistent 路线

### 第二阶段

- 接入 SymCC 到 transcript 模型
- 为 `gen_input` 增加 response 定向变异能力
- 建立 AFL++ 与 SymCC 样本回流机制

### 第三阶段

- 实现通用 resolver adapter
- 接入第二个 resolver 作为验证目标
- 开始横向实验与指标对比

## 默认假设

- 研究目标明确包含缓存投毒，而不仅仅是报文解析鲁棒性。
- 通用主线默认使用 `poison-stateful` profile。
- 当前 BIND9 system-mode 路线不废弃，作为真实行为对照。
- `preeny` 或 socket 符号化不作为主路线，仅作为特殊场景备选。
- `gen_input` 默认专注 response 结构化变异，query 仍以 AFL++ 为主。
