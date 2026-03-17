# DNS Poison Differential Fuzzing 执行清单

## 用途

这份清单用于把总方案文档落成可执行任务。

对应总方案：

- [DNSPoisonFuzzingPlan.md](./DNSPoisonFuzzingPlan.md)

使用原则：

1. 先收紧单 resolver 基线，再做横向比较。
2. 先统一 oracle 口径，再扩大 resolver 数量。
3. 先让差异样本稳定落盘，再做强语义漏洞确认。
4. 单轮并行最多保持 3 条工作线，避免互相踩文件和脚本。

## 当前入口

### BIND9 主线

入口脚本：

- `named_experiment/run_named_afl_symcc.sh`

关键命令：

```bash
export FUZZ_PROFILE=poison-stateful
. named_experiment/profiles/poison-stateful.env
named_experiment/run_named_afl_symcc.sh prepare
named_experiment/run_named_afl_symcc.sh start
named_experiment/run_named_afl_symcc.sh status
named_experiment/run_named_afl_symcc.sh stop
```

当前主语料目录：

- `named_experiment/work/query_corpus`
- `named_experiment/work/response_corpus`
- `named_experiment/work/transcript_corpus`
- `named_experiment/work/stable_transcript_corpus`

### Unbound 辅助线

入口脚本：

- `unbound_experiment/run_unbound_afl_symcc.sh`

关键命令：

```bash
unbound_experiment/run_unbound_afl_symcc.sh prepare
unbound_experiment/run_unbound_afl_symcc.sh smoke
unbound_experiment/run_unbound_afl_symcc.sh diff-test
```

当前主语料目录：

- `unbound_experiment/work/query_corpus`
- `unbound_experiment/work/response_corpus`
- `unbound_experiment/work/stable_query_corpus`
- `unbound_experiment/work/diff_results`

## 里程碑拆解

### M1. 收紧 BIND9 oracle 语义

目标：

- 让 BIND9 输出的缓存相关 oracle 语义更稳定、更不混淆。

涉及文件：

- `named_experiment/run_named_afl_symcc.sh`
- `patch/bind9/bin/named/resolver_afl_symcc_orchestrator.c`
- `patch/bind9/include/named/resolver_afl_symcc_orchestrator.h`

任务：

- 明确 `response_accepted` 的触发条件与日志语义。
- 拆开 `second_query_hit` 与 `cache_entry_created`，不再默认把两者当同义词使用。
- 重新审视 `filter-seeds` 的稳定性筛选条件，避免把“未再次发起上游请求”直接写成“缓存已创建”。
- 统一 BIND9 输出字段顺序和默认值，方便后续差分脚本直接解析。

交付物：

- 一版更清晰的 BIND9 oracle 输出格式。
- 更新后的稳定性筛选逻辑。
- 一组最小回归样本，能分别覆盖：
  - `parse_ok`
  - `response_accepted`
  - `second_query_hit`
  - `cache_entry_created`

验收标准：

- `named_experiment/run_named_afl_symcc.sh prepare` 仍能稳定完成。
- BIND9 日志中可以明确区分“命中缓存代理”与“进入缓存创建代理”的不同阶段。
- 文档不再把 `cache_entry_created` 直接当成强语义结论。

### M2. 补齐 Unbound 的可比 oracle

目标：

- 让 Unbound 至少具备与 BIND9 同口径的基础 oracle 输出。

涉及文件：

- `unbound_experiment/run_unbound_afl_symcc.sh`
- `patch/unbound/smallapp/unbound_afl_symcc_orchestrator.c`
- `patch/unbound/smallapp/unbound_afl_symcc_orchestrator.h`
- `patch/unbound/smallapp/unbound_afl_symcc_mutator_server.c`

任务：

- 统一 Unbound 侧的 oracle 键名与字段顺序。
- 为暂时还做不到强语义判断的字段输出显式默认值，而不是缺失字段。
- 明确 Unbound 当前哪些字段是真实观测，哪些字段只是占位或代理信号。
- 让 Unbound 侧也能表达最小 post-check 语义，至少为后续 `second_query_hit` 对齐预留接口。

交付物：

- 一版与 BIND9 同口径的 Unbound oracle 输出。
- 一份 Unbound oracle 语义对照表。

验收标准：

- `unbound_experiment/run_unbound_afl_symcc.sh smoke` 稳定通过。
- `diff-test` 不再因为字段缺失而只能比较低层 parser 行为。
- 至少能稳定比较以下键：
  - `parse_ok`
  - `resolver_fetch_started`
  - `response_accepted`
  - `timeout`

### M3. 把 `diff-test` 升级成正式差分入口

目标：

- 把现有差分骨架从“辅助检查脚本”升级成标准实验入口。

涉及文件：

- `unbound_experiment/run_unbound_afl_symcc.sh`

任务：

- 固定差分输入来源优先级，例如优先使用稳定语料，其次退回原始语料。
- 为差分结果增加更稳定的输出结构，至少包含：
  - 样本名
  - resolver A oracle
  - resolver B oracle
  - 差异类型
  - 原始 stderr 路径或摘要
- 把差异分成层级：
  - 解析差异
  - 上游交互差异
  - 缓存相关差异
  - 超时/异常差异
- 明确哪些差异直接丢弃，哪些差异进入人工复核。

交付物：

- 稳定的 `diff_results` 目录结构。
- 一份差异分类规则。
- 一组样例差异报告。

验收标准：

- 连续多次运行 `diff-test`，输出结构保持一致。
- 差异样本可以自动落盘并带有上下文信息。
- 结果可直接用于后续 triage，而不是只能人工翻日志。

### M4. 建立 transcript 级别的多 resolver 对齐

目标：

- 让“同一 transcript 输入多个 resolver”成为主实验路径。

涉及范围：

- `named_experiment/`
- `unbound_experiment/`
- `gen_input/`

任务：

- 明确 transcript 在跨 resolver 场景下的最小公共语义。
- 为 Unbound 补一个最小 stateful adapter，而不是一直停留在 parser-lite。
- 让 query、response、post-check 的语义顺序在两个 resolver 上尽量一致。
- 保证 transcript replay 后，两边都能输出统一 oracle。

交付物：

- 一版跨 resolver 复用的最小 transcript 语义约定。
- 一组能同时重放到 BIND9 和 Unbound 的 transcript 样本。

验收标准：

- 同一 transcript 能在两个 resolver 上稳定执行。
- 两边都能产出统一字段的 oracle。
- 差异样本开始从 query/response 层上升到 transcript 层。

### M5. 强语义复核与漏洞确认

目标：

- 把“候选差异样本”变成“可证明的漏洞证据”。

涉及范围：

- BIND9 和 Unbound 的实验 patch
- 差异复现脚本
- 日志与缓存观测辅助工具

任务：

- 引入更强的 cache 观测机制，例如更细的日志钩子、cache dump 或状态检查。
- 形成差异样本复现脚本，保证可稳定重放。
- 建立候选样本分类模板，区分：
  - parser 差异
  - 事务匹配差异
  - bailiwick / glue 差异
  - 真正疑似缓存投毒差异

交付物：

- 一套差异样本复现模板。
- 一套强语义复核记录模板。

验收标准：

- 至少一类高价值差异样本能被稳定复现。
- 复核记录中能明确写出“为何是候选漏洞”或“为何只是实现差异”。

## 近期三条工作线

建议下一轮工作只保留以下 3 条并行线：

### 工作线 A：BIND9 oracle 收紧

优先级：最高

原因：

- 它决定后续所有差分结果是否有解释力。

本轮完成标准：

- `second_query_hit` 与 `cache_entry_created` 语义分离
- `filter-seeds` 不再混淆二者

### 工作线 B：Unbound oracle 对齐

优先级：高

原因：

- 没有统一字段，差分结果很难做自动化处理。

本轮完成标准：

- Unbound 输出字段与 BIND9 至少同构
- 缺失能力使用显式默认值

### 工作线 C：`diff-test` 结构化

优先级：高

原因：

- 差异主线必须先有稳定输出，后面才能做 triage 和聚类。

本轮完成标准：

- `diff_results` 结构稳定
- 差异类别能自动标记

## 串行依赖关系

建议按以下顺序推进：

1. 先完成 M1。
2. 再推进 M2。
3. M1 与 M2 基本完成后，升级 M3。
4. 只有在 M3 稳定后，再做 M4。
5. M5 始终放在差异主线稳定之后。

原因：

- 如果先做 transcript 级多 resolver 对齐，而 oracle 语义仍混乱，后续所有差异都会难以解释。

## 本轮建议直接产出的结果

如果按最小闭环推进，下一轮最值得直接落地的是：

1. 一版统一 oracle 键集合。
2. 一版 BIND9 / Unbound oracle 对照表。
3. 一版结构化 `diff_results` 输出规范。

## 风险提示

### 风险 1

Unbound 长期停留在 parser-lite，会导致“第二 resolver 已接入”这个结论缺少实验价值。

### 风险 2

如果继续把 `cache_entry_created` 当强结论使用，后续论文和实验结论会失真。

### 风险 3

如果 `diff-test` 只输出文本日志而没有稳定结构，后面很难做批量 triage。

## 备注

这份清单是执行层文档，不替代总方案文档。

总方案负责回答“为什么这样做”和“整体架构是什么”；
本清单负责回答“下一步具体做什么、改哪些脚本、以什么标准算完成”。
