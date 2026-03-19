# DNS Poison Differential Fuzzing 执行清单

## 用途

这份清单用于把总方案文档落成可执行任务。

对应总方案：

- [DNSPoisonFuzzingPlan.md](./DNSPoisonFuzzingPlan.md)

使用原则：

1. 单轮并行最多保持 3 条工作线。
2. 先建立共享样本链路，再做更强的语义复核。
3. 先统一 cache / oracle / 指纹输出，再扩大 resolver 数量。
4. 先过滤和聚类，再人工分析差异样本。

## 当前入口

### BIND9 producer

入口脚本：

- `named_experiment/run_named_afl_symcc.sh`

当前职责：

- 构建与运行 `poison-stateful` 主 campaign
- 维护主队列
- 提供后续 follower 消费的样本来源

### Unbound adapter

入口脚本：

- `unbound_experiment/run_unbound_afl_symcc.sh`

当前职责：

- 作为第二 resolver replay 目标
- 提供 `dump-cache`
- 提供 `parse-cache`
- 提供 `replay-diff-cache`

## 当前主问题

1. BIND9 与 Unbound 还没有基于同一样本自动成对 replay。
2. `diff-test` 仍然偏离线辅助工具，不是长期实验主入口。
3. 还没有 AFL++ transcript custom mutator。
4. SymCC 还没有被限制在高价值样本与局部符号化模式。
5. 还没有统一状态指纹与差异聚类。

## 里程碑拆解

### M1. 为 transcript 增加 AFL++ custom mutator

目标：

- 让 AFL++ 主变异器更贴合当前 `DST1` transcript 输入模型

涉及范围：

- AFL++ 运行脚本
- transcript 输入格式适配代码
- 相关 mutator 代码

任务：

- 固定 `DST1` transcript 的字段边界和变异点
- 实现 query / response / post-check 分段变异
- 保持长度、计数和包装头一致

交付物：

- 一版 transcript custom mutator
- 一组最小回归样本

验收标准：

- AFL++ 可直接以 custom mutator 方式运行
- 变异后样本不会大面积退化为格式损坏输入

### M2. 建立单 producer + 双 resolver replay 主线

目标：

- 保证同一样本在 BIND9 与 Unbound 上一一对应

涉及范围：

- `named_experiment/run_named_afl_symcc.sh`
- `unbound_experiment/run_unbound_afl_symcc.sh`

任务：

- 增加 queue follower 或 broker
- 监听 BIND9 producer 队列中的新样本
- 对每个样本触发 BIND9 与 Unbound 成对 replay
- 保证样本只在 producer 侧变异一次，再 fan-out 给多个 resolver，而不是让多个 resolver 各自独立变异

交付物：

- 一版共享样本调度入口
- 一版成对 replay 目录结构

验收标准：

- 新样本能自动在两个 resolver 上 replay
- 样本路径、样本名和结果目录可稳定对应

### M3. 收敛 SymCC 为局部符号探索器

目标：

- 让 SymCC 与当前 AFL++ 变异机制协同，而不是另起一套主线

涉及范围：

- `named_experiment/run_named_afl_symcc.sh`
- `unbound_experiment/run_unbound_afl_symcc.sh`
- `symcc_fuzzing_helper`

任务：

- 只对 producer 队列中的高价值样本触发 SymCC
- 固定分段符号化范围
- 增加“覆盖新增 + 语义新增”的双重准入规则

交付物：

- 一版高价值样本筛选规则
- 一版局部符号化字段清单

验收标准：

- SymCC 新样本明显减少无效回流
- 回流样本中 cache / oracle 新差异占比提升

### M4. 统一 cache / oracle / 指纹输出

目标：

- 把当前输出收敛成稳定的结构化结果

涉及范围：

- `unbound_experiment/run_unbound_afl_symcc.sh`
- 相关 resolver adapter patch

任务：

- 固定统一 oracle 键集合
- 固定统一 cache fingerprint 格式
- 为每个样本生成结构化结果文件

交付物：

- 统一结果文件格式
- BIND9 / Unbound cache 指纹对照说明

验收标准：

- 同一样本在两边的输出可直接比较
- TTL 等纯噪声不再主导 diff

### M5. 过滤与聚类

目标：

- 降低差异分析成本

任务：

- 引入启发式规则过滤 benign 差异
- 为剩余差异生成 fingerprint
- 按 fingerprint 聚类样本

交付物：

- 一组过滤规则
- 一组 fingerprint 字段定义
- 一版 cluster 结果目录

验收标准：

- 差异结果能自动标记类别
- 分析入口从“原始样本列表”变成“cluster 列表”

### M6. 强语义复核

目标：

- 把候选差异样本变成可解释的证据

任务：

- 为高价值样本形成固定 replay 模板
- 结合 cache 前后对比、post-check 和日志做复核
- 明确“实现差异”和“疑似漏洞”的分界

交付物：

- 一套复现模板
- 一套复核记录模板

验收标准：

- 至少一类高价值样本能被稳定复现
- 复核记录中能明确写出结论与原因

## 近期三条工作线

### 工作线 A：AFL++ transcript mutator

优先级：最高

本轮完成标准：

- transcript 结构化变异落地
- 线上样本质量优于纯字节变异

### 工作线 B：共享样本调度

优先级：最高

本轮完成标准：

- producer queue 可以被 follower 稳定消费
- BIND9 与 Unbound 输出目录一一对应

### 工作线 C：SymCC 局部符号探索

优先级：高

本轮完成标准：

- SymCC 仅消费高价值 producer 样本
- 回流规则与 cache / oracle 目标一致

## 串行依赖关系

建议按以下顺序推进：

1. 先完成 M1。
2. 再推进 M2。
3. M1 与 M2 基本完成后，推进 M3。
4. 之后做 M4。
5. 再推进 M5。
6. 最后做 M6。

原因：

- 如果没有共享样本主线，后续所有 cache 比较都缺少解释力。
- 如果 SymCC 没有先被约束在局部高价值探索，它会过早放大噪声。

## 本轮建议直接产出的结果

如果按最小闭环推进，下一轮最值得直接落地的是：

1. 一版 transcript custom mutator。
2. 一版 queue follower。
3. 一版 SymCC 局部符号化字段清单。

## 风险提示

### 风险 1

继续让两个 resolver 各跑各的 campaign，会让 cache 比较失去样本对应关系。

### 风险 2

如果 SymCC 对整个 transcript 做全量符号化，会显著放大无效样本和运行成本。

### 风险 3

如果差异结果没有过滤和聚类，后续人工分析成本会快速失控。

### 风险 4

如果继续把 cache dump 直接当成漏洞证明，实验结论会失真。

## 备注

这份清单是执行层文档，不替代总方案文档。

总方案负责回答“为什么这样做”和“整体架构是什么”；
本清单负责回答“下一步具体做什么、改哪些入口、以什么标准算完成”。