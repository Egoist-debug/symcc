# SymCC `gen_input` DNS 变异（SymCC 引导）实施 TODO

## 背景与目标

目标：在 `gen_input/` 中实现**以 SymCC 约束反馈为核心**的 DNS 数据包变异流程，优先生成可被目标程序接受且能触发新路径的输入，而不是纯随机变异。

约束（来自 AGENTS.md）：
- SymCC 为 concolic：单次仅沿一条具体路径执行，必须通过持续反馈闭环扩大探索。
- `qsym` 可用于吞吐，但验证阶段需用 simple backend 兜底。
- 不修改 `third_party/`。

---

## 里程碑总览

- [x] M0 正确性解锁（阻塞问题修复）
- [x] M1 局部性优先的 SymCC 引导变异
- [x] M2 DNS 语义算子（破坏→修复，首个增量）
- [x] M3 严格格式验证与计算字段回填
- [x] M4 多 RR / 多 section 结构扩展
- [x] M5 工程化加固（超时、指标、回归）

---

## M0 正确性解锁（当前实现中）

### M0.1 尺寸与可变字段处理
- [x] 修复 `BinaryFormat::getMaxSize`：将 `DNSName` 视作可变长度字段，避免对 DNS 输入误判超长。
- [x] 对嵌套结构递归判定“是否存在可变长度字段”。

目标文件：
- `gen_input/src/BinaryFormat.cpp`

验收：
- `dns`/`dns-response` 测例不再因上界误判被提前丢弃。

### M0.2 Seed/TestCase 解析一致性
- [x] `addSeed(bytes)` 时将字节流解析为 `StructuredInput`，而不是默认空结构。
- [x] `processWorkItem` 新 testcase 入队前解析为结构化输入。

目标文件：
- `gen_input/src/FormatAwareGenerator.cpp`

验收：
- 字段级变异基于真实 testcase 语义字段执行。

### M0.3 Hybrid 模式 accepted 标注
- [x] 在 hybrid 路径中区分“生成输入”和“可接受输入”。
- [x] 输出文件命名分离：`accepted_*` 与 `generated_*`。

目标文件：
- `gen_input/src/main.cpp`

验收：
- 输出目录可直接区分 accepted 与非 accepted 语料。

---

## M1 局部性优先（紧接 M0）

- [x] 为 `FormatGeneratorConfig` 增加局部性参数（如 `MaxByteDiff`）。
- [x] testcase 入队前基于与父样本的字节差异做过滤与优先级提升。

目标文件：
- `gen_input/include/FormatAwareGenerator.h`
- `gen_input/src/FormatAwareGenerator.cpp`

验收：
- 平均每个 accepted 输入所需 SymCC 运行次数下降或持平。

---

## M2 DNS 语义算子（破坏→修复）

- [x] 引入 DNS 结构扰动算子（label 长度、压缩指针、`rdlength` 不一致等）。
- [x] 将“破坏包”交给 SymCC，保留可被修复到 accepted 的输入。

目标文件：
- `gen_input/src/FormatAwareGenerator.cpp`

验收：
- 生成样本包含更多合法但边界更强的 DNS 结构。

---

## M3 严格格式验证与计算字段

- [x] 实装 `BinaryFormat::validate` 的字段约束校验（不仅 size）。
- [x] 实装 `updateComputedFields` 并在入队前调用（长度/计数字段一致性）。
- [x] 分离 `ValidInputs` 与 `AcceptedInputs`（消除当前 TODO）。

目标文件：
- `gen_input/src/BinaryFormat.cpp`
- `gen_input/src/FormatAwareGenerator.cpp`

---

## M4 多 RR / 多 section 扩展

- [x] 最小可用 `Array` 语义（create/parse/serialize/validate）。
- [x] `dns-response` 支持多 answer/authority/additional 的结构化生成。

目标文件：
- `gen_input/src/BinaryFormat.cpp`
- `gen_input/include/BinaryFormat.h`

---

## M5 工程化与验证矩阵

- [x] `SymCCRunner::run` 增加超时 kill 与清理。
- [x] 增加统计：丢弃原因、accepted 率、每 accepted 样本的 SymCC 次数。
- [x] 更新文档（中英文 README）与示例命令。

目标文件：
- `gen_input/src/SymCCRunner.cpp`
- `gen_input/README.md`
- `gen_input/README_ZH.md`

---

## 验证计划（每阶段执行）

1. 构建：`xmake build`（至少覆盖 `gen_input`）
2. 单测：`gen_input/test/test_dns_format.cpp`（DNS 相关路径）
3. 运行样例：
   - `--format dns`
   - `--format dns-response`
   - `--hybrid`
   - `--three-phase`
4. 回归检查：TLV 与非 format-aware 路径不可退化。

---

## 执行记录

- [x] Step 1：M0.1 尺寸处理修复
- [x] Step 2：M0.2 解析一致性修复
- [x] Step 3：M0.3 hybrid accepted 标注
- [x] Step 4：M1 首个增量（局部性优先）
- [x] Step 5：构建与测试验证
- [x] Step 6：M2 首个增量（DNS 结构扰动 + SymCC 修复闭环）
- [x] Step 7：M3 完整落地（validate + computed fields + accepted/valid 分离）
- [x] Step 8：M4 最小 Array + DNS response 多 section 扩展
- [x] Step 9：M5 超时控制 + 指标统计 + 文档更新
