# 执行计划：按证据门槛推进

> 2026-10-30：首批 A1–A3 已提交并由用户推送；用户再次要求继续任务，现进入第二批代码与有限验证。pilot 与正式实验仍未启动。
> 随后用户要求暂停并提交检查点：第二批最终 check、三组生成对照迁移及审计边界修复未完成，实际状态以 `progress.md` 暂停记录为准。

## 0. 规划与批准

- [x] 创建任务并记录用户的规划授权。
- [x] 确认实际 Git 仓库、提交、工作树与现有论文主线。
- [x] 读取既有证据契约、旧实验审查和历史会话线索。
- [x] 收敛三份专项研究及受影响文件/测试清单。
- [x] 提交最终论文主线、首批实现边界和资源限制供用户批准。
- [x] 用户在后续消息中批准最新方案后，激活实际拥有交付物的任务（2026-10-30，首批 A1–A3）。

如拆子任务，当前任务保留论文规划与集成验收；先创建并启动首批修复子任务，后续符号链路与正式实验分别按验收推进，不并行修改共同 schema owner。

## 1. 首批实施：修复已核验的论文有效性阻塞

### 已选定的三个小步骤

根据 [research/code-gaps.md](research/code-gaps.md) 的有限动态验证及主会话源码复核，依次处理下列三项。路径相对 `symcc/`；详细调用位置在研究报告中。

| 顺序 | 根因与最小范围 | 必须联动的现有边界 | 回归与验收 |
| --- | --- | --- | --- |
| A1 | Python 把单端缓存变化当跨端差异；C++ 共同投影混入实现字段并不区分 RDATA 类型 | `tools/dns_diff/{cache_diff,triage,follow_diff}.py`、`dnslab_core/src/cache_analysis.cpp`、相关 schema/消费者和共享 fixture | 相同语义的真实格式 dump 不升级语义候选；真实 IP/TXT 差异保留；域名大小写按协议等价；两后端分类一致 |
| A2 | Unbound 单端截断 RR、下调计数，使实际注入与其他 resolver 不同 | `patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c`、对应 patch/构建应用路径，与 BIND 注入契约对照 | 扩展 `test/test_unbound_mutator_fidelity.c`；截断 RR、尾部垃圾、计数不符不得被单端悄悄修复；保留原报文或给出明确不可比较状态 |
| A3 | acceptance predicate 对错误 Question/截断报文仍放行，负答案与注入事实口径不统一 | `tools/{dnsmasq,smartdns,maradns,knot_resolver}_replay_harness.py`、BIND/Unbound oracle 生产点及 `tools/dns_diff/oracle.py` 等消费者 | 扩展 `test/test_replay_harness_negative_control.py`；错误 ID/Question、截断 RR、未 fetch、发送失败不计有效接纳；正 A、NXDOMAIN、NODATA 分类一致，验证最终 oracle 而非只测 predicate |

首批不重写 SymCC runtime，不扩展全部变异器边界，不运行正式 fuzzing。三个步骤依次验收，A1 的共同语义先冻结，避免并行改出不同合同。

优先级不是按旧审查的 F 编号排序，而是按**当前确认的问题**对测量与结论的影响排序：

1. 重新检查 `git status`、提交和局部指南，确认研究报告仍对应当前代码。
2. 选取当前仍成立、最影响语义结论的根因；已修复项只回归验证，不重写。
3. 先补能失败的最小正反例，覆盖真实调用链，而非只改 fixture 使旧测试通过。
4. 修复共享 owner，联动受影响的 C++/Python 消费端、adapter、patch、统计导出和必要文档。
5. 核查所有调用方及 fixture；运行对应单元/集成回归。
6. 更新旧问题状态和结果可复用边界，不直接修改历史结果文件。
7. 使用 Trellis implement/check 子代理分别实现和复核，写入范围不重叠；最多同时 3 个子任务。

**本批完成门槛**：

- 相关阴性路径不被计作成功、命中或真实差异；
- 等价输入/状态与真实差异均有回归，统计缺失值不伪装成观测值；
- 原始数据、导出表和解释的口径一致；
- 记录实际执行的验证命令和失败，不以编译通过或少数测试通过宣称全系统正确。

### 续接收尾（2026-10-30）

- [x] A1：关闭 `a1-check.md` 的遗留项。共同差异语义覆盖 Python audit 和 C++ reporting；初态不同不作有效比较；C++ replay/follow-diff 保留快照缺失状态；联动旧集成 fixture。
- [x] A2：在 A3 的发送观测改动后复跑字节保真测试，保留仅事务 ID 可变的合同。
- [x] A3：补齐四个 Python harness 与 BIND/Unbound 最终 oracle 的正负例、实际 fetch/send 观测和 post-check 边界。
- [x] 集成：独立 check 复核本批全部改动，运行相关回归，同步证据合同与实际进度。

只续接已批准的首批，不扩大至第二批、pilot 或正式实验。实现者分工、具体命令和失败记录见 `progress.md` 及各检查报告。
最终独立结果见 [final-check.md](final-check.md)：首批通过；额外运行的 `test_campaign_matrix.sh` 仍因第二批旧快照计数合同失败，未扩大范围修复，不声称仓库全测通过。

## 2. 第二批：真实 producer、符号链路和输入身份

依赖首批语义测量正确。若当前代码已具备某部分，只补缺口与验证。

- [ ] 修正预设种子被运行脚本覆盖的路径，核对 master/secondary/mutator/helper 各随机源；涉及 `named_experiment/run_named_afl_symcc.sh` 及 `test/test_named_seed_provenance.sh`。
- [ ] 版本化解释快照排除 `*.meta.json` 后的摘要规则，确保旧摘要不被伪装为现行来源证据；涉及 `matrix.py`、`publication_audit.py`、既有矩阵/审计回归。
- [ ] 冻结初始语料及逐样本身份，确认 RQ1 的对照来自可追溯转换。
- [ ] 最小目标上验证符号字节 → 分支约束 → 新候选 → 具体重放 → AFL 回流。
- [ ] 验证变体开关实际改变行为；合并等价的消融配置。
- [ ] 分离 producer 执行身份和 replay 身份，防止 queue 复制或元数据变化充当独立生成。
- [ ] 根据真实来源构造回归：缺失/矛盾来源、静态 replay 不得获得生成效果资格。
- [ ] 同一内容来自独立合法运行时不误判作弊或失败。
- [ ] 核查全部论文导出路径的单 run/缺失值处理：旧 TSV 不改写，新报告使用 `NA`/unknown；区分脚本执行 PASS 和可用于统计。复用 `test/test_multi_run_aggregate.sh`、`test/test_rq3_snapshot.sh`。

**本批完成门槛**：G1 pilot 所需来源证据可以由一次受控真实运行产生，而不是分析端补写出来。

### 第二批实施分工与合同

基线为 `c696add30c49c909e0d1d361618b71e3b1e0e754`；续接时本地与远端 `paper` 一致，工作树干净。

| 步骤 | 最小范围 | 验收 |
| --- | --- | --- |
| B1 | named producer 的执行身份初始化、随机种子传递、实际组件记录及相关脚本测试 | 显式 seed 不被覆盖；缺省才生成；非法输入不启动组件；manifest 不把未启动写成已执行 |
| B2 | matrix/publication audit 的快照版本、生成与重放身份及对应回归 | metadata 不影响内容摘要；旧 v1 不升级资格；缺失/矛盾/重放来源不冒充生成；真实独立运行不因相同内容被误拒 |
| B3 | 最小符号链路、初始输入身份与单 run/缺失值出口 | 先确认现有可执行入口及依赖，再做有时限、本地隔离验证；证据不足保留未完成，不用替身 PASS 充当真实生成 |

- 快照内容规则采用 `sha256-relative-path-size-content-v2`：路径、大小、内容参与摘要，排除 `*.meta.json`；不重写历史 v1 manifest。Python 消费端与 named producer 同步此标识和规则。
- `execution_mode` 必须区分 `independent_producer_generation` 与 `shared_queue_replay`；缺失/未知模式不能推断成实际生成。具体命令、seed、时间、组件启动事实来自生产路径，不由 replay 端补造。
- B1 独占 named producer 脚本及其测试；B2 独占 matrix/audit/schema 与对应测试。需要跨 owner 的修改由主会话协调；B3 先调查再分配写权，最多三代理并行。
- 不启动完整 DNS 矩阵或小时级 producer，不访问公共 DNS，不覆盖历史结果，不借本轮继续请求自动提交或推送新改动。

后续已明确的最小联动：

- B1 同步 `scripts/run_real_rq3_multi_resolver_ablation.sh` 的重放出口：删除固定日期/伪内容 ID，保留真实来源与当前摘要，显式标记共享队列重放；不把该脚本升级成虚构 producer。
- B3 输入/统计：`input_model_eval.py` 执行前冻结输入和 response bytes，验证可追溯关联；观测缺失不补零。`aggregate.py`、`statistics.py`、`rq3_snapshot.py` 及 matrix 统计消费者保持 `null`/`NA` 和单 run 不确定性边界。B2 冻结后才移交 matrix 统计区域写权。
- B3 符号诊断：只新增小测试，复用既有 `test/if.c`、SymCC/QSYM、C++ helper 和 AFL；在 `/tmp` 新目录、单核、180 秒进程树上限内验证真实求解/分支/回流，并尝试 3 秒真实 AFL 导入。接口队列夹具不能作 producer 证据；小目标不替代 DNS resolver 链路。没有证据要求先改通用 runtime。

## 3. G1 pilot：限时、隔离、不形成性能结论

- [ ] 执行前确认本地隔离、进程清理、端口分配、二进制身份和资源上限。
- [ ] 用 BIND9/Unbound 跑冻结正负例，验证同源性和状态因果链。
- [ ] 在用户批准的限额内跑独立 producer pilot，保存失败原因及原始计数。
- [ ] 检查缺失值、所有尝试量/排除量、组件真实运行和前后状态。
- [ ] 将成本测量用于估算正式实验，不能将短跑增益外推成正式性能。

**停止条件**：任一关键 oracle 阳性来自 harness 伪差异、来源不可信、状态残留或链路未执行，停止正式运行。

## 4. 正式实验与论文写作

该阶段不包含在“批准首批代码修复”的默认授权中；需先确认目标投稿类型、完整资源预算和人工标注安排。

- [ ] 冻结研究问题、主指标、比较组、初始语料、预算与重复/停止规则。
- [ ] 同环境复现最接近外部基线；不可复现时记录障碍并缩小结论。
- [ ] 按 RQ1–RQ5 完成独立实验，生成不可变的批次清单。
- [ ] 完成独立人工裁决和案例最小化，不伪造 reviewer 身份、标签或漏洞结论。
- [ ] 从原始产物统一生成图表和摘要，报告失败、负结果与缺失。
- [ ] 写完整论文草稿、有效性威胁、复现说明和引用清单。
- [ ] 运行产物审计、复算和干净环境抽样复现，再讨论投稿。

## 验证命令与执行条件

以下是规划阶段整理的验证入口；实现阶段的实际结果见 `progress.md` 及检查报告，不能把下列清单本身当作运行证据。工作目录为 `/home/egoist/work/symcc`。每次只运行当前修改相关目标；resolver 相关脚本须先检查其网络/进程行为。

```bash
git status --short
git diff --check

# 单独构建 DNS 目标，避免以整个 SymCC 工具链问题掩盖局部回归。
xmake build dnslabctl

# CLI、证据契约与导出链的现有回归入口。
bash test/test_dns_diff_cli_smoke.sh
bash test/test_triage_contract.sh
bash test/test_campaign_report.sh
bash test/test_publication_evidence_bundle.sh
bash test/test_publication_readiness_audit.sh
```

C++ oracle/cache/transcript/mutator 的具体测试目标、Python 测试及 patch 回归应以 `research/code-gaps.md` 的受影响清单和实际 `xmake.lua` 为准，实施前补到该批清单，不能用不相干的测试冒充覆盖。

CLI 参数通过现有 `--help` 或源码核验后再构造实验命令；不提供未经核实可直接启动完整矩阵的长命令。

### 规划阶段已经执行的有限检查

代码研究子代理在 `symcc/` 执行了下列只读测试，结果为 **3 tests / OK / exit 0**：

```bash
PYTHONPATH="$PWD/test:$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -B \
  -m unittest test_dns_diff_cache_diff test_replay_harness_negative_control -v
```

此外以内存构造输入调用了生产 cache/triage 和 acceptance 函数，复核了 A1/A3 的错误判定；没有改产品代码。首次使用不同导入路径出现 `ModuleNotFoundError`，后由显式 `PYTHONPATH` 修正。现有测试通过却没有覆盖这些反例，故仍需新增回归。C++ 编译、真实 resolver、solver 和完整实验均未运行。

规划文件校验通过：10 个必需文件非空、JSONL 各 6 条真实且存在的引用、Markdown 本地链接有效、均为 LF 并保留末尾换行。任务仍为 `planning`。最终 `git -C symcc status --short` 与 `git -C symcc diff --check` 均无输出，HEAD 未变化。研究子代理对四份最终规划文件作了只读复核，未发现阻塞性矛盾；这不是产品代码验收。

## 风险与回滚

- 分支 `paper` 的基线记录见 `research/baseline.md`；实现前若 HEAD 已变化，重新审查相关差异。
- 现有 `build/`、`experiments/subjects/` 和结果目录不作为可随意清理的临时目录。
- 所有新结果用独立批次目录，不覆盖 `audit_ready_matrix` 等历史批次。
- 对已修复模块不再重构；对无法验证的新颖性、实际漏洞或 hybrid 增益不作承诺。
- 每批实现后先质量验证再交付；本轮不提交、推送或发布任何代码。
