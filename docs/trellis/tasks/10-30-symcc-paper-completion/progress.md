# 首批代码修复与验证记录

> **当前状态：用户要求暂停，第二批作为 WIP 检查点提交，未完成独立验收。**
> 恢复时先处理文末未完成项；本文前面的“完成/通过”仅指对应批次或实施者自检。

- 日期：2026-10-30。
- 授权：用户批准 A1–A3；任务已由 `planning` 转为 `in_progress`。
- 初始基线：`symcc` / `paper` / `f08a6c8935c9d25ff0319fdc8b6723d49648322a`，工作树干净。
- 不运行正式 fuzzing，不覆盖历史实验数据，不自动推送代码。

## 进度

| 步骤 | 状态 | 范围 |
| --- | --- | --- |
| A1 | 完成，独立复核通过 | Python/C++ 共同语义、审计消费者、初态前提与快照缺失 |
| A2 | 完成，集成后复验通过 | Unbound 响应仅改事务 ID；117 checks 与 ASan/UBSan 通过 |
| A3 | 完成，独立复核通过 | 响应接纳、发送事实与缓存 proxy；重复加锁和缓冲区泄漏已修复 |
| 集成复核 | 首批通过 | 完整变更、公共消费链及 sanitizer；范围外 matrix 失败单列 |

实现按互不交叉的文件范围准备补丁，最终按 A1→A2→A3 验收；实施阶段 A1 独占 xmake，冻结后交独立 check 统一构建。任何公共契约或跨 owner 的修改先由主会话协调。

## 修改前基线检查

- A3 原有负对照：`PYTHONPATH="$PWD/test:$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest test_replay_harness_negative_control -v`，1 test / OK。
- A2 原有 C 用例在临时目录独立编译运行，通过 TC/RCODE/RA 保真断言。编译使用 `-Iexperiments/subjects/unbound/release-1.24.2-build/unbound-afl`、`-Ipatch/cache/unbound`、`-Iexperiments/subjects/unbound/release-1.24.2`、`-I.`、`-pthread`。
- A2 首次仅传仓库 include 时缺少 `config.h`；采用现有 Unbound build config 后编译退出 0、测试退出 0。没有为此修改业务文件或生成假的配置。
- 上述旧测试通过不意味着问题消失：它们尚未覆盖截断 RR、错误 Question 或等价缓存误分类。
- A2 后续发现原用例受 `config.h` 的 `NDEBUG` 影响，以上旧 PASS 不能证明断言执行；重新启用断言后，原 TC/RA/NOERROR 用例确实通过，新增尾部垃圾反例确实失败。

## A1 实施者验证

- 修复前：共享 fixture 导出的 Python 子用例有 18 项失败；C++ 同语义缓存被误报。
- 修复后：`test_dns_diff*.py` 共 36 tests / OK；13 个共享场景、两种详情开关，Python/C++ 一致。
- 实施者运行了 C++ cache/reporting 测试、`xmake build dnslabctl` 和相关 triage/taxonomy/replay-cache/parser/CLI/campaign/publication/case-study 回归，均通过。
- 日志位于 `/tmp/a1-red-*.log` 与 `/tmp/a1-verified-*.log`，独立 check 将再验证，不将该结果当作真实 resolver 实验。
- 已同步 `docs/DNSPoisonEvidenceContract.md` 第 9 节；负缓存、未支持 RR 和缺乏 RDATA 观测的情况保守保留为不可比较，旧产物不会自动获得无差异结论。

## A2 实施者验证

- 新反例在修复前将 47 字节输入静默截为 45 字节，断言退出 134。
- 修复后 `bash test/test_unbound_mutator_fidelity.sh` 通过 117 checks；覆盖内存/文件输入、TC/RA/RCODE、NXDOMAIN、尾部垃圾、截断 RR、计数、Question 和容量。
- 同套用例通过 `-Wall -Wextra -Werror`、ASan/UBSan；runner 的 `bash -n` 与改动文件 LF/空白检查通过。
- 源码删除单端 RR 修复路径；成功时只改事务 ID，其他原始响应字节不变。错误不再用空回复替代。
- A3 因真实发送事实需要获准在该 mutator/header 增加最小观测接口；必须保留此字节合同并重跑 117 checks。
- 第 10 节证据契约记录 BIND 请求绑定和 Unbound API 层输入的共同可比范围限制，未声称全部 wire 已等价。

## 续接记录

- 用户要求继续今天的任务；恢复同一 `in_progress` 任务，不新建任务，不丢弃上轮工作树。
- 主会话协调 A1 的初态合同：共同 before 投影不相同则保守不可比较，保留相对 delta 的定义。A1 实现者独占 cache/audit/C++ replay/reporting 及相关 fixture；A3 实现者独占响应 harness/oracle/patch；主会话负责合同、集成与进度。
- 续接基线：`PYTHONPATH="$PWD/test:$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest test_dns_diff_schema test_dns_diff_contract_regressions -v`，15 tests / OK / exit 0。
- 11 项 shell 基线通过（均 exit 0）：CLI smoke、failure taxonomy、triage contract、oracle audit secondary、publication readiness、campaign report、replay/cache contract、replay failure evidence、run comparability、case study、cache dump parser。
- 发现两项失败（exit 1），交 A1 联动修复：`test_sample_analysis_state.sh` 预期 `oracle_and_cache_diff` 却得到 `oracle_diff`；`test_follow_diff_pipeline.sh` 预期 `completed_no_diff` 却得到 `incomplete_cache_comparison`。需区分真实错误和旧 fixture 证据不足，不能仅放宽断言。
- 此处是修改期间的基线，不替代收尾后的全批复核；后续阶段尚未获本轮自动授权。

## 续接实现者验收

- [A1 收尾](a1-followup.md)：三个遗留点和两个旧 fixture 已闭环；38 项 Python 测试、26 组共享场景×两种明细开关、17 组双后端审计、16 个 shell 回归及 C++ release cache/reporting/oracle 测试通过。
- [C++ oracle 镜像](oracle-mirror-check.md)：可选发送字段保留 true/false/null，不改变旧解析状态或原六字段比较；严格 release 编译、有效断言及 34 条 Python/C++ 最终 JSON 对照通过。
- [A3 验证](a3-check.md)：6 个 Python 测试、BIND/cache 43、BIND/fuzz 43、Unbound 45 checks 与最终 summary 断言通过；重跑 A2 仍为 117 checks。完整路径测试发现并修复 Unbound 重入 mutex 死锁，以及宽容 parser 放过非法 A RDATA 的 oracle 缺口。
- `docs/DNSPoisonEvidenceContract.md` 第 9–11 节与 `.trellis/spec/backend/dns-evidence.md` 已同步；两份 JSONL 各 7 个引用均存在，已检查本轮文档 LF、末尾换行及本地链接。
- 上述为实施者自检；最终独立结果另记，不能用其代替真实 resolver、缓存因果、solver 或正式实验验证。

## 防复发记录

1. 根因类别：跨层传播遗漏（审计与 C++ 序列化）、测试覆盖缺口（只测 predicate/替身公式）、隐含假设（delta 默认初态相同）。
2. 之前为何未暴露：旧 fixture 只有单端标志，缺少可比较快照；部分 C 断言被 `NDEBUG` 禁用，未真正经过发送与最终 summary 路径。
3. 预防机制：共同格式 fixture 同时驱动两语言；最终 JSON、审计组合指标与完整 orchestrator 使用正反例；release 断言保持有效。
4. 系统性边界：六端网络时序、native cache 因果与真实 producer 来源仍需后续验证，不能靠本批通过的替身测试补足。
5. 知识落点：证据合同第 9–11 节、backend `dns-evidence.md`、更新后的 implement/check manifests；不为此扩大成无关重构或新任务。

## 最终独立验收与下一步

- [最终检查报告](final-check.md)：未发现仍阻塞首批交付的问题。独立检查修复 `test_campaign_close_loop.sh` 的无效成功 fixture，以及 Unbound `parse_query_packet` 重初始化 buffer 导致的泄漏；主会话已复核这两个补丁。
- 实跑通过：44 个 Python tests、9 个 C++ 测试目标、30 项公共消费链/post-check shell 检查；A2 117 checks；A3 BIND/cache 43、BIND/fuzz 43、Unbound 45 checks；A2/native A3 的 ASan/UBSan。
- `dnslabctl` 强制重建通过，C++ 源码哈希在构建前后不变；`git diff --check`、变更 shell 语法与 Python AST 检查通过。没有独立 Python 静态类型检查或完整 linter 运行证据，详见最终报告。
- **保留的失败**：`bash test/test_campaign_matrix.sh` 退出 1，实际 `file_count=1,size_bytes=17`，旧断言期待 `file_count=2`。它属于第二批排除 metadata 的快照摘要合同；相关产品与测试本轮未改，不把首批通过写成全仓测试通过。
- 下一步仍是 `implement.md` 第二批：真实 producer、符号链路及输入身份；先确认第二批范围，再同步快照版本语义与上述测试。pilot 和正式实验未启动。
- 实现验收时没有真实六端 resolver/网络时序/缓存因果/solver 验证，没有覆盖历史数据，当时尚未提交或推送；后续提交状态见下节。
- 整体任务保留 `in_progress`，不归档为论文与实验全部完成；本次完成的是已批准首批 A1–A3。

## 用户授权后的提交与推送

- 用户后续明确授权先提交并推送；69 个文件全部与最终检查的 SHA-256 清单一致，无未识别改动，暂存清单和 `git diff --cached --check` 通过。
- 已在 `symcc` 的 `paper` 分支提交 `c696add30c49c909e0d1d361618b71e3b1e0e754`：`fix(dns): 完成首批缓存比较与响应注入证据修复`。提交后工作树干净，未 amend。
- 推送目标为 `origin/paper`，远端 `https://github.com/Egoist-debug/symcc`。首次遇到 GnuTLS 握手中断；使用 HTTP/1.1 重试后报 `Invalid username or token` / `Authentication failed`。
- 用户要求关闭证书校验后，仅以命令级 `-c http.sslVerify=false` 重试，仍因认证失败退出 128。没有永久修改证书配置，没有强制推送。
- `gh auth status --hostname github.com` 明确报告当前账户的 keyring token 无效；现有 SSH 严格检查也未通过（缺少已信任的 GitHub host key），未绕过 host-key 校验。
- 下一步需用户在本机执行 `gh auth login -h github.com` 更新认证，再正常推送该现有提交；当前不能报告推送成功。matrix 旧断言问题仍留在第二批。
- `.trellis/` 位于 `symcc` 仓库之外，本地任务与规范记录未包含在该 Git 提交中；不为此新建仓库或归档未完成任务。

## 第二批续接

- 用户确认已自行推送，并再次要求继续任务。`git ls-remote origin refs/heads/paper` 实测远端为 `c696add30c49c909e0d1d361618b71e3b1e0e754`，与本地一致；工作树干净。此前认证故障不再阻塞此次代码工作。
- 进入 `implement.md` 第二批，先处理 B1 随机源与实际 producer 记录、B2 快照版本与生成/重放审计，同时调查 B3 最小符号链路、输入身份和统计出口。
- 首批验收保持不变；第二批仍需独立 check，不把首批通过自动沿用。未授权预算的 pilot 和正式实验继续不启动。

### 第二批进行中记录

- B2 实现者已冻结：[b2-check.md](b2-check.md)。v2 摘要、显式模式与实际组件门槛、同内容独立运行、NA 格式化通过 14 项单测及 matrix/publication 回归；原 matrix 计数失败已修复。尚需跨 owner 独立复核。
- B3 调查：[second-batch-symbolic.md](research/second-batch-symbolic.md)。本机有 LLVM 21 SymCC、QSYM/Z3 和 C++ helper；随后已派小目标真实诊断，不把调查中的命令清单当执行证据。
- 主会话基线中 input-model smoke、multi-run aggregate、RQ3 snapshot 脚本均 exit 0；`test_real_rq1_input_model_snapshot.sh` 也返回 0，但没有逐样本验收且二进制身份未对应当前 patch，所以只记脚本退出，不计真实 resolver 或 RQ1 科学结论通过。
- 实际函数反例：缺 `repro_rate` 被提取成 `0.0`；RQ1 超时且 oracle 全为 `None` 仍输出零成功率和 `post_check_capable_count=1`；RQ3 将单 run/insufficient 的旧零 CI 原样导出。输入/统计实现者负责根因与最终 JSON/TSV 回归。
- 另发现真实 RQ3 名称的辅助脚本实际只复制队列重放，并写固定日期和格式化伪内容 ID；已将该单一脚本及离线回归交 B1，明确不运行其完整矩阵。
- [B1](b1-check.md) 与 [B3 输入/统计](b3-input-statistics-check.md) 自检已冻结；B1 命令级对照证明 `no_cache_delta` 与 `full_stack` 等价。按原计划合并等价生成组，保留旧分析标签；另安排收尾 audit seed 数值边界和数字字符串导致的统计异常，不仅停留于风险说明。

## 用户要求暂停的检查点

- 用户要求先停止任务，将当前代码与任务资料一并提交推送。所有实现/check 子代理均已停止并关闭；真实小目标诊断的进程已回收。不再新增实现或运行完整验收。
- B1、B2、B3 输入/统计分别完成实施者自检，详见各报告；**第二批独立全范围 check 未完成**，没有 `second-batch-final-check.md`。
- [真实小目标诊断](b3-symbolic-check.md) 最终 exit 0、4.406 秒：两个 solver 候选改变具体分支，经 helper 回流后被真实 AFL 以 `sync:foreign_0` 导入。首次 AFL core_pattern 预检失败后，仅调整该测试子进程环境通过；语法和清理负例通过。尚无独立复核，不能代替 DNS 链路、named 同步或 G1 pilot。
- **尚未实施**：三组生成对照迁移。当前代码仍保留四标签；已确认 `no_cache_delta` 与 `full_stack` 等价，但合并只完成设计说明，不得说默认配置已迁移。
- **尚未修复**：publication audit 的 seed 数值/范围/前导零去重边界；数字字符串可绕过指标校验并触发未捕获 `StatisticsError`。
- **恢复时联动**：`resolver_matrix_aggregate.py` 的 TSV 表头会筛掉新增分组列，不能假定它完全透传；三组合并时需同步实际消费者及回归。
- 恢复顺序：先完成上述跨层迁移和边界修复，再冻结代码并执行第二批独立全范围检查，最后才讨论 DNS pilot 的预算与构建身份。
- 本任务资料保存到 `symcc/docs/trellis/tasks/10-30-symcc-paper-completion/` 作为版本化检查点；Trellis 校验拒绝跨任务根目录的符号链接，因此恢复原工作区真实目录，不修改或绕过安全边界。仅纳入本任务与引用的规范快照，不提交其他任务、workspace 日志、运行时状态或凭据。
- `task.json` 仍为 `in_progress`，以 `meta.paused=true` 记录暂停，清除本会话活动任务指针；不归档、不标为完成。此次提交是保存进度，不是发布就绪声明。
