# Research: 首批实现所需的实验与原始产物缺口

- Query: 只读核验 RQ1–RQ5、六 resolver 覆盖、replay/producer 独立性、seed/哈希及缺失统计，确定首批修复与最小 pilot。
- Scope: internal；仅核验下列明确批次及相关当前源码，不是全量结果审计。
- Date: 2026-10-30
- 权限：仅规划；本轮只写本文件，未修改代码、历史产物或其他工作者文件，未执行 Git 操作。
- 路径约定：下文 `R/` 表示 `/home/egoist/work/symcc/experiments/results/`，`S/` 表示 `/home/egoist/work/symcc/`。JSON 引用中的 `:1` 为文件入口，具体事实以同时列出的 JSON 键定位。

## Findings

### 1. 结论：先修测量与执行身份，不必先扩大预算

现有数据可支持链路回归、历史探索和候选案例选取，**不能支持独立 hybrid 消融、指纹误报下降或已确认缺陷数量**。已有真实接近一小时 producer，不能把历史工作概括为“全是 smoke”；但它只是一轮 full-stack 生成，后续四变体主要是共享队列回放。

当前代码已部分处理旧审查发现，不能原样复制旧 F6/F10/F11/F12：

| 历史发现 | 本轮当前源码核验 | 尚存的首批阻塞 |
| --- | --- | --- |
| F6：replay 冒充 producer、元数据制造不同哈希 | `S/tools/dns_diff/matrix.py:487-511,514-584` 已排除 `*.meta.json`，默认写 `execution_mode=shared_queue_replay`，`components.symcc.started=false` | `:529` 仍事后从 replay ID 派生 `random_seed`；`:615,631-638` 仍只调用 campaign-close 后写 manifest。没有由该矩阵启动各变体独立 producer |
| F10：RQ2 0/20 被写成 20/20 成功 | `S/docs/DNSPoisonPaperMaterialStatus.md:48` 已更正为 0/20 completed | 两批真实失败产物仍未替换成成功实验；修正文档不等于补实验 |
| F11：空 aggregate 导出为零 | `S/scripts/run_real_rq3_multi_resolver_ablation.sh:164-174,193` 已输出 `NA` | 历史 20 行 TSV 仍为零；当前脚本 `:207-215` 仍会写表并输出 `PASS`，不能把 PASS 当统计可用 |
| F12：RQ1 无逐样本身份 | `S/tools/dns_diff/input_model_eval.py:125-142` 已写路径、SHA-256、长度、命令、oracle；`S/test/test_real_rq1_input_model_snapshot.sh:8,38` 已使用仓库路径 | 所查两个历史批次均没有 `sample.meta.json`；新 sidecar 仍未冻结响应语料、二进制/配置哈希及同源转换关系，也没有复制输入本体 |

优先顺序建议：

1. **明确重复单位和成功口径**：producer generation、固定语料 replay、状态语义验证分开计数；禁止用 `comparability`、`executed_resolvers`、`diff_detected` 或历史 ready 代替执行/有效性证据。
2. **补真实种子与输入身份**：真实 producer 入口已经使用 AFL `-s`，但当前 `initialize_execution_identity()` 无条件重新生成种子并覆盖 `PRODUCER_RANDOM_SEED`，见 `S/named_experiment/run_named_afl_symcc.sh:475-484,1782-1787`。需支持预先冻结的运行种子；master、secondary、mutator/helper 随机源分别说明，不能宣称一个 master seed 决定整个系统。
3. **关闭统计假象**：缺测/不适用/单 run 不确定性不能填零；旧结果保持不变，在新派生报告标记不能进入主表。
4. **准备有真值的小语料**：先验证等价表示、正常拒绝、缓存与非缓存回答、受控错误状态和 harness 故障，再扩展 resolver 或时长。语义 oracle 的全面代码审查由其他研究材料承担，本文件不把旧 F1–F3 直接当当前缺陷。

### 2. 文件与规范索引

| 文件 | 用途 |
| --- | --- |
| `.trellis/tasks/10-30-symcc-paper-completion/prd.md:9-12,24-35` | 只批准规划；禁止把 ready 当科学有效性 |
| `.trellis/tasks/10-30-symcc-paper-completion/paper-plan.md:43-95` | 当前 RQ、独立运行定义、pilot 与预算主线 |
| `.trellis/workflow.md:341-390` | 规划与 research 持久化要求 |
| `.trellis/spec/backend/index.md:15-21`、`quality-guidelines.md:19-51`、`error-handling.md:19-51` | 后端规范目前主要是待填模板，不冒称已有实验统计规范 |
| `.trellis/spec/guides/cross-layer-thinking-guide.md` | 按 producer→replay→triage→report→audit 检查契约，不只改最终 TSV |
| `.trellis/tasks/08-17-review-symcc-experiments/review-2026-09-08.md:118-134` | 旧 F6；仅作核验线索 |
| `.trellis/tasks/08-17-review-symcc-experiments/review-2026-09-08-continuation.md:17-119` | 旧 RQ2、统计与 provenance 发现；本轮重新读实际文件 |
| `S/docs/DNSPoisonEvidenceContract.md:29-103,132-182` | 比较键、seed provenance、统计与审计契约 |
| `S/tools/dns_diff/matrix.py:591-638` | 四变体共享 source queue 的回放入口 |
| `S/tools/dns_diff/publication_audit.py:393-421,479-582,620-716` | 摘要、执行模式及重复证据审计 |
| `S/tools/dns_diff/aggregate.py:353-440` | run_count、空 aggregates 与统计拒绝条件 |
| `S/tools/dns_diff/campaign.py:434-474` | `repro_rate` 实际是 manifest 路径交集，不是语义复现率 |
| `S/dnslab_core/src/main.cpp:1583-1606,2586-2598` | batch 执行状态字段及 replay CLI 参数 |

### 3. 小规模数据账本：本轮实际读取与重算

#### RQ1：220 次样本执行，不是 220 个独立实验

`R/rq1_input_model_multi_sample/20260814_075703/summary.json:1` 的 `rows[]`，并逐个重读各模型 `bind9.stderr` 的末条 `ORACLE_SUMMARY`，计数吻合：

| model_name | sample_count | parse_ok_count | resolver_fetch_started_count | response_accepted_count | post_check_capable_count | second_query_hit_count | effective_post_check_rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| dst1_transcript | 68 | 68 | 68 | 68 | 68 | 19 | 19/68 = 0.2794117647 |
| query_only | 68 | 68 | 68 | 68 | 0 | 0 | null |
| random_packet | 16 | 0 | 0 | 0 | 0 | 0 | null |
| legacy_response_tail | 68 | 68 | 68 | 68 | 0 | 0 | null |

- 原始样本日志例：`R/rq1_input_model_multi_sample/20260814_075703/dst1_transcript/sample-08/bind9.stderr`；其他模型也有同名层级。该批共 220 份 stderr、0 份 `sample.meta.json`。
- 更旧 `20260813_114524/out/summary.json:1` 为 4/15/16/15 个样本，DST1 四项命中均为 4，另外三组前三项均为 0；共 50 份 stderr、0 份 sample meta。不可与新版 wire 对照混合聚合。
- 当前 `input_model_eval.py:145-148,174-189` 明确仅 DST1 增加 post-check 分母，其他模型的 null 是“不适用”，不是“0% 命中”。该设计不能独立证明 DST1 在同等后置观察条件下更好。
- 可复用日志验证计数与格式；不能从缺失的 sample identity 反推当时输入。正式 RQ1 用同一 source manifest 派生各表示，并补统一后置查询对照。

#### RQ2：指定重复批次全部失败；其他矩阵确有成功回放

两个批次 `R/rq2_sync_replay_repeat/{20260813_114601,20260813_122829}` 各有：

- 5 份 `run-*/summary.json`：每份 `sample_count=4`、`completed_count=0`、`failed_count=4`、`status=partial_failure`、`comparability.status=comparable`。
- 20 份 sample meta：全部 `status=failed`、`failure.stage=unbound.preflight`、`failure.process_started=false`；原因是缺少 `unbound_experiment/work_stateful/response_corpus`。
- 20 份 `sample.bin`，SHA-256 去重后每批仅 4 个输入。两批合计 40 次失败尝试，不能作为 40 个不同样本或成功 paired replay。
- 具体入口：`R/rq2_sync_replay_repeat/20260813_114601/run-1/summary.json:1`；样本例 `run-4/samples/manual__bdf78b4c/sample.meta.json:1`。
- 该样本同时写了 `executed_resolvers=["bind9","unbound"]`、`diff_detected=true`，但 Unbound preflight 根本未启动，证明这两个字段也不能充当成功指标。`process_started` 在嵌套 `.failure` 下，不是顶层字段。

当前 C++ registry 的 response corpus 默认已改为 `named_experiment/work/response_corpus`，见 `S/dnslab_core/src/concrete_adapters.cpp:1546-1559`；本轮确认新目录存在、旧目录仍不存在。**没有实际重放验证当前成功率。**

不可把上述失败扩大表述为“项目从未成功 replay”：下文五个 ready 矩阵实际有 400 份 completed 样本。它们可作为固定四样本重复回放的补充历史材料，但没有同环境独立生成基线，也不直接测量同步策略收益。

建议正式成功口径：

1. 分别记录 `attempted`、各 resolver 真正启动、执行终态、oracle 可读、语义可比较、状态预期满足；
2. `completed/attempted` 是工程完成率；`semantic_valid/attempted` 是端到端有效率；另报 `semantic_valid/completed`，不隐藏失败；
3. 同步语义复现率需同一输入、相同初态的独立 replay 及规范化 outcome 一致性，不能用 key 可比或输出文件存在代替。

另一个现行口径风险：`S/tools/dns_diff/campaign.py:440-446` 的 `reproduced_count` 是样本目录与 high-value manifest 的集合交集，`repro_rate` 是这个交集除 manifest 大小，分母为零时返回 0。它既不证明 paired replay 完成，也不证明重复得到同一语义结果。RQ4 新报告的 `manifest_size=6,reproduced_count=0,repro_rate=0` 不应写成“0% 可复现”。

#### RQ3：真实长 producer 可保留；四变体长表不是生成消融

长 producer 根：

`R/bind9_full_long_suite/20260812_101738/producer/work/`

- `afl_out/master/fuzzer_stats:1`：`run_time=3599` 秒、`execs_done=4218131`、`corpus_count=95`，`command_line` 包含真实 `-s 1197649404`。
- `afl_out/secondary/fuzzer_stats:1`：`run_time=3600`、`execs_done=4154421`、`corpus_count=104`；不是第二次独立 run，而是同轮 secondary。
- 实际 master queue **95 文件、87 个唯一 SHA-256**；secondary queue **104 文件、94 个唯一 SHA-256**；初始 `stable_transcript_corpus` 为 4 文件/4 个唯一内容。不能把 corpus 文件数当独立样本数，更不能当缺陷数。
- `producer_execution_manifest.json:1`：`status=success,variant_name=full_stack,repeat_index=1,random_seed=1197649404`，记录 master/secondary/SymCC 的 PID 和 started。可支持“存在一次真实 producer”的历史证据，不足以证明所有进程完整有效工作或各变体独立。
- 同套件其他留存 master stats：`20260812_091239` 为 180 秒/193698 execs/90 corpus，`20260812_094835` 为 875 秒/1032840 execs/103 corpus。预算不同，不能冒充同预算重复。

长回放根 `R/real_rq3_multi_resolver_ablation/20260814_090339/`：

- 五个 secondary × 四变体 × **每格 1 run**；20 reports、1900 sample meta。1744 completed、156 failed；失败均出现在 MaraDNS 四组（每组 39）。
- 五个 `*/afl_out/master/queue` 都是 95 文件、87 唯一内容，按文件内容多重集逐一核对，均等于上述长 producer master queue。
- 每份 aggregate 均为 `run_count=1,variance_status=insufficient_runs,aggregates={}`。主 `resolver_variant_summary.tsv:1` 的 20 行仍把 `total_samples_mean` 和 `semantic_diff_count_mean` 写作 `0.000000`。
- 当前脚本 `run_real_rq3_multi_resolver_ablation.sh:87-118` 先复制 queue，再循环变体调用 `campaign-close`。`budget_sec=600` 是每格报告中的回放配置，不是变体生成时长，也不是测得耗时。

实际 full_stack 原始报告：

| secondary | total_samples | included / unknown | semantic_diff_count | report 相对该长回放根的路径 |
| --- | ---: | --- | ---: | --- |
| dnsmasq | 95 | 95 / 0 | 51 | `dnsmasq/full_stack/run-01/campaign_reports/20260814_090632/summary.json:1` |
| smartdns | 95 | 95 / 0 | 76 | `smartdns/full_stack/run-01/campaign_reports/20260814_091842/summary.json:1` |
| maradns | 95 | 56 / 39 | 52 | `maradns/full_stack/run-01/campaign_reports/20260814_093836/summary.json:1` |
| knot | 95 | 95 / 0 | 64 | `knot/full_stack/run-01/campaign_reports/20260814_100859/summary.json:1` |
| unbound | 95 | 95 / 0 | 95 | `unbound/full_stack/run-01/campaign_reports/20260814_101701/summary.json:1` |

字段为 `.metric_denominators.analysis_state`、`.semantic_counts`、`.semantic_diff_count`。MaraDNS 的 52/56 是条件比例，不能不披露 39 unknown 就与其他 /95 混比。上述均是历史分类候选，不是确认缺陷。

各 resolver 四变体总候选数相同，但 Knot 子类不完全相同，例如 full_stack 为 `oracle_and_cache_diff=8,oracle_diff=47`，afl_only 为 9/46，no_mutator 为 6/48。`S/docs/DNSPoisonPaperMaterialStatus.md:26-27` 的“完全一致”“信号真实”仍超出这些数据可直接支持的结论。

**gate 小实验也有真实日志，但只有单轮：**

- `S/named_experiment/work/afl_out/master/fuzzer_stats:3,16,21,28-29`：122 秒、118911 execs、corpus_found=28、stability=18.21%、bitmap_cvg=3.30%。
- `S/named_experiment/work_gate_off/afl_out/master/fuzzer_stats:3,16,21,28-29`：123 秒、118566 execs、corpus_found=22、stability=20.64%、bitmap_cvg=3.30%。
- `work/logs/helper_persistent.log:160` 对 `work_gate_off/logs/helper_persistent.log:158`：processed 64/62，high_value_processed 6/0，high_value_new_coverage 0/0，ok/fail 为 64/0 与 61/1。
- 可证明高价值调度被触发；不能由 28 对 22 推断显著收益。工作目录可被以后运行覆盖，复用前应在批准的新实验区冻结副本。

#### ready 矩阵：当前复算发现旧摘要与现行算法不一致

核验五个根：

- `R/audit_ready_matrix/20260813_124516/unbound`
- `R/audit_ready_matrix/20260814_153000/{dnsmasq,smartdns,maradns,knot-resolver}`

每根均为 4 变体 × 5 run × 4 样本：20 reports、80 sample meta，全部 `status=completed`，每报告 `total_samples=4,included=4`。五根合计 **100 replay runs、400 样本执行**。

- 每根 `publication_audits/20260817_final/publication_readiness.json:1` 留存 `status=ready,issue_count=0`；这是历史审计结果，非本轮重跑。
- 100 份旧 `producer_execution_manifest.json` 均缺少 `execution_mode`；75 份声明 SymCC started=true，25 份 false。100 个 seed ID、100 个旧 snapshot digest，并不等于100次独立生成。
- 排除 `*.meta.json` 后，100 份 snapshot 的相对路径/内容完全一致：**4 个文件、344 字节**，现行路径/大小/内容算法重算得到同一个 SHA-256：
  `9c242c48dff0bcafda2b36b90301688cb36447b212342c1a4b8d68b269d67012`。
- 按无文件名的内容 SHA-256 多重集再比较，也只有 1 组，防止仅凭路径下结论。
- 例：`R/audit_ready_matrix/20260813_124516/unbound/matrix_runs/afl_only/run-01/producer_execution_manifest.json:1` 记录 `file_count=5,size_bytes=496,sha256=b51bccb7cd7a6c34f7ccec89b2d31ebc7b60869b3b5100f7df03c10d3459aede`。**100/100 与现行排除 meta 的摘要不匹配。**
- 当前 `matrix.py:37` 与 `publication_audit.py:29` 仍用 `sha256-relative-path-size-content-v1` 名称；排除规则变化未在该名称区分。首批实现需明确旧摘要兼容/版本判定，不能重写旧 manifest 来伪造“原本就按新算法产生”。
- 每根 80 个导出 case JSON 中 4 个 `manual_truth.status=confirmed_relevant`、76 个 not_started，但仅 4 个不同 sample_id。去重后的历史签署可以作人工复核线索；400 个文件不是400个独立裁决。

**ready 的边界**：文件完整性/统计契约通过是可复现材料的必要条件，不是语义真值、独立运行、盲审质量或漏洞有效性的证明。本轮没有执行会写输出的 publication-audit；只读摘要复算已证明不能无条件沿用旧 ready 到当前契约。

#### RQ4：2 clusters 不能证明 fingerprint 降噪

- `R/rq4_fingerprint_run/20260813_123658/work/follow_diff/*` 有 8 个 completed sample meta，但 8 个 triage 均 `analysis_state=unknown,semantic_outcome=runtime_or_parse_failure`，notes 为 `bind9=ok,dnsmasq=missing`。完成状态和分析可用性必须分开。
- 新批 `R/rq4_fingerprint_run/20260814_083114/campaign_reports/20260814_083120/summary.json:1`：6 samples、6 included、6 semantic candidates、2 clusters；语义类别 3 个 cache_diff_interesting、3 个 oracle_and_cache_diff。
- 6 份 `state_fingerprint.json` 的 `bind9.forwarding_path`、`unbound.forwarding_path` 及双方 retry_seen **全部 null**；不是所有指纹字段都为空，Unbound msg_cache_seen 为 true、rrset_cache_seen 为 3 true/3 false。
- 6 个 triage 的 cluster_key 全部含 `fp:_->_`，两簇由其他状态/标签区分。因此两簇本身不是 forwarding fingerprint 有效区分的证据。当前相关逻辑见 `S/tools/dns_diff/triage.py:208-224,346-347,378-393`。
- 新批导出 5 个 case JSON，`.manual_truth.status` 全部 not_started。例：
  `R/rq4_fingerprint_run/20260814_083114/campaign_reports/20260814_083120/case_studies/id:000002,orig:id:000001,time:0,execs:0,orig:id_000001_generated_1__bdf78b4c__bdf78b4c.json:1`。
- 没有本批同一真值池上的无过滤/启发式/fingerprint 误报与召回对照；不能把不同时期 8、6 或40样本的 cluster 数相减作为降噪效果。

### 4. 六 resolver 的覆盖事实

`S/experiments/resolvers.lock.json:1` 的 `.resolvers[]` 锁定六项：BIND9 `v9.20.22`、Unbound `release-1.24.2`、MaraDNS/Deadwood `deadwood-3.3.02`、dnsmasq `v2.92`、SmartDNS `Release47.1`、Knot Resolver `v6.2.0`。

本轮确认六个相应 source 目录存在，并找到可执行文件：

| resolver | 当前存在的可执行文件，均相对 `S/` |
| --- | --- |
| BIND9 | `experiments/subjects/bind9/v9.20.22-afl/bin/named/.libs/named`；另有 symcc tree 的 `bin/named/named` |
| Unbound | `experiments/subjects/unbound/release-1.24.2-build/unbound-afl/.libs/unbound-fuzzme` |
| dnsmasq | `experiments/subjects/dnsmasq/v2.92-build/dnsmasq` |
| SmartDNS | `experiments/subjects/smartdns/Release47.1-build/smartdns-build/src/smartdns` |
| Deadwood | `experiments/subjects/maradns/deadwood-3.3.02-build/deadwood-build/deadwood-github/src/Deadwood` |
| Knot Resolver | `experiments/subjects/knot-resolver/v6.2.0-build/knot-runtime/sbin/kresd` |

Unbound 实际入口是 `unbound-fuzzme`，不能错误检查普通 `unbound` 文件；解析规则见 `S/dnslab_core/src/concrete_adapters.cpp:621-635`。文件存在不代表本轮通过构建/启动/版本校验；没有复核 HEAD、补丁或链接库。

| RQ | 所查数据的覆盖 | 缺口 |
| --- | --- | --- |
| RQ1 | BIND9 输入模型实验 | 不能外推为六个 resolver 的有效输入率 |
| RQ2 | 专门批次 BIND9–Unbound 全失败；其他五对矩阵有成功 replay | 缺同步策略与公平独立生成/测试对照，缺有真值的语义重复率 |
| RQ3 | BIND9 单 producer；五个 secondary 消费同队列 | 没有六个 producer，也没有按四变体重新生成 |
| RQ4 | 新六样本为 BIND9–Unbound；旧八样本有 dnsmasq oracle 缺失 | 缺固定真值池及跨角色降噪验证 |
| RQ5 | BIND9 对五个 secondary 的星形覆盖 | 不等于六者任意两两比较，不默认角色/缓存语义相同 |

`S/docs/RQ5ResolverAdapterCost.tsv:1-6` 的 low/medium/high 是 proxy，0/1/9 秒构建记录不能解释为首次集成工时或干净构建成本。正式 RQ5 记录改动位置、适配人时和失败原因，不用代理标签替代实测。

### 5. 首批实现验收与历史复用边界

| 最小修复批次 | 必须闭合的验收 | 已有受影响位置/回归入口（本轮未执行） |
| --- | --- | --- |
| 执行与来源契约 | replay 不宣称 producer started；预先指定的 seed 真正传入命令；初始语料和输出语料摘要分离；相同内容既不证明也不否定运行独立性 | `matrix.py`、`publication_audit.py`、`named_experiment/run_named_afl_symcc.sh`；`test/test_campaign_matrix.sh`、`test/test_named_seed_provenance.sh`、`test/test_publication_readiness_audit.sh` |
| 统计/状态口径 | preflight failure 不计成功；n=1 或缺指标主表标 NA；只有观测到零才写 0；区分 manifest 消费率与语义复现率 | `aggregate.py`、`campaign.py`、`statistics.py`、长回放 TSV 导出、C++ batch summary；`test/test_multi_run_aggregate.sh`、`test/test_dnslabctl_batch_sync_replay_command_paths.sh`、`test/test_rq3_snapshot.sh` |
| RQ1 provenance 和公平对照 | 输入本体/内容哈希、源种子关系、响应语料和构建身份可追溯；统一后置查询后再比较状态可达性 | `input_model_eval.py`；`test/test_input_model_eval_smoke.sh`、`test/test_real_rq1_input_model_snapshot.sh` |
| 语义/指纹小样本 | 阳性、阴性及故障有预期；null 不当 false；oracle 可用性独立于 completed；过滤掉的真阳性可测 | `triage.py` 与状态观测链；`test/test_dns_diff_triage.py`、`test/test_triage_contract.sh` |

统计补充：`aggregate.py:394-402` 已挡住单 run 聚合，但低层 `statistics.py:69-73` 对 n=1 返回零 sample_stddev/SE 和退化 CI；首批回归应确保任何论文导出调用方不会绕过 run_count 门槛。不能因为表有 CI 字段就认定独立重复成立。

历史数据可以怎样用：

- **直接保留**：原始 stderr、sample.bin、cache、fuzzer_stats、失败证据，供历史描述和回归；不修改原件。
- **经批准后派生**：从完整 sample.bin 冻结 4 个小样本或长队列的 87 个唯一输入，重新做当前 oracle 与规范化分析；同时保留重复映射，不能静默把95改成87。
- **须重新运行**：当前版本的 RQ2 语义重复、统一后置查询 RQ1、各配置独立 producer、固定真值池 RQ4。
- **不能复用为因果证据**：旧 shared-queue 的四变体增益、单轮 gate 的显著性、零填充长预算均值、未裁决候选当漏洞。
- 新派生结果保存 `source_artifact` 与原始哈希、分析器版本和新输出位置；不得把补录 provenance 伪装为执行时记录。

### 6. 与 paper-plan.md 的衔接及最小实验设计

主线与 `paper-plan.md:7-15,64-95` 一致，无需重做论文规划。两项直接影响实施的接口约束：

1. `paper-plan.md:51,60` 已提醒“无回流/无 gate”不必对应现有配置。当前 `S/tools/dns_diff/config/poison_stateful_longbudget_matrix.json:15-50` 固定的是 full_stack、afl_only、no_mutator、no_cache_delta；而且 **afl_only 仍开启 DST1 mutator、cache-delta 和 triage**。它是“去掉 SymCC”的对照，不是纯原生 AFL++。首批应冻结真实开关映射，不能直接把四变体矩阵换标题作为新实验；no-gate 必须同时控制 high-value 与 semantic-frontier 输入，空环境值可能触发默认路径。
2. `paper-plan.md:65` 正确允许独立运行输出相同内容；当前 audit 的 `publication_audit.py:620-627,703-713` 对非 replay 的重复快照报错。应以真实进程/命令/种子/预算证明运行身份，内容相同作诊断而非一票否决；同时不可反过来用不同哈希证明独立性。

**最小 pilot（提案，未授权执行）：**

- 沿用主计划 BIND9–Unbound、约 10–20 个有明确预期样本；建议具体冻结16例，包含等价表示、正常拒绝、非缓存、受控错误状态、缺失产物/超时。每例同初态至少3次 replay，分别验执行状态、规范化输出和后置查询；不将故障对照的失败算系统不达标。
- RQ1 用同源派生模型并共享后置观察；每模型的分母、不适用字段、转换身份必须可核对。
- 按主计划经核对后的配置数 `V`，每配置2个独立 producer、每个60秒；若最终是4配置，则 `4×2×60=480` producer-run 秒。先验进程/seed/输入/输出完整性及符号候选真实回流，不做显著性结论。
- pilot 通过后，用同一小语料做其余四 secondary 的能力/故障分层 smoke，补齐六 resolver 星形覆盖；不在首轮扩大成多小时矩阵。
- gate/符号链未闭合、故障被误计有效差异、NA 被导出为0、原件缺失或命令种子不一致时停止升级预算。

**正式实验最小设计：**

- RQ1：固定 source pool；各输入表示配对派生；统一后置观察；报告逐输入计数及按运行分层的不确定性。
- RQ2：同源 replay 与各 resolver 独立生成/测试基线，同角色配置、受控上游、同总资源约束；baseline 额外生成成本单列。有效率同时披露全部尝试/失败，比较人工验证成本而不只比告警量。
- RQ3：仅用真实独立 producer 为重复单位；共享初始 corpus，预注册 seed 清单、主指标、总资源和停止规则；输出冻结后以统一 coverage build 评估，再交五个 secondary replay。每配置至少5轮作为起点，重复数由 pilot 波动和目标精度确定，不能用5轮作为充分性证明。
- RQ4：同一候选池离线比较无过滤/启发式/fingerprint；标注者尽量不知道变体，正例、合法策略差异、harness错误和不确定分别标；抽查被过滤集，报告 precision/召回、漏检、不确定比例、簇纯度及人工时间。至少两个案例只是材料门槛，不代表 FPR 估计充分。
- RQ5：沿用五条 BIND9–secondary 边；按递归/转发/缓存能力分层汇总，不跨 resolver 相加覆盖数、不把不同初态当公平比较。新增反向 producer 或全15对比较不属于最小设计。
- 统计：报告每 run 原值、样本标准差、预先指定95%区间及效应量；同 run 多样本、同 queue 多 resolver、同24小时run的checkpoint均保留相关性；无发现时间按预算右删失；多重比较预先限定。

**预算公式（非运行授权）：**

- 定义 `V`=真实配置数，`N`=独立producer轮数，`T`=每轮producer秒数，`K=5`=secondary数，`Q_vn`=每轮冻结待回放输入数，`r`=每输入重复回放次数。
- 单 BIND9 producer 的运行时间总和：`B_gen = V·N·T`，**不乘 K**。固定每 run CPU 配额 `c_p` 时，分配 CPU 上界为 `c_p·B_gen`；实际 user/system CPU 与 solver/helper 子进程另实测。
- paired replay 工作量：`A_replay = Σ_v,n Q_vn·K·r`。若每次两侧均有前后阶段，保守 resolver 调用上界 `E_replay ≤ 4·A_replay`；实际阶段数按实现记录。若每阶段超时 `τ`、清理/启动余量 `h`，预算上界 `B_replay ≤ E_replay·(τ+h)+B_report`，不能把 `--budget-sec` 当已测耗时。
- RQ2 独立生成基线另加 `B_ind = Σ_target N_target·T_target`；人工预算 `B_review = L·t_label + D·t_adjudicate`，其中 L 为标注案例数、D 为分歧数。
- 同主计划：4配置×5轮×1小时=20 producer-run小时；独立1/6/24小时档为620小时；嵌套24小时checkpoint为480小时，但检查点不独立。总墙钟由并发/隔离、CPU配额及最慢链路决定，不直接等于这些和。
- pilot 的回放数和超时先由16例测出，再审批完整预算；不要以默认900秒、4变体×5轮等脚本默认值代替用户批准。

### 7. 已验证命令与后续命令边界

本轮先检查 argparse 在 handler 前处理帮助（`S/tools/dns_diff/cli.py:756-760`）及 suite 的 help 分支（`S/scripts/run_bind9_full_long_suite.sh:604-626`），再执行以下命令，均退出0：

```bash
cd /home/egoist/work/symcc
python3 -B -m tools.dns_diff.cli input-model-eval --help
python3 -B -m tools.dns_diff.cli campaign-matrix --help
python3 -B -m tools.dns_diff.cli publication-audit --help
bash scripts/run_bind9_full_long_suite.sh --help
```

- `campaign-matrix` 已核对参数为 `--matrix-file --budget-sec --repeat --work-root`；**此入口是回放矩阵，不作为独立生成命令**。
- C++ `batch-sync-replay` 的 `--sample-dir --run-root --bind9-build-root --secondary-resolver --secondary-build-root --secondary-source-root --limit` 已由 `main.cpp:2592-2598` 核对源码，但本轮未启动 binary/replay。
- `publication-audit --matrix-root ... --minimum-runs 5 --minimum-case-studies 2 --output-dir ...` 参数已确认；它会写文件，本轮未运行。正式执行必须指定新的批准输出区，不能默认写回历史矩阵。
- `run_real_rq3_multi_resolver_ablation.sh` 没有本轮确认的安全 `--help` 入口，脚本顶层 `:15-16` 即创建结果目录，末尾还调用清理；**没有把 `bash ... --help` 当无副作用探针运行**。
- 所有计数、SHA-256、日志末行及 JSON 键比较均由内存中的只读 Python 脚本完成，未向结果树写索引、缓存或重算结果。

### 8. 外部参考与版本边界

本题是一手本地源码/产物核验，没有重新检索外部论文或官方版本说明。版本仅取自 `S/experiments/resolvers.lock.json`，其中保存上游 `repo_url` 与 `commit_sha`；不据此宣称当前 build tree 与锁定源树/依赖完全一致。外部对照工具与新颖性由本任务其他研究材料负责。

## Caveats / Not Found

- 本轮未运行 campaign、producer、build、测试套件、完整 publication-audit 或公共网络 DNS 实验；未验证当前二进制实际启动、六个源码 HEAD、补丁一致性与共享库。
- 所查范围未发现按当前主计划四配置、同预算、每配置多轮独立 producer 的成套结果；这不是对所有其他目录作穷尽“不存在”断言。
- 当前源码与历史数据不是同一证据版本：旧零表、旧 manifest 和旧 ready 必须保留历史身份。摘要规则改变仍沿用同一算法名，是首批兼容性风险。
- 结果目录和工作语料被 `S/.gitignore:29-38` 忽略；本机存在不等于干净 checkout 可复现。正式发布需另行打包/固定哈希/说明来源。
- 为便于其他工作者检测并发修改，本轮读取时源码 SHA-256：`matrix.py=8630322a8d994ec5bcb4001e3796c2fd98bb3623b5016e0c0059bc841245d313`；`publication_audit.py=dd6296321a3f013254956b267d46b4a47c230e53a1a46e69f59885f2d3bd6d43`；`input_model_eval.py=c13ba044f108f20cc37540656d0008d63b10d8884afab64605ffbff13891b3d7`；`run_real_rq3_multi_resolver_ablation.sh=8a8737d9ddb111ea67c067840d7cc5851dd290eccbb5e406f0b457fc652037c3`。
