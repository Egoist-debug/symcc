# DNS Poison 证据契约（单一权威）

本文档冻结 publication-facing 的证据语义，`tools/dns_diff/schema.py` 是实现 owner，本文件是对外契约说明。

## 1. 版本关系（兼容冻结）

- `schema_version`：已有结构版本字段，继续保留，不重命名。
- `contract_version`：新增语义契约版本字段，默认与 `schema_version` 对齐（当前为 `1`）。
- 兼容规则：旧 artifact 缺少 `contract_version` 时，按 `schema_version` 回填；若两者都不可用，则回落到当前契约版本。

## 2. publication-facing 状态模型（冻结）

`analysis_state` 仅允许三种枚举值：

- `included`
- `excluded`
- `unknown`

兼容规则：旧 artifact 缺失或非法值时，默认回落为 `unknown`，禁止静默计入 `included`。

`exclude_reason` 语义：

- 类型为 `string | null`
- 仅在 `analysis_state=excluded` 时应提供可读原因
- 兼容缺省值为 `null`

## 3. 比较键冻结

### 3.1 `aggregation_key` 字段组成与固定值语义（冻结）

`aggregation_key` 必须包含以下字段：

1. `resolver_pair`
2. `producer_profile`
3. `input_model`
4. `source_queue_dir`
5. `budget_sec`
6. `seed_timeout_sec`
7. `variant_name`
8. `ablation_status`
9. `contract_version`

固定值语义（不是可选建议）：

- `producer_profile` 必须冻结为 `poison-stateful`
- `input_model` 必须冻结为 `DST1 transcript`

### 3.2 `baseline_compare_key` 字段组成与固定值语义（冻结）

`baseline_compare_key` 必须包含以下字段：

1. `resolver_pair`
2. `producer_profile`
3. `input_model`
4. `source_queue_dir`
5. `budget_sec`
6. `seed_timeout_sec`
7. `repeat_count`
8. `contract_version`

`baseline_compare_key` 中同样必须冻结以下值：

- `producer_profile = poison-stateful`
- `input_model = DST1 transcript`

### 3.3 两类 key 的差异（冻结）

- `baseline_compare_key` **不包含** `variant_name`
- `baseline_compare_key` **不包含** `ablation_status`
- 这两个字段只属于 `aggregation_key`

### 3.4 baseline 作用域分层（冻结说明）

- publication-facing 的正式 baseline 固定为 `afl_only`
- publication-facing 的 acceptance variant 固定为 `full_stack`
- `tools/dns_diff/matrix.py` 生成的 `_summary/matrix_manifest.json` 与 `_summary/delta_vs_baseline.tsv` 若出现 `full_stack`，只表示 **matrix internal baseline**，不直接等于 publication-facing baseline
- publication-facing 判定必须回到正式 contract / verdict 口径，不能只根据 matrix `_summary` 产物单独下结论

## 4. `seed_provenance` 证据语义（冻结）

`seed_provenance` 是独立于 comparability key 的旁路证据对象，用来说明 producer 是 cold-start、复用已有 stable corpus，还是从 source corpus 重新筛出 stable corpus。它**不能**被塞进 `aggregation_key` 或 `baseline_compare_key`。

### 4.1 字段组成（冻结）

`seed_provenance` 若存在，必须包含以下字段：

1. `cold_start`
2. `seed_source_dir`
3. `seed_materialization_method`
4. `seed_snapshot_id`
5. `regen_seeds`
6. `refilter_queries`
7. `stable_input_dir`
8. `recorded_at`

### 4.2 字段语义（冻结）

- `cold_start`：仅当当前 active source corpus 在本轮真实重新生成，且不是直接复用既有 stable corpus 时，才允许标为 `true`
- `seed_materialization_method`：用于区分 `reused_filtered_corpus`、`filtered_from_source_corpus` 等 producer 行为；publication 文稿不得把不同 materialization method 混写成同一实验语义
- `seed_snapshot_id`：指向本轮 stable input 目录内容的稳定标识；它是审计锚点，不是 comparability 维度
- `seed_source_dir` / `stable_input_dir`：用于说明 seed 来源目录与最终投喂给 AFL 的 stable corpus 目录，可相同也可不同
- `regen_seeds` / `refilter_queries`：用于说明本轮 producer 是否显式要求重新生成 query/response/transcript 语料或重新筛 stable corpus
- `recorded_at`：producer 记录 provenance sidecar 的 UTC 时间戳

### 4.3 落盘位置（冻结说明）

- producer sidecar：`WORK_DIR/producer_seed_provenance.json`
- bounded follow-diff：`sample.meta.json`、`follow_diff.window.summary.json`
- close-loop：`WORK_DIR/campaign_close.summary.json`
- publication evidence：`WORK_DIR/campaign_reports/<timestamp>/summary.json` 与 `evidence_bundle.json`

## 5. 失败证据语义（冻结）

`sample.meta.json.failure` 是 **JSON 路径**（嵌套对象），不是独立文件名。

- 文件：`sample.meta.json`
- 路径：`.failure`
- 典型配套证据：`*.stderr`、`triage.json`

## 6. 增量兼容规则（冻结）

旧 artifact 缺少新增字段时必须可加载，按以下默认值回填：

- `analysis_state = "unknown"`
- `exclude_reason = null`
- `contract_version` 按版本关系规则回填
- `aggregation_key` / `baseline_compare_key`：按冻结字段集合补齐，未知值保持 `null`，并写入同一 `contract_version`
- `seed_provenance`：旧 artifact 缺失时允许缺省，不得伪造默认 cold-start 结论

兼容默认值只能由 schema owner（`tools/dns_diff/schema.py`）统一装配，避免并行真相源。

## 7. 多轮统计契约

`campaign-aggregate` 与 `campaign-matrix` 对每个数值指标同时保留以下字段：

- `mean`、`min`、`max`
- `stddev`：为兼容既有结果，继续表示总体标准差
- `sample_stddev`：按 `n-1` 计算的样本标准差
- `standard_error`：`sample_stddev / sqrt(n)`
- `ci95_lower`、`ci95_upper`：基于双侧 Student-t 临界值的 95% 均值置信区间

论文正文引用离散度时必须优先使用 `sample_stddev`，引用均值不确定性时必须同时给出 95% 置信区间。`stddev` 只用于兼容旧表，不得与样本标准差混写。

`matrix_manifest.json.statistics` 同时冻结计算口径：`confidence_level=0.95`、`confidence_interval_method=student_t_df_le_30_normal_asymptotic`、`sample_stddev_denominator=n-1`。自由度不超过 30 时使用双侧 Student-t 临界值表，超过 30 时使用正态渐近值 `1.96`。缺少或改变这些字段的矩阵不得与当前正式结果合并。

## 8. 证据完整性与论文就绪审计

`publication_evidence_bundle` 中每个必需产物引用必须包含：

- 绝对路径
- `size_bytes`
- SHA-256 摘要
- 再生成命令

`matrix_manifest.json` 还必须记录每个 run 的 `evidence_bundle_path`、
`evidence_bundle_integrity.size_bytes` 与 `evidence_bundle_integrity.sha256`。
这使矩阵清单可以发现 evidence bundle 本身在聚合完成后的漂移，而 bundle 内部的
SHA-256 则继续保护各个报告产物。

正式矩阵完成后运行：

```bash
python3 -m tools.dns_diff.cli publication-audit \
  --matrix-root MATRIX_ROOT \
  --minimum-runs 5 \
  --minimum-case-studies 2
```

审计结果落盘为 `publication_readiness.json` 与 `publication_readiness_issues.tsv`。只有 `status=ready` 的矩阵才允许进入论文主表。审计至少检查：

1. 四个消融变体完整且每个变体达到最低独立重复次数；
2. 每个指标具备总体标准差、样本标准差、标准误与 95% 置信区间，并可由各 run
   的 `summary.json` 重算得到；
3. 每个 run 的目录关系、`campaign_close.summary.json` 成功状态与
   `comparability.status=comparable`；
4. evidence bundle 契约版本、seed provenance、重建命令、claims 与原始样本
   目录完整，claim 值与其 `summary.json` 字段一致；
5. 必需产物文件以及 evidence bundle 自身存在，大小与 SHA-256 未发生漂移；
6. 原始样本目录至少保留一份同时含 `sample.meta.json` 和 `sample.bin` 的样本；
7. 去重后的 case study 数量达到设定门槛，且每条索引都指向真实导出产物。

审计失败仍会写出完整问题清单并返回非零状态，便于 CI 和批量实验驱动脚本直接阻止未就绪结果进入正式材料。

## 9. 跨 resolver 缓存比较（`cache_comparison_version=1`）

缓存比较的实现 owner 是 `tools/dns_diff/cache_diff.py` 与
`dnslab_core/src/cache_analysis.cpp`；两端使用
`test/fixtures/cache_semantics/cases.tsv` 的共同输入验收。
本节版本独立于外层 `schema_version`，不重命名既有字段。

### 比较对象与输出

- 原始观察、TTL 和单端 before/after delta 继续保留。
- 跨端比较先投影成类型感知的共同 RR 集合，再比较增删的语义 delta。
  resolver 身份、dump 结构、计时/命中元数据、TTL 漂移不是该结构比较的依据。
- 两端 before 的共同投影必须等价；初态不同则不可比较，即使终态相同也不能把不同 delta 当作缺陷。共同投影不证明 resolver 内部完整状态等价。
- 域名型 RDATA 按 DNS 名称归一化；IP 地址按值比较；TXT 大小写、字节和字符串边界不得按域名规则折叠。
- 当前共同正 RR 支持 A、AAAA、NS、CNAME、DNAME、PTR、TXT。MSG 只有名称、类型、class、QD、TC 等条件与共同 RRset 相符时才可作为冗余观察折叠；不完整或不匹配的 MSG 保守不可比较。特殊标签保留边界，但不支持的共同名称投影不得强行等价。
- `cache_delta_triggered` 只控制明细，不决定是否存在语义差异。

| 字段 | 语义 |
| --- | --- |
| `cache_comparison_version` | 当前为 `1` |
| `cache_comparison_status` | `comparable`：可比较；`incomparable`：状态不在共同投影范围或共同初态不同；`unknown`：快照缺失或证据不足 |
| `cache_comparison_reason` | 保留不能比较的原因；`initial_state_mismatch` 表示共同初态不同，`missing_snapshot` 表示必要快照缺失 |
| `diff_detected` | 只有共同投影得到的跨端差异才可支持肯定判断；不能单独把 `false` 当作无差异证据 |
| `resolver_diffs` | 具体跨端比较结果；单端 `has_cache_diff` 不能替代它 |

例如，两端从空缓存插入相同 RR，虽然各自都有 delta，
仍应得到 `cache_comparison_status=comparable`、`diff_detected=false`，
不得升级为缓存语义缺陷候选。

### 不完整证据与兼容

- 旧 artifact 缺少新比较版本/状态时仍可读取，但不能自动认定 `no_diff`。
- triage、审计组合指标与两种后端均须遵守相同的可比较门槛；`oracle_diff_plus_cache_diff` 不能回退使用单端 `has_cache_diff`，也不能凭 legacy 的 `diff_detected` 补足新版证据。
- 缺失快照、不支持的 RR/负缓存状态及不能观察 RDATA 的后端，不得伪造成空缓存。
- 无其他独立 oracle 差异证据时，不完整比较输出
  `cache_comparison_incomplete`，`analysis_state=unknown`，不进入有效阴性或语义缺陷计数。
- 当前沿用 `input_parse_failure` 分类桶并保留
  `failure_bucket_detail=cache_comparison_incomplete`；它描述比较证据不完整，
  不意味着目标收到的 DNS 输入一定畸形。
- `maradns`、`knot-resolver` 当前 cache 观测缺少共同 RDATA 证据，不能用其缓存投影声称与 BIND9 等价；
  独立可用的 oracle 观察不因此被抹除。

语义规则改变后，旧 ready 报告和旧候选不能直接沿用为新结论。
结构/哈希审计通过也不证明真实独立 producer、人工真值或安全漏洞成立。

## 10. Unbound 响应注入的字节合同

`patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c` 的生产 builder
对内存响应和文件 fallback 使用同一规则：

- 成功输出长度等于输入响应长度，仅将 `[0, 2)` 两个事务 ID 字节替换为实时 query 的 ID。
- 不替换 Question，不修复 AN/NS/AR 计数，不截断 RR 或尾部字节，不重写 flags。
  即使响应畸形，也不能先把它改好再交给目标。
- 输入缺失、读取失败、响应不足 12 字节、超过输出容量或 IPv4 UDP 载荷上限
  `65507` 字节时返回失败；线程记录 `parse_errors`，不构造替代的空回复。
- 原始输入不变；不同 Question 或其中的压缩指针也原样保留，是否接受由目标决定。

该合同修复 Unbound 单端静默改写，**不等于六端原始 wire 已完全等价**。
BIND 当前仍存在 Question/部分 flags 的请求绑定行为；共同可比子集需要满足这些
绑定不改变原响应语义的条件。Unbound 的 `ub_resolve` 入口也不能用于宣称
原始 client-wire opcode、flags、EDNS 行为的公平比较。

回归入口：`bash test/test_unbound_mutator_fidelity.sh`。
用例必须在读取 Unbound `config.h` 后重新启用断言；仅输出 PASS 而断言被
`NDEBUG` 禁用不算验证。runner 使用独立临时目录并优先加载受版本管理的 patch header。

## 11. 响应接纳与发送事实

四个 Python replay harness 复用 `tools/dns_replay_support.py`；BIND 的
cache/fuzz patch 与 Unbound patch 使用各自实际注入和客户端完成路径。

- `resolver_fetch_started` 表示观察到匹配 QNAME/QTYPE/QCLASS 的上游请求。
- 可选 `fake_reply_dispatched` 表示匹配请求的成功注入：Python/Unbound 要求完整发送，
  MaraDNS TCP 要求 `sendall` 成功；BIND 表示 hook 成功返回非空响应并交由既有 dispatch
  同步投递，不是 socket 发送计数。
- `response_accepted` 同时要求匹配 fetch、成功注入和合格的客户端完成结果。
  错误 ID/Question、截断、TC、非 QUERY opcode、SERVFAIL/REFUSED/NOTIMP、
  未 fetch 或发送失败都不能算接纳。
- 正 A、NXDOMAIN、NOERROR/NODATA 均可接纳；负答案本身不代表投毒。
  已支持 RDATA 检查不等于完整实现所有 RR 的语义验证，且不得反向改写注入字节。
- Unbound `ub_resolve` 的完成报文按当前 `libworker_fg` 的映射 ID `0` 校验；
  它不是原始客户端 wire 接口。升级锁定的 Unbound 版本时须重新核验此映射。

只有显式 post-check 确实执行、首次已接纳、后续回答匹配且完整，并且期间没有新增
上游请求，`second_query_hit` / `cache_entry_created` 才为 `1`。这两个字段仍是
**proxy**，不证明真实 cache entry、新增缓存状态或投毒因果。没有 post-check 时的
`0` 只表示缺少命中证据，不能解释为“实际执行过且结果为阴性”。

`fake_reply_dispatched` 不加入原六个 `ORACLE_FIELDS` 的语义差异比较。
Python/C++ 都保留旧日志的可读性：缺失或非法发送字段输出 `null`，
不从 `response_accepted` 反推，也不单独改变 `stderr_parse_status`。
历史 artifact 没有自动获得新接纳口径的可信等级。

回归必须检查最终 oracle：
`test/test_replay_harness_negative_control.py`、
`test/test_native_replay_oracle.sh` 和 C++ `test_oracle.cpp`。
native 测试直接编译当前 patch、使用锁定 headers/parser 库和事件替身；
通过这些测试不等于真实 resolver 网络时序或缓存因果已验证。
