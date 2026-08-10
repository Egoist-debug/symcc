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
