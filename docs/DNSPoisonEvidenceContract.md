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
