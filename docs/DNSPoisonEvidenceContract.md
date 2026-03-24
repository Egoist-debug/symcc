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

## 4. 失败证据语义（冻结）

`sample.meta.json.failure` 是 **JSON 路径**（嵌套对象），不是独立文件名。

- 文件：`sample.meta.json`
- 路径：`.failure`
- 典型配套证据：`*.stderr`、`triage.json`

## 5. 增量兼容规则（冻结）

旧 artifact 缺少新增字段时必须可加载，按以下默认值回填：

- `analysis_state = "unknown"`
- `exclude_reason = null`
- `contract_version` 按版本关系规则回填
- `aggregation_key` / `baseline_compare_key`：按冻结字段集合补齐，未知值保持 `null`，并写入同一 `contract_version`

兼容默认值只能由 schema owner（`tools/dns_diff/schema.py`）统一装配，避免并行真相源。
