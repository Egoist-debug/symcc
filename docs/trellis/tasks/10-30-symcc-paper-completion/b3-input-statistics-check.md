# B3：输入身份与统计缺失值

## 结论与冻结边界

**本报告所列授权实现及离线回归已完成，文件冻结。** 基线为
`c696add30c49c909e0d1d361618b71e3b1e0e754`。没有提交、推送、启动真实
resolver、producer、solver 或 xmake，没有修改历史实验结果。

**有一项跨 owner 收尾尚未解决**：publication audit 对数字字符串的校验与
聚合的 JSON 数值合同不一致，实测会抛出未捕获的 `StatisticsError`，详见末节。
已报告主会话，没有越权修改该文件。因此本报告不宣称第二批整体通过。

本次只完成输入身份与统计出口，不替代 B3 的真实符号回流验证。

## 修改文件

路径相对 `/home/egoist/work/symcc`：

- `tools/dns_diff/input_model_eval.py`：执行前快照、逐文件身份、DST1 投影关联、
  显式观测分母及失败退出。
- `tools/dns_diff/aggregate.py`：所有指标的缺失/非法值保留未知、拒绝无证据
  聚合，输出缺失字段清单和 `NA`。
- `tools/dns_diff/statistics.py`：单观测的 sample stddev、SE、CI 为 `None`。
- `tools/dns_diff/rq3_snapshot.py`：新报告归一旧单 run 表及缺失单元格；
  不改写输入 TSV。
- `tools/dns_diff/matrix.py`：主会话在 B2 冻结后追加授权；只改统计类型、
  `_aggregate_variant` 缺失门槛、`_write_variant_summary_tsv` 和
  `_write_delta_vs_baseline_tsv` 的缺字段/`None` 消费。**没有修改 provenance
  实现或独立生成门槛。**
- `tools/dns_replay_support.py` 与
  `tools/{dnsmasq,smartdns,maradns,knot_resolver}_replay_harness.py`：
  四份 `parse_transcript` 原样移动为共享函数，各 harness 仍导出同名函数；
  没有改解析、发送、oracle 或重放行为。
- 新增 `test/test_input_model_eval.py`、`test/test_dns_diff_statistics.py`、
  `test/test_rq3_snapshot.py`，共 16 项小测试。
- `test/test_input_model_eval_smoke.sh`、`test/test_multi_run_aggregate.sh`、
  `test/test_rq3_snapshot.sh`：追加完整 CLI 的最终 JSON/TSV 断言。
- 另新增本报告；没有修改 docs、任务主文档、named、schema 或
  publication audit。并行会话在上述范围外的改动未回退。

## 执行身份合同

1. `_run_single_sample` 创建新的样本目录，先读取并写入 `input.bin` 与
   `responses/`，再启动 subprocess；文件设为只读。主输出目录和样本目录已
   存在时直接拒绝，**包括预先创建的空输出目录**，不会复用旧结果。
2. `sample.meta.json` 保留旧 `sample_path`，增加 `source_path`、
   `snapshot_path`、`response_source_dir`、`response_snapshot_dir`、
   `response_snapshots`。`sha256`/`byte_length` 对应实际交给命令的快照，
   不再执行后重读原输入计算。
3. legacy 响应沿现有 BIND tail loader 的规则选择：顶层、非隐藏、普通文件，
   按文件名字节排序。冻结后命令使用快照目录；清除继承的 direct tail、
   symbolic suffix、preserve 覆盖变量，避免绕过冻结字节。来源目录的后续
   修改不会改变本次命令所用文件。
4. 运行前先写 prepared metadata；完成后保留 command、原始 returncode、
   oracle、stderr、stdout 和执行状态。输入快照不是注入成功、完整 on-wire
   响应或缓存因果的证明；legacy adapter 的既有报文变换未修改。

复用前已检查 `artifact_digest.file_integrity`：它独立 stat/hash 文件，不能
替代“同一批读到的字节写入快照并记录长度/摘要”的边界，故这里直接对读取到的
字节使用标准库 `hashlib`，没有再造摘要框架。

## 投影关联与观测分母

- `transcript` 记录现有 DST1 parser 抽取的 query、按序 responses、post-check
  的 SHA-256/长度，能够从保留的 DST1 快照重新核对。
- `input_relation` 对 query-only 要求 query 字节投影唯一匹配；对 legacy
  还要求按序响应字节一致。唯一匹配为 `verified/exact_byte_projection`，
  无匹配或多个匹配为 `unverified`，不会按样本序号或文件名造配对。
- `random_packet` 固定记录 `negative_control`，没有 DST1 配对；
  所有模型均明确 `semantic_equivalence_claimed=false`。字节投影可验证，
  不表示四模型语义、post-check 或 on-wire 行为等价。
- 各 rate 分母改为对应字段实际可解析的布尔观测数，并导出
  `*_observed_count` / `*_missing_count`。真/假均保留；没有观测时 JSON 为
  `null`、TSV 为 `NA`，不是 0。
- post-check 能力需要快照可被 DST1 parser 解析、有非空 post-check，且该次
  oracle 实际 `parse_ok=true`；不从模型名推断。second-query 分母仅含有能力
  且有该字段观测的样本。
- 任何非零子进程退出、oracle timeout 或必要 oracle 字段缺失，最终
  `input-model-eval` 返回 4；仍生成可诊断结果。合法 false、NXDOMAIN 等负
  答案的原始 oracle 不被删除，也不因为整个执行失败而改写成未知。
- 这不是完整观测样本的选择性成功率：报告同时保留 sample 总数、缺失数、
  `failed_execution_count` 与 `missing_observation_count`。

## 统计及消费者合同

- `_extract_metrics` 延续既有内部 `math.nan` 未知哨兵；不把 `None`、缺键、
  bool、负数、非整数计数、非法字符串或非有限数转换为 0。`repro_rate` 必须
  是有限 JSON 数值且在 `[0,1]`；合法零与完整合法数据不变。
- campaign aggregate 先输出 `run_matrix.tsv` / comparability，再拒绝缺失
  聚合，`aggregates={}`，summary 带 `missing_metrics` 字段清单。原 canonical
  缺失仍保留 `missing_canonical_metrics` 状态，其他指标缺失为
  `missing_metrics`。输入 summary 不修改。
- matrix 对缺失指标给出 `missing_metrics`，不计算部分指标来冒充完整聚合；
  最终 summary/delta 的空字典、缺字段或 `None` 都不再补零或调用
  `float(None)`，而是输出 `NA`。
- `compute_metric_statistics([x])` 保留 count/mean/min/max/population stddev；
  sample stddev、SE、CI 上下界为 `None`。完整多 run 的原公式、Student-t
  口径、population `stddev` 语义保持不变。
- 修改前已检索所有共享统计消费者：aggregate、matrix、publication audit
  及其测试。aggregate/matrix 的公开单 run 出口本来已有 `insufficient_runs`
  保护，**没有把内部虚假 CI 夸大为已证实的公开 CLI 单 run 统计漏洞**。
  audit 的重算已有 `len(run_metrics) < 2` 保护。
- RQ3 对 run 数不足、variance 非 ok、缺失/非法统计单元格输出 `NA`。
  旧单 run 表的均值也可能是空 `aggregates` 的补零，故不保留它来冒充观测。
  缺失 run 数/状态变为 `NA`/`unknown`；已知单 run 状态纠正为
  `insufficient_runs`。正常多 run 数值原样保留，不对旧源 TSV 回写。

## 真实 red / green 记录

工作目录 `/home/egoist/work/symcc`，Python 设置：

```bash
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$PWD/test:$PWD"
```

| 阶段 | 命令 / 检查 | 真实结果 |
| --- | --- | --- |
| 红 | `python3 -B -m unittest test_input_model_eval test_dns_diff_statistics test_rq3_snapshot -v` | exit 1；初始 12 tests，12 failures / 4 errors（含子案例）；源文件被直接执行、缺失当零/能力、CLI 假成功、单 run 虚假统计、旧 TSV 补零均复现 |
| 红 | `python3 -B -m unittest test_dns_diff_statistics.StatisticsMissingValueTest.test_matrix_missing_metrics_and_nullable_statistics_export -v` | exit 1；新共享缺失值到 matrix 后抛 `CampaignMatrixError`，未形成缺失状态报告，随后联动修复 |
| 绿，最终 | 下列 6 模块 unittest 命令 | exit 0；36 tests / OK，含本批 16、A3 harness 6、B2 provenance 9、既有 track4 5 |
| 绿，最终 | `bash test/test_input_model_eval_smoke.sh` | exit 0；正常字节身份/关联、缺 oracle 返回 4、最终 JSON null/TSV NA、原始失败 stderr |
| 绿，最终 | `bash test/test_multi_run_aggregate.sh` | exit 0；合法双 run、单 run、不可比、canonical 缺失、其他缺失/非法计数；缺失 CLI 实际返回 2 |
| 绿，最终 | `bash test/test_rq3_snapshot.sh` | exit 0；正常表缺失统计 NA、旧单 run 零 CI/均值归一、JSON/TSV 一致、旧 TSV `cmp` 不变 |
| 绿，最终 | `bash test/test_campaign_matrix.sh` | exit 0；B2 已冻结的真实 CLI 替身回归未放宽 |
| 绿，最终 | `bash test/test_publication_readiness_audit.sh` | exit 0；合法生产来源/重放拒绝等既有门槛保持 |
| 绿，最终 | `bash test/test_resolver_matrix_aggregate.sh` | exit 0；中间导出消费链回归 |
| 静态 | 13 个本批 Python 文件 `compile(bytes, path, "exec")` | exit 0，不写 `.pyc` |
| 静态 | 本批 3 个 shell `bash -n`、16 个代码/测试文件 LF 与末尾换行断言 | exit 0 |
| 等价移动 | 四份基线 parser AST 对共享 parser；四 harness 去掉该函数/新增 import 后整体 AST 对照 | exit 0；其他行为完全相同 |
| 静态，最终 | `git diff --check` | exit 0 |

最终 unittest：

```bash
python3 -B -m unittest \
  test_input_model_eval test_dns_diff_statistics test_rq3_snapshot \
  test_replay_harness_negative_control \
  test_publication_producer_provenance test_track4_metrics_and_provenance -v
```

日志：

- `/tmp/b3-red-unit.log`、`/tmp/b3-red-matrix.log`；
- `/tmp/b3-final-unit.log`；
- `/tmp/b3-final-{input_model_eval_smoke,multi_run_aggregate,rq3_snapshot,campaign_matrix,publication_readiness_audit,resolver_matrix_aggregate}.log`；
- `/tmp/b3-final-code-sha256.txt` 为本批 16 个代码/测试文件的冻结校验清单。

## 未完成的跨 owner 收尾与边界

**确认的 audit 数字字符串问题，不是推测：**

1. 用完整合法 summary，仅把 `repro_rate` 改为 `"0.5"`。
2. 直接调用生产 `_audit_run_metrics(...)`，实际 `issues=[]`，
   返回的 `repro_rate=nan`。其 `_coerce_finite_float` 宽松接收字符串，而
   `_extract_metrics` 要求 JSON 数值。
3. 把两个返回值传入生产 `_audit_statistics_against_runs(...)`，实测抛出
   `StatisticsError("统计指标必须全部为有限数值")`。

建议主会话只在 `_audit_run_metrics` 已有校验入口拒绝非 `int/float`，
保留 bool 拒绝与其他指标范围校验，并补数字字符串反例，复跑 audit 回归。
不要因此允许无证据字符串参与聚合，也不要改独立生成门槛。本次无该文件写权，
没有把真实异常隐藏为 PASS。

未执行 `test_real_rq1_input_model_snapshot.sh`（默认会运行真 resolver），也未
修改它；历史脚本 PASS 不作为本批证据。本批没有全仓 linter、独立类型检查、
真实网络/缓存因果、native C/C++ 编译、solver 或 producer 实验结果。
所有动态测试仅用替身及临时目录；新的严格 RQ1 输出目录/退出码合同需要调用方
为每次运行选择新目录，并区分“生成了诊断产物”和“观测完整”。
