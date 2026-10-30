# B2：矩阵与 producer 来源审计

## 结论

**B2 范围内实现和离线回归通过，现冻结。** 基线为
`c696add30c49c909e0d1d361618b71e3b1e0e754`，未提交、未推送。
这不是实际 producer、符号回流或 resolver 实验通过的结论。

## 修改文件

路径相对 `/home/egoist/work/symcc`：

- `tools/dns_diff/schema.py`：定义共享
  `QUEUE_SNAPSHOT_DIGEST_ALGORITHM = "sha256-relative-path-size-content-v2"`。
- `tools/dns_diff/matrix.py`：使用 v2；删除 `is_replay` 可选参数和伪生成分支；
  仅记录 `shared_queue_replay`、`symcc.started=false`，不再从 replay ID 编造
  `random_seed`，该值为 `null`。按主会话追加要求，缺失指标格式化为 `NA`，
  单 run 的 `variant_summary.tsv` 不可用统计单元格也复用该格式化规则。
- `tools/dns_diff/publication_audit.py`：只允许显式
  `independent_producer_generation` 进入生成证据资格；补时间区间、manifest
  `run_dir`、组件启动事实及 pid/命令非空检查；移除 snapshot ID/内容必须不同的
  判据，保留 run ID/seed 重复拒绝。v1/未知算法可加载但报告
  `invalid_queue_snapshot_algorithm`，不按 v2 重新解释旧摘要，不修改输入文件。
- `test/test_campaign_matrix.sh`：不再仅以文件数常量断言；实际核对 payload
  数量/大小，证明 metadata 不影响两个摘要实现而 payload 改变会影响摘要；
  校验 replay 身份和无伪造 seed，以及不可比较/单 run TSV 的 `NA`。
- `test/test_publication_readiness_audit.sh`：使用实际矩阵摘要实现替代测试内重复
  摘要函数；补实际字段形状的离线 producer fixture；通过完整 CLI 验证相同
  payload/snapshot ID 的独立来源不误拒，随后将模式改成 replay 必须拒绝。
- `test/test_track4_metrics_and_provenance.py`：同步两处已移除的参数调用。
- `test/test_publication_producer_provenance.py`：新增 9 个小回归，覆盖缺失/未知/
  replay 模式、真实身份字段矛盾、重复 run/seed、同内容合法独立来源、v1
  降级、metadata/payload/文件名变化、越界及符号链接拒绝、矩阵伪生成入口和 `NA`。

另新增本报告。没有修改 named producer、其他统计模块、docs 或任务主文件；
工作树中的 named 相关改动属于并行 B1，不计入本报告交付。

## 调用链与实际消费者

- `_write_producer_execution_manifest` 的生产调用只有
  `_run_single_matrix_entry`，后者实际只调用 `run_campaign_close`，所以删除
  可选伪生成路径，不新增并不存在的 producer 编排器。
- 两个 `_queue_snapshot_digest` 的真实 Python 生产/审计与对应测试均已核对。
  schema 只承载版本常量；未为此新增抽象框架。
- 全库检索以下 C++ 范围未命中，`rg` **exit 1（无匹配）**：

  ```bash
  rg -n 'producer_execution_manifest|execution_mode|queue_snapshot|sha256-relative-path-size-content|publication-audit|campaign-matrix' \
    --glob '*.cpp' --glob '*.cc' --glob '*.cxx' --glob '*.h' --glob '*.hpp'
  ```

  因此本批没有 C++ 镜像改动，也没有运行 xmake。
- 只读观察到 B1 工作树已采用 v2 和 `execution_mode`；B1 的 producer 端验证
  以其报告为准，不能把本批离线 manifest fixture 当成真实生成证据。

## 先红后绿

所有测试工作目录均为 `/home/egoist/work/symcc`；使用独立临时目录，
不读写历史实验结果。Python 设置
`PYTHONDONTWRITEBYTECODE=1`、`PYTHONPATH="$PWD/test:$PWD"`。

| 阶段 | 命令 | exit / 实际结果 |
| --- | --- | --- |
| 红 | `python3 -B -m unittest test_publication_producer_provenance -v` | 1；初始 8 tests，18 个失败断言/子案例，实际复现 v1 升级、伪生成参数、同内容误拒、模式/时间/组件边界缺失 |
| 红 | `bash test/test_campaign_matrix.sh` | 1；原始计数断言要求 2，实际 payload 为 1，metadata 不应计入 |
| 红 | `python3 -B -m unittest test_publication_producer_provenance.PublicationProducerProvenanceTest.test_matrix_missing_metric_is_na_not_zero -v` | 1；`'' != 'NA'` |
| 红 | `bash test/test_publication_readiness_audit.sh` | 2；新相同内容正例被旧 snapshot ID/digest 判据拒绝，共 2 个问题 |
| 中间 | `bash test/test_campaign_matrix.sh` | 1；第一次转绿时漏改缺 comparability 的旧空白字符串期望，随后同步成 `NA` |
| 红 | `bash test/test_campaign_matrix.sh` | 1；追加单 run 出口回归后，发现 `variant_summary.tsv` 绕过格式化函数仍输出空白，已联动修复 |
| 绿，最终复跑 | `python3 -B -m unittest test_publication_producer_provenance test_track4_metrics_and_provenance -v` | 0；14 tests，OK |
| 绿，最终复跑 | `bash test/test_campaign_matrix.sh` | 0；PASS |
| 绿，最终复跑 | `bash test/test_publication_readiness_audit.sh` | 0；PASS |
| 静态 | `bash -n test/test_campaign_matrix.sh` | 0 |
| 静态 | `bash -n test/test_publication_readiness_audit.sh` | 0 |
| 静态 | Python 对上述 5 个 `.py` 调用 `compile(path.read_bytes(), str(path), "exec")` | 0；不生成 `.pyc` |
| 静态 | Python 断言上述 7 个代码/测试文件无 `\r`、以 `\n` 结尾 | 0；保持原 LF |
| 静态，最终复跑 | `git diff --check` | 0；无输出 |

另有一次只读版本约束检索指定了不存在的 `pyproject.toml`，`rg` exit 2；
这不是测试失败，也没有据此声称任何 Python 最低版本支持。

## 证据资格与后续边界

- 同内容可以来自独立运行；内容摘要只说明队列内容，不能证明或否定执行独立性。
  身份、seed、时间和组件仍需真实 producer 提供，审计不补造。
- 组件检查使用现有 `afl_master`、`afl_secondary`、`symcc`：
  enabled/started 必须自洽，master 必须启动，symcc 与开关一致；
  已启动组件要求正 pid 和非空 `command_summary`。这验证记录结构和一致性，
  **不等同于外部认证进程确实运行，更不证明命令实际改变了目标行为**。
- 普通 replay 矩阵仍能生成报告，已由 CLI 回归验证；它不能因此获得正式生成
  效果资格。只把 replay 的 mode/symcc.started 改成生成也会被组件证据门拒绝。
- v1 原文件保持可读且不会被改写；当前生成资格只认 v2。未迁移历史结果，
  未运行对历史目录有写入副作用的重分析。
- `_aggregate_variant`、`aggregate.py`、`statistics.py`、`rq3_snapshot` 未修改。
  主会话提到的缺失计数/`repro_rate` 默认零问题交由统计 owner；
  本报告不将内部单 run 方差/CI 行为夸大为已证实的公开 CLI 缺陷。
- 未跑真实 resolver、producer、solver、xmake、完整矩阵或仓库全量测试。
  G1 pilot、B1 真实 manifest 与 B2 审计的受控联调仍由主会话按授权安排。
