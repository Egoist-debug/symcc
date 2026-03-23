# BIND9 Stateful DNS 缓存投毒实验流程

本文档对应 `FUZZ_PROFILE=poison-stateful` 的实验线，目标是让 AFL++ 与 SymCC 在不改 resolver 网络协议代码的前提下，直接对状态化 transcript 输入进行 fuzz。

## 实验目标

- 输入不是单个 query，而是 `DST1` transcript：
  - `client_query`
  - `upstream_response_seq`
  - `post_check_query`
- AFL++ 主跑 transcript 状态空间。
- SymCC 用于补洞，直接对 AFL 队列中的 transcript 再求解。
- `gen_input` 负责生成：
  - `dns-poison-response`
  - `dns-stateful-transcript`
- response 语料默认采用“投毒模板 + DNS response 语法变异 + hybrid payload 探索”的综合方式生成。

## 当前阶段定位

这条实验线当前只服务于单 BIND9，目标是先把以下事项做扎实：

- 稳定执行短序列 transcript，而不是覆盖完整网络时序。
- 在同一 resolver 上同时保留 system-mode 与 transcript-mode 两条线做对照。
- 用外部可观测 oracle 先筛出“可能影响缓存状态”的样本，再决定后续是否做更强的 cache 证明。
- 让 AFL++ 与 SymCC 在同一批 transcript 语料上协同，而不是分别维护两套输入模型。

当前阶段不直接声称：

- 已具备跨 resolver 的统一结论。
- 已具备论文级 differential testing 判真能力。
- `cache_entry_created` 已由强语义 oracle 严格证明。

## 一次性准备

```bash
cd /home/ubuntu/symcc
export FUZZ_PROFILE=poison-stateful
. named_experiment/profiles/poison-stateful.env
```

如果你想覆盖 profile 默认值，也可以在 source 之前先导出变量，例如：

```bash
export TRANSCRIPT_MAX_ITER=512
export AFL_TIMEOUT_MS=5000+
export REPLY_TIMEOUT_MS=120
```

## 标准执行流程

1. 构建实验目标：

```bash
named_experiment/run_named_afl_symcc.sh build
```

2. 生成 seeds：

```bash
named_experiment/run_named_afl_symcc.sh gen-seeds
```

这一步会生成三个目录：

- `named_experiment/work/query_corpus`
- `named_experiment/work/response_corpus`
- `named_experiment/work/transcript_corpus`

其中：

- `response_corpus` 来自 `gen_input -f dns-poison-response --hybrid --seed-dir query_corpus`
  - 会综合投毒模板 seeds、`BinaryFormatFactory::createDNSResponse()` 驱动的语法变异，以及 hybrid payload 探索
  - query seeds 会直接参与 response 骨架生成，不再只依赖内置默认 query
  - 当前默认只采样前若干个 query seeds 参与这条综合生成链，以控制 prepare 成本
- `transcript_corpus` 来自 `gen_input -f dns-stateful-transcript --seed-dir transcript_seed_mix`
  - `transcript_seed_mix` 由运行脚本临时组装
  - 同时包含 `query_corpus` 中的 query seeds 与 `response_corpus` 中选取的一批综合 response seeds

3. 过滤稳定 transcript：

```bash
named_experiment/run_named_afl_symcc.sh filter-seeds
```

过滤后的 AFL 输入目录为：

```bash
named_experiment/work/stable_transcript_corpus
```

过滤标准是一次运行中至少满足：

- `Transcript cases: 1`
- `Oracle parse_ok: 1`
- `Oracle resolver_fetch_started: 1`
- `Oracle response_accepted: 1`
- `Oracle second_query_hit: 1`

补充说明：

- 当前脚本中的稳定性过滤要求第一轮 query 确实触发过上游抓取并接受过伪造响应，且 post-check 后未再次触发新的上游交互。
- 这意味着当前 `stable_transcript_corpus` 更偏向“已经走到伪造响应接受 + post-check 命中代理”的样本，而不是“只要看起来可能影响缓存状态就保留”。

4. 一键准备：

```bash
named_experiment/run_named_afl_symcc.sh prepare
```

这相当于串行执行：

```bash
build -> gen-seeds -> filter-seeds
```

5. 启动实验：

```bash
named_experiment/run_named_afl_symcc.sh start
```

启动后：

- AFL++ master/secondary 读取 `stable_transcript_corpus`
- `named` 通过 stdin 接收 transcript
- orchestrator 在运行时把 transcript 中的 response 序列落到临时目录并执行 post-check
- SymCC helper 会直接对 AFL 队列中的 transcript 继续求解，不再额外注入 `RESPONSE_TAIL`
- `poison-stateful` 主线中的 transcript 不再只依赖内置模板 response，而是直接复用 `response_corpus` 里的综合变异结果

6. 查看状态：

```bash
named_experiment/run_named_afl_symcc.sh status
```

7. 停止实验：

```bash
named_experiment/run_named_afl_symcc.sh stop
```

## 目录说明

- `named_experiment/work/query_corpus`
  - 基础 query seeds
- `named_experiment/work/response_corpus`
  - 缓存投毒导向 response seeds
- `named_experiment/work/transcript_seed_mix`
  - transcript 生成阶段临时组装的 query/response 混合种子目录
- `named_experiment/work/transcript_corpus`
  - 原始 stateful transcript seeds
- `named_experiment/work/stable_transcript_corpus`
  - 可直接供 AFL++ 使用的稳定 transcript
- `named_experiment/work/afl_out`
  - AFL++ 输出目录
- `named_experiment/work/logs`
  - master、secondary、helper 日志

## 关键观察指标

建议同时记录 AFL 与 resolver oracle 两类指标。

### AFL++ 常规指标

- `execs_done`
- `cycles_done`
- `corpus_count`
- `saved_crashes`
- `saved_hangs`
- `bitmap_cvg`
- `pending_total`
- `last_find`

### resolver/orchestrator 指标

查看日志中的：

- `Transcript cases`
- `Transcript parse errors`
- `Oracle parse_ok`
- `Oracle resolver_fetch_started`
- `Oracle response_accepted`
- `Oracle second_query_hit`
- `Oracle cache_entry_created`
- `Oracle timeout`

其中最关键的是：

- `Oracle response_accepted`
- `Oracle second_query_hit`
- `Oracle cache_entry_created`

它们当前只应被解释为“是否把伪造 response 推进到缓存影响路径的代理信号”。

需要特别注意：

- `Oracle response_accepted` 表示第一轮 query 后，mutator 确实向 resolver 返回过伪造上游响应。
- `Oracle second_query_hit` 表示 post-check 阶段没有再观察到新的上游取数行为。
- `Oracle cache_entry_created` 现在比 `Oracle second_query_hit` 更严格：它要求第一轮 query 已触发上游抓取并接受过伪造响应，同时 post-check 阶段没有再观察到新的上游交互；它仍然只是更强的代理信号，不能直接等价为“cache 中已新增恶意条目”。
- **BIND9 Replay 隔离性**：在 differential 模式下，BIND9 replay 必须与 producer 实例隔离，禁止复用 `WORK_DIR` 或 55300/55301 端口。
- **Python-first Ownership**：`tools/dns_diff/` 承担核心 follower 调度与样本分发；shell 仅用于 `timeout -k` 包装与外部环境配置。
- **Sample Identity**：遵循 `queue_event_id`, `sample_sha1`, `sample_id` 标识约定。
- **Timeout Budget (Strict)**：
  | 环节 | Timeout (软) | Kill (硬) |
  | :--- | :--- | :--- |
  | Pair Replay | 180s | 185s |
  | Single Resolver | 15s | 18s |

## 复现实验建议

### 最小 smoke test

```bash
export FUZZ_PROFILE=poison-stateful
. named_experiment/profiles/poison-stateful.env
named_experiment/run_named_afl_symcc.sh prepare
named_experiment/run_named_afl_symcc.sh start
sleep 30
named_experiment/run_named_afl_symcc.sh status
named_experiment/run_named_afl_symcc.sh stop
```

### 长时间实验

```bash
export FUZZ_PROFILE=poison-stateful
export TRANSCRIPT_MAX_ITER=512
export RESPONSE_MAX_ITER=512
export AFL_TIMEOUT_MS=5000+
. named_experiment/profiles/poison-stateful.env
named_experiment/run_named_afl_symcc.sh prepare
named_experiment/run_named_afl_symcc.sh start
```

### 实验总结与消融报告

在实验运行结束后，使用以下命令生成汇总报告：

```bash
# 生成包含时间戳的 campaign 报告目录
./unbound_experiment/run_unbound_afl_symcc.sh campaign-report
# 或直接使用 Python 工具
python3 -m tools.dns_diff.cli campaign-report
```

报告产物说明：
- `summary.json`: 核心计数、消融模块状态与复现成功率汇总
- `ablation_matrix.tsv`: 记录当前实验开启的模块 (Mutator/Cache-Delta/Triage/SymCC)
- `cluster_counts.tsv`: 各 Fingerprint 聚类下的样本分布
- `repro_rate.tsv`: 高价值样本在当前 Campaign 中的复现达成度

### 消融实验开关

可以通过环境变量在启动实验前控制各增强模块：

```bash
# 示例：关闭 SymCC 进行对比实验
export ENABLE_SYMCC=0
# 启动实验
./named_experiment/run_named_afl_symcc.sh start
```

## 当前限制

- transcript 目前主要覆盖单 query、1 到 2 个 response、以及一次 post-check。
- `gen_input` 已经能生成 poisoning-oriented response，但更细的 authority/additional 约束探索还可以继续增强。
- helper 在 `poison-stateful` 线中是“直接求解 transcript”，不是“额外给 transcript 再外挂第二套 response 目录”。
- 当前 transcript 对 `response_corpus` 的复用仍是“按文件 seed 批量扩展”，还不是运行时按 query 上下文动态选择语法变异策略。
- `response_corpus` 现阶段采用采样后的 query seeds 驱动综合生成，优先保障回归和 smoke 可运行，再逐步放大覆盖面。

## 与论文的差距

和 ResolverFuzz、BGF-DR 相比，这条单 BIND9 实验线目前还有以下差距：

- 还没有 differential testing，也没有第二个 resolver 参与横向比较。
- 还没有 state coverage、状态指纹或差异聚类流程。
- transcript 还不能表达完整的 transport、delay、乱序和 TCP fallback 语义。
- 当前 oracle 仍以外部可观察代理信号为主，尚未做到强语义缓存证明。

## 下一步改进重点

建议优先推进以下事项：

1. 把 `second_query_hit` 和 `cache_entry_created` 拆成不同层级的指标，避免语义混淆。
   - `cache_entry_created` 语义边界：目前仅作为“更强代理信号”，表示第一轮 query 触发抓取、接受伪造响应且 post-check 命中；这**不代表**缓存中已新增恶意条目的最终漏洞证据。
2. 为 BIND9 增加更强的 cache 观测或日志钩子，用于校验当前代理 oracle。
   - BIND9 Replay 隔离：必须与 producer 进程完全隔离，使用独立的 `WORK_DIR`、非竞争端口（避免 55300/55301 冲突）及独立的运行时环境。
3. 在不破坏当前吞吐的前提下，为 transcript 增加最小必要的时序与传输元数据。
4. 等单 BIND9 线稳定后，再引入第二个 resolver 做 differential baseline。
