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

- `response_corpus` 来自 `gen_input -f dns-poison-response`
- `transcript_corpus` 来自 `gen_input -f dns-stateful-transcript`

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
- `Oracle response_accepted: 1`

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

它们直接对应“是否把伪造 response 推进到缓存影响路径”。

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

## 当前限制

- transcript 目前主要覆盖单 query、1 到 2 个 response、以及一次 post-check。
- `gen_input` 已经能生成 poisoning-oriented response，但更细的 authority/additional 约束探索还可以继续增强。
- helper 在 `poison-stateful` 线中是“直接求解 transcript”，不是“额外给 transcript 再外挂第二套 response 目录”。
