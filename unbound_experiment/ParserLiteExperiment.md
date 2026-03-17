# Unbound 第二 Resolver 接入说明

本文档对应 `unbound_experiment/run_unbound_afl_symcc.sh`。当前这条实验线已经包含两层能力：

- 阶段一：`parser-lite`
- 阶段二：实验性 `poison-stateful`

其总体目标仍然是把第二个 resolver 接进来，并逐步从 parser-lite 推进到与 BIND9 可对齐的最小 stateful transcript adapter。

## 当前阶段目标

- 第二个 resolver 选型为 `Unbound`。
- 使用官方 release `1.24.2` 作为本地源码基线。
- 当前保留 upstream 自带的 `unbound-fuzzme` parser-lite 入口。
- 当前已经补入实验性的 `DST1` transcript 消费能力。
- 继续复用本仓库现有的 `gen_input` query seeds 能力。
- 同时构建 AFL 与 SymCC 两个版本的 `unbound-fuzzme`，为后续协同实验做准备。

## 为什么先做 parser-lite

当前 BIND9 线已经有自己的 orchestrator、oracle 和 transcript 运行模型，但这些逻辑强绑定 BIND9 内部线程与 resolver 主链。第二个 resolver 一开始直接照搬，会把“引入第二目标”和“重写实验框架”两个任务绑在一起，风险太高。

因此第一阶段先做最小闭环：

1. 把 Unbound 源码树纳入工作区。
2. 为 AFL 与 SymCC 各自构建一个可执行目标。
3. 用 `gen_input --format dns` 生成 query seeds。
4. 对两个目标做 smoke，确认基本输入链路与构建链路可用。

这一步的价值是：

- 先打通第二个 resolver 的工程入口。
- 先确认编译工具链与目标程序兼容。
- 先积累后续 adapter 设计所需的本地源码上下文。

## 当前命令

```bash
unbound_experiment/run_unbound_afl_symcc.sh fetch
unbound_experiment/run_unbound_afl_symcc.sh build
unbound_experiment/run_unbound_afl_symcc.sh gen-seeds
unbound_experiment/run_unbound_afl_symcc.sh smoke
unbound_experiment/run_unbound_afl_symcc.sh status
```

也可以直接执行：

```bash
unbound_experiment/run_unbound_afl_symcc.sh prepare
```

如果要启用最小 stateful transcript 模式，则使用：

```bash
export FUZZ_PROFILE=poison-stateful
unbound_experiment/run_unbound_afl_symcc.sh gen-seeds
unbound_experiment/run_unbound_afl_symcc.sh filter-seeds
unbound_experiment/run_unbound_afl_symcc.sh smoke
unbound_experiment/run_unbound_afl_symcc.sh diff-test
```

## 当前实现范围

- 会创建或复用以下源码树：
  - `unbound-1.24.2`
  - `unbound-1.24.2-afl`
  - `unbound-1.24.2-symcc`
- AFL 与 SymCC 版本都通过 upstream `contrib/unbound-fuzzme.patch` 引入 `unbound-fuzzme`。
- query seeds 输出到：
  - `unbound_experiment/work/query_corpus`
- smoke 使用 query corpus 中的一个样本分别喂给：
  - `unbound-1.24.2-afl/unbound-fuzzme`
  - `unbound-1.24.2-symcc/unbound-fuzzme`
- 在 `FUZZ_PROFILE=poison-stateful` 下，脚本还会额外生成：
  - `unbound_experiment/work/transcript_corpus`
  - `unbound_experiment/work/stable_transcript_corpus`

## 当前最小 stateful transcript 支持

当前 Unbound 已经可以直接消费与 BIND9 相同的 `DST1` transcript 输入模型，最小语义包括：

- `client_query`
- 顺序 response 序列
- `post_check_query`

当前 transcript oracle 语义为：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `second_query_hit`
- `cache_entry_created`
- `timeout`

其中：

- `second_query_hit` 表示 post-check 阶段没有再次触发新的上游交互
- `cache_entry_created` 表示更强一层的缓存命中代理，要求第一轮 query 已触发上游抓取并接受过伪造响应
- transcript 组装阶段会把 query 归一化为 `RD=1`，确保进入缓存投毒主线的都是递归查询语义

需要明确的是，这两个字段在 `parser-lite` 模式下仍只是显式占位输出；只有在 `poison-stateful` transcript 模式下，它们才具备最小 stateful 语义。

当前已完成的最小验证包括：

- `poison-stateful` 下，Unbound AFL / SymCC 目标都能对 transcript 样本执行 smoke
- `diff-test` 已经可以从 `stable_transcript_corpus` 读取样本并输出结构化差异结果

## 当前 oracle 输出边界

当前 Unbound 线已经会显式输出以下 oracle 键：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `second_query_hit`
- `cache_entry_created`
- `timeout`

其中需要特别注意：

- `parse_ok`
- `resolver_fetch_started`
- `response_accepted`
- `timeout`

这四项是当前 parser-lite 线已有实际观测意义的字段。

而以下两项在不同模式下语义不同：

- `second_query_hit`
- `cache_entry_created`

- 在 `parser-lite` 模式下，它们会显式输出，但默认保持 `0`
- 在 `poison-stateful` 模式下，它们具备最小 stateful 代理语义

## 现阶段不承诺的事项

- 还没有接入 Unbound daemon system-mode。
- 还没有把 transcript 主线推广到完整 AFL campaign 评估和长期运行结论。
- 还没有实现 Unbound 版本的强语义 cache 观测或漏洞确认。
- 还没有把 SymCC helper 正式挂到 Unbound campaign 上。
- 还没有开始做跨 resolver 的正式统计比较。

## 与 BIND9 主线的关系

这条 Unbound 线当前只承担“第二目标接入”的职责，不替代 BIND9 主线：

- BIND9 继续承担当前 stateful transcript 主实验线。
- Unbound 当前先承担 parser-lite 和后续 adapter 落点验证。
- 等 Unbound system-mode 或最小 transcript adapter 跑通后，再开始真正的 differential baseline。

## 当前 diff-test 输出

执行：

```bash
unbound_experiment/run_unbound_afl_symcc.sh diff-test
```

当前会在 `unbound_experiment/work/diff_results` 下生成：

- `summary.tsv`
  - 结构化汇总表，包含 `sample`、`diff`、`diff_type`、`unbound_oracle`、`bind9_oracle`
- `<sample>.detail`
  - 差异详情，包含样本路径、来源目录、差异类型、两边 oracle 和原始 stderr 文件名
- `<sample>.unbound.stderr`
  - Unbound 原始 stderr
- `<sample>.bind9.stderr`
  - BIND9 原始 stderr

当前 `diff_type` 的分类规则是按 oracle 差异优先级划分：

- `timeout_diff`
- `parse_diff`
- `fetch_diff`
- `response_accept_diff`
- `cache_behavior_diff`
- `oracle_diff`

其中 `cache_behavior_diff` 仍要谨慎解释：

- 在 `parser-lite` 模式下，它仍可能只是占位差异
- 在 `poison-stateful` 模式下，它已经具备最小 stateful 解释力，但仍不是强语义缓存证明

## 下一步建议

建议按以下顺序推进：

1. 先验证 `prepare` 能稳定完成。
2. 再为 Unbound 选择一个最小 daemon-mode 入口，优先打通真实递归解析链。
3. 补一层统一的 resolver adapter shell 接口，而不是直接改 BIND9 orchestrator。
4. 等 Unbound 也能输出同口径 oracle 后，再开始做 BIND9 vs Unbound 的对照实验。
