# Unbound 第二 Resolver 接入说明（阶段一）

本文档对应 `unbound_experiment/run_unbound_afl_symcc.sh`，目标不是立刻复刻 BIND9 的 stateful transcript harness，而是先把第二个 resolver 的最小工程入口接进来，建立一个可构建、可跑 smoke、可继续扩展的基线。

## 当前阶段目标

- 第二个 resolver 选型为 `Unbound`。
- 使用官方 release `1.24.2` 作为本地源码基线。
- 当前先接入 upstream 自带的 `unbound-fuzzme` parser-lite 入口。
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

## 现阶段不承诺的事项

- 还没有接入 Unbound daemon system-mode。
- 还没有接入 `client_query -> upstream_response_seq -> post_check_query` 的 transcript 执行模型。
- 还没有实现 Unbound 版本的 `parse_ok` / `response_accepted` / `second_query_hit` / `cache_entry_created` 统一 oracle。
- 还没有把 SymCC helper 正式挂到 Unbound campaign 上。
- 还没有开始做跨 resolver 的正式统计比较。

## 与 BIND9 主线的关系

这条 Unbound 线当前只承担“第二目标接入”的职责，不替代 BIND9 主线：

- BIND9 继续承担当前 stateful transcript 主实验线。
- Unbound 当前先承担 parser-lite 和后续 adapter 落点验证。
- 等 Unbound system-mode 或最小 transcript adapter 跑通后，再开始真正的 differential baseline。

## 下一步建议

建议按以下顺序推进：

1. 先验证 `prepare` 能稳定完成。
2. 再为 Unbound 选择一个最小 daemon-mode 入口，优先打通真实递归解析链。
3. 补一层统一的 resolver adapter shell 接口，而不是直接改 BIND9 orchestrator。
4. 等 Unbound 也能输出同口径 oracle 后，再开始做 BIND9 vs Unbound 的对照实验。
