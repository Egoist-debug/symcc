# 调研：论文规划基线

- 范围：本地仓库、现有论文文档、历史任务和环境发现。
- 核验日期：2026-10-30。
- 任务状态：`planning`；用户仅批准建立任务与规划。

## 仓库与已有方向

- 实际 Git 仓库是 `/home/egoist/work/symcc`，不是 `/home/egoist/work`。
- `git -C symcc branch --show-current` 返回 `paper`。
- `git -C symcc rev-parse HEAD` 返回 `f08a6c8935c9d25ff0319fdc8b6723d49648322a`。
- 调研开始时 `git -C symcc status --short` 无输出；不得覆盖其他会话之后的改动。
- `symcc/docs/DNSPoisonFuzzingPlan.md:5-29` 已定义单一 BIND9 producer、DST1 transcript、多 resolver 同源重放，以及 RQ1–RQ5。不是从空仓库设计新系统。
- `symcc/docs/DNSPoisonFuzzingPlan.md:49-53` 提出正式独立重复、案例证据及投稿方向，但这些要求不代表已经完成，更不保证录用。
- `symcc/docs/DNSPoisonEvidenceContract.md:3` 指定 `tools/dns_diff/schema.py` 为证据语义 owner；`74-77` 区分正式 `afl_only` 基线和矩阵内部基线。
- `.trellis/tasks/08-17-review-symcc-experiments/` 的两份旧审查报告基于较旧提交，必须重新核验；本轮各专项报告记录现状，不能直接复制旧问题清单。
- `trellis mem search '论文' --cwd /home/egoist/work --until 2026-10-29 --limit 6 --json` 找到历史用户“完善 symcc 项目的内容，其实能达到论文发表的水平”的诉求，以及过往证据审计工作。历史助手的“完成”表述不代替当前代码、产物或用户授权。

## 环境发现，不等于可执行性验收

| 项目 | 当前观测 |
| --- | --- |
| CPU | `os.cpu_count()` 与 affinity 均为 16 |
| 内存 | `MemTotal=15798860 kB`，查询时 `MemAvailable=13000544 kB` |
| 可用磁盘 | 仓库所在文件系统约 94.1 GiB |
| Python | `Python 3.14.4` |
| Clang | `Ubuntu clang version 21.1.8 (6ubuntu1)` |
| xmake | `v3.1.1+20260904` |
| AFL | `/usr/local/bin/afl-fuzz` 在 PATH；版本和目标运行能力未验收 |
| SymCC | PATH 未发现，但 `build/linux/x86_64/release/symcc`、`sym++`、`libsymcc.so`、`libsymcc-rt.so` 存在 |
| DNS CLI | `build/linux/x86_64/release/dnslabctl` 存在；不能据此认定与当前源码一致 |
| 本地解析器树 | 发现 BIND9 的原始、AFL 和 SymCC 目录；是否可用由后续 preflight 核验 |
| cgroup | 根路径 `cpu.max`、`memory.max` 不存在；不据此声称资源无限制 |

主机空闲资源是查询时快照，不是完整实验的资源授权。首轮实现应先查工具链和二进制身份，再进行隔离、限时的本地测试。

## 源码版本锁

从 `symcc/experiments/resolvers.lock.json` 读取的 `resolved_tag`：

| resolver | 锁定版本 |
| --- | --- |
| BIND9 | `v9.20.22` |
| Unbound | `release-1.24.2` |
| MaraDNS / Deadwood | `deadwood-3.3.02` |
| dnsmasq | `v2.92` |
| SmartDNS | `Release47.1` |
| Knot Resolver | `v6.2.0` |

本轮此处只读取 lock，不重新联网冻结版本，也不把标签存在等同于 patch、二进制或实验结果一致。正式产物还须记录源码提交、补丁哈希、构建参数和实际二进制哈希。

## 规范与边界

- `.trellis/spec/backend/index.md`、`quality-guidelines.md`、`error-handling.md` 仍以待填模板为主，不能作为已经建立的具体编码约定。实现应继续读取现有代码、测试和证据契约。
- 新任务文档使用中文；现有文件编辑前须核对换行符。
- 只写当前任务目录，不修改原论文结果、不变更 subject 源码、不运行 `task.py start`。
- 本文件记录的是规划调研；没有执行编译、单元测试、真实 fuzzing 或完整 replay 矩阵。
