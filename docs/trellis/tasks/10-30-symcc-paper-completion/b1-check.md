# B1：named producer 与独立 RQ3 replay 出口

## 结论

**B1 及主会话追加的独立 replay 脚本修复已通过隔离自检，现冻结。**
基线仍为 `c696add30c49c909e0d1d361618b71e3b1e0e754`，未提交、未推送。
这不是实际 DNS producer、solver、AFL 回流或消融增益通过的结论。

特别结论：**`no_cache_delta`、`ENABLE_TRIAGE=0` 没有关闭 named helper
反馈，与 `full_stack` 是等价的生成配置；不能用不同 manifest 标签声称独立生成消融。**

## 修改文件与边界

路径相对 `/home/egoist/work/symcc`：

1. `named_experiment/run_named_afl_symcc.sh`
   - 保留显式 producer seed；先校验再 prepare/stop/cleanup/删除 manifest。
   - master/secondary 均收到相同的显式 `-s`；helper 收到派生的
     `SYMCC_RANDOM_SEED`，完整环境与参数复用实际启动数组写入 `command_summary`。
   - 新执行记录 `execution_mode=independent_producer_generation`，
     queue snapshot 使用 v2、排除 `*.meta.json`。
   - 启动后按实际 PID 观察更新组件；master 未就绪会失败，tmux 不再把等待 shell
     当成 helper。继承 `ERR` trap，启动失败记录失败并清理本轮组件。
   - 独立 `stop` shell 保留原 seed、开关、命令及 PID；不把编排退出码冒充
     子进程退出码，未采集的 `components.*.exit_status` 为 `null`。
   - 当前关闭 SymCC 也会清理上一轮 helper；legacy/missing-mode manifest
     不被 finish 路径改写成新版产物。
2. `test/test_named_seed_provenance.sh`：保留初始语料 sidecar 回归，增加 seed
   边界和三条入口非法输入不碰旧 manifest/组件的测试；强制临时 `BIND9_WORK_DIR`。
3. `test/test_named_producer_execution.sh`：新增真实脚本调用、外部进程替身测试；
   覆盖命令/环境/PID、开关、失败、收尾、v2、等价配置及 B1→B2 合同联调。
4. `scripts/run_real_rq3_multi_resolver_ablation.sh`（主会话明确追加写权）
   - 删除固定 `recorded_at` 和 `rq3queue...` 伪身份，记录当前 UTC 时间、
     实际源目录、实际复制内容的 v2 摘要和算法。
   - 复用 `matrix._queue_snapshot_digest` 与 schema 的版本常量；
     排除 metadata 后再应用 `QUEUE_LIMIT`，拒绝非正 limit/空 payload。
   - 保留原入口和参数；新 `status.tsv`、汇总 TSV、汇总 JSON 顶层及每行
     明确 `execution_mode=shared_queue_replay`、`generation_evidence=false`。
     JSON 为布尔值，TSV 为小写 `false`；汇总行还记录真实 `source_queue_dir`。
   - 不新增 producer manifest；同名时间戳目录已存在即拒绝，不能覆盖旧批次。
5. `test/test_real_rq3_replay_provenance.sh`：复制生产脚本及 cleanup 库到临时
   仓库，仅替换 campaign CLI，验证真实内联 provenance/汇总代码；
   覆盖 metadata 不改变摘要、payload 改变摘要、输入不变、空输入/非法 limit、
   同名批次不覆盖、单 run 保持 `NA`、没有伪 producer manifest。

另新增本报告。没有修改 unbound runner、`tools/dns_diff`、docs 或任务主工件；
当前其他工作树改动属于主会话/其他 owner。

## 精确 seed 合同

正确标识符是 `PRODUCER_RANDOM_SEED`。

| 输入 | 行为 |
| --- | --- |
| 未设置或空字符串 `""` | 缺省生成，保留旧生成范围 `1..2147483647` |
| ASCII 十进制整数，数值 `0..9223372036854775807` | 接受，含两端点 |
| `0007` | 接受；变量与 AFL `-s` 保留原字符串 `0007`，manifest 写 JSON 整数 `7` |
| `0`、全零数字字符串 | 接受；manifest 整数 `0`，solver seed `0` |
| 空白、前后空格、换行、正负号、`1.5`、`1e2`、`0x10`、非数字 | 拒绝，不 trim 成合法 seed |
| 超过 `9223372036854775807` | 拒绝，避免 AFL signed seed 接口转换后改变声明值 |

校验用 `[0-9]+`，不接受 Unicode 数字。数值解析先去前导零，
不使用 shell 八进制解释。合法显式 seed 不重新随机化；
run UUID 仍每次生成，内容身份不参与 run UUID 的生成。

本机 `/usr/local/bin/afl-fuzz -h` 输出 AFL++ **5.02c**，退出 1 是帮助行为；
安装 binary 的调试路径为 `/home/egoist/AFLplusplus`。该源码
`src/afl-fuzz.c:967-971` 将 `strtoul(...,10)` 交给
`rand_set_seed`；`include/afl-fuzz.h:1593`、`src/afl-performance.c:30-38`
确认参数与存储为 `s64`。本批采用其非负、无转换损失范围，
不是错误地把 AFL seed 限制成正 31 位。未验证其他 AFL 版本/32 位宿主。

**给最终 check / B2 owner：** 当前 B2 仅检查非空 int/str，不完整校验数字/范围。
named writer 输出已经是 JSON 整数，但其他来源仍可能绕过；B1 没越权改 audit。
审计若允许字符串，应按上述数值语义处理前导零的重复身份，不能把 `7` 与 `0007`
当作两个 seed；布尔值、非数字和越界值不应获得生成资格。

## 随机源与实际调用链

- 调用方已检索：`run_bind9_full_long_suite.sh`、
  `run_bind9_resolver_experiment_suite.sh` 的 prepare/run，及 named 相关回归。
  `initialize_execution_identity` 的生产调用只有 named `start_all`。
- AFL master 与 secondary：本轮实际命令都包含 `-s "$PRODUCER_RANDOM_SEED"`；
  不将 secondary 当作第二次独立 producer。命令数组位于 named `:1881` 起。
- DST1 mutator：AFL 的 `src/afl-fuzz-mutators.c:429` 用
  `rand_below(afl, 0xFFFFFFFF)` 传入 `afl_custom_init`；
  本仓 `gen_input/src/afl_dst1_mutator.cpp:145,649-651`
  用该派生值初始化 `std::mt19937`。它受对应 AFL RNG 控制，
  **不是直接使用相同数值的 root seed**；未伪造具体 mutator 子 seed。
- 实际 helper 是 `util/symcc_fuzzing_cpp/`（`xmake.lua:1`），不是 Rust 目录。
  helper CLI `src/main.cpp:459-523` 没有独立 RNG 参数；但目标继承环境，
  `src/process.cpp:13-16,38-46,86` 没有清空父环境。
- runtime `src/Config.cpp:97-108` 支持 `SYMCC_RANDOM_SEED`，
  QSYM `src/backends/qsym/Runtime.cpp:188-190` 将其传给 Z3。
  `z3 -p` 退出 0，显示 `random_seed (unsigned int)`。
  因此 helper 环境固定为 **`PRODUCER_RANDOM_SEED % 2**32`**，
  在实际 `command_summary` 中可见，例如 root `4294967296` 对应 solver `0`。
  继承的任意 `SYMCC_RANDOM_SEED` 会被这个派生值覆盖，避免不受记录的 solver seed。
- 仍未控制：helper `src/util.cpp:40-46` 的临时目录 `random_device`、
  OS/并发/超时与 solver 调度、resolver 内部随机性、外部反馈 manifest 内容。
  初始 `gen_input` 发生在执行身份初始化之前；其 `--seed` 是输入内容，
  不是 RNG seed，不能假称本次 producer seed 控制了初始 corpus 的重新生成。
  初始 corpus 沿用既有 SHA-1 sidecar provenance，不改既有字段语义。

所以本批证明的是种子传递和记录，**不声称整个 pipeline bit-for-bit 可复现**。

## 消融开关实际差别

| 开关/变体 | 生产命令与组件的实际差别 |
| --- | --- |
| `ENABLE_SYMCC=0` / `afl_only` | 不启动 helper；准备路径不构建 helper/SymCC named；仍可能为初始输入生成构建 SymCC 工具链。AFL 与 DST1 mutator 保留，不能叫“原生 AFL 无其他组件” |
| `ENABLE_DST1_MUTATOR=0` / `no_mutator` | master/secondary 环境无 `AFL_CUSTOM_MUTATOR_LIBRARY` 和 `AFL_CUSTOM_MUTATOR_ONLY`；清除继承值，helper 仍启用 |
| `DST1_MUTATOR_ONLY=0` | 保留配置的 DST1 library，不保留继承的 custom-mutator-only |
| `ENABLE_SECONDARY=0` | 不启动 secondary，master/helper 的其他配置不变 |
| `ENABLE_CACHE_DELTA=0` / `no_cache_delta` | named 只记录开关并警告；不改变 master/secondary/helper 的生成命令，不关闭反馈 |
| `ENABLE_TRIAGE=0` | named 同样只记录开关并警告；不关闭 helper/反馈 |

测试将实际子进程收到的 argv/env 与 writer 的命令逐项比较，
并只归一化临时工作目录后断言：

```text
commands(full_stack) == commands(no_cache_delta) == commands(no_triage)
helper_feedback(full_stack) == helper_feedback(no_cache_delta) == helper_feedback(no_triage)
```

反馈比较覆盖 `SYMCC_HIGH_VALUE_MANIFEST`、
`SYMCC_SEMANTIC_FRONTIER_MANIFEST`、`SYMCC_FRONTIER_RELOAD_SEC`、
`SYMCC_FRONTIER_RETRY_LIMIT`，不是只比较组件名称。
helper C++ 全目录未找到 `ENABLE_CACHE_DELTA` / `ENABLE_TRIAGE` 消费者。
下游 A1 合同中 `cache_delta_triggered` 仍可进入标记/明细
（如 `tools/dns_diff/triage.py:465-466`），不能据此声称语义分类或生成反馈关闭。
若未来由另一个外部进程写入不同反馈文件，属于另一个待固定的实验条件；
这里没有证明那条实时反馈链发生变化。

## B1 → B2 联调与替身边界

`test_named_producer_execution.sh` 直接调用实际 named writer，
然后将未改写的最终 manifest 交给
`publication_audit._audit_producer_execution_manifest`。
9 个成功场景均无 audit issues；审计前后 manifest 字节不变。
其中 full/wide-seed 使用同一身份去重集合，**相同队列内容、不同 run/seed**
可以同时通过。其他相同 seed 的场景是独立单元案例，不混充统计矩阵。

这些 PID 来自隔离的 Python 常驻替身，queue 为固定 fixture，
tmux 分支由测试传输替身执行组装的 shell 命令。
**没有启动实际 AFL、helper 或 resolver，也没有实际 tmux server 验证；
该 PASS 只证明生产 writer 与审计字段/摘要合同兼容。**

## 实际测试与退出码

工作目录均为 `/home/egoist/work/symcc`；所有输出在临时目录，
不写 `.sisyphus/evidence` 或历史 `experiments/results`。

### 先红后绿的主要证据

| 测试/阶段 | 真实结果 |
| --- | --- |
| seed 首次红灯 | exit 1；显式 `0` 被覆盖成 `175908291` |
| producer 命令首次红灯 | exit 1；旧未引用路径/命令前缀无法还原实际 argv |
| 启动失败红灯 | exit 1；failed-master 的 manifest 仍是 `running` |
| 中间 ERR 修复 | exit 1；Bash 5.3.9 的 ERR handler `return` 与 EXIT/local 组合报错；最小复现后将 fatal handler 改为 `exit "$rc"`，最终失败场景保持 23 |
| legacy 红灯 | exit 1；旧 running/v1 文件被 finish 改写 |
| 关闭 SymCC 清理红灯 | exit 1；上一轮 helper 仍存活 |
| solver seed 红灯 | exit 1；helper 收到继承的 `19`，未收到声明的派生 seed |
| RQ3 replay 出口红灯 | exit 1；读到 `2026-05-22T08:00:00Z`、`rq3queue000001` 和错误 source 路径 |

### 最终复跑（追加 replay 修改之后）

| 命令 | exit / 结果 |
| --- | --- |
| `bash test/test_named_seed_provenance.sh` | 0 / PASS |
| `bash test/test_named_producer_execution.sh` | 0 / 9 成功场景、3 启动失败场景、等价配置/B2 联调及旧 helper 清理 PASS |
| `bash test/test_real_rq3_replay_provenance.sh` | 0 / 3 内容/metadata 场景、3 非法输入场景、同名批次保护 PASS |
| `bash test/test_named_bind9_git_bootstrap.sh` | 0 / PASS；autoreconf 为该测试自带替身 |
| `bash test/test_named_poison_stateful_semantic_profile.sh` | 0 / PASS |
| `bash test/test_named_transcript_current_format_acceptance.sh` | 0 / PASS |
| `bash test/test_named_transcript_seed_migration.sh` | 0 / PASS |
| 分别对上述 5 个 B1 修改/新增 `.sh` 执行 `bash -n FILE` | 全部 0 |
| `git diff --check` | 0 / 无输出 |
| Python 断言上述 5 个文件无 `\r` 且末尾为 `\n` | 通过，保持 LF |

## 未做与后续风险

- 没运行 xmake、真实 DNS/AFL/solver、长 fuzzing、真实矩阵或全仓测试；没有新性能结果。
  `shellcheck` 未安装。未运行会写固定 `.sisyphus/evidence` 的
  `test_named_patch_split.sh`。
- 没修改历史 artifact；独立 RQ3 脚本只对未来新目录输出真实 replay 标签。
  旧固定来源/旧 v1 不会自动获得新版资格。
- `started=true` 是进程启动观察，不等于完整预算内健康、有效求解或队列已消费；
  实际组件退出码仍未知。G1 必须另查日志、进程终态及内容来源。
- 生产脚本沿用 live queue 快照、默认 session/端口等结构；正式并行实验仍须
  独立 work/session/端口和冻结后的内容，不凭相同或不同 hash 证明独立性。
- 最终 check 需联动 B2 seed 数值边界；并把等价生成配置合并/降格为分析开关，
  不把四个标签直接当四种已验证的生成机制。
