# B3 最小真实符号回流检查

## 结论与冻结范围

**通过：`test/if.c` 的真实输入 → QSYM/Z3 求解 → 新候选 → 具体分支改变 → C++ helper 两处队列 → 真实 AFL 外部队列导入。**

**未证明：DNS/DST1/RDATA 符号链、named 的现有同步配置、独立 DNS producer 或 G1 pilot。**
手写 `fuzzer_stats` 仅用于 helper 接口准备，不是 producer 来源证据。

- 日期：2026-10-30。
- 仓库：`/home/egoist/work/symcc`；开始时 HEAD：
  `c696add30c49c909e0d1d361618b71e3b1e0e754`。
- 只新增 `symcc/test/test_symcc_real_feedback.sh` 与本报告。
  复用原有 `test/if.c`，没有新增 C fixture、修改产品代码、重建依赖或改动其他 worker 文件。
- 最终脚本 SHA-256：
  `e7c9dfe572f64c6a0879c1f8814ff8ad3a25a9354ce7181cbd4d9a7da996a1e5`。
- 最终原始产物：`/tmp/symcc-real-feedback.5k3wre2d/`。
  `result.json` 保存实际命令 argv、环境增量、PID、退出码、耗时、工具与候选哈希。
  日志在 `logs/`，求解原件在 `solve/`，两处 helper 队列在 `afl_out/exp/`，
  真实 AFL 产物单独在 `live-afl/master/`。临时目录保留供独立 check，不覆盖历史路径。

复跑入口：

```bash
cd /home/egoist/work/symcc
B3_OUTPUT_ROOT=/tmp bash test/test_symcc_real_feedback.sh
```

只有所有断言成立才退出 `0`。缺少现有依赖退出 `77` 并打印 `SKIP`；
其他失败退出 `1`。不自动安装、运行 xmake 或补造成功产物。

## 实际执行与首次失败

| 执行 | 目录后缀 | 退出码 | 耗时 | 结果 |
| --- | --- | ---: | ---: | --- |
| 首次真实诊断 | `dh2t8sai` | 1 | 1.547 秒 | solver、重放、helper、showmap 已通过；AFL 在启动预检被 `core_pattern` 管道阻止 |
| 最小环境修正后 | `g01w67gd` | 0 | 4.331 秒 | 真实 AFL 导入两个候选 |
| 冻结断言版本 | `5k3wre2d` | 0 | 4.406 秒 | 新增严格 `foreign_0` / `src` 原件对应检查后再次通过 |

首次实际报错位于 `dh2t8sai/logs/afl-import.stdout`：

```text
PROGRAM ABORT : Pipe at the beginning of 'core_pattern'
Location : check_crash_handling(), src/afl-fuzz-init.c:2689
```

只对 AFL 子进程设置它建议的
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`，未修改 `/proc/sys/kernel/core_pattern`。
本诊断不测试崩溃检测，不从该选项下的 crash 数作结论。
首轮失败原件没有改写；总实际诊断时长约 10.3 秒，未扩大 180 秒预算。

## 输入、求解和具体执行事实

两端都由当前 `test/if.c` 以 `-O0 -fwrapv` 单文件编译。
没有使用旧的 `test/Output` 二进制，也没有伪造 solver 或 fuzzer。

| 来源 | 字节（hex） | 有符号输入整数 | `foo(x, 7)` stderr 结果 |
| --- | --- | ---: | ---: |
| seed | `05000000` | 5 | 7 |
| `solve/000000` | `00000000` | 0 | 0 |
| `solve/000001` | `092f8010` | 276836105 | 276836112 |

SHA-256：

```text
seed         2594b6a92ebfb1c3312deb7d01c015fb95e9fbe9bd7bc6b527af07813ec7b910
solve/000000 df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
solve/000001 bc48d704dabb02315e707b7a7d38e5903011e073c0e678d9602705eb7c6731fa
```

最终 `logs/solver.stderr` 实际含有：

```text
This is SymCC running with the QSYM backend
5
[STAT] SMT: { "solving_time": 0, "total_time": 1913 }
[STAT] SMT: { "solving_time": 6531 }
[INFO] New testcase: /tmp/symcc-real-feedback.5k3wre2d/solve/000000
[STAT] SMT: { "solving_time": 6531, "total_time": 9011 }
[STAT] SMT: { "solving_time": 19053 }
[INFO] New testcase: /tmp/symcc-real-feedback.5k3wre2d/solve/000001
7
```

脚本检查完整 4 字节、输入整数和符合 `-fwrapv` 的具体返回值，
不把“有候选文件”直接当分支变化；全部候选必须对应 `New testcase` 日志。
真实 `afl-showmap -e` 对零候选得到相对 seed 的新增 edge `000006:1`。

## helper 与真实 AFL 来源

helper 首次处理 seed 后记录：

```text
Merged AFL queue coverage baseline: scanned=1 coverage_updates=1 total_scanned=1 response_tail=<no-response-tail>
Generated 2 test cases, copied 2 to AFL queue
```

两份候选分别出现在：

- `afl_out/exp/exp_symcc/queue/id:000000,src:000000`
- `afl_out/exp/exp_symcc/queue/id:000001,src:000000`
- `afl_out/exp/master/queue/id:000000,src:000000,symcc`
- `afl_out/exp/master/queue/id:000001,src:000000,symcc`

两处集合哈希一致，并与上述 solver 原件一致；各文件均再次具体执行。
观察到文件和完成日志后主动给常驻 helper 发 SIGTERM，最终状态为
`returncode=-15, stop_reason=feedback_observed`，**不是 helper 自然退出成功，也不是超时 PASS**。
其可能已经启动的后续求解子孙由 subreaper 回收。

实际 AFL 命令（环境增量完整保存在 `result.json`）：

```bash
/usr/local/bin/afl-fuzz -M master \
  -F /tmp/symcc-real-feedback.5k3wre2d/afl_out/exp/exp_symcc/queue \
  -i /tmp/symcc-real-feedback.5k3wre2d/seed \
  -o /tmp/symcc-real-feedback.5k3wre2d/live-afl \
  -s 1 -V 3 -m none -t 1000 -- /tmp/symcc-real-feedback.5k3wre2d/if.afl
```

真实 `live-afl/master/fuzzer_stats`：`run_time=3`、`execs_done=20943`、
`corpus_imported=2`、`corpus_found=1`。这些不是性能比较数据。
日志实际记录先同步队列及 `Time limit was reached`，进程退出 `0`。

以下两个真实 queue 文件带唯一外部队列来源 `foreign_0`：

```text
id:000001,sync:foreign_0,src:id:000001,src:000000,+cov
id:000002,sync:foreign_0,src:id:000000,src:000000,+cov
```

二者分别对应 helper 的 `id:000001,src:000000` 与 `id:000000,src:000000`，
完整字节和哈希一致，导入后重放仍分别返回 `276836112` 和 `0`。
脚本同时检查真实 stats 的 `-F` 路径、导入计数、日志、
`sync:foreign_0`、`src` 文件名与内容，不能用 AFL 自己产生同样字节替代因果证据。
这只验证独立 `-F` 路径，不证明 named 的 sibling 同步配置。

## 二进制身份

完整路径、大小、解析符号链接后的路径均在最终 `result.json.binaries`。
关键 SHA-256：

```text
symcc                 1bf9c6a6bd5d258c22b37018c0d33871d3f3f853480c906e7950e247cfd2307a
libsymcc.so           bb2b325e42576e9349aa2a2b48503cc88ecceb1a567b68d700e4206b7675f9d1
libsymcc-rt.so        a883056334193165a0bef23d26421df895642bf6ffce081d352847308e88c737
symcc_fuzzing_helper  df70fae8cc7e6b735f0784aff46a28bfe11dc648c52179511220edf715ec69d0
clang                412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932
afl-clang-fast        eb9a6392dbf250d13e6d345295fc9e7e823396cc5ac529f6176d21481f94b500
afl-fuzz              d6d14a8c177017c0a72cec2ebf3a580c0df61592c1a51468b085f6472afd1745
afl-showmap           ef619a4d1c68fe23e6b94062338ba13b14f9ae73243537e671035368837cdbe4
libz3.so.4            eff8f0f91482d0809aae7aa0ed54cb52ff5ee9b5fe1ed1d2bfa9153c4a2fcfaf
libLLVM.so.21.1       12dca1fc2d9f5d4ff35315fc2aa3a97b615b41ec6a71d3ce545efb62c075d902
if.sym               c805193d7cd52c67e35c1ff3e2f5b6218aa92e791a4abaa608b38fbc172f2ff6
if.afl               ac706d55c8be58634f282143616c6bfa0cd97766bbc4824e6a971e34487d4a97
```

`ldd libsymcc-rt.so` 实际解析到上述 LLVM21 和 Z3 共享库，无 `not found`；
没有把独立 `z3` 命令行版本冒充实际链接版本。
现有工具本体只做身份记录，不声称整个旧 build 已与当前所有源文件逐一同步。

## 资源、清理与测试

- CPU affinity 固定为当前允许集合的单核 `0`，子孙继承。
- 编译每项最多 20 秒、直接 solver 5 秒；helper 内部目标额外套现有
  `timeout -k 1 5`，helper 主控 10 秒；真实 AFL `-V 3`，主控 8 秒。
- 总 180 秒，178 秒触发信号/监控失败并预留清理。
  每 50 ms 检查输出总量（逻辑长度与分配块取较大值）和文件数；
  目标 64 MiB/256 文件，单文件 16 MiB、禁止 core dump。
  这是合理轮询监测，不是文件系统硬配额。
- 最终运行监测峰值 `491520` 字节/`61` 文件（写 `result.json` 前），远低于上限。
  完整诊断耗时 `4.406` 秒。
- 主控记录各命令真实退出码：编译、solver、具体重放、showmap、AFL 都是 `0`；
  helper 是上述有证据主动停止的 `-15`；`remaining_descendants=[]`。
- `bash -n test/test_symcc_real_feedback.sh` 和嵌入 Python `compile(...)` 通过。
  断言使用显式 `require`，不受 Python `-O` 禁用。
- `PATH=/nonexistent /bin/bash ...` 依赖负例退出 `77`；
  `B3_OUTPUT_ROOT=/home/egoist/work` 边界负例退出 `1`，都在创建运行目录前拒绝。
- 从同一脚本加载 runner 函数的本地负例通过：
  0.2 秒超时能回收自行 `setsid()` 的孙进程；
  子命令返回 `124` 且无回流证据时必须拒绝。
  负例记录在 `/tmp/symcc-real-feedback.xe1rph7f/selfcheck.json`，
  只测试进程控制，不是 solver/fuzzer 成功替身。

未使用网络、启动 resolver、改系统设置或执行正式 fuzzing；没有全仓审计。
后续统一独立 check 由主会话安排。DNS 专项仍须在新授权下建立原始 DST1 偏移、
实际 RDATA 消费点 shadow、严格有效候选和真实 resolver 分支证据，不能用本报告补齐。
