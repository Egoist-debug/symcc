# Research: 第二批 B3 最小真实符号链路

- Query: 核验既有 SymCC 编译器/runtime/solver、DNS 输入传播、helper 与 AFL 回流的最小可执行边界。
- Scope: internal；`/home/egoist/work/symcc` 只读；不派生代理，不执行 resolver/fuzzing，不生成实验结果。
- Date: 2026-10-30

## Findings

### 结论与立即可分派的最小计划

**工具链不缺 binary/backend；按主会话选择复用 `test/if.c`，不重建 SymCC、不启动 DNS。** 现有编译器为 LLVM 21，runtime 含真实 QSYM/Z3 求解器，helper 实际是 **C++ 版本**，不是同名 Rust 目录的实现。

1. 获批后只新建一个真实集成测试，编译 `test/if.c` 的 SymCC/AFL 两个小二进制，验证输入整数 5 → `foo` 分支约束 → solver 产出候选 → 具体 `foo` 返回值由 7 改变 → 真实 `afl-showmap` 筛选 → helper 队列文件。下文给出命令。
2. 此测试可证明工具链与队列落盘，**不能直接证明运行中 AFL 已消费，更不能证明 BIND RDATA 求解**；另用 3 秒隔离 AFL 的 `-F` 导入验证消费，须单独批准执行。
3. DNS 小 parser 可以快速另编译为 SymCC 目标，但现存 `dns_parser` / `dns_response_parser` 是普通二进制；BIND SymCC binary 虽存在，源树与当前 patch 不完全相同，不能直接把旧 binary 跑通当当前源码证据。
4. 当前没有已验证的默认 DST1 内存链断点，**不应先改通用 runtime 或开 `SYMCC_MEMORY_INPUT`**。真实 BIND 分支证据保留未完成，交主会话另分配测试写权/原生构建与执行额度。

下文路径除特别说明均相对 `/home/egoist/work/symcc`；本报告已冻结，不调查 RQ1/统计、全 DNS 协议或全仓。

### 1. 可用构建及源码身份

| 已读文件 / 二进制 | 本轮确认 |
| --- | --- |
| `build/linux/x86_64/release/symcc` | `:17-20,41-47` 指向同目录 pass/runtime 与 `/usr/lib/llvm-21/bin/clang`；`timeout 3 …/symcc --version` 退出 0，Clang **21.1.8**。版本输出不等于 pass 已成功插桩。 |
| `build/linux/x86_64/release/sym++` | `:17-21,38-43` 同工具链；未设置 libc++ 路径时要求显式 `SYMCC_REGULAR_LIBCXX`。本计划用 C，无需此项。 |
| `.xmake/linux/x86_64/xmake.conf:2-13` | `arch=x86_64`、`mode=release`、`backend=qsym`、LLVM prefix `/usr/lib/llvm-21`。 |
| `build/linux/x86_64/release/libsymcc.so` | ELF 依赖 `libLLVM.so.21.1`；源码 owner `compiler/Symbolizer.cpp`，构建见 `xmake.lua:195-252`。 |
| `build/linux/x86_64/release/libsymcc-rt.so` | ELF 依赖 `libz3.so.4`、`libLLVM.so.21.1`；`nm -D -C` 实见 `qsym::Solver::addJcc`、`_sym_get_input_byte`、`read_symbolized`、`fread_symbolized`。 |
| `runtime/xmake.lua:9-32` | QSYM 后端编入 `src/backends/qsym/Runtime.cpp` 和内嵌 QSYM `solver.cpp` 等，链接 Z3/LLVM；不是外部 `z3` 子进程。`/usr/bin/z3 --version` 为 **4.13.3**，未调用共享库 API 核实库版本。 |
| `build/linux/x86_64/release/symcc_fuzzing_helper` | `--help` 退出 0，支持 `-a/-o/-n/-t`、`@@`、`--require-poison-eligible`。`strings` 含 C++ banner、AFL baseline 文本；owner 为 `util/symcc_fuzzing_cpp/`，构建在该目录 `xmake.lua:1-14`。 |
| `util/symcc_fuzzing_helper/` | Rust 源码仍在，`Cargo.toml:15-19` 为 0.1.0；本轮未找到/验证它的已编译 target，不需要 Cargo 重建。 |
| `/usr/local/bin/afl-{fuzz,showmap,clang-fast}` | AFL++ **5.02c**；前两者 `-h` 正常打印帮助、退出 1，非启动实验；`afl-clang-fast --version` 退出 0、Clang 21.1.8。 |
| `build/linux/x86_64/release/test/Output/{read,if,file_input}.c.tmp` | 旧测试产物存在；不直接复用为当前源码证据。重新编译一个小文件更清楚。 |
| `build/linux/x86_64/release/{dns_parser,dns_response_parser}` | `readelf -d` 无 `libsymcc-rt`，`nm -D` 为普通 `read@GLIBC_2.2.5`；构建 `gen_input/xmake.lua:139-151` 未加 SymCC 插桩。现有文件不能作符号 parser 运行证据。 |

本轮 ELF SHA-256（身份快照，不声称所有源文件与 build 一致）：

```text
libsymcc.so           bb2b325e42576e9349aa2a2b48503cc88ecceb1a567b68d700e4206b7675f9d1
libsymcc-rt.so        a883056334193165a0bef23d26421df895642bf6ffce081d352847308e88c737
symcc_fuzzing_helper  df70fae8cc7e6b735f0784aff46a28bfe11dc648c52179511220edf715ec69d0
```

BIND 最小身份检查：

- `experiments/subjects/bind9/v9.20.22-{afl,symcc}/bin/named/named` 均是 libtool wrapper；真实 ELF 为各自 `bin/named/.libs/named`。
- SymCC ELF 直接依赖 `libsymcc-rt.so`，RUNPATH 为上述 release 目录，SHA-256 为 `f3cdc8a00baead50179886b51d867667c0fc57ad1f76c1be4832bd550d3d29a6`；AFL ELF 为 `8f43c7e5d828fb61648ecb866b9af38f4d4959797c4268c3f5e7676874f7f3c6`。
- 两树 `Makefile:268,271` 分别使用 `/usr/local/bin/afl-clang-fast` 与 release `symcc`，`CFLAGS=-g -O2 …`。
- 两树的 `bin/named/resolver_afl_symcc_mutator_server.c` 与当前 fuzz patch 字节相同；**orchestrator、`lib/dns/dispatch.c` 均不相同**。差异可能含版本适配 `[INFERENCE]`，未展开；不能据此断言“未打补丁”，也不能证明当前构建已同步。
- producer 构建意图见 `named_experiment/run_named_afl_symcc.sh:1359-1373`：`CC/CXX` 为 SymCC，`CPPFLAGS=-DENABLE_AFL`，configure 暂用 `SYMCC_NO_SYMBOLIC_INPUT=1`。该脚本由 B1 修改，行号仅为本轮读取快照。

### 2. 已核对的真实链路

**工具链：** `test/if.c:36-43,48-53` 是本次执行路线：stdin 整数进入 `foo(x,7)`，首先比较 `2*x < 7`，否则比较 `x % 7`。用 `-O0 -fwrapv` 编译两端，避免不同优化/有符号溢出语义干扰。以下 `read.c` 是已读的更简单同源链说明，不再另开路线：

`test/read.c:26` 的 `read(0,…,1)` → `runtime/src/LibcWrappers.cpp:97-101,174-190` 默认识别 stdin，调用 `_sym_make_symbolic` 并维护输入偏移 → QSYM runtime `:332-334` 为该偏移创建 `Read` 表达式 → `test/read.c:35` 的比较 → `compiler/Symbolizer.cpp:485-498` 插入路径约束调用 → `runtime/src/backends/qsym/Runtime.cpp:324-329` → QSYM `solver.cpp:160-187,518-527` 否定分支、求解 → `solver.cpp:296-335` 用 model 覆盖原输入字节并输出真实 testcase。

这里 `solver.cpp` 的完整前缀是 `runtime/src/backends/qsym/qsym/qsym/pintool/`。QSYM 也会输出 optimistic 候选，因此必须具体重放，不能仅数文件。

**实际 C++ helper 与 AFL 入口：**

- `util/symcc_fuzzing_cpp/src/symcc.cpp:75-88,95-142` 把输入复制到 `.cur_input`；无 `@@` 时送 stdin，有 `@@` 时替换路径并设 `SYMCC_INPUT_FILE`，子目标使用 `timeout -k 5 90`。
- `src/main.cpp:1235-1244` 的路径是 **`-o ROOT -n exp -a master` → `ROOT/exp/master/queue`，输出 `ROOT/exp/exp_symcc/queue`**。Rust `util/symcc_fuzzing_helper/src/main.rs:284-301` 则是 `ROOT/master/queue` 与 `ROOT/name`，两者参数布局不可混用。
- C++ `src/main.cpp:1014-1055,1157-1174` 合并已有 AFL 队列覆盖，避免旧覆盖假回流；`:1078-1085` 可校验 DST1；`:1090-1114` 真跑 showmap 后写两个队列。showmap 命令在 `src/afl.cpp:285-320`，单次 5000 ms。
- 新候选同时进入 `exp_symcc/queue/id:NNNNNN,src:XXXXXX` 和 `master/queue/id:NNNNNN,src:XXXXXX,symcc`，见 `src/testcase.cpp:42-62`、`src/afl.cpp:335-350`。
- **落入 master 文件夹不等于 AFL 内存队列已经消费**。可通过 sibling queue 的同步或 `afl-fuzz -M … -F <helper队列>` 验证；本轮只核验 `-F` 的本地帮助，未读 AFL 实现/跑导入，消费行为仍标 `[INFERENCE]`。
- `src/afl.cpp:347-350` 吞掉复制错误，`src/main.cpp:1103-1114` 也可在复制失败后返回 New；故 `Generated … copied …` 不是可靠的单独验收依据，必须检查实际文件与内容哈希。

### 3. 经批准后执行的精确最小命令

**以下全部未执行。** `B3_OUTPUT_ROOT` 必须由主会话批准，不能指向历史结果/现有 `named_experiment/work`。这是**真实 compiler/runtime/solver/showmap + 显式队列夹具**，不是独立 producer 实验；`fuzzer_stats` 明确是为接口准备的夹具，不用于 provenance/audit。

```bash
set -euo pipefail
S=/home/egoist/work/symcc
W=$(mktemp -d "${B3_OUTPUT_ROOT:?先指定获批的新输出父目录}/symbolic.XXXXXX")
export W
mkdir -p "$W"/{tmp,solve,seed,afl_out/exp/master/queue}
export TMPDIR="$W/tmp"
unset SYMCC_MEMORY_INPUT SYMCC_NO_SYMBOLIC_INPUT SYMCC_INPUT_FILE \
  SYMCC_AFL_COVERAGE_MAP SYMCC_LOG_FILE SYMCC_RUNTIME_DIR SYMCC_PASS_DIR \
  SYMCC_CLANG SYMCC_HIGH_VALUE_MANIFEST SYMCC_SEMANTIC_FRONTIER_MANIFEST
export SYMCC_RANDOM_SEED=1
ulimit -c 0
ulimit -f 16384
CPU=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
B="$S/build/linux/x86_64/release"
timeout -k 1 20 taskset -c "$CPU" "$B/symcc" -O0 -fwrapv \
  "$S/test/if.c" -o "$W/if.sym"
timeout -k 1 20 taskset -c "$CPU" /usr/local/bin/afl-clang-fast -O0 -fwrapv \
  "$S/test/if.c" -o "$W/if.afl"
printf '\x05\x00\x00\x00' >"$W/seed/five"
timeout -k 1 5 taskset -c "$CPU" env SYMCC_OUTPUT_DIR="$W/solve" \
  "$W/if.sym" <"$W/seed/five" >"$W/sym.stdout" 2>"$W/sym.stderr"
timeout -k 1 2 "$W/if.afl" <"$W/seed/five" 2>"$W/baseline.stderr"
test "$(tail -n 1 "$W/baseline.stderr")" = 7
python3 - "$W" <<'PY'
import pathlib, subprocess, sys
w = pathlib.Path(sys.argv[1])
for p in sorted((w / "solve").iterdir())[:32]:
    if not p.is_file() or p.stat().st_size != 4:
        continue
    data = p.read_bytes()
    r = subprocess.run([str(w / "if.afl")], input=data, capture_output=True, timeout=1)
    lines = r.stderr.splitlines()
    if r.returncode == 0 and lines and lines[-1] != b"7":
        (w / "candidate").write_bytes(data)
        break
else:
    raise AssertionError("未找到具体 foo 返回值改变的 solver 候选")
PY
timeout -k 1 2 "$W/if.afl" <"$W/candidate" 2>"$W/concrete.stderr"
test "$(tail -n 1 "$W/concrete.stderr")" != 7
cp "$W/seed/five" "$W/afl_out/exp/master/queue/id:000000,orig:seed"
printf 'command_line : /usr/local/bin/afl-fuzz -i %s/seed -o %s/afl_out/exp -- %s/if.afl\n' \
  "$W" "$W" "$W" >"$W/afl_out/exp/master/fuzzer_stats"
rc=0
timeout -k 2 10 taskset -c "$CPU" "$B/symcc_fuzzing_helper" \
  -o "$W/afl_out" -n exp -a master -t "$W/if.afl" -- "$W/if.sym" \
  >"$W/helper.log" 2>&1 || rc=$?
printf 'helper_wrapper_exit=%s\n' "$rc"
python3 - "$W" <<'PY'
import pathlib, subprocess, sys
w = pathlib.Path(sys.argv[1])
for rel, pattern in [("exp_symcc/queue", "id:*"), ("master/queue", "*,symcc")]:
    found = False
    for p in sorted((w / "afl_out/exp" / rel).glob(pattern))[:32]:
        if p.stat().st_size != 4:
            continue
        r = subprocess.run([str(w / "if.afl")], input=p.read_bytes(),
                           capture_output=True, timeout=1)
        lines = r.stderr.splitlines()
        if r.returncode == 0 and lines and lines[-1] != b"7":
            found = True
            break
    assert found, "队列没有可具体重放的分支变化候选：" + rel
PY
```

验收还须保存 `sym.stderr` 的真实 backend/SMT/New testcase 信息，以及 seed/candidate/两个队列副本 SHA-256。退出 124 仅表示 helper 的常驻循环被时限终止，**不是 PASS**；以实际求解/重放/队列内容断言为准。如果工具环境污染或任一断言失败，停止，不用替身目标补成功。

**另行批准 3 秒真实 AFL 消费时：**

```bash
env -u AFL_CUSTOM_MUTATOR_LIBRARY -u AFL_CUSTOM_MUTATOR_ONLY \
  AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_IMPORT_FIRST=1 \
  timeout -k 2 8 taskset -c "$CPU" /usr/local/bin/afl-fuzz \
  -M master -F "$W/afl_out/exp/exp_symcc/queue" \
  -i "$W/seed" -o "$W/live-afl" -s 1 -V 3 -m none -t 1000 \
  -- "$W/if.afl" >"$W/afl-import.log" 2>&1
```

`-F` / `-V` 已核对本地帮助；`AFL_IMPORT_FIRST` 未单独验证。需看到 `live-afl/master/queue` 中与 helper 候选哈希相同且带同步来源的条目、导入日志/计数，不能把 AFL 自己生成同类输入当 helper 因果证据。若 3 秒内无可区分导入来源，记未完成，不自动延长。此独立 `-F` 验证也不证明 named 现有 sibling 同步设置已经工作。

**资源与清理：** 单核串行；编译上限各 20 秒、直接 solver 5 秒、helper 外层 10 秒、导入外层 8 秒，不启动 resolver。主会话应为完整测试设置 **180 秒进程树预算**；helper 内层另建 `timeout` 进程组，外层退出不保证子孙已清理，最坏内部还有 90+5 秒，结束时必须检查/回收本测试进程。目标输出预算 **64 MiB、256 个文件**，仅新目录，超出即停止；`ulimit -f` 只是单文件 16 MiB 限制，不是总磁盘硬配额，硬限制须由主控监控/已有隔离环境实施。不要给 SymCC 设置未经验证的紧 `RLIMIT_AS`（shadow 映射不同于实际驻留内存）。

### 4. DNS 读取/生成与缺少的证据

| 路径 | 当前证据与边界 |
| --- | --- |
| `gen_input/src/SymCCRunner.cpp:75-120` | 输入先写临时文件，fork 后 stdin 模式 `dup2`，再 exec 目标；`gen_input/src/main.cpp:546-553` 默认 `UseStdin=true`。**父进程 shadow 不跨 exec**，但子目标的插桩 `read(0)` 会重新按真实输入字节建表达式，所以这段临时文件不是天然断点。文件模式只设置路径、不传 argv，不能套用需 `argv[1]` 的目标。 |
| `gen_input/test/dns_{parser,response_parser}.c:118-121 / :89-91` | 都读 stdin，不需手工标记；缺的是对应**已插桩的小 parser binary**。获批后可用上述 `symcc -O0 gen_input/test/dns_response_parser.c -o "$W/dns-response.sym"` 单文件编译。response parser `:104-107` 的 QR 分支可做真实 DNS wire smoke，但它不是 resolver RDATA 分支，也不是 DST1。 |
| `patch/fuzz/bind9/bin/named/resolver_afl_symcc_orchestrator.c:489-505,567-626,1192-1218` | stdin/指定文件读取；DST1 按原输入偏移保留 response 指针。虽仍 materialize response 文件，但随后调用 `set_responses`，默认可走内存。 |
| `patch/fuzz/bind9/bin/named/resolver_afl_symcc_mutator_server.c:325-337,410,466` | 内存 response 优先，经 memcpy 到 packet、sections、response；`runtime/src/RuntimeCommon.cpp:104-110` 负责复制 shadow。 |
| `patch/fuzz/bind9/lib/dns/dispatch.c:2225-2249` | synthetic UDP hook 将 response 直接送 `udp_dispatch_response`，绕过实际 socket 收包。**源码支持内存链必要条件，但没有本轮真实 shadow/分支/候选观察。** |
| fallback 文件与 socket | 非输入文件 `fread` 会清 shadow：`LibcWrappers.cpp:258-272`。helper 外挂 response-tail 只复制文件/传路径，不能因此声称第二文件也符号化；默认单输入模型不会自动串联 socket/独立进程 shadow。Unbound socket 边界沿用 `research/code-gaps.md:154`，未重查。 |

最终 DNS 门槛仍是：原始 DST1 偏移 → 实际 RDATA 消费点 `_sym_read_memory` 非空 → 受该字节控制的分支产生候选 → 候选 DST1 严格有效 → 具体执行分支改变 → AFL 实际导入。不能用 parser QR 翻转、手工 `make_symbolic` 或普通 replay 替代。

### 5. 最小写权 / 可测试边界

- **立即必要：** 只分配新测试 `test/test_symcc_real_feedback.sh`（建议名，尚未创建），复用 `test/if.c` 与现有工具；涵盖清理、真实 solver/重放/队列断言、资源预算。**目前没有证据要求先改 compiler/runtime/solver 产品代码。**
- **现有测试不能替代：** `test/test_track3_harness_and_shadow.sh:11-29,45-84` 是 gcc 字节测试 + 单独 memory-input probe；`test/test_symcc_afl_coverage_baseline.sh:55-109` 使用假的 `afl-showmap` 与复制输出的 shell target，仅测调度/合同。
- **若要求 helper 的“copied”本身成为可信计数：** 最小候选 owner 为 `util/symcc_fuzzing_cpp/src/afl.cpp:335-350` 和 `src/main.cpp:1098-1114`，让复制失败可见且不计 New；先加不可写目标目录的负例。并非跑通小目标的前置修改。
- **DNS 下一步只给测试写权：** 新 DNS 真实 shadow/分支测试，或扩展现有 Track 3 测试，但须编译生产 mutator/实际消费点，不能复制 parser 假装生产路径；先解决当前 BIND source/build 对应性。若第一个 shadow 丢失点被观测到，再由主会话授权那个具体产品文件，不先改整条链。
- 不触及 B1 的 named producer、B2 的 matrix/audit/schema；不扩展 `gen_input` 架构、RQ1/统计或实验编排。

### 6. 相关规范与参考

- 已读任务 `prd.md`、`design.md:35-44,57-63`、`implement.md:57-86`，优先复用 `research/code-gaps.md:138-160`、`research/experiment-gaps.md`；未加载角色隔离的 JSONL。
- 已读 `.trellis/workflow.md`、`.trellis/spec/backend/{index,dns-evidence,quality-guidelines,directory-structure}.md`；要求原始输入保真、真实状态/来源与测试证据，不把旧 build 或 ready 当科学结论。
- 外部参考：未检索 web/论文；版本来自本地 `--version/-h` 和 ELF。没有 Git 操作，未重新确认提交身份。

## Caveats / Not Found

- **已验证**仅指文件/源码/ELF/版本帮助核验；上述命令方案的可运行结果均为 `[INFERENCE]`。没有编译、求解、重放、fuzzing、resolver 启动或新实验结果。
- 没有发现工具链缺 backend；已确认现成 DNS parser 未插桩，BIND build 与 patch 的完整对应关系未建立。最小测试可立即实施，完整 DNS B3 不能先标完成。
- 仅修改本报告；没有修改产品/其他代理文件、安装依赖、重建、清理旧结果或使用网络。
