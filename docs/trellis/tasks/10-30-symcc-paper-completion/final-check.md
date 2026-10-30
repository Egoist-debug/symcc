# 首批 A1–A3 独立整批复核

## 结论

2026-10-30：**首批 A1–A3 独立复核完成，未发现仍阻塞本批交付的问题。** 本审查者直接修复一处集成 fixture 和一处 Unbound 缓冲区泄漏；预审发现的 UDP 截断问题由 A3 在冻结前修复，现已独立复验。另有一项第二批 matrix 快照测试失败，明确保留，不声称仓库全测通过。

最终实跑：44 个 Python tests、9 个 C++ 测试目标、30 项公共消费链/post-check shell 检查，以及 A2 的 117 checks 和 native A3 的 BIND/cache 43、BIND/fuzz 43、Unbound 45 checks，均退出 0。A2 与 native A3 的 ASan/UBSan 复验也通过。

上下文按 fallback 读取 `check.jsonl` 全部引用（含 `backend/dns-evidence.md`）、`prd.md`、`design.md`、`implement.md`、`progress.md`。旧 `a1-check.md` 未当作现状缺陷；检查的是当前源码。未派生代理。

复核基线仍为 `paper` / `f08a6c8935c9d25ff0319fdc8b6723d49648322a`；覆盖完整 tracked diff、未跟踪的新测试/support/fixtures、调用方与文档。冻结前遵守写权限制；本审查者只改了下述两个产品仓库文件和本报告，没有覆盖实施者代码。

## Findings (fixed)

### F1：campaign-close 成功 fixture 缺少有效缓存证据（本审查者修复）

- 文件：`symcc/test/test_campaign_close_loop.sh:48-80`。
- 问题：`dump_success` 替身写入无法解析的 `"cache-entry"`，却要求成功场景 `included=1`；扩大公共消费链回归后实际退出 1，得到 `unknown=1`。
- 修复：复用 `test/fixtures/cache_semantics/{bind,unbound}.cache`，为各 resolver 提供等价且共同初态相同的真实格式快照；保留原成功/超时/缺报告断言，没有改产品语义或放宽断言。
- 复验：`bash test/test_campaign_close_loop.sh` 退出 0；`bash -n test/test_campaign_close_loop.sh` 与 `git diff --check` 均退出 0。日志 `/tmp/symcc-final-check-close-loop-fixed.log`。

### F2：UDP 响应被截成可接纳前缀（A3 冻结前修复，本审查者复验）

- 文件：`symcc/tools/dnsmasq_replay_harness.py:125,168,177`、`symcc/tools/smartdns_replay_harness.py:142,164,173`、`symcc/tools/maradns_replay_harness.py:218,307,319`、`symcc/tools/knot_resolver_replay_harness.py:186,214,223`。
- 问题：原 `recv(4096)` 在完整性校验前静默丢掉 UDP 尾部。本审查者用 `PYTHONDONTWRITEBYTECODE=1 python3 -B -` 内联构造报文和本地临时 socket 复现，退出 0：4098 字节（4096 字节合法 TXT 响应加 `dead`）的完整校验为 False，截断后的 4096 字节前缀为 True；未启动 resolver。
- 修复：冻结版本将四端首查、post-check、上游 UDP 接收统一为 `65535`，未重复改写 A3 补丁。
- 回归：`test/test_replay_harness_negative_control.py:60-66,129-151` 的 socket 替身按真实接收容量截断；完整 4096 字节响应保留阳性，附加垃圾保持阴性，验证四个 `main()` 的最终 oracle，6 tests / exit 0。

### F3：Unbound 解析缓冲区被重复初始化而泄漏（本审查者修复）

- 文件：`symcc/patch/cache/unbound/smallapp/unbound_afl_symcc_orchestrator.c:513-589`，关键位置 `:535,541,586`。
- 问题：原函数先 `sldns_buffer_new(input_len)` 分配自有数据，再用 `sldns_buffer_init_frm_data()` 覆盖数据指针；后者实现会 `memset` buffer 并改为外部固定内存，旧分配丢失。既有分配误用被本批新增的 fetch/answer 校验调用进一步触发。
- 证据：`CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' bash test/test_native_replay_oracle.sh` 原退出 1，LeakSanitizer 报 **6061 bytes / 185 allocations**，分配点在锁定 Unbound 的 `sldns/sbuffer.c:27`。日志 `/tmp/symcc-final-check-native-a3-sanitized.log`。
- 修复：删除额外 `input_copy` 的分配和释放，直接复制到 `sldns_buffer_begin(pkt)`，统一由 `sldns_buffer_free()` 释放；原始输入仍不被 parser 修改。已检索三个生产调用点（fetch、answer、query），不改语义判断或公共接口。
- 复验：同一 ASan/UBSan 命令退出 0，BIND/cache 43、BIND/fuzz 43、Unbound 45 checks 全过；严格编译警告检查与 A2 117 checks 也退出 0。没有关闭 LeakSanitizer。日志 `/tmp/symcc-final-check-native-a3-sanitized-fixed.log`。
- 防回归：保留 native runner 的 `CFLAGS` sanitizer 入口；以后修改此解析器应连同泄漏检测执行，普通断言 PASS 无法发现分配所有权错误。

## Findings (not fixed)

### 范围外失败：matrix 快照测试仍按包含 metadata 的旧计数断言

- 文件：`symcc/test/test_campaign_matrix.sh:153-158,266-274`；`symcc/tools/dns_diff/matrix.py:487-511,536-553`。
- 命令：`bash test/test_campaign_matrix.sh`，退出 1；日志 `/tmp/symcc-final-check-campaign_matrix.log`。
- 实际结果：`file_count=1,size_bytes=17`，断言期待 `file_count=2`。fixture 只放了一个 payload，当前摘要函数明确排除 `*.meta.json`，包括生成的 `queue_snapshot.meta.json`。
- 不修原因：属于 `implement.md` 第二批的快照摘要规则/旧合同回归范围，不是 A1–A3 改动。两份源码/测试本轮均未修改；不能为了全绿顺手升级该合同或覆盖历史摘要。建议第二批同步版本语义与该测试。
- `git diff --quiet HEAD -- tools/dns_diff/matrix.py tools/dns_diff/publication_audit.py test/test_campaign_matrix.sh` 退出 0，确认这些实现与测试未被本轮改动。

## Verification（实现全部冻结及机械修复后）

工作目录：`/home/egoist/work/symcc`。以下为本审查者实际执行，不引用实施者 PASS 代替验证。

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `xmake build dnslab_core_cache_analysis_test` | 0 | 增量构建通过 |
| `xmake build dnslab_core_reporting_test` | 0 | 增量构建通过 |
| `xmake build dnslab_core_oracle_test` | 0 | 增量构建通过 |
| `xmake build dnslabctl` | 0 | 增量构建通过 |
| `xmake build -r dnslabctl` | 0 | 强制重建通过；构建前后 C++ 源码/头文件/测试 SHA-256 相同，无 warning/error |
| `build/linux/x86_64/release/dnslab_core_cache_analysis_test` | 0 | 共享 fixture 回归通过 |
| `build/linux/x86_64/release/dnslab_core_reporting_test` | 0 | 通过 |
| `build/linux/x86_64/release/dnslab_core_oracle_test` | 0 | 可选字段与 JSON 回归通过 |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -B -m unittest discover -s test -p 'test_dns_diff*.py'` | 0 | 38 tests / OK |

最终 Python 全量命令（退出 **0**，**44 tests / OK**，包含 `test_dns_diff_io`）：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/test:$PWD" python3 -B -m unittest \
  test_dns_diff_cache_diff test_dns_diff_cache_parser \
  test_dns_diff_contract_regressions test_dns_diff_io test_dns_diff_schema \
  test_dns_diff_triage test_replay_harness_negative_control -v
```

以下 9 个目标均先运行 `xmake build dnslab_core_<名称>_test`，再从仓库根运行
`build/linux/x86_64/release/dnslab_core_<名称>_test`，每条命令退出 **0**：

```text
cache_analysis reporting oracle transcript contract replay_failure
concrete_adapters experiment_config lock
```

共同 cache fixture 为 26 场景 × 两种明细模式，Python/C++ 各覆盖 52 组合；
双后端审计另有 17 组合同对照。共享库强制重建时源码哈希未变，后续测试重新链接；
不直接引用旧 build 的历史成功。

下列 28 项 `bash test/test_<名称>.sh` 最终均退出 0（`campaign_close_loop` 含上述 fixture 修复）：

```text
oracle_audit_report
dnslabctl_sync_replay_secondary
dnslabctl_follow_diff_close_smoke
sample_analysis_state
follow_diff_pipeline
replay_diff_cache_contract
replay_failure_evidence
triage_contract
failure_taxonomy_report
cache_dump_parser
oracle_audit_secondary_resolver
oracle_audit_secondary_knot
campaign_report
publication_evidence_bundle
publication_readiness_audit
dns_diff_cli_smoke
case_study_contract
multi_run_aggregate
rq3_snapshot
run_comparability_contract
campaign_close_loop
campaign_secondary_knot_smoke
campaign_secondary_maradns_smoke
campaign_secondary_resolver_smoke
campaign_secondary_smartdns_smoke
dnslabctl_batch_sync_replay_command_paths
dnslabctl_sync_replay_secondary_knot
resolver_backend_matrix_compare
```

另执行下列两项，均退出 **0**（上面 28 项加这两项共 30 项）：

```bash
bash test/test_named_transcript_postcheck_generation.sh
bash test/test_named_transcript_postcheck_generation.sh --case empty-postcheck
```

### A2 / native A3 与 sanitizer

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `bash test/test_unbound_mutator_fidelity.sh` | 0 | 117 checks |
| `bash test/test_native_replay_oracle.sh` | 0 | 43 / 43 / 45 checks，最终 summary 解析一致 |
| `CFLAGS='-Wall -Wextra -Werror -Wno-unused-function -Wno-unused-but-set-variable' bash test/test_native_replay_oracle.sh` | 0 | 修复泄漏后再次通过 |
| `CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g' bash test/test_native_replay_oracle.sh` | 1 → 0 | 泄漏修复前红灯、修复后 43 / 43 / 45 checks 全过 |

A2 sanitizer 的实际编译/运行命令如下，编译与运行均退出 **0**，117 checks：

```bash
tmp=$(mktemp -d /tmp/symcc-final-a2-sanitized.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
gcc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -fno-omit-frame-pointer -g \
  -Ipatch/cache/unbound \
  -Iexperiments/subjects/unbound/release-1.24.2-build/unbound-afl \
  -Iexperiments/subjects/unbound/release-1.24.2 -I. -pthread \
  test/test_unbound_mutator_fidelity.c -o "$tmp/fidelity"
TMPDIR="$tmp" "$tmp/fidelity"
```

native runner 直接 include 整个生产文件，所以严格编译保留两项既有 unused 抑制；
仍有锁定 Unbound 静态库的 `lto-wrapper: warning: using serial compilation of 13 LTRANS jobs` 提示。
这不是零警告构建，也没有为了 PASS 隐藏新的内存错误。

### 日志与静态检查

- `/tmp/symcc-final-frozen-results.json`：最终 Python/C++/shell 命令与退出码；机械修复后重新跑全批，不只复验最新 chunk。
- `/tmp/symcc-final-frozen-*.log`：最终 9 个 C++ 目标、30 项 shell 与 Python 日志；最终 Python 完整记录为 `symcc-final-frozen-python-all.log`。
- `/tmp/symcc-final-check-native-a3*.log`、`/tmp/symcc-final-check-a2*.log`：native、字节合同、警告与 sanitizer 的真实执行记录。
- `/tmp/symcc-final-check-final-hashes.json`：最终源码与 fixture 哈希；冻结后的额外产品改动仅为上述泄漏修复。F1 在 A1 冻结后、全批冻结前完成。

- Lint：`git diff --check`、10 个变更 shell 的 `bash -n` 均退出 0；16 个 Python 变更文件 AST 编译通过，源码保持 LF。环境未安装 `ruff`、`flake8`、`shellcheck`、`clang-tidy`、`clang-format`，不声称独立 linter 全绿。
- TypeCheck：C/C++ 编译 **PASS**；环境未安装 `mypy`、`pyright`，Python 静态类型检查 **未运行**。
- Tests：本批所列回归 **PASS**；额外 matrix 测试 **FAIL（范围外，见未修项）**。

## 已复核要点、文档一致性与限制

- A1：`tools/dns_diff/cache_diff.py:13-28,278-307` 与 C++ `cache_analysis.cpp:1478-1521,1682-1689` 保守区分 unknown/incomparable；共同初态不等仍保留单端 delta，不生成有效差异或阴性。`main.cpp:666-673,898-904` 和 `follow_diff.cpp:919-929` 不伪造缺失快照。
- 公共消费：Python `audit.py:146-147` / `triage.py:401-462` 复用共同 gate，C++ `reporting.cpp:2029-2038` 要求整数版本 1、comparable、布尔真差异与非空 pair 列表；不回退单端 `has_cache_diff`。case-study 中保留该字段只是原始观察，不作为新增语义指标。
- A2：`unbound_afl_symcc_mutator_server.c:233-251,274-345` 的成功路径只写 `[0,2)` 的事务 ID，内存/文件的容量和读取失败不生成替代响应；在 A3 observer 修改后已复跑 117 checks。
- A3：四端共享 predicate 与真实 send 结果，BIND hook 的实际同步投递链位于 `patch/cache/bind9/lib/dns/dispatch.c:2256-2279`。BIND cache/fuzz 两个镜像的核心观察函数一致；已有 cache dump/persistent 差异未被误当作本次漏改。
- C++/Python `fake_reply_dispatched` 缺失/非法值均为 `null`；见 `oracle.hpp:19`、`oracle.cpp:100-104,120-121`、`test_oracle.cpp:33-79` 与 Python `oracle.py:4-11,70-73`。六项语义字段未扩展，未从接纳反推发送。
- 已复核冻结文档 `docs/DNSPoisonEvidenceContract.md:184-281`（第 9–11 节）及 `.trellis/spec/backend/dns-evidence.md`，初态/未知、发送事实、Unbound API ID=0 与 post-check proxy 均与实际代码相符；无需为上述机械修复新增语义合同。
- **验证限制**：未运行真实 resolver 端到端、真实 producer、正式 fuzzing 或论文实验；native 使用当前 patch、锁定 parser 库和事件替身，不包含真实网络调度或完整第三方库 sanitizer 重建。未跑 TSan；A2/A3 的 ASan/UBSan PASS 不证明无线程竞态。
- `second_query_hit` / `cache_entry_created` 仍只是显式 post-check 的无新增上游请求 proxy，不证明真实缓存项或投毒因果；无 post-check 的 0 不当成执行过后检的阴性。
- 第二批、真实 producer 与正式实验仍未授权，不以本轮测试替代其门槛。没有提交、推送或覆盖历史结果。
