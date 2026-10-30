# A3 实现与检查记录

## 结论

2026-10-30：A3 实现已冻结，可交独立 check。必要回归通过；没有现存测试失败。未启动真实 resolver、xmake、正式 fuzzing 或长实验，未修改历史结果、提交代码。

本记录由 A3 实施者生成，不替代独立复核或真实 resolver pilot。

## 改动路径

路径相对 `/home/egoist/work/symcc`。

| 路径 | 本轮状态与职责 |
| --- | --- |
| `tools/dns_replay_support.py` | 保留上轮共享校验和线程安全发送事实：Question、ID、QR/opcode/TC/RCODE、RR 边界及已支持 RDATA 校验 |
| `tools/{dnsmasq,smartdns,maradns,knot_resolver}_replay_harness.py` | 保留上轮接纳/发送事实联动；本轮将 UDP 接收缓冲从 4096 扩为 65535，避免无效长报文被截成合法前缀 |
| `tools/dns_diff/oracle.py` | 保留上轮可选 `fake_reply_dispatched` 解析；未改原 `ORACLE_FIELDS` |
| `patch/{cache,fuzz}/bind9/bin/named/resolver_afl_symcc_orchestrator.c` | 保留匹配 fetch、成功 hook、客户端完整结果的接纳链；同步两个镜像的 post-check proxy 表述与等价赋值 |
| `patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c` | 修复 `dispatch_query` 持锁后 `load_response_packet` 再次获取同一 mutex 的死锁；不改 A2 响应字节合同 |
| `patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.h` | 保留上轮 observer 接口；注册/注销等待回调，回调不得重入 server API |
| `patch/cache/unbound/smallapp/unbound_afl_symcc_orchestrator.c` | 补充 native parser 宽容接受的已知 RDATA 边界检查；核对 API 完成结果的映射 ID=0；保留 observer 事实和显式 post-check |
| `patch/cache/unbound/smallapp/unbound_afl_symcc_orchestrator.h` | 保留上轮可选发送事实对应成员 |
| `test/test_replay_harness_negative_control.py` | 六组最终 oracle 回归，四端 main 替身执行，包含 UDP/TCP 发送失败、首次/后续超时、4096 字节截断前缀、正负答案与旧日志兼容 |
| `test/test_native_replay_oracle.{c,sh}` | 从原 predicate/测试内公式提升为完整生产 transcript orchestrator、发送与客户端完成事件、最终 summary 解析断言；直接编译 canonical patch |
| `test/test_unbound_mutator_fidelity.{c,sh}` | 保留已有 A2 修改，本轮未续写；重跑确认仍为 117 checks |

未修改 docs、task 主工件、cache/triage/audit/reporting/main/follow_diff 或 C++ oracle owner。

## 最终合同

1. **唯一新增可选日志字段**：`fake_reply_dispatched=0|1`。Python 旧日志缺失或字段非法时为 `None`，不改变原六个字段的 `stderr_parse_status` 判定，不加入 `ORACLE_FIELDS` 比较。C++ 镜像由其他实施者负责。
2. `resolver_fetch_started` 必须来自匹配 QNAME/QTYPE/QCLASS 的实际上游请求，不从输入列表或不带 Question 的提交事件推断。
3. `fake_reply_dispatched` 必须来自匹配请求的成功注入：Python/Unbound 要求完整发送；MaraDNS TCP 要求 `sendall` 成功；BIND 要求 hook 返回成功且提供非空 response，现有 dispatch 随后同步投递。BIND 的该字段不是 socket 发送计数。
4. `response_accepted` 要求匹配 fetch、成功注入、合格客户端完成结果同时成立。错误 ID/Question、截断或不完整的已支持 RR、TC、非 QUERY opcode、本地 SERVFAIL/REFUSED/NOTIMP、未 fetch、发送失败均不能获得接纳。
5. 正 A、NXDOMAIN、NOERROR/NODATA 均可归入接纳；带 SOA 的 NXDOMAIN/NODATA 也有跨端回归。此处只统一接纳布尔分类，没有新增 `response_kind`，也不把负答案当投毒。
6. Unbound 使用 `ub_resolve` 的 API 请求，而不是原始客户端 wire；锁定源码 `libunbound/libworker.c:617` 的 `libworker_fg` 将 `qid` 设为 0。因此校验完成报文 ID=0，而非 transcript 原始 ID。此约束随上游实现升级需重新核验；不宣称 Unbound 完整 wire 与其他端相同。
7. **实际 post-check**：transcript 显式包含非空查询，producer 确实执行该查询，后续结果与该查询匹配且完整，首次已接纳，且两次查询之间没有新增上游请求，才令 `second_query_hit` 和 `cache_entry_created` 为 1。没有从首次接纳自动补造后续命中的路径。
8. 两个缓存字段始终是 **proxy**，不证明 native cache entry、新增缓存状态或投毒因果。无 post-check 时为 0 只表示没有命中证据，不能解释为“实际做过后续查询且结果为阴性”；未新增 `post_check_executed` 字段。
9. A2 保真不变：成功注入只改事务 ID，其余响应字节不修复、不截断、不下调计数。新的 RDATA 校验只作用于 oracle，不修改注入内容。

## 验证命令与退出码

工作目录均为 `/home/egoist/work/symcc`，除注明外退出码均为 **0**。

| 命令/检查 | 结果 |
| --- | --- |
| `python3 -B -m unittest discover -s test -p test_replay_harness_negative_control.py -v` | 6 tests / OK；四个 harness 最终 oracle 路径 |
| `bash test/test_native_replay_oracle.sh` | BIND/cache 43、BIND/fuzz 43、Unbound 45 checks；逐例解析生产 `ORACLE_SUMMARY` 并核对最终字段 |
| `CFLAGS='-Wall -Wextra -Werror -Wno-unused-function -Wno-unused-but-set-variable' bash test/test_native_replay_oracle.sh` | 同上通过；两个抑制项针对直接 include 整个生产文件及非 AFL fallback 的未使用项 |
| `bash test/test_unbound_mutator_fidelity.sh` | 117 checks / PASS，断言实际启用 |
| `bash test/test_named_transcript_postcheck_generation.sh` | 显式 post-check 回归通过 |
| `bash test/test_named_transcript_postcheck_generation.sh --case empty-postcheck` | 空 post-check 不生成实际查询，回归通过 |
| `bash -n test/test_native_replay_oracle.sh test/test_unbound_mutator_fidelity.sh` | 通过 |
| `git diff --check` | 通过 |
| Python `ast.parse`、字节级 LF/末尾换行检查 | 7 个 Python 文件及相关 native 文件通过 |
| BIND 两个镜像实际函数体比较 | `matching_dns_message`、`observed_dispatch_hook`、客户端 sendcb、`inject_request_bytes`、`emit_oracle_summary` 一致 |

最终日志：`/tmp/a3-python-final.log`、`/tmp/a3-native-final.log`、`/tmp/a3-native-warnings.log`、`/tmp/a3-a2-final.log`、`/tmp/a3-postcheck-{happy,empty}.log`、`/tmp/a3-{shell-syntax,whitespace}.log`。

已查 `parse_oracle_summary` 的 replay/input-model 消费点；已查 BIND cache/fuzz 两个 patch 应用清单（`named_experiment/run_named_afl_symcc.sh:955,968`）与 dispatch hook 实际投递路径。未运行会写 `.sisyphus/evidence` 的 patch-split 脚本，避免覆盖历史证据。

## 真实失败与修复证据

- 恢复时 Python 4 tests、A2 117 checks 通过，但 native runner 在 Unbound 缺 `dump_cache` 符号处退出 **1**。补充只用于测试且禁止执行的 dump 替身，避免把缓存观测模拟成成功。
- 扩大到完整 orchestrator 后，测试支架先缺 `named_g_port`、BIND/fuzz set/clear responses 符号，之后出现 `ub_resolve`/`ub_resolve_free` 与静态库重复定义，均为退出 **1**。已补最小替身，并重命名测试 API，未改真实依赖或 subjects。
- 解决链接后，Unbound 发送路径死锁由 `timeout 25s bash test/test_native_replay_oracle.sh` 复现，退出 **124**；修复重复获取 mutex 后通过。日志 `/tmp/a3-native-red-4.log`。
- 新增错误 A RDATA 长度反例在 Unbound 最终 oracle 被接纳，assert 退出 **134**；补充已知 RDATA 检查后通过。日志 `/tmp/a3-rdata-red.log`。
- 中间编译发现 `pkt_dname_len` 隐式声明，已补实际 header；严格检查还揭示非 AFL fallback 的既有未使用变量，未借机修改无关逻辑。
- 新增 MaraDNS 超时替身两次出现 `StopIteration`，退出 **1**：先漏模拟重试，再将默认 5 秒误设为 4 秒退出；最终替身推进到 6 秒，6 tests 全部通过。
- 链接仍有 `lto-wrapper: warning: using serial compilation of 13 LTRANS jobs`，是既有静态库的 LTO 提示，不是测试失败。

## 已知边界与后续

- 没有实际启动六端 resolver，未做完整二进制重建、真实网络/调度时序、native cache 因果、solver 或符号回流验证；这些属于后续 pilot，不在本批证据内。
- native 测试编译当前 patch，但使用现有锁定版本的 BIND/Unbound headers、config 和 parser 库；runner 依赖本机 subject 构建树及 AFL runtime。断言在 include `config.h` 后重新启用。
- 已知常见 RDATA 有边界检查；未知 RR 类型主要验证整体编码边界，不声称完整实现所有 RR 的语义验证。Unbound 的宽容 parser 与严格 oracle 的边界也不等于 resolver 协议一致性证明。
- 本轮没有重跑 ASan/UBSan/TSan；没有以先前 A2 sanitizer 记录冒充本轮验证。
- 旧 artifact 可读不等于符合新接纳口径；历史结果没有重新分析或改写。请独立 check 复核此冻结版本，文档与 C++ 合同镜像由主会话集成。
