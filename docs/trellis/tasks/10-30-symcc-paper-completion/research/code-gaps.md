# Research: SymCC 论文有效性代码缺口复核

- Query: 复核旧审查 F1–F5/F7–F9，识别首批实施所需的阻塞、已修复项和最小回归标准。
- Scope: internal；只读当前 `/home/egoist/work/symcc` 工作树，聚焦缓存语义、响应注入、acceptance oracle、符号传播。
- Date: 2026-10-30
- 主基线：主会话提供 `f08a6c8935c9d25ff0319fdc8b6723d49648322a`。未执行任何 git 操作，未独立验证工作树与该提交完全一致。
- 阶段：planning；本报告不是实施授权。按最新要求收敛为 **3 项确认的代码阻塞 + 1 项符号执行证据门槛**，不再扩大测试。

## Findings

### 结论

**旧 F1–F9 不能照抄成“仍全部存在”，也不能凭新增回归文件宣布全部解决。** 当前源码已修复多个原始案例，但仍有三项直接影响论文归因的缺口：

1. **F1：Python 仍把两端同义缓存填充升级为 `semantic_diff`；C++ 的语义投影也未消除真实 parser 的实现细节。**
2. **F2：Unbound 的 TC/RA/RCODE 原始问题已修，但仍单方面截断、修复输入报文。**
3. **F3：本地 NOTIMP 等错误响应的旧误报条件已收紧，但 acceptance 判定仍不完整且跨 resolver 不一致。**
4. **F4：默认 BIND9 transcript 的文件重读断点已有内存路径绕过；现有测试仍不足以证明“真实 resolver RDATA 分支求解并生成可回放 DST1”。** 这是待补的论文证据，不是本轮确认默认符号链仍然断裂。

状态定义：

- `confirmed`：当前源码能直接确定，或本轮有限安全断言已验证；会明确区分静态与动态证据。
- `historical`：旧审查的具体缺陷条件已被当前源码改变；不代表所有相关场景已通过运行验证。
- `inference / [INFERENCE]`：推断或未运行的边界，不能当作已复现结果。

### 旧发现逐项状态

代码路径以下均相对 `symcc/`；`.trellis/` 路径相对 `/home/egoist/work`。

| 旧项 | 当前状态 | 首批处理 |
| --- | --- | --- |
| F1 缓存身份差异及单端变化误分类 | **部分 historical，残留 confirmed**。C++ 已排除 resolver/view/section 并改用成对差异；Python 仍有旧分类条件，C++ 实际字段仍缺统一语义。 | 阻塞 B1 |
| F2 Unbound 改写响应 | **部分 historical，残留 confirmed**。有效 tail 已保留 TC/RA/RCODE；RR 截断和计数修复仍在。 | 阻塞 B2 |
| F3 本地错误响应被接受 | **部分 historical，残留 confirmed**。三种 Python adapter 加了 fetch、RCODE 条件；query identity、完整性、实际发送证据和负缓存口径未统一。 | 阻塞 B3 |
| F4 文件重读丢 shadow | **默认 BIND9 transcript 旧断点 historical；真实分支闭环待验证**。不能继续说默认必然从文件读取响应。 | 证据门槛 B4 |
| F5 QNAME 变长不重定位 | **旧示例 historical；边界待验证**。已有指针重定位、部分 RDATA 域名校验和专项测试源码。 | 不纳入本批扩展测试 |
| F7 压缩 donor 被一律拒绝 | **旧 `c0 0c` 示例 historical；跨 RR 移植待验证**。已接受压缩 RR，异名 donor 有重编码；同 identity 仍直接复制 RR。 | 待验证清单 |
| F8 Hybrid 丢掉原响应骨架 | **旧有 Answer 种子的固定拼接问题 historical；通用字段保持待验证**。现在沿用完整 seed 的前后两段。 | 待验证清单 |
| F9 未初始化 cleanup 状态 | **原始未初始化问题 historical；环境恢复边界待验证**。生产声明和 parser 早退初始化已修改。 | 可独立安排小修，不据旧报告重报未初始化 |

### B1 / F1：缓存 canonicalization 与 Python/C++ 分类契约不闭合

**confirmed（动态 + 静态），优先级 P1。**

已修部分：

- `dnslab_core/src/cache_analysis.cpp:954-968` 的 `toSemanticJson` 不再放入 `resolver/view/section`。
- `dnslab_core/src/cache_analysis.cpp:1005-1007` 的 `cacheHasDiff` 改为检查 `ResolverDifferences`，不再以单端变化直接判跨端差异。
- `dnslab_core/test/test_cache_analysis.cpp:148-178` 新增同 RR、仅 TTL 不同、真正 RDATA 不同三个成对测试。这里只读过源码，未编译运行。

当前阻塞：

1. **Python 旧分类仍在。** `tools/dns_diff/triage.py:85-89` 对两端 `has_cache_diff` 做 `any()`；`:455-458` 在细节触发且有 delta 时给出 `cache_diff_interesting`。`tools/dns_diff/cache_diff.py:108-134` 只构建单端 before/after payload，没有跨端语义比较。
2. **本轮直接调用生产 Python 函数**：空 before，两端 after 都只有 `example.com. A 192.0.2.1`，只有 resolver 名不同；oracle 两端一致且 `timeout=False`。`triggered=True` 得到：

   ```text
   diff_class=cache_diff_interesting
   failure_bucket_primary=semantic_diff
   case_study_candidate=True
   ```

   `triggered=False` 则是 `cache_diff_benign / valid_negative`。因此不能把“删掉 C++ resolver 字段”视为整个流水线已修好。
3. **C++ 投影仍包含异构表示。** `cache_analysis.cpp:960-966` 保留 `qtype/rrtype/cache_type/flags`。BIND RR parser 生成 `cache_type=rrset`、`class=IN`（`:143-156`）；SmartDNS 同类 RR 生成 `cache_type=packet`，并把 `class=1`、命中次数、速度和插入/替换时间放入 flags（`:662-678`）。Unbound 还会生成独立 MSG 记录（`:162-185`）。这些差异仍会进入比较。
4. `cache_analysis.cpp:963-965` 对所有 RDATA 文本做小写转换，没有按 RR 类型区分域名和 TXT 等不应忽略大小写的数据；`:817-820`、`:826-838` 则先按含实现字段的原始 key 求 delta。**[INFERENCE]** 可同时造成表示噪声假阳性及大小写敏感 RDATA 假阴性；本轮未运行 C++ 成对样例测量。

调用方与影响范围：

- C++：`dnslab_core/src/main.cpp:848-875`，先判断是否存在状态变化，再构建详细 cache diff 和 triage。
- Python：`tools/dns_diff/follow_diff.py:552-585`，读取两端缓存、调用 `build_cache_diff` 并继续生成 triage。
- 下游分类投影：`dnslab_core/src/cache_analysis.cpp:1059-1076`、`tools/dns_diff/triage.py:282-302`。因此会影响候选选择，而不只是显示文本。

最小修复建议：

- 在现有缓存分析边界上明确“原始观测 / 单端变化 / 跨端语义差异”，不要新增另一套平行报告系统。
- 先对现有 RR 类型实现类型感知的共同投影，再求语义 delta；排除实现计时、命中计数等元数据，保留真正的类型、class、正负答案与 RDATA 区别。
- 让 Python 和 C++ 消费同一语义契约并使用同一组 fixture；历史 JSON 保持可读，不重写历史结果来掩盖口径变化。

最小回归：

- 两端相同 RR 必须 `no_diff`、不得升级 case candidate；TTL 漂移同样不构成结构差异；真正 IP 不同必须保留。
- 至少一组从真实格式 dump parser 进入比较的 BIND/Unbound/SmartDNS fixture，而非只手工构造同形 `CacheRecord`。
- TXT 大小写不同必须保留差异；域名大小写、末尾点按明确规则等价。Python/C++ 的 triage 结果一致。

### B2 / F2：Unbound 响应保真只修复了 header 特例

**confirmed（静态），优先级 P1。**

- **historical**：`patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c:501-511` 已采用 `tail_flags_hi & 0x06` 和完整 `tail_flags_lo`，不再对有效空 NOERROR 强制 NXDOMAIN；原 TC/RA 问题已改变。`test/test_unbound_mutator_fidelity.c:22-60` 覆盖这个具体案例，未在本轮运行。
- **仍然改写**：该 mutator `:401-446` 逐 RR 解析、在失败时下调 AN/NS/AR 计数，并只复制 `safe_end` 之前的字节。BIND fuzz 对应路径 `patch/fuzz/bind9/bin/named/resolver_afl_symcc_mutator_server.c:406-414` 保留 Question 后全部尾段，规则不一致。
- Unbound `:477-494` 在 tail 无效时还可能返回新造的空回复；有效 tail 的 Question 及高位部分 flags 也取自实时 upstream query（`:477-504`），而不是仅改事务 ID。Python dnsmasq 的正常响应注入主要只换 ID（`tools/dnsmasq_replay_harness.py:134-140`）。
- 另一输入边界：Unbound 从 client packet 提取 qname/qtype/qclass（`patch/cache/unbound/smallapp/unbound_afl_symcc_orchestrator.c:442-492`），再调用 `ub_resolve`（`:531`），并不是把原始 client wire 直接送入 resolver。**[INFERENCE]** 若论文比较 opcode/flags 等 client-wire 行为，必须先限定共同可比输入范围，不能认为同一 DST1 自然保证同一操作。

调用链：

`execute_transcript_case`（Unbound orchestrator `:648-675`）→ 内存 response 列表 → `load_response_sections`（mutator `:338-446`）→ `build_dns_response`（`:450-515`）→ UDP `sendto`（`:540-551`）。

最小修复建议：

- 统一允许改写字段和无效输入策略；默认只改关联所必需的字段，不为单个 resolver 静默修复 RR。
- 记录实际注入字节与原 response 的对应关系；被统一排除的输入要与 resolver 自行拒绝区分。
- client-wire 不可比较部分可以先明确排除，避免为了第一批验证重写整个 Unbound harness。

最小回归：

- 不启动 resolver，直接比较各 builder 的实际输出：空 NOERROR+TC、NXDOMAIN、尾部垃圾、截断 RR、计数不符。
- 断言除白名单字段外逐字节一致；若拒绝，所有 adapter 返回同一类受控失败，不能一端修复、一端原样发送。

### B3 / F3：acceptance oracle 仍不足以支持跨 resolver 接受率

**confirmed（动态 + 静态），优先级 P1。**

已修部分：

- dnsmasq、SmartDNS、MaraDNS 已要求首次出现 upstream 查询，并检查响应 QR/RCODE；原 `bool(response)` 不再是唯一条件：分别见 `tools/dnsmasq_replay_harness.py:179-197`、`tools/smartdns_replay_harness.py:175-193`、`tools/maradns_replay_harness.py:326-342`。
- `test/test_replay_harness_negative_control.py:8-56` 的 NOTIMP/REFUSED/SERVFAIL 控制本轮运行通过。但它测试的是响应判定函数，不是完整 oracle 状态机。

当前缺口：

- 三个 `is_acceptable_dns_response` 只看长度、事务 ID、QR、RCODE；没有验证 Question identity 或完整 RR（dnsmasq `:76-88`；SmartDNS `:76-88`；MaraDNS `:68` 起）。
- 本轮直接调用当前函数，**同 ID 但错误 Question**、**声称有 Answer 但只有 12 字节 header** 都返回 `True`。
- Knot `tools/knot_resolver_replay_harness.py:114-121` 不接收 query 参数，仅要求 `QR=1, RCODE=0, ANCOUNT>0`；错误 ID 且截断 RR 也返回 `True`。NXDOMAIN 在前三者返回 `True`、Knot 返回 `False`。这是确认的判定口径不一致，不是对 NXDOMAIN 是否应算“漏洞”的判断。
- `fake_reply_dispatched` 由“出现 upstream query 且 response 列表非空”推导（如 dnsmasq `:181-182`），没有以成功发送事件为事实来源；列表先 append，之后才 `sendto`（`:134-140`）。**[INFERENCE]** 发送异常等路径可能与宣称的 dispatched 不一致，本轮未模拟。
- Unbound 用 `UB_NOERROR && result->answer_len > 0`（orchestrator `:531-533,684-688`）；上游 `libunbound/unbound.h:149-173` 明确另有 `rcode/havedata/nxdomain`，`answer_len` 只是报文长度。BIND cache 则用请求完成加 replied 增量（`patch/cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c:1100-1104`）。
- Knot 还有无 post-check 时从 `response_accepted` 推导 `cache_entry_created` 的分支（`:239`），不能与观察到第二次缓存命中混称同一事实。

最小修复建议：

- 统一六端必要事实：匹配的 fetch、成功注入的具体 response、匹配且可完整解析的客户端结果；分别记录正答案、负答案、本地拒绝、格式错误、超时。
- `second_query_hit` 保持明确的缓存代理含义；没有 native cache 证据时，不宣称已证明真实 cache entry 或投毒。
- 复用同一响应校验逻辑/fixture，避免继续复制三份略有差异的 predicate。

最小回归：

- 保留现有本地错误负对照，增加错误 ID、错误 QNAME/QTYPE/QCLASS、截断 RR、未 fetch、发送失败。
- 增加正 A、NXDOMAIN、NODATA；先确定正负答案合同，再要求六端使用一致分类。
- 使用替身事件/纯函数验证最终 oracle 字段，而不仅测试 `is_acceptable_dns_response`。

### B4 / F4：先补真实符号闭环证据，不重复修已经绕过的文件路径

**historical + 待验证证据门槛；不是本轮已确认的默认链路故障。**

已确认当前代码变化：

- BIND fuzz orchestrator `patch/fuzz/bind9/bin/named/resolver_afl_symcc_orchestrator.c:1123-1125` 将 transcript 中 response 指针交给 mutator；mutator `:325-337` 优先 `memcpy` 内存响应并提前返回，不走 `fread`。
- 同文件 `:410,466` 继续用内存拷贝传递尾段；`patch/fuzz/bind9/lib/dns/dispatch.c:2225-2249` 经合成 UDP hook 直接交给 response dispatch。
- `runtime/src/LibcWrappers.cpp:405-415` 的插桩 memcpy 调用 `_sym_memcpy`；`runtime/src/RuntimeCommon.cpp:104-110` 复制 shadow。文件 fallback 仍会清空非输入文件 shadow（`LibcWrappers.cpp:266-272`），但不能再用这个 fallback 证明默认 transcript 必经它。
- 默认构建脚本使用 `PATCH_VARIANT=fuzz`（`named_experiment/run_named_afl_symcc.sh:15`）及 SymCC CC/CXX（`:1344-1366`）；helper 的 stdin/file 选择见 `util/symcc_fuzzing_helper/src/symcc.rs:496-517`。未检查现有二进制是否与这些源码同步。

现有测试边界：

- `test/test_track3_harness_and_shadow.c:236-268` 检查 BIND 内存拷贝后的具体 RDATA 字节。
- `test/test_track3_harness_and_shadow.sh:11-29` 用 gcc 构建 mutator 测试；`:45-84` 的 SymCC probe 是独立的 memory-input + memcpy 程序，不是实际 resolver 消费点，也没有反解生成 DST1 后回放。
- **[INFERENCE]** 源码显示内存方案具备保留 shadow 的必要基础，但这些测试不能证明深层 resolver 约束和原始 DST1 偏移已端到端闭合。
- Unbound 的内存列表只解决进入 mutator 的传输；之后仍 `sendto`（mutator `:548-551`），上游在 `experiments/subjects/unbound/release-1.24.2/util/netevent.c:1149-1169` 收包。**[INFERENCE]** 若将来宣称 Unbound 也有同进程响应符号闭环，需另外验证 socket 边界；不把 concrete replay 当成 SymCC producer。

首批最小行动：

- **先加验证，不先重写 runtime，也不默认打开 `SYMCC_MEMORY_INPUT`。**
- 获批后用一个短预算、单样本测试：默认 stdin DST1 → 实际 BIND RDATA 消费点 shadow 非空且对应原始偏移 → 一个受该字节控制的分支反解 → 新 DST1 严格解析成功 → concrete replay 命中目标分支。
- 若失败，再根据第一个失去 shadow 的位置修复；在通过前只能宣称“已实现内存注入路径”，不能宣称已证明响应载荷求解增益。

### 其余项：记录已修部分，不扩大本轮测试

| 项目 | 当前代码与测试依据 | 留给后续的最小问题 |
| --- | --- | --- |
| F5 | `gen_input/src/DST1Mutator.cpp:195-229` 校验 NS/CNAME/PTR/MX/SOA 域名；`:1280-1370` 已重定位 Question 变长后的指针。`test/test_track2_generator_mutator_fidelity.cpp:69-129` 用 `ns_name_uncompress` 检查旧 `a.example → long.example` 案例。调用方包括同源码 `:682,819,1405` 及 `gen_input/src/FormatAwareGenerator.cpp:358`。 | 待验证：`:1344-1348` 找不到原 suffix 时按长度差平移是否改变非耦合 RDATA；RDATA 校验仅检查未越界，是否应要求恰好消费长度。最小增加“原 suffix 消失”和带额外 RDATA 字节两个案例。 |
| F7 | `DST1Mutator.cpp:236-273` 接受带报文外部引用的 RR slice；`:710-743,766-807` 为异名 donor 解码并重编码。专项测试 `test_track2_generator_mutator_fidelity.cpp:132-227` 覆盖压缩 owner。AFL 调用入口 `gen_input/src/afl_dst1_mutator.cpp:631-632`。 | 待验证：相同 identity 快路径仍直接复制 RR（`:703-707,758-763`），但两报文先前 RR 布局未必相同；失败仍可静默回退（`:1522-1533`）。最小补同名但 Answer 长度不同、Authority/Additional 指向前一 RR 的 donor，验证实际消费 donor 而非仅有返回值。 |
| F8 | `FormatAwareGenerator.cpp:1646-1656` 至少保留完整 Question，`:1670-1672` 保留原 seed 余下字节，旧“只保留 20 字节再换固定骨架”的描述已过时。专项测试 `test_track2_generator_mutator_fidelity.cpp:230-285` 只测带 A Answer 的 seed。调用入口 `gen_input/src/main.cpp:221-234,693-717`。 | 待验证：`:1673-1682` 盲改最后一个字节，不保证该字节是普通 payload；`:1684-1711` 对无剩余 payload 的 response 追加记录但不更新计数。最小补末尾压缩 CNAME 与空 NOERROR/NXDOMAIN；若不要求额外初始变体，优先删除盲变体而不是增加通用修复器。 |
| F9 | Unbound orchestrator `:596-604` 已零初始化 transcript、counter、response_dir；`:211-219` parser 先清零再早退。旧未初始化路径不应继续报告。 | 待验证异常链：parse 失败 `:613-615` 先于环境保存 `:626-630`，cleanup `:731-733` 仍调用 `restore_env_var(NULL)`，后者 `:383-391` 会 unset 原变量。最小修复是只恢复已保存/改变的环境；测试真实 parser/cleanup，不运行 resolver。现有 `test_track3_harness_and_shadow.c:59-114` 是复制 parser，不是生产函数；`:131-139` 的 count 断言还需核对，不能因测试文件存在声称实际错误路径已覆盖。 |

上表边界均未运行 C++ 复现；仅用于后续实施拆分，不作为新增“已复现漏洞”。

### 建议首批实施拆分

1. **语义合同与纯回归**：B1、B3；先落同义负对照和统一分类，再修生产逻辑。影响 Python/C++ 两套入口及六端 oracle，不能只改一个 comparator。
2. **注入保真**：B2；限定允许改写字段和不可比 client-wire 范围，加 builder 级字节对照。依赖上一批明确有效/拒绝/未知语义。
3. **符号闭环资格测试**：B4；独立验收，不以“helper 启动”或“memcpy probe 成功”代替真实分支解。必要的小修由失败位置决定。

F5/F7/F8 和 F9 环境恢复可作为独立后续小批次；未将它们扩展成要求立即完成的完整重构。F6、producer 独立性和统计产物由另一研究者负责。

### Files found

| 文件/文件组 | 用途 |
| --- | --- |
| `.trellis/tasks/10-30-symcc-paper-completion/prd.md` | 本任务范围、规划授权和验收边界 |
| `.trellis/tasks/08-17-review-symcc-experiments/review-2026-09-08.md` | F1–F9 历史定义；其旧运行结果不算本轮验证 |
| `dnslab_core/src/cache_analysis.cpp`、`dnslab_core/test/test_cache_analysis.cpp` | C++ cache delta、语义投影、triage 和新增成对测试 |
| `tools/dns_diff/{cache_diff,triage,follow_diff,oracle}.py` | Python 缓存分类入口及 oracle schema |
| `tools/{dnsmasq,smartdns,maradns,knot_resolver}_replay_harness.py` | 外部 resolver replay 与 acceptance 实现 |
| `patch/cache/unbound/smallapp/unbound_afl_symcc_{mutator_server,orchestrator}.c` | 响应修复、查询适配和清理边界 |
| `patch/{cache,fuzz}/bind9/bin/named/resolver_afl_symcc_orchestrator.c` | BIND replay 与 producer 两条入口 |
| `patch/fuzz/bind9/bin/named/resolver_afl_symcc_mutator_server.c`、`patch/fuzz/bind9/lib/dns/dispatch.c` | 内存响应注入和进程内 dispatch |
| `gen_input/src/{DST1Mutator,FormatAwareGenerator}.cpp` | 压缩重定位、donor 和 Hybrid seed 生成 |
| `runtime/src/{LibcWrappers,RuntimeCommon}.cpp` | 文件读取与 memcpy 的符号语义 |
| `test/test_replay_harness_negative_control.py`、`test/test_dns_diff_cache_diff.py` | 本轮实际运行的三个纯 Python 测试 |
| `test/test_unbound_mutator_fidelity.c`、`test/test_track{2_generator_mutator_fidelity.cpp,3_harness_and_shadow.c,3_harness_and_shadow.sh}` | 新增历史问题回归；本轮只读 |

### 已执行的有限验证

- 使用 `rg`、context-mode 和带行号源码读取；`symcc/` 与直接父目录 `/home/egoist/work` 没有 `.codegraph/`。主会话发现 `/home/egoist/.codegraph` 存在，但未核验其项目映射；本轮未使用或创建图谱。
- 运行以下命令，**3 tests / OK / exit 0**，没有启动 resolver 或 producer：

  ```bash
  PYTHONPATH="$PWD/test:$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -B \
    -m unittest test_dns_diff_cache_diff test_replay_harness_negative_control -v
  ```

- 首次使用 `test.test_...` 导入路径失败，报 `ModuleNotFoundError`，退出 1；随后以上面的显式 `PYTHONPATH` 修正执行方式。没有因此修改项目文件。
- 另用 `python3 -B -` 内联调用当前 `build_cache_diff`、`build_triage` 和四个 acceptance predicate，得到 B1/B3 的输出。禁写 bytecode；输入仅为内存构造报文，未创建脚本、临时语料或网络连接。
- 未运行 C++ 回归、构建或 shadow probe。相关 shell 脚本本身会写 `/tmp` 并编译，因此只读不执行。

### Related specs

- 已读 `.trellis/workflow.md`，尤其研究材料落盘及 planning 审批门。
- 已读 `.trellis/spec/guides/cross-layer-thinking-guide.md`：SymCC DNS 跨层契约要求严格 DST1、真实组件证据；其 2026-09-08 补充明确要求检查压缩指针、shadow、同义缓存和本地错误负对照。这些是验收目标，不是当前实现已经达成的事实。
- 已读 `.trellis/spec/guides/{index,code-reuse-thinking-guide}.md`；本轮依照实际调用链判断，不以历史报告替代源码。
- `.trellis/spec/backend/{index,quality-guidelines,error-handling}.md` 主要仍是模板，未发现可替代上述实验合同的更具体后端规范。

### External references / versions

- 本轮未作网络文献检索；结论以本地一手实现为准。
- 已核对本地 Unbound `release-1.24.2` 的 `libunbound/unbound.h:149-173`，用于区分报文长度、RCODE、正/负数据；不据目录名声称本机运行二进制版本已验证。
- BIND 回归脚本引用 `v9.20.22-afl` 构建树（`test/test_track3_harness_and_shadow.sh:13-18`）；没有运行版本命令或验证编译产物来源。
- 旧报告的 dnsmasq v2.92 及 `/tmp` 复现属于历史证据，没有复用成当前运行结果。

## Caveats / Not Found

- 本轮证明的是当前代码条件和少量纯函数行为，未测量真实差分误报率、符号覆盖增益或漏洞数量。
- 未核验完整 DNS RR 类型、完整六端网络 replay、二进制与 patch 同步状态；上述待验证项不得直接升级为已复现缺陷。
- B1 的 C++ canonicalization、B2 的尾段修复属于静态确认；B4 是必须补齐的实验资格证据，不能反向宣称默认 BIND 符号链已证实失败。
- 未核验 F6 或统计产物，也未覆盖旧续审 F10–F12。未更改产品代码、spec、任务状态或其他研究者文件。
- 多工作者环境下源码并非原子快照。以下为本轮读取结束时关键文件 SHA-256 前 16 位，可供后续识别报告是否过期；不代替提交/构建溯源：

  | 文件 | SHA-256 前缀 |
  | --- | --- |
  | `dnslab_core/src/cache_analysis.cpp` | `8cc4f5beba55901f` |
  | `tools/dns_diff/triage.py` | `a9c29192de560f18` |
  | `tools/dnsmasq_replay_harness.py` | `016d3de071b437c4` |
  | `patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c` | `08ba14946c7bdb5b` |
  | `patch/cache/unbound/smallapp/unbound_afl_symcc_orchestrator.c` | `1a21fff2851efe2d` |
  | `patch/fuzz/bind9/bin/named/resolver_afl_symcc_orchestrator.c` | `e7feb0b3f8daa323` |
  | `patch/fuzz/bind9/bin/named/resolver_afl_symcc_mutator_server.c` | `a58ff113b0442787` |
  | `gen_input/src/DST1Mutator.cpp` | `88a9a7a72fdeeead` |
  | `gen_input/src/FormatAwareGenerator.cpp` | `c8d127a9b7e7c93` |
