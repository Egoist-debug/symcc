# A1 独立审查（2026-10-30）

## 结论

**A1 门暂未通过**：已直接修复授权范围内的局部问题，全部本轮回归通过；但审计报告仍把单端缓存变化计为跨端缓存差异，涉及当前未授权写入的消费者。初态与 delta 的解释也需要主会话确认。

基线：`symcc` 提交 `f08a6c8935c9d25ff0319fdc8b6723d49648322a`。路径除另有说明外相对 `symcc/`。未派生子代理，未修改 A2/A3、任务规划、spec、证据合同或历史数据。

## Findings (fixed)

### 1. 异构 MSG 被错误折叠为冗余记录

- 文件：`tools/dns_diff/cache_diff.py:112-145`、`tools/dns_diff/cache_parser.py:178`、`dnslab_core/src/cache_analysis.cpp:172,1026`。
- 原问题：正 MSG 只要找到同名 RRset 就被忽略；即使 MSG 请求 `AAAA`、class 为 `CH`，或 TC 置位，也能与只有 `IN A` 的另一端比较为 `no_diff`。短 MSG 在已有合法 RRset 时还会被直接丢弃。
- 修复：检查 MSG 的名称、RR 类型、归一化 class、QD 和 TC；无法由共同 RRset 支撑的 MSG 保守不可比较。短 MSG 保留不可比较记录。
- 验证：新增 `msg-wrong-type`、`msg-wrong-class`、`msg-truncated`、`msg-incomplete` 共享 fixture。

### 2. SmartDNS 名称解码损失标签边界；Python 丢失根名称

- 文件：`tools/dns_diff/cache_parser.py:573,716`、`dnslab_core/src/cache_analysis.cpp:253`。
- 原问题：wire `\x03a.b\x00` 与 `\x01a\x01b\x00` 均解码为 `a.b`，导致不同名称误相等；Python 对根名称执行 `rstrip(".")` 得到空串，与 C++ 不一致。
- 修复：标签内特殊字节使用十进制 DNS 转义保留，当前不支持该名称的共同投影时保守不可比较；保留根名称 `.`。
- 验证：`wire-label-boundary` 阴性及 `root-name` 正例；均经实际二进制 SmartDNS parser。

### 3. 完全未识别的文本 dump 被当作空缓存

- 文件：`tools/dns_diff/cache_parser.py:813`、`dnslab_core/src/cache_analysis.cpp:1399`。
- 原问题：BIND/Unbound 文件内容为 `not a cache dump` 时，parser 返回空数组，triage 得到 `no_diff/included`。
- 修复：无可识别记录且含非格式标记文本时，保留 `unparsed` 观测，进入不可比较状态；没有把目标 DNS 输入宣称为畸形。
- 验证：`unrecognized-bind`、`unrecognized-unbound`。
- 边界：这是已复现空集降级的局部修复，不是完整的 dump 语法验证器。

### 4. 缺少 status 的部分升级 artifact 仍能成为候选

- 文件：`tools/dns_diff/triage.py:85-101`、`test/test_dns_diff_cache_diff.py`。
- 原问题：`cache_comparison_version=1`、`diff_detected=true`、非空 `resolver_diffs`，但缺少 `cache_comparison_status` 时，先进入 `_cache_has_diff` 分支，绕过 unknown。
- 修复：缓存差异肯定判断先经过完整可比较合同检查。
- 验证：分别删除 version/status 的回归，均为 `unknown` 且不成为 case-study candidate。

### 5. 保留 TXT 原始制表符后会破坏 TSV 列数

- 文件：`tools/dns_diff/cache_parser.py:66`、`test/test_dns_diff_cache_parser.py`。
- 原问题：TXT 内部制表符保留到原始观察后，直接拼 TSV 会产生第 11 列。
- 修复：仅在 TSV 序列化时将 tab/CR/LF 编成 DNS 十进制转义；原始 `rdata_norm` 不变。
- 验证：实际 parser 输入 `"Keep\tCase"`，检查原始值保留、输出仍为 10 列。

此外新增 TXT 转义等价、TXT 字符串边界不等价、RR class 真差异正反例。共享 fixture 从 13 扩展为 24 组，两种详情开关均执行。

## Findings (not fixed)

### P1：审计报告的组合指标仍消费旧的单端差异

- 文件：`tools/dns_diff/audit.py:145-155,216`、`dnslab_core/src/reporting.cpp:2029-2050,2111-2112`。
- 真实反例：两端从空缓存新增完全相同的 `example.com. IN A 192.0.2.1`，仅 oracle 的 `response_accepted` 不同。
- `cache_diff.diff_detected=false`，triage 正确输出 `oracle_diff`，但两后端 `oracle_reliability.json` 的 `signal_combos.oracle_diff_plus_cache_diff.eligible_count` 都是 **1**。
- 原因：Python `_cache_diff_any` 和 C++ `cacheDiffAny` 仍回退读取单端 `has_cache_diff`；因此审计口径未随 A1 闭合。
- 未修理由：`audit.py` 不在写入范围；`reporting.cpp` 本轮仅授权分类白名单，不包括指标语义。
- 建议：主会话授权这两个消费者按新版共同比较合同判断，并联动各自审计测试；对 legacy 不凭单端变化补足跨端差异。
- 原始复现目录：`/tmp/a1-check-audit-vxhi7ox2/`，包含 Python 结果 `probe-results.json` 和 C++ `campaign_reports/*/oracle_reliability.json`。

### 判断项：初态不同时，语义 delta 不等价于终态差异

- 文件：`tools/dns_diff/cache_diff.py:148-155,277-279`、`dnslab_core/src/cache_analysis.cpp:1057-1076,1208-1216`。
- 已运行生产函数反例：BIND before/after 均为 `{A=192.0.2.1}`；secondary before 为 `{}`、after 为相同 `{A=192.0.2.1}`。结果为 `comparable/cache_diff_interesting`，虽然终态完全相同。两端各保持不同初态则 delta 均空，不能解释为终态相同。
- 生产入口 `main.cpp:1129-1171` 分别调用 `dumpCache` 和 `runSample`；当前比较边界没有初态等价检查。`concrete_adapters.cpp` 的 BIND/Unbound dump 是独立进程调用，不是天然携带同一进程内前状态的证明。
- 未修理由：需要决定“比较基线相对变化”还是“比较最终 RRset”，以及允许何种初态差异。这是合同判断，不是安全的机械改动。
- 建议：明确 delta 的适用初态和含义；必要时对不同初态保守 unknown，而不是直接将它们作为语义缺陷候选。不能从空初态 fixture 泛化为所有真实初态已验证。

### 非分类阻塞，但 artifact 状态表达仍不严谨

- 文件：`dnslab_core/src/main.cpp:666-678,897`、`dnslab_core/src/follow_diff.cpp:921-935`。
- 主入口 `parseCacheRowsIfPresent` 对缺失文件返回空 vector；follow-diff 补缺路径主动为两端构造空快照。传给新版 `buildCacheDiff` 后，这些快照可被标作 `comparable`。
- **不应夸大为已证实的 included 漏洞**：主 replay 的 before/after 都有 `classifyMissingReplayArtifact`，缺失与零字节文件被失败分类拦截；triage 的 failure 分支优先。已核对这些保护。
- 未修理由：入口文件不在授权写入范围。
- 建议：保留快照缺失状态到 cache artifact；与合同第 9 节“缺失快照不得伪造成空缓存”的表述一致。

## Verification

- Lint：`git diff --check`、相关 Shell `bash -n`、8 个 Python 文件语法编译通过。仓库没有独立配置的 Python linter；环境未提供 `ruff`/`mypy`，没有把语法编译冒充静态类型检查。
- TypeCheck：C++17 release 构建通过，目标启用 `-Wall -Wextra -Wpedantic`；本轮构建日志无编译警告。Python 静态类型检查未运行。
- Python：`PYTHONPATH=. python3 -m unittest discover -s test -p 'test_dns_diff*.py'`，**38 tests passed**。
- C++：
  - `xmake build dnslab_core_cache_analysis_test`；从仓库根执行 `build/linux/x86_64/release/dnslab_core_cache_analysis_test`。
  - `xmake build dnslab_core_reporting_test`；从仓库根执行对应二进制。
  - `xmake build dnslabctl`。
  - 24 组共享 fixture × 2 种开关，每个后端执行 48 个组合。
- Shell 全部通过：
  - `test/test_cache_dump_parser.sh`
  - `test/test_replay_diff_cache_contract.sh`
  - `test/test_triage_contract.sh`
  - `test/test_failure_taxonomy_report.sh`
  - `test/test_dns_diff_cli_smoke.sh`
  - `test/test_campaign_report.sh`
  - `test/test_publication_evidence_bundle.sh`
  - `test/test_publication_readiness_audit.sh`
- 定向下游验证：unknown 经 triage rewrite、schema defaults、Python report、case-study 筛选后仍 unknown、无候选；C++ campaign-report 的 exclusion summary 为 `input_parse_failure/unknown=1`，included=0。沿用分类桶不代表目标输入畸形。
- 日志：`/tmp/a1-check-*.log`。

### Release 断言有效性与 red 证据

`dnslab_core/test/test_cache_analysis.cpp:23-28` 使用自定义 `require()`，失败直接 `std::abort()`；fixture 分类不符也在 `:77` 显式 abort，不依赖 `assert` 或 `NDEBUG`。

修复前实际 release 二进制输出：

```text
msg-wrong-type triggered=0: expected=cache_comparison_incomplete actual=no_diff
```

进程返回 `-6`（SIGABRT），保存在 `/tmp/a1-check-cpp-red.log`。Python 共享 fixture 修复前有 12 个断言失败，见 `/tmp/a1-check-python-red.log`。

实际测试入口必须从仓库根运行二进制；尝试 `xmake run dnslab_core_cache_analysis_test` 会因工作目录不同而找不到相对 fixture，未将此失败伪装成 red 语义证据。Python 的 `test` 与环境包名冲突，采用 discover 入口，不使用 `test.test_*` 导入。

## 第 9 节文档同步建议（未直接修改）

- `docs/DNSPoisonEvidenceContract.md:184` 的版本、状态、unknown 与 `input_parse_failure` 兼容解释，与已验证的主分类链一致。
- 补充上述 MSG 匹配条件和支持边界；特殊 DNS 标签经转义保留后，目前共同投影保守不可比较。
- 增补 delta 的初态前提；不能把相对变化等价表述成任意终态等价。
- “不得伪造成空缓存”目前尚未覆盖上述 C++ 失败补缺 artifact。
- 当前支持共同正 RR：A、AAAA、NS、CNAME、DNAME、PTR、TXT；未补所有 RR、负缓存、仅名称观测等能力。

未运行真实 resolver、长实验或全项目 SymCC 构建；未审 A2/A3 正在变动的文件。上述测试是离线格式 fixture，不是新的真实 resolver 实验记录。
