# A1 收尾报告（2026-10-30）

## 结论

**三个未修点已闭环，本轮定向回归全部通过。** 保留语义 delta，没有改成最终快照比较；不同共同初态不生成缓存差异或有效阴性。两个旧测试补足了实际比较证据，没有放宽为接受错误结果。

- 基线提交仍为 `f08a6c8935c9d25ff0319fdc8b6723d49648322a`；接续已有工作树，没有回退、提交或覆盖其他代理文件。
- 未见完整 hook marker，已按 fallback 读取任务上下文、引用、`progress.md` 和 `a1-check.md`；最终补读主会话新增的 `backend/dns-evidence.md`。
- 下列路径相对 `/home/egoist/work/symcc`。本轮仅写 17 个 A1 文件及本报告；没有修改 docs、任务主工件、oracle 或 replay harness/patch。
- xmake 已结束，可释放构建独占权。另一个代理的 oracle 镜像已纳入本次构建和测试，三份源码在构建前后及最终检查时哈希一致。

## 修改内容

### 1. 审计只消费完整的跨端比较证据

- `tools/dns_diff/cache_diff.py`：集中提供 `cache_comparable` / `cache_has_diff`。
- `tools/dns_diff/triage.py`：复用上述合同检查，拒绝缺字段或非法版本。
- `tools/dns_diff/audit.py`：`_cache_diff_any` 不再读取单端 `has_cache_diff`。
- `dnslab_core/src/reporting.cpp`：`cacheDiffAny` 要求整数版本 `1`、`comparable`、布尔真 `diff_detected` 及非空数组 `resolver_diffs` 同时成立。
- `test/test_oracle_audit_report.sh`：原阳性 fixture 改由生产 builder 构造；新增 17 组 Python/C++ 最终审计对照，包括相同 delta、真实差异、不同初态、缺快照、legacy、缺合同字段、非法版本及不可比较状态。

相同 RR 从空缓存插入两端，即使 oracle 独立有差异，组合指标 `oracle_diff_plus_cache_diff.eligible_count` 仍为 **0**；真实缓存差异为 **1**。legacy 可读取，但不补足证据资格；独立 oracle 差异不被抹除。

### 2. 共同初态是 delta 的比较前提

- `tools/dns_diff/cache_diff.py`、`dnslab_core/src/cache_analysis.cpp`：先检查两端 before 的共同 RR 投影等价；否则顶层状态为 `incomparable`，原因为 `initial_state_mismatch`，`diff_detected=false`、`resolver_diffs=[]`。
- `dnslab_core/include/dnslab_core/cache_analysis.hpp`：增加顶层原因字段，随 cache JSON 序列化。
- 单端原始观察、TTL、结构变化及语义 delta 均保留。无独立 oracle 差异时，triage 为 `cache_comparison_incomplete` / `unknown`。
- C++ 多 resolver 比较同样保守：比较组证据不完整或共同初态不一致时，不用其他 pair 补足整体缓存差异证据。
- `test/fixtures/cache_semantics/cases.tsv`：增加 `initial-mismatch-same-final` 与 `initial-mismatch-no-change`。共享场景由 24 增至 **26**，每种语言各执行明细开/关 **52** 个组合。
- `test/test_dns_diff_cache_diff.py`、`dnslab_core/test/test_cache_analysis.cpp`：检查原因、状态、候选和单端 delta 保留。C++ 原多端阳性 fixture 改为共同空初态、真实 RR 差异，不再用不可投影的 SERVFAIL 初态支撑阳性。

### 3. 缺失快照保持 unknown

- `dnslab_core/src/main.cpp`：读取结果使用 `optional<vector<CacheRecord>>`；缺失或零字节文件不插入快照 map。已有 replay failure 分类及优先级保持不变。
- `dnslab_core/src/follow_diff.cpp`：补缺使用缺失 map，不主动创建两端空快照；不伪造缓存执行列表。
- `dnslab_core/src/cache_analysis.cpp`：缺少必要 resolver 或任一前后快照时保持 `unknown`；兼容字段保留 `missing_snapshot` 原因。
- `tools/dns_diff/follow_diff.py`：终检发现零字节 dump 仍返回空集合，补一处大小检查，与 C++ 保持一致；有合法格式标记的空缓存仍返回已观测空集合。
- `test/test_dnslabctl_sync_replay_secondary.sh`：实际 C++ CLI 验证 before/after × 缺失/零字节四种情况，保留 `replay_missing_artifact`、unknown 和无候选。
- `test/test_dnslabctl_follow_diff_close_smoke.sh`：实际补缺入口验证 cache 缺失，以及 cache 已存在但 triage 缺失两条路径；不覆盖已有 cache artifact。

### 4. 两个旧 fixture 的处理

- `test/test_sample_analysis_state.sh`：旧 fixture 只有单端布尔标记，缺新版比较合同。改用生产 builder 生成真实 RR 差异；明细关闭仍必须为 `cache_diff_interesting`，不再错误期待 benign。另保留 legacy 输入并断言 unknown、无候选。
- `test/test_follow_diff_pipeline.sh`：旧 completed fixture 没有前后 dump，只写过时 JSON。现从共享 BIND/Unbound 格式 fixture 提供可复核的四份快照并生成新 cache JSON；保留原 `completed_no_diff` 断言及 legacy 缺 oracle 检查。

## 修复前红灯

所有命令工作目录为 `/home/egoist/work/symcc`。

| 命令 | 退出码 | 实际结果 |
| --- | ---: | --- |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -B -m unittest discover -s test -p 'test_dns_diff_cache_diff.py'` | 1 | 两个初态反例、两种明细开关，共 4 个断言失败 |
| `xmake build dnslab_core_cache_analysis_test` | 0 | 先构建新增反例的 release 测试 |
| `build/linux/x86_64/release/dnslab_core_cache_analysis_test` | 134 | 同终态、不同初态误判 `cache_diff_interesting`，显式 abort |
| `bash test/test_oracle_audit_report.sh` | 1 | `same-delta` 的 Python 组合指标错误为 1 |
| `bash test/test_sample_analysis_state.sh` | 1 | 实际 `oracle_diff`，旧 fixture 期待 `oracle_and_cache_diff` |
| `bash test/test_follow_diff_pipeline.sh` | 1 | 实际 `failed_replay=2,incomplete_cache_comparison=1` |
| `bash test/test_dnslabctl_sync_replay_secondary.sh` | 1 | 旧二进制缺少快照原因字段，`KeyError: cache_comparison_reason` |
| `bash test/test_dnslabctl_follow_diff_close_smoke.sh` | 1 | 旧二进制补缺生成 `comparable` 空快照及虚构 resolver 列表 |
| 上述 Python cache 单测再次执行，加入零字节反例后 | 1 | `[] is not None` |

main 的旧失败路径已有 failure gate；**本报告不把缺快照元数据错误宣称为已证实的 included 漏洞**。
C++ cache 回归使用显式 `require` / `abort`，不依赖 release 的 `assert`。

## 最终验证

### 构建与 C++ 测试

以下逐条执行，退出码均为 **0**；xmake 日志无 `warning:`，release 构建启用既有 `-Wall -Wextra -Wpedantic`。

```bash
xmake build dnslab_core_cache_analysis_test
xmake build dnslab_core_reporting_test
xmake build dnslab_core_oracle_test
xmake build dnslabctl
build/linux/x86_64/release/dnslab_core_cache_analysis_test
build/linux/x86_64/release/dnslab_core_reporting_test
build/linux/x86_64/release/dnslab_core_oracle_test
```

### Python 与 shell

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -B -m unittest discover -s test -p 'test_dns_diff*.py'
```

退出码 **0**，**38 tests / OK**。

以下 16 条命令最终均退出 **0**：

```bash
bash test/test_oracle_audit_report.sh
bash test/test_dnslabctl_sync_replay_secondary.sh
bash test/test_dnslabctl_follow_diff_close_smoke.sh
bash test/test_sample_analysis_state.sh
bash test/test_follow_diff_pipeline.sh
bash test/test_replay_diff_cache_contract.sh
bash test/test_replay_failure_evidence.sh
bash test/test_triage_contract.sh
bash test/test_failure_taxonomy_report.sh
bash test/test_cache_dump_parser.sh
bash test/test_oracle_audit_secondary_resolver.sh
bash test/test_oracle_audit_secondary_knot.sh
bash test/test_campaign_report.sh
bash test/test_publication_evidence_bundle.sh
bash test/test_publication_readiness_audit.sh
bash test/test_dns_diff_cli_smoke.sh
```

### 静态检查

以下均退出 **0**：

```bash
git diff --check
for script in test/test_oracle_audit_report.sh test/test_dnslabctl_sync_replay_secondary.sh test/test_dnslabctl_follow_diff_close_smoke.sh test/test_sample_analysis_state.sh test/test_follow_diff_pipeline.sh; do
  bash -n "$script" || exit
done
python3 - <<'PY'
from pathlib import Path
for name in ('tools/dns_diff/cache_diff.py', 'tools/dns_diff/triage.py', 'tools/dns_diff/audit.py', 'tools/dns_diff/follow_diff.py', 'tools/dns_diff/cache_parser.py', 'test/test_dns_diff_cache_diff.py'):
    compile(Path(name).read_bytes(), name, 'exec')
print('6 files syntax OK')
PY
```

17 个本轮改动文件均检查为 LF、保留末尾换行。
环境没有 `ruff` / `mypy`，未将语法检查宣称为 Python lint 或静态类型检查。

记录位置：

- `/tmp/a1-followup-results.json`：各次实际命令、退出码与日志路径。
- `/tmp/a1-followup-*.log`：红灯、构建及最终回归输出。
- `/tmp/a1-followup-final-files.json`：本轮 17 个文件的最终 SHA-256。
- `/tmp/a1-followup-oracle-build-hashes.json`：构建时 oracle 三份文件的 SHA-256。

## 未验证边界与后续

- 没有运行真实 resolver 网络实验、长 fuzzing、完整 SymCC 工具链构建或正式论文实验；CLI 集成使用临时 fake executable/harness，不能作为真实实验记录。
- 共同投影仍不覆盖所有 RR、负缓存或缺少 RDATA 的后端；相同共同初态不证明 resolver 内部全部状态相同。
- 旧报告和候选不能直接获得新版证据资格；历史结果未改写，后续重分析及真实独立 producer 验证由主会话另行安排。
- 本报告是实施者定向自检，不替代主会话的独立集成验收。没有修改 oracle 三文件，只构建并运行了其当前版本。
