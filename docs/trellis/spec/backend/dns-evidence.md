# DNS 差分证据的跨层回归

## 1. 范围与触发

修改 `symcc/` 的缓存比较、oracle、resolver patch、producer 来源、triage 或审计指标时适用。
详细字段以 [DNSPoisonEvidenceContract.md](../../../DNSPoisonEvidenceContract.md)
为准；本页规定不能漏掉的实现与验收边界，不把离线测试当成真实实验。

## 2. 接口与 owner

- 缓存：`tools/dns_diff/cache_diff.py` 与 `dnslab_core/src/cache_analysis.cpp`；
  同步 triage、replay/follow-diff、Python audit 与 C++ reporting。
- oracle：`parse_oracle_summary()` 与 `parseOracleSummary()` / `toJson()`；
  同步四个 Python harness 及 BIND cache/fuzz、Unbound patch 的生产点。
- Unbound 注入：`patch/cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c`；
  不把被忽略的 subject/build 树当作修复来源。
- 执行身份：named producer、`matrix.py` 与 `publication_audit.py`；
  摘要版本常量在 `schema.py`，实际 helper 为 `util/symcc_fuzzing_cpp`。

## 3. 输入输出合同

- 共同 RR 投影和相同初态是语义 delta 可比较的前提；原始观察仍保留。
- `cache_comparison_version`、`cache_comparison_status` 与跨端差异共同决定证据；
  不从单端 `has_cache_diff` 推出跨端差异。
- `fake_reply_dispatched` 是可选发送事实，不是新增语义差异指标；
  缺失或非法值保持 `null`，不能从 `response_accepted` 反推。
- Unbound 成功注入仅替换事务 ID，长度与其他字节不变；容量或读取失败不产生替代回复。
- v2 队列摘要排除 `*.meta.json`；显式区分实际生成与共享队列重放，
  不从复制文件推断执行身份，也不以内容相同否定独立执行。

## 4. 校验与错误矩阵

| 输入或观察 | 必需处理 |
| --- | --- |
| 共同初态不同 | 不可比较，不算有效差异或有效阴性 |
| 快照缺失、失败补缺 | 保留 unknown，不构造可比较空快照 |
| legacy 缺少版本/状态 | 可读取，不自动升级新版证据资格 |
| 未 fetch、未完整发送、错误 Question 或截断响应 | 不计有效接纳 |
| 无 post-check 或缺因果证据 | 不宣称已证明缓存命中或投毒 |
| 缺失/未知 execution mode 或 replay | 不授予正式生成效果资格 |
| 旧 v1 摘要 | 可读但不自动升级，不改写历史记录 |

## 5. 正例、基线与反例

- 正例：同一初态插入不同 IP 或不同 TXT，保留真实跨端差异。
- 基线：两端从空缓存插入同一 RR，即使两端各有 delta，也无跨端差异。
- 反例：相同终态但初态不同，不能因为 delta 不同就成为缺陷候选。
- 反例：合法本地响应但注入发送失败，不能因为有回答就记录接纳成功。

## 6. 必需回归

- Python/C++ 共用 `test/fixtures/cache_semantics/cases.tsv`；检查分类、状态与审计组合指标。
- oracle 同时测试可选发送字段的 true/false/缺失/非法值与最终 JSON。
- `test/test_replay_harness_negative_control.py` 检查最终 oracle，不只测试 predicate。
- `test/test_unbound_mutator_fidelity.sh` 与 `test/test_native_replay_oracle.sh`；
  release/config.h 的 `NDEBUG` 不能使断言失效。
- 从仓库根运行 C++ fixture 测试；记录构建、测试命令及退出码，避免使用过期二进制。
- producer 显式 seed、组件命令与启动记录、v2 metadata/payload 正反例、同内容独立来源，
  必须经过实际 writer 与审计联调；替身启动记录不当成真实实验。

## 7. 错误与正确对照

错误：triage 已改成共同差异，但 audit 仍用任一单端 delta；C++ 序列化丢掉 Python 新字段。

正确：先检索全部生产点和消费者，用相同正负例验证分类、原始 artifact、汇总指标；
未知事实保持未知，未执行的真实 resolver 或 producer 实验另列边界。
