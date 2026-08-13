# RQ3 gate 对照实验数据（2026-08-13）

## 实验设置

- producer：BIND9 v9.20.22-afl（AFL++ 5.02c persistent + DST1 mutator-only）
- 时长：各 120 秒；AFL_TIMEOUT_MS=5000；REPLY_TIMEOUT_MS=80
- 语料：基线批次 stable_transcript_corpus（4 个 DST1 transcript seed）
- 本轮修复（影响数据的代码变更）：
  - orchestrator 每次 testcase 前通过 mainloop 异步 flush 视图 cache（修复 persistent 迭代间 cache 状态累积导致的路径不稳定与校准 crash）
  - helper 高价值 manifest 需绝对路径（相对路径会被 base_dir 双重拼接，导致 tier 永不匹配）

## 结果

| 指标 | gate-on（manifest=65 队列样本） | gate-off（无 manifest，coverage-first） |
| --- | --- | --- |
| AFL execs_done | 118911 | 118566 |
| AFL corpus_found | 28 | 22 |
| AFL stability | 18.21% | 20.64% |
| AFL bitmap_cvg | 3.30% | 3.30% |
| helper processed | 64 | 62 |
| helper high_value_processed | 6 | 0 |
| helper high_value_new_coverage | 0 | 0 |
| helper ok/fail | 64/0 | 61/1 |

## 保守结论

- gate-on 下 SymCC helper 有 6 次高价值样本处理，gate-off 为 0——gate 机制在两个分支上的语义差异可观测。
- 本批 120s 短预算内高价值优先 pick 的 corpus_found（28）不低于 coverage-first（22），未观察到 gate 损害探索。
- stability 仍在 18-21%：cache flush 后从 10% 提升，残余噪声（fetch 异步尾巴、query 随机化等）记录为已知限制，需要后续轮次继续降噪。
- 该对照是 producer 链观测，不能与 matrix 链的 4 变体消融混写为同一实验口径。

## 产物路径

- gate-on：`named_experiment/work/afl_out/`、`named_experiment/work/logs/helper_persistent.log`
- gate-off：`named_experiment/work_gate_off/afl_out/`、`named_experiment/work_gate_off/logs/helper_persistent.log`
- 原始日志快照：`.trellis/tasks/08-13-symcc-full-experiment-paper-data/runs/<run-ts>/`（收尾时复制）
