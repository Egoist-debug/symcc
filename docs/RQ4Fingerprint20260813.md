# RQ4 状态指纹降噪数据（2026-08-13）

## 修复

- 根因：`state_fingerprint.json` 的全部语义字段在 replay 链中从不填充（C++ `buildSyncReplayFingerprint` 只写 schema/generated_at/sample_id 骨架；Python 链同样不提取）→ 指纹无区分度（历史批次 40 样本 = 1 个 cluster）。
- 修复：
  - C++ `buildSyncReplayFingerprint` 从 replay 后的 cache 记录（`parseCacheDump` 的 `Section`/`CacheType`）提取 `msg_cache_seen` / `rrset_cache_seen` / `negative_cache_seen`；`forwarding_path`/`retry_seen` 当前 resolver stderr 无稳定信号源，保持 null 并由 triage 的 `partial_fingerprint` 标签显式区分。
  - Python follow_diff 链从 dnslabctl artifact 目录同步指纹；修复了 artifact_dir 与 sample_dir 相同时的 `SameFileError`。
- 附带修复：orchestrator 每 testcase 前通过 mainloop 异步 flush 视图 cache（stability 10.69% → 18-34%，dry run crash 消除）。

## 数据（follow-diff 链，8 个基线队列样本，20260813_123658）

- 样本 8 个，全部 `analysis_state=included`，失败 0。
- 指纹聚类：**2 个 cluster**（5 + 3），按 bind9/unbound 的 msg/rrset/negative 缓存信号区分。
- 修复前对照：同批样本在旧链下 40 样本 = 1 个 cluster（无区分度）。
- `oracle_audit_candidates=0`：本批样本语义为 no_diff，无 oracle 差异候选——与基线批次 unbound 的 oracle_and_cache_diff 分布不同，说明本批队列抽样偏向无差异样本。

## 降噪链路口径（保守）

| 阶段 | 候选数 | 说明 |
| --- | --- | --- |
| 无过滤 | 8 | 全部 included 样本 |
| 启发式（oracle_audit_candidate） | 0 | 本批无 oracle 差异候选 |
| fingerprint 聚类 | 2 | 缓存状态信号可区分 |
| 人工真值裁决 | 0/8 | 待人工双评 + adjudicator（缺口） |

## 产物路径

- `experiments/results/rq4_fingerprint_run/20260813_123658/`
