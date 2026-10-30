# Cross-Layer Thinking Guide

> **Purpose**: Think through data flow across layers before implementing.

---

## The Problem

**Most bugs happen at layer boundaries**, not within layers.

Common cross-layer bugs:

- API returns format A, frontend expects format B
- Database stores X, service transforms to Y, but loses data
- Multiple layers implement the same logic differently

---

## Before Implementing Cross-Layer Features

### Step 1: Map the Data Flow

Draw out how data moves:

```
Source → Transform → Store → Retrieve → Transform → Display
```

For each arrow, ask:

- What format is the data in?
- What could go wrong?
- Who is responsible for validation?

### Step 2: Identify Boundaries

| Boundary              | Common Issues                     |
| --------------------- | --------------------------------- |
| API ↔ Service         | Type mismatches, missing fields   |
| Service ↔ Database    | Format conversions, null handling |
| Backend ↔ Frontend    | Serialization, date formats       |
| Component ↔ Component | Props shape changes               |

### Step 3: Define Contracts

For each boundary:

- What is the exact input format?
- What is the exact output format?
- What errors can occur?

---

## Common Cross-Layer Mistakes

### Mistake 1: Implicit Format Assumptions

**Bad**: Assuming date format without checking

**Good**: Explicit format conversion at boundaries

### Mistake 2: Scattered Validation

**Bad**: Validating the same thing in multiple layers

**Good**: Validate once at the entry point

### Mistake 3: Leaky Abstractions

**Bad**: Component knows about database schema

**Good**: Each layer only knows its neighbors

### Mistake 4: Every Consumer Parses The Same Payload

**Bad**: A command reads JSONL events and casts fields inline:

```typescript
const thread = (ev as { thread?: string }).thread;
const labels = (ev as { labels?: string[] }).labels;
```

This looks local, but it means every consumer owns a private version of the
event contract. The next field change will update one command and miss another.

**Good**: Decode once at the event boundary, then export typed projections:

```typescript
if (!isThreadEvent(ev)) return false;
return ev.thread === filter.thread;
```

**Rule**: For append-only logs, JSON streams, RPC payloads, or config files,
create one owner for:

- event / payload type definitions
- type guards and normalization from `unknown`
- metadata projections used by UI commands
- reducers that replay state from the source of truth

Rendering code may format fields, but it must not redefine the payload contract.

---

## Checklist for Cross-Layer Features

Before implementation:

- [ ] Mapped the complete data flow
- [ ] Identified all layer boundaries
- [ ] Defined format at each boundary
- [ ] Decided where validation happens

After implementation:

- [ ] Tested with edge cases (null, empty, invalid)
- [ ] Verified error handling at each boundary
- [ ] Checked data survives round-trip
- [ ] Checked that consumers import shared decoders / projections instead of
      casting payload fields locally
- [ ] Checked that derived state points back to the source event identifier
      (`seq`, `id`, `version`) instead of inventing a second cursor

## SymCC DNS 实验跨层契约

### 1. 范围 / 触发条件

- 触发：DST1 transcript 从 seed producer 经过 AFL++ custom mutator、SymCC
  helper、campaign report 和 publication audit 的跨层流转。
- 目标：普通历史 artifact 继续可读，但进入投毒主链或论文证据门时必须经过
  同一份严格契约。

### 2. 签名

- `DST1Mutator::validateWire(bytes)`：检查 magic、header、length table 和
  section 边界，允许零 response，返回结构化 `ValidationResult`。
- `DST1Mutator::validatePoisonEligible(bytes)`：在 wire-valid 基础上要求非空
  post-check、至少一个 response，以及 query/post-check/response question 的
  QNAME、QTYPE、QCLASS 一致。
- SymCC helper 的 `--require-poison-eligible`：启用后输入和输出均调用共享
  `validatePoisonEligible`，拒绝样本不得进入回流 queue。
- producer 的 `producer_execution_manifest.json`：记录开关、随机种子、run
  id、组件启动状态、命令摘要和 queue snapshot。

### 3. 契约（输入 / 输出 / 环境）

- DST1 的显式 post-check wire format 保持现有 magic/header；结构化变异必须
  同步更新 query、post-check 和所有 response question。
- `ENABLE_SYMCC`、`ENABLE_DST1_MUTATOR`、`ENABLE_CACHE_DELTA`、
  `ENABLE_TRIAGE` 只能取 `0` 或 `1`；`ENABLE_SYMCC=0` 不构建、不启动 helper，
  `ENABLE_SYMCC=1` 必须在 execution manifest 中留下实际启动证据。
- SymCC 覆盖统计先合并 AFL queue 的 showmap bitmap，再计算相对新增 bit；只有
  poison-eligible 且相对 AFL/已接受 SymCC bitmap 有新增覆盖的输出才可回流。
- publication audit 的 `aggregation_key` 与 `baseline_compare_key` 必须包含
  契约字段并跨 run 一致；论文硬门槛固定为至少 5 个独立 run、2 个完整 case
  study 和每个 run 的 `cluster.tsv`。

### 4. 验证与错误矩阵

| 条件 | 处理 | 统计 / 错误 |
| --- | --- | --- |
| DST1 header、length table 或字段边界截断 | 拒绝，不进入主链 | `wire_invalid` |
| 空 post-check、零 response、DNS identity 不一致 | 普通 parser 可读；严格主链拒绝 | `poison_ineligible` |
| `max_size` 小于完整候选 | 结构化缩减；仍超限返回 0 | `mutation_rejected_size` |
| SymCC 输出与 AFL 已知覆盖相同 | 不回流 | `afl_relative_new_coverage=0` |
| 消融开关不是 `0/1` 或 manifest 与声明不符 | 命令失败，审计非零退出 | `invalid_component_switch` |
| 缺 key、独立性证据、cluster 或完整 case study | publication `ready` 失败 | `publication_gate_failed` |

### 5. 正常 / 基线 / 异常案例

- 正常：非空 post-check、至少一个 response 且 questions 一致的 DST1；
  `ENABLE_SYMCC=1` 有 helper 进程和 manifest，新增覆盖样本通过严格验证后回流。
- 基线：历史零 response 或空 post-check artifact 只能由 wire parser 和普通
  报告读取，不得被计入 poison corpus 或 SymCC 增益。
- 异常：只修改 report 元数据的伪消融、共享固定 queue 的重复 run、残缺
  comparability key、空壳 case study，均必须被 publication audit 拒绝。

### 6. 必需测试（断言点）

- DST1 单元 / custom callback：截断 length table、零 response、多 response、
  donor splice、trim、`max_size` 和 query identity 耦合；所有非零输出可重新解析。
- SymCC helper：AFL 已知 bitmap 不产生伪新增；只有 poison-eligible 新 bit 回流；
  非 regular file 和 parser-error-only 输出被忽略。
- producer：`bash -n`、`ENABLE_SYMCC=0/1` 的 build/start manifest；随机种子、
  run id 和 queue snapshot 可追溯。
- publication：低于 5 runs/2 cases、残缺或不一致 key、固定 queue、缺 cluster 或
  缺人工裁决时非零退出；Python 与 C++ 均生成 `cluster.tsv`。

### 7. 错误与正确对照

#### 错误

```text
对每个 RQ3 变体复用同一 source_queue_dir，运行结束只写 cluster_counts.tsv，
并把 ENABLE_SYMCC=0 写入元数据但仍启动 helper。
```

#### 正确

```text
每次 producer 记录独立 seed/run/queue snapshot；开关控制真实组件生命周期；
campaign report 和 bundle 写入 cluster.tsv；publication audit 校验完整 key、
独立性证据和 case-study 产物，缺任一项即拒绝 ready。
```

### 审查检查点补充（2026-09-08）

以下是后续审查需要核对的问题，不代表当前实现已满足上述契约：

- [ ] `aggregates` 为空时，下游是否区分“统计不可用”和数值零？
- [ ] 是否分别核对 `comparability`、`completed_count`、每个 resolver 的
  `process_started` 与真实响应，而不是把 key 可比较等同于执行成功？
- [ ] queue 的样本内容与运行元数据是否分开比较？固定语料重复 replay 可用于复现，
  但不等同于按不同开关运行独立 producer。
- [ ] DNS 响应经过落盘、变长 QNAME 或 donor 移植后，压缩指针、RDATA 语义与
  SymCC shadow 是否仍保持到 resolver 消费点？
- [ ] 正常等价缓存和本地错误响应是否有负对照，避免把身份字段差异或错误回复当成
  语义差异、缓存命中？
- [ ] 文档结论是否回指准确批次、原始输入身份和人工裁决状态？不同批次的通过结果
  不能自动补足原实验的失败或未裁决状态。

依据见
[resolver 与种子流程审查](/home/egoist/work/.trellis/tasks/08-17-review-symcc-experiments/review-2026-09-08.md)
及 [RQ 续审](/home/egoist/work/.trellis/tasks/08-17-review-symcc-experiments/review-2026-09-08-continuation.md)。

### DNS 语义回归约束（2026-10-30）

#### 1. 范围

涉及 cache parser、Python/C++ triage、resolver 注入或 oracle 时，必须同时检查
观察、跨端比较、最终分类和测试是否真正执行。完整字段合同位于
`symcc/docs/DNSPoisonEvidenceContract.md`，这里不另立第二套语义。

#### 2. 实现边界

- `build_cache_diff` 与 C++ `buildCacheDiff` 的共同 RR 投影必须使用共享输入验证。
- Unbound 生产 `build_dns_response` 只允许改事务 ID；内存和文件输入行为一致。
- 接纳判定必须消费匹配的查询、完整响应及真实发送事件，不能由输入列表非空推断发送成功。

#### 3. 输入与输出

保留原始观察和单端 delta，但只由共同语义决定跨端差异；TTL/格式噪声不能升级候选。
缺快照或不支持的状态保留未知/不可比较，不能伪装为空缓存或有效阴性。
不能把正常的 NXDOMAIN/NODATA 自动当漏洞，也不能把收到任意报文等同于有效接纳。

#### 4. 错误矩阵

| 输入/条件 | 必须满足 |
| --- | --- |
| 同 RR 不同 resolver 名称、格式或计时字段 | 不报语义缺陷 |
| TXT 大小写/字节不同、真实 IP 不同 | 不得被域名归一化吞掉 |
| 缺快照、不支持的 cache 状态 | 明确保留不可比较原因 |
| 截断 RR 或计数不符 | 不得由某一 adapter 单方面修复后参与公平比较 |
| 发送失败、错误 ID/Question、截断客户端响应 | 不计有效接纳或由此推导的缓存命中 |
| native `config.h` 定义 `NDEBUG` | 回归必须重新启用断言，证明反例会失败 |

#### 5. 正反例

空缓存两侧插入相同 RR 是“都有状态变化但无跨端差异”；47 字节响应被悄悄截为
45 字节是输入保真失败，不是 resolver 自己拒绝了尾部数据。二者必须独立测试。

#### 6. 必需回归

- 共享 `test/fixtures/cache_semantics/cases.tsv`，Python/C++、明细开/关两种模式。
- `test/test_unbound_mutator_fidelity.sh`：逐字节、文件/内存、容量、失败及断言启用。
- `test/test_replay_harness_negative_control.py`：最终 oracle 字段和发送失败替身，不只测 helper。
- 若直接 include native patch，优先 canonical patch header；不得仅因旧 subject 副本能编译就算新接口已验证。

#### 7. 失败模式与预防

本类问题同时属于跨层合同、变更漏传和测试覆盖缺口：只修 C++ 而 Python 仍按单端
delta 分类、只测 flags 不测完整输入、断言被配置关闭后仍输出 PASS。
预防措施是共享真实格式 fixture、修复前红灯证据、最终消费端断言和独立复核。
本轮修复范围不涵盖真实 producer 独立性或完整实验复现；这些门槛仍需另行验收。

---

## Cross-Platform Template Consistency

In Trellis, command templates (e.g., `record-session.md`) exist in **multiple platforms** with identical or near-identical content. This is a cross-layer boundary.

### Checklist: After Modifying Any Command Template

- [ ] Find all platforms with the same command: `find src/templates/*/commands/trellis/ -name "<command>.*"`
- [ ] Update all platform copies (Markdown `.md` and TOML `.toml`)
- [ ] For Gemini TOML: adapt line continuations (`\\` vs `\`) and triple-quoted strings
- [ ] Run `/trellis:check-cross-layer` to verify nothing was missed

**Real-world example**: Updated `record-session.md` in Claude to use `--mode record`, but forgot iFlow, Kilo, OpenCode, and Gemini — caught by cross-layer check.

---

## Generated Runtime Template Upgrade Consistency

Some generated files are both documentation and runtime input. In Trellis,
`.trellis/workflow.md` is parsed by `get_context.py`, `workflow_phase.py`,
SessionStart filters, and per-turn hooks. Template changes must be validated
against both fresh init and upgrade paths.

### Checklist: After Modifying A Runtime-Parsed Template

- [ ] Identify every runtime parser that reads the template, not just the file
      writer that installs it
- [ ] Check whether relevant syntax lives outside obvious managed regions
      such as tag blocks
- [ ] Verify fresh `init` output and a versioned `update` scenario that writes
      the older `.trellis/.version`
- [ ] Add an upgrade regression using an older pristine template fixture, then
      assert the installed file reaches the current packaged shape
- [ ] Update the backend spec that owns the runtime contract

---

## Versioned Documentation Boundary

Versioned documentation is a cross-layer boundary: source paths, `docs.json`
version routing, and the rendered version selector must all describe the same
release line.

### Checklist: Before Editing Versioned Docs

- [ ] Identify the target release line: stable, beta, or RC
- [ ] Verify the edited MDX path matches that line:
  - stable: `docs-site/{start,advanced,...}` and `docs-site/zh/{start,advanced,...}`
  - beta: `docs-site/beta/**` and `docs-site/zh/beta/**`
  - RC: `docs-site/rc/**` and `docs-site/zh/rc/**`
- [ ] Verify `docs.json` navigation points the version label to the same paths
- [ ] Grep the opposite tree for release-line-specific terms before committing
- [ ] Treat beta content appearing under root release paths as a source-path bug,
      not a rendering bug

**Real-world example**: A beta-only task workflow change documented
`prd.md` + `design.md` + `implement.md`, task-creation consent, and Codex
mode banners under root `start/` and `advanced/` paths. The docs site then
served 0.6 beta behavior under the Release selector. The fix was to restore root
release docs, move the 0.6 content to `beta/` and `zh/beta/`, and add a grep
audit for beta markers against the root release tree.

**Real-world example**: Codex inline mode changed workflow platform markers from
`[Codex]` / `[Kilo, Antigravity, Windsurf]` to `[codex-sub-agent]` /
`[codex-inline, Kilo, Antigravity, Windsurf]`. Fresh init was correct, but
`trellis update` only merged `[workflow-state:*]` blocks and preserved stale
markers outside those blocks. Result: upgraded projects got new hook scripts
but old workflow routing, so `get_context.py --mode phase --platform codex`
could return empty Phase 2.1 detail.

---

## Mode-Detection Probe Checklist

When a CLI auto-detects a mode by probing a remote resource (e.g., checking if `index.json` exists to decide marketplace vs direct download):

### Before implementing:

- [ ] Probe runs in **ALL** code paths that use the result (interactive, `-y`, `--flag` combos)
- [ ] 404 vs transient error are distinguished — don't treat both as "not found"
- [ ] Transient errors **abort or retry**, never silently switch modes
- [ ] Shared state (caches, prefetched data) is **reset** when context changes (e.g., user switches source)
- [ ] **Shortcut paths** (e.g., `--template` skipping picker) must have the same error-handling quality as the probed path — check that downstream functions don't call catch-all wrappers

### After implementing:

- [ ] Trace every path from probe result to the mode-decision branch — no fallthrough
- [ ] External format contracts (giget URI, raw URLs) are tested or at least documented as comments
- [ ] Metadata reads consume a complete response or use a streaming parser — never parse a fixed-size prefix as full JSON
- [ ] When reconstructing a composite identifier from parsed parts, verify **all** fields are included and in the **correct position** (e.g., `provider:repo/path#ref` not `provider:repo#ref/path`)
- [ ] Verify that **action functions** called after a shortcut don't internally use the old catch-all fetch — they must use the probe-quality variant when error distinction matters

**Real-world example**: Custom registry flow had 8 bugs across 3 review rounds: (1) probe only ran in interactive mode, (2) transient errors fell through to wrong mode, (3) giget URI had `#ref` in wrong position, (4) prefetched templates leaked across source switches, (5) `--template` shortcut bypassed probe but `downloadTemplateById` internally used catch-all `fetchTemplateIndex`, turning timeouts into "Template not found".

**Real-world example**: Agent-session update hints fetched npm `latest` metadata with `response.read(4096)` and then parsed it as complete JSON. The `@mindfoldhq/trellis` package metadata exceeded 4 KB, so the JSON was truncated, parse failed silently, and the first session injection showed no update hint. Fix: read the complete response before parsing, and add a regression where `version` is followed by an 8 KB metadata tail.

---

## Cross-Platform Template Consistency

In Trellis, command templates (e.g., `record-session.md`) exist in **multiple platforms** with identical or near-identical content. This is a cross-layer boundary.

### Checklist: After Modifying Any Command Template

- [ ] Find all platforms with the same command: `find src/templates/*/commands/trellis/ -name "<command>.*"`
- [ ] Update all platform copies (Markdown `.md` and TOML `.toml`)
- [ ] For Gemini TOML: adapt line continuations (`\\` vs `\`) and triple-quoted strings
- [ ] Run `/trellis:check-cross-layer` to verify nothing was missed

**Real-world example**: Updated `record-session.md` in Claude to use `--mode record`, but forgot iFlow, Kilo, OpenCode, and Gemini — caught by cross-layer check.

---

## Generated Runtime Template Upgrade Consistency

Some generated files are both documentation and runtime input. In Trellis,
`.trellis/workflow.md` is parsed by `get_context.py`, `workflow_phase.py`,
SessionStart filters, and per-turn hooks. Template changes must be validated
against both fresh init and upgrade paths.

### Checklist: After Modifying A Runtime-Parsed Template

- [ ] Identify every runtime parser that reads the template, not just the file
  writer that installs it
- [ ] Check whether relevant syntax lives outside obvious managed regions
  such as tag blocks
- [ ] Verify fresh `init` output and a versioned `update` scenario that writes
  the older `.trellis/.version`
- [ ] Add an upgrade regression using an older pristine template fixture, then
  assert the installed file reaches the current packaged shape
- [ ] Update the backend spec that owns the runtime contract

**Real-world example**: Codex inline mode changed workflow platform markers from
`[Codex]` / `[Kilo, Antigravity, Windsurf]` to `[codex-sub-agent]` /
`[codex-inline, Kilo, Antigravity, Windsurf]`. Fresh init was correct, but
`trellis update` only merged `[workflow-state:*]` blocks and preserved stale
markers outside those blocks. Result: upgraded projects got new hook scripts
but old workflow routing, so `get_context.py --mode phase --platform codex`
could return empty Phase 2.1 detail.

---

## Mode-Detection Probe Checklist

When a CLI auto-detects a mode by probing a remote resource (e.g., checking if `index.json` exists to decide marketplace vs direct download):

### Before implementing:
- [ ] Probe runs in **ALL** code paths that use the result (interactive, `-y`, `--flag` combos)
- [ ] 404 vs transient error are distinguished — don't treat both as "not found"
- [ ] Transient errors **abort or retry**, never silently switch modes
- [ ] Shared state (caches, prefetched data) is **reset** when context changes (e.g., user switches source)
- [ ] **Shortcut paths** (e.g., `--template` skipping picker) must have the same error-handling quality as the probed path — check that downstream functions don't call catch-all wrappers

### After implementing:
- [ ] Trace every path from probe result to the mode-decision branch — no fallthrough
- [ ] External format contracts (giget URI, raw URLs) are tested or at least documented as comments
- [ ] Metadata reads consume a complete response or use a streaming parser — never parse a fixed-size prefix as full JSON
- [ ] When reconstructing a composite identifier from parsed parts, verify **all** fields are included and in the **correct position** (e.g., `provider:repo/path#ref` not `provider:repo#ref/path`)
- [ ] Verify that **action functions** called after a shortcut don't internally use the old catch-all fetch — they must use the probe-quality variant when error distinction matters

**Real-world example**: Custom registry flow had 8 bugs across 3 review rounds: (1) probe only ran in interactive mode, (2) transient errors fell through to wrong mode, (3) giget URI had `#ref` in wrong position, (4) prefetched templates leaked across source switches, (5) `--template` shortcut bypassed probe but `downloadTemplateById` internally used catch-all `fetchTemplateIndex`, turning timeouts into "Template not found".

**Real-world example**: Agent-session update hints fetched npm `latest` metadata with `response.read(4096)` and then parsed it as complete JSON. The `@mindfoldhq/trellis` package metadata exceeded 4 KB, so the JSON was truncated, parse failed silently, and the first session injection showed no update hint. Fix: read the complete response before parsing, and add a regression where `version` is followed by an 8 KB metadata tail.

---

## When to Create Flow Documentation

Create detailed flow docs when:

- Feature spans 3+ layers
- Multiple teams are involved
- Data format is complex
- Feature has caused bugs before

---

## Event Log / Projection Boundary

Append-only logs are cross-layer contracts. A single event travels through:

```
CLI input → event writer → events.jsonl → reader → filter → reducer → display
```

### Checklist: After Adding A New Event Kind Or Field

- [ ] Add the event kind to the central event taxonomy
- [ ] Add a typed event variant or type guard at the event layer
- [ ] Add normalization helpers for array/object fields that come from
      user input or JSON
- [ ] Keep `seq` / `id` assignment in the event writer only
- [ ] Make filters and reducers consume the typed event guard, not local casts
- [ ] Make display code consume reducer output or typed events, not raw JSON
- [ ] Add at least one regression that proves history replay and live filtering
      use the same filter model

**Real-world example**: Thread channels added `kind: "thread"`, `description`,
`context`, labels, and `lastSeq`. The first implementation replayed thread
state correctly, but several commands still re-parsed event payload fields with
local casts. The fix was to make the core event layer own `ThreadChannelEvent`
and `isThreadEvent`, make `reduceChannelMetadata` the only channel metadata
projection, and make `reduceThreads` the only thread replay reducer.
