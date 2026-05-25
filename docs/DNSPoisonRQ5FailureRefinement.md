# DNS Poison RQ5 failure refinement

## 目的

把 `unbound / smartdns` 在当前多样本主表里的 `runtime_or_parse_failure` 进一步收敛成更稳妥的论文表述。

## 汇总表

| resolver | total_samples | completed_samples | bind9_parse_ok_samples | secondary_parse_ok_samples | semantic_outcome | diff_class | interpretation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `unbound` | `20` | `20` | `20` | `20` | `runtime_or_parse_failure` | `oracle_parse_incomplete` | 样本已完成 replay，当前只是 oracle 证据不完整 |
| `smartdns` | `20` | `20` | `20` | `20` | `runtime_or_parse_failure` | `oracle_parse_incomplete` | 样本已完成 replay，当前只是 oracle 证据不完整 |

## 可直接写入论文的表述

> 在当前 `queue_limit=4` 的多样本批次中，`unbound` 和 `smartdns` 的 `20/20` 个样本均完成 replay，且 `bind9` 与 secondary 的 `parse_ok` 都为真。当前 `runtime_or_parse_failure` 更适合被保守地解释为 `oracle_parse_incomplete`，而不是目标未运行或目标崩溃。这一结果说明，我们当前的失败标签已经开始区分“语义证据不足”与“真实运行失败”。

## 结论边界

- 这张表只说明当前批次的失败标签需要更细
- 它不说明 `unbound` 或 `smartdns` 已经出现漏洞
- 它只说明当前 `runtime_or_parse_failure` 过粗，适合进一步拆分
