# DNS Poison RQ1 真实快照

## 文档目的

本文档记录 `docs/DNSPoisonFuzzingPlan.md` 中 RQ1“输入有效性”的当前真实最小快照，给出：

- 可复用运行命令
- 当前输入模型对比表
- 当前结果的解释边界

对应快照时间：

- `2026-05-14`

repo 内快照表：

- [RQ1InputModelSnapshot.tsv](/home/ubuntu/codex/symcc/docs/RQ1InputModelSnapshot.tsv)

原始真实产物：

- `/home/ubuntu/tmp/rq1_input_model_snapshot_probe/out/summary.tsv`

## 当前运行命令

```bash
bash test/test_real_rq1_input_model_snapshot.sh
```

该脚本会在 `/home/ubuntu/tmp/rq1_input_model_snapshot/<timestamp>/` 下生成：

- `out/summary.tsv`
- `out/summary.json`

## 当前快照表

| model_name | parse_accept_rate | recursive_or_cache_path_rate | response_accept_rate | effective_post_check_rate |
| --- | --- | --- | --- | --- |
| `dst1_transcript` | `1.000000` | `1.000000` | `1.000000` | `0.000000` |
| `query_only` | `1.000000` | `1.000000` | `1.000000` | `-` |
| `random_packet` | `0.000000` | `0.000000` | `0.000000` | `-` |
| `legacy_response_tail` | `1.000000` | `1.000000` | `1.000000` | `-` |

## 当前结论

### 1. `random_packet` 在当前最小快照下明显无效

在当前单样本探针中，`random_packet` 的：

- `parse_accept_rate = 0`
- `recursive_or_cache_path_rate = 0`
- `response_accept_rate = 0`

这符合 RQ1 的预期方向：无结构随机包对当前 producer 路径几乎没有有效贡献。

### 2. 结构化输入模型在当前最小快照下都能进入 resolver 路径

`dst1_transcript`、`query_only` 与 `legacy_response_tail` 当前都达到：

- `parse_accept_rate = 1`
- `recursive_or_cache_path_rate = 1`

这说明结构化输入在当前 producer 路径中确实优于随机输入。

### 3. `DST1 transcript` 的当前单样本快照还没有体现更高的 post-check 有效性

当前 `dst1_transcript` 的：

- `effective_post_check_rate = 0`

这说明当前使用的单一 transcript 样本还没有稳定命中 post-check 代理信号。它不能说明 `DST1 transcript` 不如其它输入模型，只能说明当前快照样本过小、过弱。

## 当前局限

1. 当前快照只用了 1 个样本/模型。
2. `query_only` 与 `legacy_response_tail` 在这份最小探针上没有拉开差距。
3. `DST1 transcript` 的 post-check 优势仍未在当前单样本快照中体现出来。

## 下一步建议

1. 扩大每类输入模型的样本数。
2. 优先接入 `named_experiment/work/query_corpus`、`transcript_corpus`、`stable_*` 目录，而不再只用手工单样本。
3. 对 `dst1_transcript` 选取一批 `second_query_hit=1` 的真实 transcript，再重做这张表。
