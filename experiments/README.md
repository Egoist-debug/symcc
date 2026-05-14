# experiments 目录约定

本目录承载 DNS 多解析器同步差分测试的源码冻结与运行产物。

## 布局

- `resolvers.manifest.tsv`
  - resolver 仓库、目标 tag、候选 tag 与备注说明
- `resolvers.lock.json`
  - 由 `./build/linux/x86_64/release/dnslabctl lock-generate` 生成的权威冻结文件
- `subjects/<resolver>/<tag>/`
  - 对应 resolver 的源码冻结目录
- `runs/<timestamp>/`
  - 单次实验运行目录，当前 `batch-sync-replay` 已能生成
    `summary.json`、`ablation_matrix.tsv`、`cluster_counts.tsv`、
    `repro_rate.tsv`、`oracle_audit.tsv`、`oracle_reliability.json`、
    `failure_taxonomy.tsv`、`exclusion_summary.tsv`、`cluster.tsv`、
    `case_studies/index.tsv`、`case_studies/*.md` 与 `evidence_bundle.json`

## 当前命令

```bash
./build/linux/x86_64/release/dnslabctl lock-generate \
  --manifest experiments/resolvers.manifest.tsv \
  --output experiments/resolvers.lock.json
```

```bash
./build/linux/x86_64/release/dnslabctl lock-resolved-tag \
  --resolver bind9
```

```bash
./build/linux/x86_64/release/dnslabctl prepare-subject \
  --resolver bind9
```

```bash
./build/linux/x86_64/release/dnslabctl prepare-subjects
```

```bash
./build/linux/x86_64/release/dnslabctl export-patch \
  --resolver bind9 \
  --purpose cache
```

```bash
./build/linux/x86_64/release/dnslabctl adapter-build \
  --resolver dnsmasq \
  --build-root experiments/subjects/dnsmasq/v2.92-build
```

```bash
./build/linux/x86_64/release/dnslabctl adapter-build \
  --resolver smartdns \
  --build-root experiments/subjects/smartdns/Release47.1-build
```

```bash
./build/linux/x86_64/release/dnslabctl adapter-build \
  --resolver maradns \
  --build-root experiments/subjects/maradns/deadwood-3.3.02-build
```

```bash
./build/linux/x86_64/release/dnslabctl adapter-build \
  --resolver knot-resolver \
  --build-root experiments/subjects/knot-resolver/v6.2.0-build
```

```bash
./build/linux/x86_64/release/dnslabctl adapter-dump-cache \
  --resolver dnsmasq \
  --build-root experiments/subjects/dnsmasq/v2.92-build \
  --run-root experiments/runs/<timestamp>/dnsmasq_dump \
  --sample <dst1-sample>
```

```bash
./build/linux/x86_64/release/dnslabctl sync-replay \
  --sample <dst1-sample> \
  --run-root experiments/runs/<timestamp>/sync_replay \
  --bind9-build-root <bind9-afl-tree> \
  --unbound-build-root <unbound-afl-tree>
```

```bash
./build/linux/x86_64/release/dnslabctl sync-replay \
  --sample <dst1-sample> \
  --run-root experiments/runs/<timestamp>/sync_replay_dnsmasq \
  --bind9-build-root <bind9-afl-tree> \
  --secondary-resolver dnsmasq \
  --secondary-build-root experiments/subjects/dnsmasq/v2.92-build
```

```bash
./build/linux/x86_64/release/dnslabctl batch-sync-replay \
  --sample-dir <stable-corpus-dir> \
  --run-root experiments/runs/<timestamp> \
  --bind9-build-root <bind9-afl-tree> \
  --secondary-resolver knot-resolver \
  --secondary-build-root experiments/subjects/knot-resolver/v6.2.0-build
```

```bash
python3 -m tools.dns_diff.cli campaign-matrix \
  --matrix-file tools/dns_diff/config/poison_stateful_knot_matrix.json \
  --budget-sec 3600 \
  --repeat 5 \
  --work-root experiments/matrix_runs/knot
```

```bash
python3 -m tools.dns_diff.cli resolver-matrix-aggregate \
  --matrix-root experiments/matrix_runs/unbound \
  --matrix-root experiments/matrix_runs/dnsmasq \
  --matrix-root experiments/matrix_runs/smartdns \
  --matrix-root experiments/matrix_runs/maradns \
  --matrix-root experiments/matrix_runs/knot \
  --output-dir experiments/matrix_runs/_resolver_summary
```

```bash
bash test/test_real_resolver_replay_matrix.sh
```

该脚本会在 `/home/ubuntu/tmp/real_resolver_replay_matrix/<timestamp>/` 下生成：

- `matrix.tsv`
- `manifest.json`
- `logs/*.log`

```bash
bash test/test_real_campaign_matrix_multi_resolver.sh
```

该脚本会在 `/home/ubuntu/tmp/real_campaign_matrix_batch/<timestamp>/` 下生成：

- `matrix_run_status.tsv`
- `<resolver>/_summary/*.tsv`
- `_resolver_summary/resolver_full_stack.tsv`
- `_resolver_summary/resolver_variant_summary.tsv`

```bash
python3 -m tools.dns_diff.cli resolver-capability-report \
  --replay-matrix-dir /home/ubuntu/tmp/real_resolver_replay_matrix/<timestamp> \
  --matrix-batch-dir /home/ubuntu/tmp/real_campaign_matrix_batch/<timestamp> \
  --output-dir /home/ubuntu/tmp/real_campaign_matrix_batch/<timestamp>/_resolver_capability
```

该命令会生成：

- `_resolver_capability/resolver_capability_summary.tsv`
- `_resolver_capability/resolver_capability_summary.json`
- `_resolver_capability/resolver_adapter_cost.tsv`
- `_resolver_capability/resolver_build_replay_matrix.tsv`
- `_resolver_capability/resolver_semantic_distribution.tsv`

```bash
python3 -m tools.dns_diff.cli resolver-backend-matrix-compare \
  --baseline-batch-dir /home/ubuntu/tmp/real_campaign_matrix_batch/<timestamp> \
  --candidate-batch-dir /home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/<timestamp> \
  --baseline-label python \
  --candidate-label dnslabctl \
  --output-dir /home/ubuntu/tmp/real_campaign_matrix_batch_dnslabctl/<timestamp>/_backend_compare
```

```bash
bash test/test_real_campaign_matrix_multi_resolver_dnslabctl.sh
```

可直接复用的 resolver matrix 配置：

- `tools/dns_diff/config/poison_stateful_longbudget_matrix.json`：`bind9_vs_unbound`
- `tools/dns_diff/config/poison_stateful_dnsmasq_matrix.json`：`bind9_vs_dnsmasq`
- `tools/dns_diff/config/poison_stateful_smartdns_matrix.json`：`bind9_vs_smartdns`
- `tools/dns_diff/config/poison_stateful_maradns_matrix.json`：`bind9_vs_maradns`
- `tools/dns_diff/config/poison_stateful_knot_matrix.json`：`bind9_vs_knot-resolver`

```bash
./build/linux/x86_64/release/dnslabctl adapter-list
```

```bash
./build/linux/x86_64/release/dnslabctl evidence-bundle \
  --output experiments/runs/<timestamp>/evidence_bundle.json \
  --run-id <run-id> \
  --summary experiments/runs/<timestamp>/summary.json \
  --oracle-audit experiments/runs/<timestamp>/oracle_audit.tsv \
  --failure-taxonomy experiments/runs/<timestamp>/failure_taxonomy.tsv \
  --cluster experiments/runs/<timestamp>/cluster.tsv \
  --case-index experiments/runs/<timestamp>/case_studies/index.tsv
```
