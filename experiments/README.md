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
  --secondary-build-root experiments/subjects/dnsmasq/v2.92-build \
  --unbound-build-root experiments/subjects/dnsmasq/v2.92-build
```

```bash
./build/linux/x86_64/release/dnslabctl batch-sync-replay \
  --sample-dir <stable-corpus-dir> \
  --run-root experiments/runs/<timestamp> \
  --bind9-build-root <bind9-afl-tree> \
  --unbound-build-root <unbound-afl-tree>
```

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
