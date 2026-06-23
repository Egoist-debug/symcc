# Patch Layout

当前 patch 目录按“用途 -> resolver”组织：

- `patch/fuzz/bind9`
- `patch/cache/bind9`
- `patch/cache/unbound`

其中：

- `fuzz` 表示 producer 侧 AFL/SymCC fuzz 运行所需 patch。
- `cache` 表示 cache replay / oracle / diff 观察链路所需 patch。
- 当前只有 `bind9` 参与 fuzz 入口，因此没有 `patch/fuzz/unbound`。
- BIND9 的 `resolver-afl-symcc` 源文件同时服务 producer 和 diff/cache-dump；因此在 `fuzz/bind9` 与 `cache/bind9` 中保留角色副本，由对应入口显式选择。

## Bind9

| File | Category | Why |
| --- | --- | --- |
| `fuzz/bind9/bin/named/Makefile.am` | fuzz | producer named 需要编入 resolver-afl-symcc orchestrator 与 mutator server。 |
| `fuzz/bind9/bin/named/main.c` | fuzz | producer 入口解析 `resolver-afl-symcc` AFL 模式并启动 orchestrator。 |
| `fuzz/bind9/bin/named/resolver_afl_symcc_orchestrator.c` | fuzz | producer 侧 DST1 transcript、persistent AFL loop 与 oracle 统计主编排。 |
| `fuzz/bind9/bin/named/resolver_afl_symcc_mutator_server.c` | fuzz | producer 侧 in-process response 合成与 mutator server。 |
| `fuzz/bind9/include/named/resolver_afl_symcc_orchestrator.h` | fuzz | producer 侧 orchestrator 对外 API。 |
| `fuzz/bind9/include/named/resolver_afl_symcc_mutator_server.h` | fuzz | producer 侧 response hook API。 |
| `fuzz/bind9/lib/dns/dispatch.c` | fuzz | producer 侧 UDP response hook plumbing。 |
| `fuzz/bind9/lib/dns/include/dns/dispatch.h` | fuzz | producer 侧 dispatcher hook 声明。 |
| `fuzz/bind9/lib/isc/managers.c` | fuzz | producer 侧 manager lifecycle 兼容修正。 |
| `cache/bind9/bin/named/Makefile.am` | cache | diff/cache-dump named 需要编入 resolver-afl-symcc orchestrator 与 mutator server。 |
| `cache/bind9/bin/named/main.c` | cache | `resolver-afl-symcc` 模式解析与 orchestrator 生命周期入口。 |
| `cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c` | cache | DST1 transcript、oracle、second-query 与 cache-dump 主编排。 |
| `cache/bind9/bin/named/resolver_afl_symcc_mutator_server.c` | cache | in-process response 合成与 mutator server。 |
| `cache/bind9/include/named/resolver_afl_symcc_orchestrator.h` | cache | cache 模式 orchestrator 对外 API。 |
| `cache/bind9/include/named/resolver_afl_symcc_mutator_server.h` | cache | cache 模式 response hook API。 |
| `cache/bind9/lib/dns/dispatch.c` | cache | cache 模式 UDP response hook plumbing。 |
| `cache/bind9/lib/dns/include/dns/dispatch.h` | cache | cache 模式 dispatcher hook 声明。 |
| `cache/bind9/lib/isc/managers.c` | cache | cache 模式 manager lifecycle 兼容修正。 |

## Unbound

| File | Category | Why |
| --- | --- | --- |
| `cache/unbound/libunbound/libworker.c` | cache | cache/replay 路径下的 worker hook。 |
| `cache/unbound/smallapp/unbound-fuzzme.c` | cache | 单样本运行入口。 |
| `cache/unbound/smallapp/unbound_afl_symcc_orchestrator.c` | cache | unbound transcript/oracle/cache orchestrator。 |
| `cache/unbound/smallapp/unbound_afl_symcc_orchestrator.h` | cache | orchestrator 头文件。 |
| `cache/unbound/smallapp/unbound_afl_symcc_mutator_server.c` | cache | mutator server 实现。 |
| `cache/unbound/smallapp/unbound_afl_symcc_mutator_server.h` | cache | mutator server 头文件。 |
| `cache/unbound/smallapp/worker_cb.c` | cache | fake callback glue。 |

## Other Resolvers

这些 resolver 目前参与差分测试，但没有源码级 active patch；replay / dump-cache / oracle 汇总由 `tools/*_replay_harness.py` 脚本在 resolver 外部完成：

| Resolver | Source patch | Why |
| --- | --- | --- |
| `dnsmasq` | none | scripted cache/diff harness; no active source patch |
| `smartdns` | none | scripted cache/diff harness; no active source patch |
| `maradns` | none | scripted cache/diff harness; no active source patch |
| `knot-resolver` | none | scripted cache/diff harness; no active source patch |

若这些 resolver 后续需要源码级 diff/cache patch，必须放入 `patch/cache/<resolver>`，不能放入 `patch/fuzz` 或散落在 `experiments/subjects` 源树中。`patch/fuzz` 仅保留 producer 侧 fuzz patch。

## 同步约定

- `named_experiment/run_named_afl_symcc.sh` 只消费 `patch/<variant>/bind9`，producer 默认 `PATCH_VARIANT=fuzz`。
- 差分 replay / cache dump 入口显式传 `PATCH_VARIANT=cache`。
- `PATCH_VARIANT=cache|fuzz`；兼容旧值 `diff`，内部按 `cache` 处理。
- `bin/named/fuzz.c` 与 `lib/ns/client.c` 的旧副本不再作为 active patch 分发；同步时会恢复 baseline，清理历史 build tree 中可能残留的旧 patch。
- patch fan-out 默认目标树是 `experiments/subjects/bind9/<tag>`、`<tag>-afl`、`<tag>-symcc`；缺少 lock/subjects 时回落到旧 `bind-9.18.46*` 路径。切换 variant 时会先恢复非激活 variant 的基线文件，再覆盖当前 variant。
