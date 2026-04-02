# Patch Layout

当前 patch 目录按“用途 -> resolver”组织：

- `patch/fuzz/bind9`
- `patch/cache/bind9`
- `patch/cache/unbound`

其中：

- `fuzz` 表示 producer 侧 AFL fuzz 运行所需 patch。
- `cache` 表示 cache replay / oracle / diff 观察链路所需 patch。
- 当前只有 `bind9` 参与 fuzz 入口，因此没有 `patch/fuzz/unbound`。

## Bind9

| File | Category | Why |
| --- | --- | --- |
| `fuzz/bind9/bin/named/fuzz.c` | fuzz | AFL 输入驱动与持久循环逻辑。 |
| `fuzz/bind9/lib/ns/client.c` | fuzz | fuzz 模式也依赖的 resolver cleanup/notify 路径。 |
| `cache/bind9/bin/named/main.c` | cache | `resolver-afl-symcc` 模式解析与 orchestrator 生命周期入口。 |
| `cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c` | cache | DST1 transcript、oracle、second-query 与 cache-dump 主编排。 |
| `cache/bind9/bin/named/resolver_afl_symcc_mutator_server.c` | cache | in-process response 合成与 mutator server。 |
| `cache/bind9/include/named/resolver_afl_symcc_orchestrator.h` | cache | cache 模式 orchestrator 对外 API。 |
| `cache/bind9/include/named/resolver_afl_symcc_mutator_server.h` | cache | cache 模式 response hook API。 |
| `cache/bind9/lib/dns/dispatch.c` | cache | cache 模式 UDP response hook plumbing。 |
| `cache/bind9/lib/dns/include/dns/dispatch.h` | cache | cache 模式 dispatcher hook 声明。 |
| `cache/bind9/lib/ns/client.c` | cache | cache 模式依赖的 resolver cleanup/notify 路径。 |
| `cache/bind9/residual/main.c` | residual | 历史顶层副本，不参与同步。 |
| `cache/bind9/residual/resolver_afl_symcc_orchestrator.c` | residual | 历史顶层 orchestrator 副本，不参与同步。 |
| `cache/bind9/residual/resolver_afl_symcc_mutator_server.c` | residual | 历史顶层 mutator 副本，不参与同步。 |

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

## 同步约定

- `named_experiment/run_named_afl_symcc.sh` 只消费 `patch/<variant>/bind9`。
- `PATCH_VARIANT=cache|fuzz`；兼容旧值 `diff`，内部按 `cache` 处理。
- `bind-9.18.46*` 中仍是 patch fan-out 目标树；切换 variant 时会先恢复非激活 variant 的基线文件，再覆盖当前 variant。
