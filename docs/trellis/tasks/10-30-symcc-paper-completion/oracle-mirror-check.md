# C++ Oracle 发送观测镜像检查

结论：最小补丁与自检通过；未运行 `xmake`、resolver 或长实验，未提交代码。

## 改动与边界

仅修改 `symcc/` 下三个独占文件，保留已有 A1–A3 改动：

- `dnslab_core/include/dnslab_core/oracle.hpp:19`：追加 `std::optional<bool> FakeReplyDispatched`。
- `dnslab_core/src/oracle.cpp:101-105,120-121`：复用 `parseBoolToken` 独立解析，用 `setOptional` 输出布尔值或显式 `null`。缺失/非法值不改变 `stderr_parse_status`，不从 `response_accepted` 反推。
- `dnslab_core/test/test_oracle.cpp`：覆盖 `0/1`、缺失、非法 `2/true/false/空值`，交叉检查两种 resolver 和 accepted 状态，以及缺 stderr、缺 summary、旧必需字段不完整与最终 JSON；在头文件之后取消 `NDEBUG`，保证断言执行。

全仓搜索未发现位置式 `OracleSnapshot` 聚合初始化。消费者位于
`concrete_adapters.cpp:557-562,734-740,984-988,1146-1150` 和
`main.cpp` 的 `runOracleParseCommand`，均复用 `toJson`；后续原样传递字段对象，
无需范围外适配。Python `ORACLE_FIELDS`、C++ `kOracleDiffFieldNames` 和
`kOracleFields` 保持原六字段，发送观测不加入语义差异统计。

## 实际验证

工作目录：`/home/egoist/work/symcc`。

```bash
g++ -std=c++17 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror \
  -I dnslab_core/include dnslab_core/src/oracle.cpp \
  dnslab_core/test/test_oracle.cpp \
  -o /tmp/symcc-oracle-mirror.D2DAJy/oracle_test
/tmp/symcc-oracle-mirror.D2DAJy/oracle_test

g++ -std=c++17 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror \
  -I dnslab_core/include dnslab_core/src/oracle.cpp \
  /tmp/symcc-oracle-mirror.D2DAJy/oracle_dump.cpp \
  -o /tmp/symcc-oracle-mirror.D2DAJy/oracle_dump
PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /tmp/symcc-oracle-mirror.D2DAJy/check_parity.py

git diff --check -- dnslab_core/include/dnslab_core/oracle.hpp \
  dnslab_core/src/oracle.cpp dnslab_core/test/test_oracle.cpp
```

- 上述最终命令分别退出 `0`；编译无警告。
- 修复生产实现之前，同样的 `-DNDEBUG` 编译退出 `0`，测试因缺少 `"unbound.fake_reply_dispatched":null` 断言失败，shell 退出 `134`（SIGABRT；Python 返回 `-6`）。证明回归确实执行且捕获原缺口。
- 临时驱动只链接生产 `oracle.cpp`，34 条输出经 `json.loads` 与当前 Python 完整字典逐项比较一致；同时断言三处语义字段清单仍为原六字段。
- 初始只读探查误用了不存在的 `json.hpp/json_value.cpp`，出现退出 `1/2`；随后确认 JSON 实现实际在 `json_value.hpp`，不需要额外源文件。未修改相关文件。
- 三个源码文件原为 LF，本次保持 LF 和末尾换行。

## 待统一验证

由 A1/最终 check 执行 `dnslab_core_oracle_test`、`dnslabctl` 的完整构建/集成检查。
本次没有证明真实 resolver 发送链路或全系统正确；临时对照驱动留在上述 `/tmp` 目录，不属于仓库交付。
