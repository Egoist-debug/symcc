# gen_input：基于语法挖掘的输入生成器

`gen_input` 是一个利用动态符号执行技术发现解析器有效输入的工具。它实现了论文 "Generating Inputs for Grammar Mining using Dynamic Symbolic Execution" (Pointner et al., 2025) 中描述的方法。

该工具通过利用 SymCC 的符号执行能力，系统性地探索输入空间，找到目标程序所接受的有效字节扩展。

## 目录

- [功能概述](#功能概述)
- [核心算法](#核心算法)
- [架构设计](#架构设计)
- [先决条件](#先决条件)
- [构建说明](#构建说明)
- [使用方法](#使用方法)
- [格式感知生成](#格式感知生成)
- [混合 DNS 模糊测试模式](#混合-dns-模糊测试模式)
- [创建兼容的解析器](#创建兼容的解析器)
- [工作原理](#工作原理)
- [三阶段算法详解](#三阶段算法详解)
- [关键组件](#关键组件)
- [API 参考](#api-参考)
- [限制与注意事项](#限制与注意事项)

## 功能概述

`gen_input` 的主要功能是**自动发现解析器的有效输入**。给定一个用 SymCC 编译的解析器程序，它能够：

1. **探索输入空间**：系统性地搜索所有可能的字节序列
2. **发现有效输入**：找到被解析器接受（返回码为 0）的输入
3. **生成测试用例**：输出所有发现的有效输入到指定目录
4. **避免路径爆炸**：使用三阶段算法和茎（Stem）注入技术处理递归语法

### 应用场景

- **语法挖掘**：从程序行为中推断输入语法
- **模糊测试种子生成**：为 fuzzer 生成高质量的初始种子
- **协议逆向**：发现程序接受的协议格式
- **解析器测试**：自动生成解析器的测试用例

## 核心算法

### 占位符技术（Placeholder Technique）

这是 `gen_input` 的核心技术，工作流程如下：

```
1. 给定一个有效前缀 P（初始可为空）
2. 构造测试输入：I = P + '~'（'~' 是占位符字符）
3. 用 SymCC 执行目标程序，输入为 I
4. SymCC 在分支点生成满足不同路径的测试用例
5. 从生成的测试用例中提取位置 |P| 处的字节值
6. 这些字节值就是可以扩展 P 的有效字符
7. 对每个有效扩展 P' = P + c，重复步骤 2-6
```

### 直观理解

```
假设解析器检查输入是否以 "AB" 开头

初始：P = ""
步骤1：测试 "~" → SymCC 发现分支 input[0]=='A'
       → 生成测试用例 "A..."
       → 提取有效字符：{'A'}

P = "A"
步骤2：测试 "A~" → SymCC 发现分支 input[1]=='B'
       → 生成测试用例 "AB..."
       → 提取有效字符：{'B'}

P = "AB"
步骤3：测试 "AB~" → 程序接受 "AB"（返回 0）
       → 找到有效输入！
```

## 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                          main.cpp                                │
│                    (命令行接口 & 主循环)                           │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SymCCRunner                                 │
│          (SymCC 进程管理 & 测试用例收集)                           │
│  • run() - 执行 SymCC                                            │
│  • findValidExtensions() - 查找有效扩展                           │
│  • isAccepted() - 检查输入是否被接受                               │
└─────────────────────────────┬───────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────────┐
│ ThreePhase      │ │ Placeholder     │ │ ConstraintManager       │
│ Generator       │ │ Engine          │ │                         │
│                 │ │                 │ │ • Z3 约束求解            │
│ • Phase1: 初始化│ │ • 占位符技术    │ │ • findValidNextChars()  │
│ • Phase2: 模块化│ │ • 约束收集      │ │ • solve() / solveNegated│
│ • Phase3: 完成  │ │ • 有效字符发现  │ │                         │
└────────┬────────┘ └────────┬────────┘ └────────────┬────────────┘
         │                   │                        │
         └───────────────────┼────────────────────────┘
                             ▼
              ┌──────────────────────────┐
              │      InputPrefix         │
              │                          │
              │ • 当前输入数据           │
              │ • 路径约束               │
              │ • 函数调用深度           │
              │ • 茎（Stem）标记         │
              └──────────────────────────┘
```

## 先决条件

- SymCC 已构建且可用
- 目标程序必须使用 SymCC 编译
- 目标程序必须：
  - 对有效输入返回退出码 **0**
  - 对无效输入返回**非零**退出码
- Z3 库（用于约束求解）

## 构建说明

`gen_input` 集成在 SymCC 构建系统中：

```bash
# 从 symcc 根目录
cd /path/to/symcc

# 使用 xmake 构建
xmake build -P gen_input gen_input

# 构建测试目标（可选）
xmake build -P gen_input test_dns_format
xmake build -P gen_input dns_parser
xmake build -P gen_input dns_response_parser

# 二进制文件位置
./build/linux/x86_64/debug/gen_input
```

### 运行测试

```bash
# 运行 DNS 格式单元测试
./build/linux/x86_64/debug/test_dns_format
```

### 构建产物

| 文件 | 描述 |
|------|------|
| `gen_input` | 主可执行文件 |
| `libgeninput.a` | 静态库（供其他项目集成） |

## 使用方法

```bash
gen_input [选项] <程序路径>
```

### 命令行选项

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `-o, --output <目录>` | 存储有效输入的目录 | `/tmp/geninput_output` |
| `-s, --seed <字符串>` | 初始种子输入 | 空字符串 |
| `-f, --format <名称>` | 二进制格式（dns, dns-response, tlv） | 无（逐字节模式） |
| `-l, --max-length <n>` | 生成输入的最大长度 | 64 字节 |
| `-i, --max-iter <n>` | 最大探索迭代次数 | 1000 |
| `-t, --timeout <秒>` | 每次 SymCC 执行的超时时间 | 10 秒 |
| `-a, --all-chars` | 允许非可打印字符 | 仅可打印 |
| `-v, --verbose` | 启用详细输出 | 禁用 |
| `-h, --help` | 显示帮助信息 | - |

### 使用示例

1. **编译目标程序**：
   ```bash
   symcc simple_parser.c -o simple_parser_sym
   ```

2. **运行 gen_input**：
   ```bash
   # 发现最长 10 字节的输入，最多 100 次迭代
   ./gen_input -v -l 10 -i 100 -o ./valid_inputs ./simple_parser_sym
   ```

3. **查看结果**：
   ```bash
   ls ./valid_inputs/
   # 输出: valid_0 valid_1 ...
   
   # 查看具体内容
   xxd ./valid_inputs/valid_0
   ```

### 输出格式

生成的有效输入保存为二进制文件：
- 文件名格式：`valid_N`（N 从 0 开始递增）
- 文件内容：原始字节数据

## 格式感知生成

对于具有已知结构的二进制协议，`gen_input` 支持格式感知生成，在字段级别而非逐字节进行输入探索。这显著提高了结构化格式的探索效率。

### 支持的格式

| 格式 | 描述 |
|------|------|
| `dns` | DNS 查询数据包格式（RFC 1035）- 头部 + 查询部分 |
| `dns-response` | DNS 响应数据包格式 - 头部 + 查询 + 应答部分 |
| `tlv` | 类型-长度-值格式（大端序） |

### DNS 格式示例

1. **使用 SymCC 编译 DNS 解析器**：
   ```bash
   ./build/linux/x86_64/debug/symcc gen_input/test/dns_parser.c -o dns_parser_sym
   ```

2. **生成 DNS 数据包种子**：
   ```bash
   ./build/linux/x86_64/debug/gen_input --format dns -v -i 100 -o ./dns_seeds ./dns_parser_sym
   ```

3. **生成器将会**：
   - 创建具有正确头部结构的有效 DNS 查询包
   - 探索不同的查询类型（A, AAAA, MX 等）
   - 生成各种域名模式
   - 遵守 DNS 协议约束

4. **验证生成的种子**：
   ```bash
   ls ./dns_seeds/
   # 输出: valid_0 valid_1 valid_2 ...
   
   # 检查生成的数据包
   xxd ./dns_seeds/valid_0
   ```

### DNS 数据包结构

DNS 格式生成的数据包包含：
- **头部**（12 字节）：ID、标志、问题/回答计数
- **问题部分**：DNS 名称（标签编码）+ 查询类型 + 查询类

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### 自定义格式 API

`BinaryFormat` 类可用于编程方式定义自定义格式：

```cpp
#include "BinaryFormat.h"

geninput::BinaryFormat format("MyProtocol");
format.setDefaultEndian(geninput::ByteOrder::Big);

format.addField(geninput::FieldDef::U16("magic"));
format.addField(geninput::FieldDef::U8("version"));
format.addField(geninput::FieldDef::U16("length"));
format.addField(geninput::FieldDef::VarLen("payload", "length"));

auto seed = format.createSeed();
```

## 混合 DNS 模糊测试模式

对于需要处理响应数据包的 DNS 解析器模糊测试，`gen_input` 提供了混合模式，结合 AFL++ 变异和 SymCC 符号探索。

### 工作原理

在混合模式下：
- **头部字节**（可配置，默认 20 字节）保留给 AFL++ 进行变异
- **载荷字节**（应答/授权/附加部分）由 SymCC 进行探索

这允许：
1. AFL++ 高效地变异 DNS 头部和查询部分
2. SymCC 探索响应数据中的复杂约束（RR 类型、TTL、RDATA 格式）

### 使用方法

```bash
./gen_input --format dns-response --hybrid --preserve 20 -v -i 500 -o ./seeds ./dns_resolver_sym
```

| 选项 | 描述 | 默认值 |
|------|------|--------|
| `--hybrid` | 启用混合模式 | 禁用 |
| `--preserve <n>` | 要保留的头部字节数 | 20 |
| `--format dns-response` | 使用 DNS 响应格式 | 响应模糊测试必需 |

### 示例：模糊测试 DNS 解析器

```bash
# 1. 使用 SymCC 编译 DNS 解析器
./build/linux/x86_64/debug/symcc dns_resolver.c -o dns_resolver_sym

# 2. 使用混合模式生成响应种子
./gen_input --format dns-response --hybrid --preserve 20 -v -i 1000 -o ./response_seeds ./dns_resolver_sym

# 3. 将生成的种子用于 AFL++
afl-fuzz -i ./response_seeds -o ./findings -- ./dns_resolver_afl
```

### DNS 响应结构

DNS 响应数据包包含：
- **头部**（12 字节）：ID、标志（QR=1）、查询/应答/授权/附加计数
- **查询部分**（约 8+ 字节）：回显的查询名称、类型、类
- **应答部分**：资源记录，包含名称、类型、类、TTL、RDLENGTH、RDATA
- **授权部分**：NS 记录（可选）
- **附加部分**：胶水记录（可选）

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |  ─┐
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |   │ 头部
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │ (12 字节)
|                    QDCOUNT                    |   │
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|                    ANCOUNT                    |   │
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|                    NSCOUNT                    |   │
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|                    ARCOUNT                    |  ─┘
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |  ─┐ 查询部分
|                 Question Section              |   │ (可变长度)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  ─┘
|                                               |  ─┐
|              Answer Section (RRs)             |   │ SymCC
|                                               |   │ 探索
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │ 这些
|           Authority Section (RRs)             |   │ 部分
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|           Additional Section (RRs)            |  ─┘
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### DNS 响应生成 API 类

| 类 | 用途 |
|-------|---------|
| `BinaryFormatFactory::createDNSResponse()` | 创建 DNS 响应格式规范 |
| `BinaryFormatFactory::createDNSResourceRecord()` | 创建独立的 RR 格式 |
| `DNSPacketBuilder` | DNS 数据包（查询/响应）的流式构建器 |
| `DNSPacketBuilder::buildResponseFromQuery()` | 创建与查询 TxID 匹配的响应 |
| `DNSQueryResponseGenerator` | 生成配对的查询-响应数据包 |
| `HybridDNSGenerator` | 保留头部字节，使用 SymCC 探索载荷 |

## 创建兼容的解析器

### 基本要求

1. **从标准输入读取**：工具通过管道将输入传递给程序
2. **退出码约定**：
   - 返回 **0** 表示输入有效/被接受
   - 返回 **非零** 表示输入无效/被拒绝

### 示例解析器

```c
// simple_parser.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    char buffer[100];
    int len = read(0, buffer, sizeof(buffer));
    
    // 检查特定语法："A" 后面跟 "B"
    if (len >= 2 && buffer[0] == 'A' && buffer[1] == 'B') {
        return 0;  // 有效输入
    }
    
    return 1;  // 无效输入
}
```

### 更复杂的示例

```c
// json_like_parser.c - 简化的 JSON 解析器
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

int pos = 0;
char *input;
int len;

char peek() { return pos < len ? input[pos] : '\0'; }
char next() { return pos < len ? input[pos++] : '\0'; }
void skip_ws() { while (isspace(peek())) next(); }

int parse_value();

int parse_string() {
    if (next() != '"') return 0;
    while (peek() && peek() != '"') next();
    return next() == '"';
}

int parse_number() {
    if (!isdigit(peek())) return 0;
    while (isdigit(peek())) next();
    return 1;
}

int parse_array() {
    if (next() != '[') return 0;
    skip_ws();
    if (peek() == ']') { next(); return 1; }
    
    do {
        skip_ws();
        if (!parse_value()) return 0;
        skip_ws();
    } while (peek() == ',' && next());
    
    return next() == ']';
}

int parse_value() {
    skip_ws();
    char c = peek();
    if (c == '"') return parse_string();
    if (isdigit(c)) return parse_number();
    if (c == '[') return parse_array();
    return 0;
}

int main() {
    char buffer[1024];
    len = read(0, buffer, sizeof(buffer) - 1);
    buffer[len] = '\0';
    input = buffer;
    
    if (parse_value() && pos == len) {
        return 0;  // 有效 JSON
    }
    return 1;  // 无效
}
```

### DNS 解析器示例

`test/dns_parser.c` 中提供了完整的 DNS 数据包验证器，它验证：
- 最小数据包大小（12 字节头部）
- 查询标志（QR=0）
- 问题计数 > 0
- 有效的 DNS 名称编码
- 有效的查询类型和类

## 工作原理

### 主循环流程

```
┌──────────────────┐
│   初始化队列     │  ← 种子输入（默认为空）
│   Q = {seed}     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Q 非空 且       │  ← 迭代限制检查
│  迭代 < 最大值？ │
└────────┬─────────┘
         │ 是
         ▼
┌──────────────────┐
│ 从 Q 取出前缀 P  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 长度达到上限？   │
└────────┬─────────┘
         │ 否
         ▼
┌──────────────────┐
│ P 被接受？       │──是──▶ 保存为有效输入
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 查找有效扩展     │  ← 占位符技术
│ Extensions =     │
│ findValidExt(P)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 对每个有效字符 c │
│ Q.push(P + c)    │
└────────┬─────────┘
         │
         └──────────▶ 返回循环
```

### SymCC 集成详解

```
┌─────────────────────────────────────────────────────────────────┐
│                    findValidExtensions(P, '~')                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 构造输入：TestInput = P + '~'                               │
│                                                                  │
│  2. 准备环境：                                                   │
│     • 创建临时输出目录                                           │
│     • 设置 SYMCC_OUTPUT_DIR 环境变量                            │
│                                                                  │
│  3. 执行 SymCC 编译的程序：                                      │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │  fork()                                                  │ │
│     │    └─▶ 子进程:                                          │ │
│     │        • dup2(stdin, tempfile)                          │ │
│     │        • execl(program_sym)                             │ │
│     │        • SymCC 在分支点生成测试用例                      │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                  │
│  4. 收集结果：                                                   │
│     • 读取输出目录中的所有测试用例                               │
│     • 提取位置 |P| 处的字节值                                   │
│     • 过滤掉占位符本身                                          │
│                                                                  │
│  5. 清理：                                                       │
│     • 删除临时文件                                               │
│     • 删除输出目录                                               │
│                                                                  │
│  返回：有效字节集合 {c1, c2, ...}                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 三阶段算法详解

三阶段算法用于处理递归语法，避免路径爆炸：

### 阶段 1：初始化

- 从初始种子开始探索
- 收集每个语法函数的"茎"（Stem）
- 茎是函数产生的部分输入片段

```
示例：解析表达式 expr → term (('+' | '-') term)*

在解析 "1+2" 时：
  • 进入 expr()
  • 进入 term() → 收集茎 "1"
  • 看到 '+'
  • 进入 term() → 收集茎 "2"
  • 退出 expr()

收集到的茎：
  term: ["1", "2"]
```

### 阶段 2：模块化扩展

- 遇到函数调用时，注入预计算的茎
- 避免重复探索相同的子结构

```
探索新输入 "3*" 时：
  • 不需要完全探索 term()
  • 直接注入已知的茎 "1" 或 "2"
  • 生成 "3*1", "3*2" 等
```

### 阶段 3：完成

- 限制队列大小，强制完成输入
- 生成最终的有效输入

## 关键组件

### 1. SymCCRunner

负责与 SymCC 编译程序的交互：

```cpp
class SymCCRunner {
public:
    // 执行程序并收集测试用例
    RunResult run(const std::vector<uint8_t> &Input);
    
    // 查找有效的下一字节
    std::set<uint8_t> findValidExtensions(
        const std::vector<uint8_t> &Prefix,
        uint8_t Placeholder);
    
    // 检查输入是否被接受
    bool isAccepted(const std::vector<uint8_t> &Input);
};
```

### 2. PlaceholderEngine

实现占位符技术的核心引擎：

```cpp
class PlaceholderEngine {
public:
    // 查找所有有效的下一字符
    std::set<uint8_t> findValidNextChars(const InputPrefix &Prefix);
    
    // 扩展前缀
    ExtensionResult extendPrefix(const InputPrefix &Prefix);
    
    // 分支回调（用于约束收集）
    void onBranch(z3::expr Constraint, bool Taken, uintptr_t SiteId);
};
```

### 3. ConstraintManager

管理 Z3 约束和求解：

```cpp
class ConstraintManager {
public:
    // 创建符号字节
    z3::expr createInputByte(size_t Position);
    
    // 查找有效字符（核心算法）
    std::set<uint8_t> findValidNextChars(
        const InputPrefix &Prefix,
        uint8_t Placeholder = '~');
    
    // 求解约束
    SolveResult solve(const InputPrefix &Prefix);
    SolveResult solveNegated(const InputPrefix &Prefix);
};
```

### 4. InputPrefix

表示探索状态：

```cpp
class InputPrefix {
    std::vector<uint8_t> Data_;        // 当前输入数据
    std::vector<Constraint> Constraints_; // 路径约束
    size_t CallDepth_;                 // 函数调用深度
    std::optional<std::string> FunctionName_; // 关联的函数名
    bool IsStem_;                      // 是否是茎
};
```

### 5. ThreePhaseGenerator

三阶段算法实现：

```cpp
class ThreePhaseGenerator {
public:
    // 运行完整的三阶段算法
    std::vector<std::vector<uint8_t>> run();
    
    // 单独运行各阶段
    void runPhase1();  // 初始化
    void runPhase2();  // 模块化扩展
    void runPhase3();  // 完成
    
    // 添加种子
    void addSeed(const std::vector<uint8_t> &Seed);
    
    // 获取收集的茎
    const std::map<std::string, std::vector<Stem>> &getAllStems() const;
};
```

## API 参考

### RunConfig

```cpp
struct RunConfig {
    std::string ProgramPath;    // SymCC 编译的程序路径
    std::string OutputDir;      // 输出目录
    unsigned TimeoutSec = 30;   // 执行超时（秒）
    bool UseStdin = true;       // 是否使用标准输入
};
```

### GeneratorConfig

```cpp
struct GeneratorConfig {
    size_t MaxInputLength = 1024;     // 最大输入长度
    size_t MaxQueueSize = 1000;       // 阶段3队列大小限制
    size_t MaxStemsPerFunction = 10;  // 每函数最大茎数量
    size_t MaxIterations = 10000;     // 最大迭代次数
    unsigned SolverTimeoutMs = 5000;  // Z3 超时（毫秒）
    bool OnlyPrintable = true;        // 仅生成可打印字符
    bool VerboseLogging = false;      // 详细日志
};
```

### PlaceholderConfig

```cpp
struct PlaceholderConfig {
    uint8_t PlaceholderChar = '~';    // 占位符字符
    bool OnlyPrintable = true;        // 仅可打印字符
    size_t MaxInputLength = 1024;     // 最大输入长度
    unsigned SolverTimeoutMs = 5000;  // Z3 超时
};
```

## 限制与注意事项

### 性能考虑

- **复杂语法**：探索队列可能增长很大，使用 `-i` 限制迭代次数
- **递归深度**：深度递归的语法可能导致路径爆炸
- **约束复杂度**：复杂的数学约束可能导致 Z3 超时

### 磁盘使用

- SymCC 在执行过程中在 `/tmp/` 生成临时测试用例
- `gen_input` 会自动清理这些文件
- 确保 `/tmp/` 有足够空间

### 符号可达性

- 只能发现 SymCC 路径探索可达的输入
- 如果解析器需要 SymCC 无法求解的复杂约束，这些输入可能被遗漏
- 某些程序特性（如非确定性、系统调用）可能影响探索

### 已知限制

1. **非可打印字符**：默认只探索可打印 ASCII（0x20-0x7E）
2. **二进制协议**：对于复杂二进制格式可能需要调整占位符
3. **状态依赖**：无法处理依赖全局状态的解析器
4. **超时敏感**：某些复杂约束需要更长的求解时间
5. **格式限制**：格式感知模式目前支持 DNS、DNS-Response 和 TLV。自定义 JSON/YAML 格式规范计划中但尚未实现

## 参考文献

- Pointner, S., et al. "Generating Inputs for Grammar Mining using Dynamic Symbolic Execution." 2025.
- SymCC 原始论文：Poeplau, S., Francillon, A. "Symbolic execution with SymCC: Don't interpret, compile!" USENIX Security 2020.

## 许可证

本项目采用 GPL-3.0-or-later 许可证，与 SymCC 主项目保持一致。
