# gen_input: Grammar Mining Input Generator

`gen_input` is a tool that discovers valid inputs for a parser using dynamic symbolic execution. It implements the approach described in "Generating Inputs for Grammar Mining using Dynamic Symbolic Execution" (Pointner et al., 2025).

The tool systematically explores the input space by leveraging SymCC's symbolic execution capabilities to find valid byte extensions that are accepted by the target program.

## Prerequisites

- SymCC must be built and available
- Target program must be compiled with SymCC
- Target program must exit with code 0 for valid inputs and non-zero for invalid inputs

## Build Instructions

`gen_input` is integrated into the SymCC build system. To build it:

```bash
# From the symcc root directory
xmake build -P gen_input gen_input

# Build test targets (optional)
xmake build -P gen_input test_dns_format
xmake build -P gen_input dns_parser
```

The binary will be available in `build/linux/x86_64/debug/gen_input` or `build/linux/x86_64/release/gen_input` (path may vary based on architecture and build mode).

### Running Tests

```bash
# Run DNS format unit tests
./build/linux/x86_64/debug/test_dns_format
```

## Usage

```bash
gen_input [options] <program>
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <dir>` | Directory to store valid inputs | `/tmp/geninput_output` |
| `-s, --seed <string>` | Initial seed input to start exploration | Empty string |
| `-f, --format <name>` | Binary format for structured generation (dns, tlv) | None (byte-by-byte) |
| `-l, --max-length <n>` | Maximum length of generated inputs | 64 bytes |
| `-i, --max-iter <n>` | Maximum number of exploration iterations | 1000 |
| `-t, --timeout <s>` | Timeout for each SymCC execution in seconds | 10 |
| `-a, --all-chars` | Allow non-printable characters (default: printable only) | Printable only |
| `-v, --verbose` | Enable verbose output | Disabled |
| `-h, --help` | Show help message | - |

### Basic Example

1. Compile your parser with SymCC:
   ```bash
   symcc simple_parser.c -o simple_parser_sym
   ```

2. Run `gen_input` to discover valid inputs:
   ```bash
   ./gen_input -v -l 10 -i 100 -o ./valid_inputs ./simple_parser_sym
   ```

3. View results:
   ```bash
   ls ./valid_inputs/
   # Output: valid_0 valid_1 ...
   ```

## Format-Aware Generation

For binary protocols with known structure, `gen_input` supports format-aware generation that explores inputs at the field level rather than byte-by-byte. This significantly improves efficiency for structured formats.

### Supported Formats

| Format | Description |
|--------|-------------|
| `dns` | DNS query packet format (RFC 1035) - header + query section |
| `dns-response` | DNS response packet format - header + query + answer sections |
| `tlv` | Type-Length-Value format (big-endian) |

### DNS Format Example

1. Compile the DNS parser with SymCC:
   ```bash
   ./build/linux/x86_64/debug/symcc gen_input/test/dns_parser.c -o dns_parser_sym
   ```

2. Generate DNS packet seeds:
   ```bash
   ./build/linux/x86_64/debug/gen_input --format dns -v -i 100 -o ./dns_seeds ./dns_parser_sym
   ```

3. The generator will:
   - Create valid DNS query packets with proper header structure
   - Explore different query types (A, AAAA, MX, etc.)
   - Generate various domain name patterns
   - Respect DNS protocol constraints

4. Verify generated seeds:
   ```bash
   ls ./dns_seeds/
   # Output: valid_0 valid_1 valid_2 ...
   
   # Check a generated packet
   xxd ./dns_seeds/valid_0
   ```

### DNS Packet Structure

The DNS format generates packets with:
- **Header** (12 bytes): ID, flags, question/answer counts
- **Question Section**: DNS name (label-encoded) + query type + query class

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

## Creating a Compatible Parser

For `gen_input` to work correctly, your target program must:

1. **Read from STDIN**: The tool pipes input to the program's standard input.
2. **Exit Code Signal**: 
   - Return **0** if the input is valid/accepted.
   - Return **non-zero** if the input is invalid/rejected.

### Example Parser (`simple_parser.c`)

```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    char buffer[100];
    int len = read(0, buffer, sizeof(buffer));
    
    if (len >= 2 && buffer[0] == 'A' && buffer[1] == 'B') {
        return 0;
    }
    
    return 1;
}
```

### Example DNS Parser (`test/dns_parser.c`)

A complete DNS packet validator is provided in `test/dns_parser.c`. It validates:
- Minimum packet size (12 bytes header)
- Query flag (QR=0)
- Question count > 0
- Valid DNS name encoding
- Valid query type and class

## How It Works

### Byte-by-Byte Mode (default)

1. **Initialization**: Starts with a seed input (default empty).
2. **Exploration**: 
   - For each current valid prefix, it appends a placeholder byte.
   - Runs SymCC on this input.
   - SymCC generates test cases that explore different paths for that byte.
3. **Validation**: 
   - The tool checks each generated extension by running the program.
   - If the program exits with code 0, the input is marked as valid.
4. **Queue Management**: Valid inputs are added to a queue for further extension until `max-length` or `max-iter` is reached.

### Format-Aware Mode (`--format`)

1. **Seed Creation**: Creates initial seed based on format specification with default values.
2. **Field-Level Exploration**: 
   - Mutates individual fields based on their constraints (e.g., query type can be A, AAAA, MX, etc.)
   - Maintains format validity throughout exploration
3. **Constraint Enforcement**: Generated inputs always conform to the format structure.
4. **SymCC Integration**: Uses SymCC to discover additional valid inputs that satisfy the parser.

## API for Custom Formats

The `BinaryFormat` class can be used programmatically to define custom formats:

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

## Notes & Limitations

- **Performance**: For complex grammars, the exploration queue can grow very large. Use `-i` to limit iterations.
- **Disk Usage**: SymCC generates temporary test cases in `/tmp/` during execution. `gen_input` cleans these up automatically.
- **Symbolic Reachability**: The tool can only discover inputs that are reachable via SymCC's path exploration. If the parser requires complex constraints that SymCC cannot solve, those inputs may be missed.
- **Format Limitations**: Format-aware mode currently supports DNS, DNS-Response, and TLV. Custom JSON/YAML format specifications are planned but not yet implemented.

## Hybrid DNS Fuzzing Mode

For fuzzing DNS resolvers that process response packets, `gen_input` provides a hybrid mode that combines AFL++ mutation with SymCC symbolic exploration.

### How It Works

In hybrid mode:
- **Header bytes** (configurable, default 20 bytes) are preserved for AFL++ to mutate
- **Payload bytes** (Answer/Authority/Additional sections) are explored by SymCC

This allows:
1. AFL++ to efficiently mutate the DNS header and question section
2. SymCC to explore complex constraints in the response data (RR types, TTLs, RDATA formats)

### Usage

```bash
./gen_input --format dns-response --hybrid --preserve 20 -v -i 500 -o ./seeds ./dns_resolver_sym
```

| Option | Description | Default |
|--------|-------------|---------|
| `--hybrid` | Enable hybrid mode | Disabled |
| `--preserve <n>` | Number of header bytes to preserve | 20 |
| `--format dns-response` | Use DNS response format | Required for response fuzzing |

### Example: Fuzzing a DNS Resolver

```bash
# 1. Compile the DNS resolver with SymCC
./build/linux/x86_64/debug/symcc dns_resolver.c -o dns_resolver_sym

# 2. Generate response seeds with hybrid mode
./gen_input --format dns-response --hybrid --preserve 20 -v -i 1000 -o ./response_seeds ./dns_resolver_sym

# 3. Use generated seeds with AFL++
afl-fuzz -i ./response_seeds -o ./findings -- ./dns_resolver_afl
```

### DNS Response Structure

DNS response packets contain:
- **Header** (12 bytes): ID, flags (QR=1), question/answer/authority/additional counts
- **Question Section** (~8+ bytes): Echoed query name, type, class
- **Answer Section**: Resource records with name, type, class, TTL, RDLENGTH, RDATA
- **Authority Section**: NS records (optional)
- **Additional Section**: Glue records (optional)

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |  ─┐
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |   │ Header
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │ (12 bytes)
|                    QDCOUNT                    |   │
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|                    ANCOUNT                    |   │
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|                    NSCOUNT                    |   │
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|                    ARCOUNT                    |  ─┘
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |  ─┐ Question
|                 Question Section              |   │ (variable)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  ─┘
|                                               |  ─┐
|              Answer Section (RRs)             |   │ SymCC
|                                               |   │ explores
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │ these
|           Authority Section (RRs)             |   │ sections
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+   │
|           Additional Section (RRs)            |  ─┘
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### API Classes for DNS Response Generation

| Class | Purpose |
|-------|---------|
| `BinaryFormatFactory::createDNSResponse()` | Creates DNS response format specification |
| `BinaryFormatFactory::createDNSResourceRecord()` | Creates standalone RR format |
| `DNSPacketBuilder` | Fluent builder for DNS packets (query/response) |
| `DNSPacketBuilder::buildResponseFromQuery()` | Creates response matching query's TxID |
| `DNSQueryResponseGenerator` | Generates paired Query-Response packets |
| `HybridDNSGenerator` | Preserves header bytes, explores payload with SymCC |
