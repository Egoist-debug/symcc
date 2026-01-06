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
xmake build gen_input
```

The binary will be available in `gen_input/build/linux/x86_64/release/gen_input` (path may vary based on architecture).

## Usage

```bash
gen_input [options] <program>
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <dir>` | Directory to store valid inputs | `/tmp/geninput_output` |
| `-s, --seed <string>` | Initial seed input to start exploration | Empty string |
| `-l, --max-length <n>` | Maximum length of generated inputs | 64 bytes |
| `-i, --max-iter <n>` | Maximum number of exploration iterations | 1000 |
| `-t, --timeout <s>` | Timeout for each SymCC execution in seconds | 10 |
| `-a, --all-chars` | Allow non-printable characters (default: printable only) | Printable only |
| `-v, --verbose` | Enable verbose output | Disabled |
| `-h, --help` | Show help message | - |

### Example

1. Compile your parser with SymCC:
   ```bash
   symcc simple_parser.c -o simple_parser_sym
   ```

2. Run `gen_input` to discover valid inputs:
   ```bash
   # Discover inputs up to length 10, max 100 iterations
   ./gen_input -v -l 10 -i 100 -o ./valid_inputs ./simple_parser_sym
   ```

3. View results:
   ```bash
   ls ./valid_inputs/
   # Output: valid_0 valid_1 ...
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
    
    // Check for specific grammar: "A" followed by "B"
    if (len >= 2 && buffer[0] == 'A' && buffer[1] == 'B') {
        return 0; // Valid input
    }
    
    return 1; // Invalid input
}
```

## How It Works

1. **Initialization**: Starts with a seed input (default empty).
2. **Exploration**: 
   - For each current valid prefix, it appends a placeholder byte.
   - Runs SymCC on this input.
   - SymCC generates test cases that explore different paths for that byte.
3. **Validation**: 
   - The tool checks each generated extension by running the program.
   - If the program exits with code 0, the input is marked as valid.
4. **Queue Management**: Valid inputs are added to a queue for further extension until `max-length` or `max-iter` is reached.

## Notes & Limitations

- **Performance**: For complex grammars, the exploration queue can grow very large. Use `-i` to limit iterations.
- **Disk Usage**: SymCC generates temporary test cases in `/tmp/` during execution. `gen_input` cleans these up automatically.
- **Symbolic Reachability**: The tool can only discover inputs that are reachable via SymCC's path exploration. If the parser requires complex constraints that SymCC cannot solve, those inputs may be missed.
