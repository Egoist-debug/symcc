#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="/tmp/test_track3_harness_and_shadow"
BIND9_OBJ="/tmp/resolver_afl_symcc_mutator_server_gcc.o"
PROBE_BIN="/tmp/test_symcc_probe"
PROBE_SRC="/tmp/test_symcc_probe.c"
SYMCC_OUT="/tmp/symcc_test_out_$$"

# 1. Compile BIND9 mutator server helper
gcc -c "$ROOT_DIR/patch/fuzz/bind9/bin/named/resolver_afl_symcc_mutator_server.c" \
    -include "$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl/config.h" \
    -I"$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl/bin/named/include" \
    -I"$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl/include" \
    -I"$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl/lib/isc/include" \
    -I"$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl/lib/dns/include" \
    -I"$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl/lib/ns/include" \
    -o "$BIND9_OBJ"

# 2. Compile and run Track 3 unit test (Unbound + BIND9 + F9)
gcc "$ROOT_DIR/test/test_track3_harness_and_shadow.c" "$BIND9_OBJ" \
    -I"$ROOT_DIR/experiments/subjects/unbound/release-1.24.2-build/unbound-afl" \
    -I"$ROOT_DIR/experiments/subjects/unbound/release-1.24.2" \
    -I"$ROOT_DIR" \
    -lpthread \
    -o "$BIN"

"$BIN"
rm -f "$BIN" "$BIND9_OBJ"

# 3. SymCC empirical shadow taint preservation probe
cat << 'PROBE' > "$PROBE_SRC"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

extern void symcc_make_symbolic(const void *start, size_t byte_length) __attribute__((weak));
extern void* _sym_read_memory(uint8_t *addr, size_t length, bool little_endian) __attribute__((weak));

int main(void) {
    uint8_t input[32] = "DST1\x01\x00querypayloadresponse";
    if (symcc_make_symbolic) {
        symcc_make_symbolic(input, sizeof(input));
    }
    
    // In-memory transfer via memcpy (as done by mutator server in-memory path)
    uint8_t in_mem[32];
    memcpy(in_mem, input, sizeof(input));
    
    // File transfer via write + fread (as was previously done)
    char path[] = "/tmp/symcc_probe_tmp_XXXXXX";
    int fd = mkstemp(path);
    ssize_t w = write(fd, input, sizeof(input));
    (void)w;
    close(fd);
    
    FILE *fp = fopen(path, "rb");
    uint8_t file_buf[32];
    size_t r = fread(file_buf, 1, sizeof(file_buf), fp);
    (void)r;
    fclose(fp);
    unlink(path);

    bool input_sym = (_sym_read_memory != NULL) ? (_sym_read_memory(input, 4, true) != NULL) : false;
    bool in_mem_sym = (_sym_read_memory != NULL) ? (_sym_read_memory(in_mem, 4, true) != NULL) : false;
    bool file_sym = (_sym_read_memory != NULL) ? (_sym_read_memory(file_buf, 4, true) != NULL) : false;

    printf("input_sym=%d in_mem_sym=%d file_sym=%d\n", input_sym, in_mem_sym, file_sym);
    if (input_sym && in_mem_sym && !file_sym) {
        printf("VERIFIED: In-memory transfer preserves SymCC shadow taint; file fread strips it!\n");
        return 0;
    }
    return 1;
}
PROBE

mkdir -p "$SYMCC_OUT"
"$ROOT_DIR/build/linux/x86_64/release/symcc" "$PROBE_SRC" -o "$PROBE_BIN"
env SYMCC_MEMORY_INPUT=1 SYMCC_OUTPUT_DIR="$SYMCC_OUT" "$PROBE_BIN"
rm -rf "$PROBE_BIN" "$PROBE_SRC" "$SYMCC_OUT"

echo "Track 3 (F4, F9) all tests passed successfully."
