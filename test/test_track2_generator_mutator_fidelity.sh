#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="/tmp/test_track2_generator_mutator_fidelity_bin"

"${CXX:-g++}" -std=c++17 -Wall -Wextra -Wpedantic \
  -I"$ROOT_DIR/gen_input/include" \
  -I"$ROOT_DIR/runtime/include" \
  "$ROOT_DIR/test/test_track2_generator_mutator_fidelity.cpp" \
  "$ROOT_DIR/gen_input/src/DST1Mutator.cpp" \
  "$ROOT_DIR/gen_input/src/FormatAwareGenerator.cpp" \
  "$ROOT_DIR/gen_input/src/BinaryFormat.cpp" \
  "$ROOT_DIR/gen_input/src/SymCCRunner.cpp" \
  -lresolv \
  -o "$BIN_PATH"

"$BIN_PATH"
rm -f "$BIN_PATH"
