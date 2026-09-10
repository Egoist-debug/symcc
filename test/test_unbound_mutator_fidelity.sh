#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="/tmp/test_unbound_mutator_fidelity"

gcc "$ROOT_DIR/test/test_unbound_mutator_fidelity.c" \
    -I"$ROOT_DIR/experiments/subjects/unbound/release-1.24.2-build/unbound-afl" \
    -I"$ROOT_DIR/experiments/subjects/unbound/release-1.24.2" \
    -I"$ROOT_DIR" \
    -o "$BIN"

"$BIN"
rm -f "$BIN"
