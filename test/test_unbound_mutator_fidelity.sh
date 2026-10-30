#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/unbound-mutator-fidelity.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
export TMPDIR="$TMP_DIR"
BIN="$TMP_DIR/fidelity"

gcc -std=gnu11 "$ROOT_DIR/test/test_unbound_mutator_fidelity.c" \
    -I"$ROOT_DIR/patch/cache/unbound" \
    -I"$ROOT_DIR/experiments/subjects/unbound/release-1.24.2-build/unbound-afl" \
    -I"$ROOT_DIR/experiments/subjects/unbound/release-1.24.2" \
    -I"$ROOT_DIR" \
    -pthread -o "$BIN"

"$BIN"
