#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FILE="$ROOT_DIR/patch/cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c"

if ! grep -Fq "__AFL_LOOP(100000)" "$SOURCE_FILE"; then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must use __AFL_LOOP\n' >&2
	exit 1
fi

if grep -Fq "raise(SIGSTOP)" "$SOURCE_FILE"; then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must not hand-roll SIGSTOP\n' >&2
	exit 1
fi

printf 'PASS: named AFL persistent driver uses AFL loop handshake\n'
