#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT_DIR/build/linux/x86_64/release/test_dst1_mutator"
MODE="both"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      if [ "$#" -lt 2 ]; then
        printf 'ERROR: --mode 缺少参数\n' >&2
        exit 2
      fi
      MODE="$2"
      shift 2
      ;;
    *)
      printf 'USAGE: %s [--mode baseline|mutator|both]\n' "$0" >&2
      exit 2
      ;;
  esac
done

if [ ! -x "$BIN" ]; then
  printf 'ERROR: 缺少可执行文件 %s\n' "$BIN" >&2
  exit 1
fi

run_one() {
  local mode="$1"
  printf '[dst1-mutator-smoke] run mode=%s\n' "$mode"
  "$BIN" --mode "$mode"
}

case "$MODE" in
  baseline)
    run_one baseline
    ;;
  mutator)
    run_one mutator
    ;;
  both)
    run_one baseline
    run_one mutator
    ;;
  *)
    printf 'ERROR: 不支持的 mode=%s\n' "$MODE" >&2
    exit 2
    ;;
esac

printf '[dst1-mutator-smoke] PASS: mode=%s\n' "$MODE"
