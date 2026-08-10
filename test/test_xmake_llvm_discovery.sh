#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
PROJECT_DIR="$TMP_DIR/project"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$PROJECT_DIR"
cp "$ROOT_DIR/xmake.lua" "$PROJECT_DIR/xmake.lua"
ln -s "$ROOT_DIR/runtime" "$PROJECT_DIR/runtime"
ln -s "$ROOT_DIR/util" "$PROJECT_DIR/util"
ln -s "$ROOT_DIR/gen_input" "$PROJECT_DIR/gen_input"
ln -s "$ROOT_DIR/dnslab_core" "$PROJECT_DIR/dnslab_core"

run_xmake() (
  cd "$PROJECT_DIR"
  xmake "$@"
)

run_xmake_without_llvm_env() (
  unset SYMCC_LLVM_PREFIX SYMCC_LLVM_MAJOR
  cd "$PROJECT_DIR"
  xmake "$@"
)

mapfile -t LLVM_INSTALLATIONS < <(
  for prefix in /usr/lib/llvm-*; do
    major="${prefix##*/llvm-}"
    if [[ "$major" =~ ^[0-9]+$ ]] &&
       [[ -x "$prefix/bin/clang" ]] &&
       [[ -x "$prefix/bin/clang++" ]]; then
      printf '%s\t%s\n' "$major" "$prefix"
    fi
  done | sort -nr
)

if [[ ${#LLVM_INSTALLATIONS[@]} -eq 0 ]]; then
  printf 'ASSERT FAIL: no usable versioned LLVM installation under /usr/lib\n' >&2
  exit 1
fi

highest_major="${LLVM_INSTALLATIONS[0]%%$'\t'*}"
highest_prefix="${LLVM_INSTALLATIONS[0]#*$'\t'}"
auto_config="$TMP_DIR/auto-config.lua"

run_xmake_without_llvm_env f -c --export="$auto_config" >/dev/null
grep -Fq "symcc_llvm_prefix = \"$highest_prefix\"" "$auto_config"
grep -Fq "symcc_llvm_major = \"$highest_major\"" "$auto_config"

explicit="${LLVM_INSTALLATIONS[${#LLVM_INSTALLATIONS[@]}-1]}"
explicit_major="${explicit%%$'\t'*}"
explicit_prefix="${explicit#*$'\t'}"
explicit_config="$TMP_DIR/explicit-config.lua"

SYMCC_LLVM_PREFIX="$explicit_prefix" SYMCC_LLVM_MAJOR="$explicit_major" \
  run_xmake f -c \
  --export="$explicit_config" >/dev/null
grep -Fq "symcc_llvm_prefix = \"$explicit_prefix\"" "$explicit_config"
grep -Fq "symcc_llvm_major = \"$explicit_major\"" "$explicit_config"

override_config="$TMP_DIR/override-config.lua"
SYMCC_LLVM_PREFIX="$explicit_prefix" SYMCC_LLVM_MAJOR="$explicit_major" \
  run_xmake f -c \
  --symcc_llvm_prefix="$highest_prefix" \
  --symcc_llvm_major="$highest_major" \
  --export="$override_config" >/dev/null
grep -Fq "symcc_llvm_prefix = \"$highest_prefix\"" "$override_config"
grep -Fq "symcc_llvm_major = \"$highest_major\"" "$override_config"

run_xmake f -c \
  --symcc_llvm_prefix="$explicit_prefix" \
  --symcc_llvm_major="$explicit_major" \
  --export="$explicit_config" >/dev/null
grep -Fq "symcc_llvm_prefix = \"$explicit_prefix\"" "$explicit_config"
grep -Fq "symcc_llvm_major = \"$explicit_major\"" "$explicit_config"

cached_config="$TMP_DIR/cached-config.lua"
run_xmake_without_llvm_env f --export="$cached_config" >/dev/null
grep -Fq "symcc_llvm_prefix = \"$explicit_prefix\"" "$cached_config"
grep -Fq "symcc_llvm_major = \"$explicit_major\"" "$cached_config"

invalid_log="$TMP_DIR/invalid-prefix.log"
if run_xmake f -c \
     --symcc_llvm_prefix="$TMP_DIR/missing-llvm" \
     --symcc_llvm_major="$highest_major" >"$invalid_log" 2>&1; then
  printf 'ASSERT FAIL: invalid LLVM prefix unexpectedly configured\n' >&2
  exit 1
fi
grep -Fq "Invalid SymCC LLVM prefix '$TMP_DIR/missing-llvm'" "$invalid_log"

nonexec_prefix="$TMP_DIR/nonexec-llvm"
mkdir -p "$nonexec_prefix/bin"
touch "$nonexec_prefix/bin/clang" "$nonexec_prefix/bin/clang++"
chmod 0644 "$nonexec_prefix/bin/clang" "$nonexec_prefix/bin/clang++"
nonexec_log="$TMP_DIR/nonexec-prefix.log"
if run_xmake f -c \
     --symcc_llvm_prefix="$nonexec_prefix" \
     --symcc_llvm_major="$highest_major" >"$nonexec_log" 2>&1; then
  printf 'ASSERT FAIL: non-executable LLVM prefix unexpectedly configured\n' >&2
  exit 1
fi
grep -Fq "Invalid SymCC LLVM prefix '$nonexec_prefix': expected executable" "$nonexec_log"

invalid_major_log="$TMP_DIR/invalid-major.log"
if run_xmake f -c \
     --symcc_llvm_prefix="$highest_prefix" \
     --symcc_llvm_major=not-a-major >"$invalid_major_log" 2>&1; then
  printf 'ASSERT FAIL: invalid LLVM major unexpectedly configured\n' >&2
  exit 1
fi
grep -Fq "Invalid SymCC LLVM major version 'not-a-major'" "$invalid_major_log"

printf '[xmake-llvm-discovery] PASS\n'
