#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
PROJECT_DIR="$TMP_DIR/project"
XMAKE_PROGRAM="$(command -v xmake)"

mkdir -p "$TMP_DIR/path-bin"
cat > "$TMP_DIR/path-bin/lit" <<'EOF'
#!/bin/sh
printf 'ASSERT FAIL: PATH lit fallback was selected\n' >&2
exit 99
EOF
chmod 0755 "$TMP_DIR/path-bin/lit"

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
ln -s "$ROOT_DIR/compiler" "$PROJECT_DIR/compiler"
ln -s "$ROOT_DIR/test" "$PROJECT_DIR/test"

run_xmake() (
  cd "$PROJECT_DIR"
  xmake "$@"
)

run_xmake_without_llvm_env() (
  unset SYMCC_LLVM_PREFIX SYMCC_LLVM_MAJOR
  cd "$PROJECT_DIR"
  xmake "$@"
)

run_xmake_without_llvm_path() (
  PATH="$TMP_DIR/path-bin:$(dirname "$XMAKE_PROGRAM"):/usr/local/bin:/usr/bin:/bin"
  export PATH
  cd "$PROJECT_DIR"
  "$XMAKE_PROGRAM" "$@"
)

has_llvm_link_library() {
  local prefix="$1"
  local major="$2"
  local candidate

  for candidate in \
    "$prefix/lib/libLLVM-$major.so" \
    "$prefix/lib/libLLVM-$major.a" \
    "$prefix/lib/libLLVM-$major.dylib" \
    "$prefix/lib/libLLVM-$major.dll.a" \
    "$prefix/lib/LLVM-$major.lib"; do
    if [[ -f "$candidate" ]]; then
      return 0
    fi
  done
  return 1
}

mapfile -t LLVM_INSTALLATIONS < <(
  for prefix in /usr/lib/llvm-*; do
    major="${prefix##*/llvm-}"
    if [[ "$major" =~ ^[0-9]+$ ]] &&
       [[ -x "$prefix/bin/clang" ]] &&
       [[ -x "$prefix/bin/clang++" ]] &&
       [[ -f "$prefix/include/llvm/Passes/PassPlugin.h" ]] &&
       has_llvm_link_library "$prefix" "$major"; then
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

missing_header_prefix="$TMP_DIR/missing-header-llvm"
mkdir -p "$missing_header_prefix/bin" "$missing_header_prefix/lib"
ln -s "$highest_prefix/bin/clang" "$missing_header_prefix/bin/clang"
ln -s "$highest_prefix/bin/clang++" "$missing_header_prefix/bin/clang++"
touch "$missing_header_prefix/lib/libLLVM-$highest_major.so"
missing_header_log="$TMP_DIR/missing-header-prefix.log"
if run_xmake f -c \
     --symcc_llvm_prefix="$missing_header_prefix" \
     --symcc_llvm_major="$highest_major" >"$missing_header_log" 2>&1; then
  printf 'ASSERT FAIL: LLVM prefix without PassPlugin.h unexpectedly configured\n' >&2
  exit 1
fi
grep -Fq "required SymCC development header '$missing_header_prefix/include/llvm/Passes/PassPlugin.h' was not found" "$missing_header_log"

missing_library_prefix="$TMP_DIR/missing-library-llvm"
mkdir -p "$missing_library_prefix/bin" "$missing_library_prefix/include/llvm/Passes"
ln -s "$highest_prefix/bin/clang" "$missing_library_prefix/bin/clang"
ln -s "$highest_prefix/bin/clang++" "$missing_library_prefix/bin/clang++"
touch "$missing_library_prefix/include/llvm/Passes/PassPlugin.h"
missing_library_log="$TMP_DIR/missing-library-prefix.log"
if run_xmake f -c \
     --symcc_llvm_prefix="$missing_library_prefix" \
     --symcc_llvm_major="$highest_major" >"$missing_library_log" 2>&1; then
  printf 'ASSERT FAIL: LLVM prefix without a linkable library unexpectedly configured\n' >&2
  exit 1
fi
grep -Fq "expected a linkable LLVM $highest_major library under '$missing_library_prefix/lib'" "$missing_library_log"

invalid_major_log="$TMP_DIR/invalid-major.log"
if run_xmake f -c \
     --symcc_llvm_prefix="$highest_prefix" \
     --symcc_llvm_major=not-a-major >"$invalid_major_log" 2>&1; then
  printf 'ASSERT FAIL: invalid LLVM major unexpectedly configured\n' >&2
  exit 1
fi
grep -Fq "Invalid SymCC LLVM major version 'not-a-major'" "$invalid_major_log"

simple_build_dir="$TMP_DIR/simple-build"
run_xmake f -c \
  --backend=simple \
  --symcc_llvm_prefix="$highest_prefix" \
  --symcc_llvm_major="$highest_major" \
  --builddir="$simple_build_dir" >/dev/null
run_xmake build SymCCRuntime_shared >/dev/null
find "$simple_build_dir" -type f -name 'libsymcc-rt.so' -print -quit |
  grep -q .
simple_check_log="$TMP_DIR/simple-check.log"
run_xmake_without_llvm_path build check >/dev/null
run_xmake_without_llvm_path run check >"$simple_check_log" 2>&1
grep -Fq "running lit test suite (simple backend)" "$simple_check_log"
if grep -Fq "PATH lit fallback was selected" "$simple_check_log"; then
  printf 'ASSERT FAIL: LLVM bindir lit was not preferred\n' >&2
  exit 1
fi

printf '[xmake-llvm-discovery] PASS\n'
