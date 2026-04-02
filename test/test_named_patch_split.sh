#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-patch-split.XXXXXX")"
EVIDENCE_DIR="$ROOT_DIR/.sisyphus/evidence/task-3-patch-split"
PATCH_VARIANT_REQUESTED="${PATCH_VARIANT:-cache}"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

source "$SCRIPT_PATH"
PATCH_VARIANT_UNDER_TEST="$(normalize_patch_variant "$PATCH_VARIANT_REQUESTED")"

assert_same_file() {
	local expected="$1"
	local actual="$2"
	if ! cmp -s "$expected" "$actual"; then
		printf 'ASSERT FAIL: 文件内容不一致: %s <-> %s\n' "$expected" "$actual" >&2
		exit 1
	fi
}

assert_file_contains_text() {
	local path="$1"
	local text="$2"
	if ! grep -Fq -- "$text" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含 %s\n' "$path" "$text" >&2
		exit 1
	fi
}

prepare_baseline_tree() {
	local tree="$1"
	python3 - "$tree" <<'PY'
from pathlib import Path
import sys

tree = Path(sys.argv[1])
baseline = {
    "bin/named/main.c": "baseline main\n",
    "bin/named/fuzz.c": "baseline fuzz\n",
    "bin/named/resolver_afl_symcc_orchestrator.c": "baseline orchestrator\n",
    "bin/named/resolver_afl_symcc_mutator_server.c": "baseline mutator\n",
    "bin/named/include/named/resolver_afl_symcc_orchestrator.h": "baseline orchestrator header\n",
    "bin/named/include/named/resolver_afl_symcc_mutator_server.h": "baseline mutator header\n",
    "lib/dns/dispatch.c": "baseline dispatch\n",
    "lib/dns/include/dns/dispatch.h": "baseline dispatch header\n",
    "lib/ns/client.c": "baseline client\n",
}
for rel_path, content in baseline.items():
    path = tree / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
PY
}

assert_diff_variant_tree() {
	local tree="$1"
	assert_same_file "$PATCH_ROOT/cache/bind9/lib/ns/client.c" "$tree/lib/ns/client.c"
	assert_same_file "$PATCH_ROOT/cache/bind9/bin/named/main.c" "$tree/bin/named/main.c"
	assert_same_file "$PATCH_ROOT/cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c" "$tree/bin/named/resolver_afl_symcc_orchestrator.c"
	assert_same_file "$PATCH_ROOT/cache/bind9/bin/named/resolver_afl_symcc_mutator_server.c" "$tree/bin/named/resolver_afl_symcc_mutator_server.c"
	assert_same_file "$PATCH_ROOT/cache/bind9/include/named/resolver_afl_symcc_orchestrator.h" "$tree/bin/named/include/named/resolver_afl_symcc_orchestrator.h"
	assert_same_file "$PATCH_ROOT/cache/bind9/include/named/resolver_afl_symcc_mutator_server.h" "$tree/bin/named/include/named/resolver_afl_symcc_mutator_server.h"
	assert_same_file "$PATCH_ROOT/cache/bind9/lib/dns/dispatch.c" "$tree/lib/dns/dispatch.c"
	assert_same_file "$PATCH_ROOT/cache/bind9/lib/dns/include/dns/dispatch.h" "$tree/lib/dns/include/dns/dispatch.h"
	assert_file_contains_text "$tree/bin/named/fuzz.c" "baseline fuzz"
}

assert_fuzz_variant_tree() {
	local tree="$1"
	assert_same_file "$PATCH_ROOT/fuzz/bind9/lib/ns/client.c" "$tree/lib/ns/client.c"
	assert_same_file "$PATCH_ROOT/fuzz/bind9/bin/named/fuzz.c" "$tree/bin/named/fuzz.c"
	assert_file_contains_text "$tree/bin/named/main.c" "baseline main"
	assert_file_contains_text "$tree/bin/named/resolver_afl_symcc_orchestrator.c" "baseline orchestrator"
	assert_file_contains_text "$tree/bin/named/resolver_afl_symcc_mutator_server.c" "baseline mutator"
	assert_file_contains_text "$tree/bin/named/include/named/resolver_afl_symcc_orchestrator.h" "baseline orchestrator header"
	assert_file_contains_text "$tree/bin/named/include/named/resolver_afl_symcc_mutator_server.h" "baseline mutator header"
	assert_file_contains_text "$tree/lib/dns/dispatch.c" "baseline dispatch"
	assert_file_contains_text "$tree/lib/dns/include/dns/dispatch.h" "baseline dispatch header"
}

run_variant_case() {
	local variant="$1"
	local src_tree="$WORKDIR/$variant/src"
	local afl_tree="$WORKDIR/$variant/afl"
	local symcc_tree="$WORKDIR/$variant/symcc"
	local evidence_file="$EVIDENCE_DIR/$variant.txt"

	prepare_baseline_tree "$src_tree"
	prepare_baseline_tree "$afl_tree"
	prepare_baseline_tree "$symcc_tree"

	SRC_TREE="$src_tree"
	AFL_TREE="$afl_tree"
	SYMCC_TREE="$symcc_tree"
	sync_patch "$variant"

	case "$variant" in
	cache)
		assert_diff_variant_tree "$src_tree"
		assert_diff_variant_tree "$afl_tree"
		assert_diff_variant_tree "$symcc_tree"
		python3 - "$evidence_file" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)
Path(sys.argv[1]).write_text(
    "variant=cache\n"
    "resolver=bind9\n"
    "overwritten=cache/bind9/lib/ns/client.c\n"
    "overwritten=cache/bind9/bin/named/main.c\n"
    "overwritten=cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c\n"
    "overwritten=cache/bind9/bin/named/resolver_afl_symcc_mutator_server.c\n"
    "overwritten=cache/bind9/include/named/resolver_afl_symcc_orchestrator.h\n"
    "overwritten=cache/bind9/include/named/resolver_afl_symcc_mutator_server.h\n"
    "overwritten=cache/bind9/lib/dns/dispatch.c\n"
    "overwritten=cache/bind9/lib/dns/include/dns/dispatch.h\n"
    "retained=bin/named/fuzz.c\n",
    encoding="utf-8",
)
PY
		;;
	fuzz)
		assert_fuzz_variant_tree "$src_tree"
		assert_fuzz_variant_tree "$afl_tree"
		assert_fuzz_variant_tree "$symcc_tree"
		python3 - "$evidence_file" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)
Path(sys.argv[1]).write_text(
    "variant=fuzz\n"
    "resolver=bind9\n"
    "overwritten=fuzz/bind9/lib/ns/client.c\n"
    "overwritten=fuzz/bind9/bin/named/fuzz.c\n"
    "retained=bin/named/main.c\n"
    "retained=bin/named/resolver_afl_symcc_orchestrator.c\n"
    "retained=bin/named/resolver_afl_symcc_mutator_server.c\n"
    "retained=bin/named/include/named/resolver_afl_symcc_orchestrator.h\n"
    "retained=bin/named/include/named/resolver_afl_symcc_mutator_server.h\n"
    "retained=lib/dns/dispatch.c\n"
    "retained=lib/dns/include/dns/dispatch.h\n",
    encoding="utf-8",
)
PY
		;;
	*)
		printf 'ASSERT FAIL: 不支持的 PATCH_VARIANT=%s\n' "$variant" >&2
		exit 1
		;;
	esac
}

run_variant_switch_case() {
	local from_variant="$1"
	local to_variant="$2"
	local case_name="${from_variant}-to-${to_variant}"
	local src_tree="$WORKDIR/$case_name/src"
	local afl_tree="$WORKDIR/$case_name/afl"
	local symcc_tree="$WORKDIR/$case_name/symcc"
	local evidence_file="$EVIDENCE_DIR/$case_name.txt"

	prepare_baseline_tree "$src_tree"
	prepare_baseline_tree "$afl_tree"
	prepare_baseline_tree "$symcc_tree"

	SRC_TREE="$src_tree"
	AFL_TREE="$afl_tree"
	SYMCC_TREE="$symcc_tree"
	sync_patch "$from_variant"
	sync_patch "$to_variant"

	case "$to_variant" in
	cache)
		assert_diff_variant_tree "$src_tree"
		assert_diff_variant_tree "$afl_tree"
		assert_diff_variant_tree "$symcc_tree"
		;;
	fuzz)
		assert_fuzz_variant_tree "$src_tree"
		assert_fuzz_variant_tree "$afl_tree"
		assert_fuzz_variant_tree "$symcc_tree"
		;;
	*)
		printf 'ASSERT FAIL: 不支持的 PATCH_VARIANT 切换目标=%s\n' "$to_variant" >&2
		exit 1
		;;
	esac

	python3 - "$evidence_file" "$from_variant" "$to_variant" <<'PY'
from pathlib import Path
import sys

target = Path(sys.argv[1])
from_variant = sys.argv[2]
to_variant = sys.argv[3]
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(
    f"from={from_variant}\n"
    f"to={to_variant}\n"
    "result=pass\n",
    encoding="utf-8",
)
PY
}

case "$PATCH_VARIANT_UNDER_TEST" in
cache|fuzz)
	run_variant_case "$PATCH_VARIANT_UNDER_TEST"
	run_variant_switch_case cache fuzz
	run_variant_switch_case fuzz cache
	printf 'PASS: patch split variant %s verified\n' "$PATCH_VARIANT_REQUESTED"
	;;
*)
	printf 'ASSERT FAIL: 不支持的 PATCH_VARIANT=%s\n' "$PATCH_VARIANT_REQUESTED" >&2
	exit 1
	;;
esac
