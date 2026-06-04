#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH_LAYOUT_DOC="$ROOT_DIR/patch/PATCH_LAYOUT.md"
ADAPTER_SOURCE="$ROOT_DIR/dnslab_core/src/concrete_adapters.cpp"
NON_PRODUCER_RESOLVERS=(dnsmasq smartdns maradns knot-resolver unbound)
SCRIPTED_CACHE_RESOLVERS=(dnsmasq smartdns maradns knot-resolver)

assert_dir_exists() {
	local path="$1"
	if [ ! -d "$path" ]; then
		printf 'ASSERT FAIL: 缺少目录 %s\n' "$path" >&2
		exit 1
	fi
}

assert_file_exists() {
	local path="$1"
	if [ ! -f "$path" ]; then
		printf 'ASSERT FAIL: 缺少文件 %s\n' "$path" >&2
		exit 1
	fi
}

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		exit 1
	fi
}

assert_path_absent() {
	local path="$1"
	if [ -e "$path" ]; then
		printf 'ASSERT FAIL: 非 producer resolver 不应出现在 fuzz patch 区: %s\n' "$path" >&2
		exit 1
	fi
}

assert_dir_exists "$ROOT_DIR/patch/cache/bind9"
assert_dir_exists "$ROOT_DIR/patch/cache/unbound"
assert_dir_exists "$ROOT_DIR/patch/fuzz/bind9"

for resolver in "${NON_PRODUCER_RESOLVERS[@]}"; do
	assert_path_absent "$ROOT_DIR/patch/fuzz/$resolver"
done

for resolver in "${SCRIPTED_CACHE_RESOLVERS[@]}"; do
	case "$resolver" in
	knot-resolver) harness_path="$ROOT_DIR/tools/knot_resolver_replay_harness.py" ;;
	*) harness_path="$ROOT_DIR/tools/${resolver}_replay_harness.py" ;;
	esac
	assert_file_exists "$harness_path"
	assert_file_contains "$PATCH_LAYOUT_DOC" "| \`$resolver\` | none | scripted cache/diff harness; no active source patch |"
done

assert_file_contains "$ADAPTER_SOURCE" '"patch" / "cache" / "unbound"'
assert_file_contains "$ADAPTER_SOURCE" '{"PATCH_VARIANT", "cache"}'
assert_file_contains "$PATCH_LAYOUT_DOC" "若这些 resolver 后续需要源码级 diff/cache patch，必须放入 \`patch/cache/<resolver>\`"

printf 'PASS: resolver cache patch layout verified\n'
