#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMED_WRAPPER="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-semantic-profile.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

locked_tag_for() {
	local resolver="$1"

	python3 - "$ROOT_DIR/experiments/resolvers.lock.json" "$resolver" <<'PY'
import json
import pathlib
import sys

lock_path = pathlib.Path(sys.argv[1])
resolver = sys.argv[2]
payload = json.loads(lock_path.read_text(encoding="utf-8"))
for entry in payload.get("resolvers", []):
    if entry.get("resolver") != resolver:
        continue
    print(entry.get("resolved_tag") or entry.get("desired_tag") or "")
    raise SystemExit(0)
raise SystemExit(1)
PY
}

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

assert_file_not_contains() {
	local path="$1"
	local unexpected="$2"
	if grep -Fq -- "$unexpected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 不包含: %s\n' "$path" "$unexpected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

BIND9_TAG="$(locked_tag_for bind9)"
EXPECTED_SRC_TREE="$ROOT_DIR/experiments/subjects/bind9/$BIND9_TAG"
EXPECTED_AFL_TREE="$ROOT_DIR/experiments/subjects/bind9/${BIND9_TAG}-afl"
EXPECTED_SYMCC_TREE="$ROOT_DIR/experiments/subjects/bind9/${BIND9_TAG}-symcc"

POISON_WORK="$WORKDIR/poison-work"
POISON_MANIFEST_DIR="$WORKDIR/shared-manifests"
POISON_TEXT_MANIFEST="$POISON_MANIFEST_DIR/high_value_samples.txt"
POISON_TRACE="$WORKDIR/poison.trace"
POISON_STATUS="$WORKDIR/poison.status"
mkdir -p "$POISON_WORK" "$POISON_MANIFEST_DIR"
touch "$POISON_TEXT_MANIFEST"

if ! env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$POISON_WORK" \
	SYMCC_HIGH_VALUE_MANIFEST="$POISON_TEXT_MANIFEST" \
	bash -x "$NAMED_WRAPPER" help >/dev/null 2>"$POISON_TRACE"
then
	:
fi

assert_file_contains "$POISON_TRACE" "export ENABLE_DST1_MUTATOR=1"
assert_file_contains "$POISON_TRACE" "export DST1_MUTATOR_ONLY=1"
assert_file_contains "$POISON_TRACE" "AFL_TIMEOUT_MS=7000"
assert_file_not_contains "$POISON_TRACE" "AFL_TIMEOUT_MS=7000+"
assert_file_contains "$POISON_TRACE" "export NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS=100000"
assert_file_contains "$POISON_TRACE" "export SYMCC_FRONTIER_RELOAD_SEC=15"
assert_file_contains "$POISON_TRACE" "export SYMCC_FRONTIER_RETRY_LIMIT=1"
assert_file_contains "$POISON_TRACE" "SRC_TREE=$EXPECTED_SRC_TREE"
assert_file_contains "$POISON_TRACE" "AFL_TREE=$EXPECTED_AFL_TREE"
assert_file_contains "$POISON_TRACE" "SYMCC_TREE=$EXPECTED_SYMCC_TREE"
assert_file_contains "$POISON_TRACE" "SYMCC_HIGH_VALUE_MANIFEST=$POISON_TEXT_MANIFEST"
assert_file_contains "$POISON_TRACE" "export SYMCC_SEMANTIC_FRONTIER_MANIFEST=$POISON_MANIFEST_DIR/semantic_frontier_manifest.json"
assert_file_not_contains "$POISON_TRACE" "export SYMCC_SEMANTIC_FRONTIER_MANIFEST=$POISON_WORK/semantic_frontier_manifest.json"

LEGACY_WORK="$WORKDIR/legacy-work"
LEGACY_TRACE="$WORKDIR/legacy.trace"
mkdir -p "$LEGACY_WORK"

if ! env \
	PYTHONDONTWRITEBYTECODE=1 \
	FUZZ_PROFILE=legacy-response-tail \
	WORK_DIR="$LEGACY_WORK" \
	bash -x "$NAMED_WRAPPER" help >/dev/null 2>"$LEGACY_TRACE"
then
	:
fi

assert_file_contains "$LEGACY_TRACE" "ENABLE_DST1_MUTATOR=0"
assert_file_contains "$LEGACY_TRACE" "DST1_MUTATOR_ONLY=0"
assert_file_not_contains "$LEGACY_TRACE" "export ENABLE_DST1_MUTATOR=1"
assert_file_not_contains "$LEGACY_TRACE" "export SYMCC_FRONTIER_RELOAD_SEC=15"
assert_file_not_contains "$LEGACY_TRACE" "export SYMCC_FRONTIER_RETRY_LIMIT=1"
assert_file_not_contains "$LEGACY_TRACE" "export SYMCC_SEMANTIC_FRONTIER_MANIFEST="

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$POISON_WORK" \
	SYMCC_HIGH_VALUE_MANIFEST="$POISON_TEXT_MANIFEST" \
	bash "$NAMED_WRAPPER" status >"$POISON_STATUS"

assert_file_contains "$POISON_STATUS" "Producer semantic 配置:"
assert_file_contains "$POISON_STATUS" "$POISON_TEXT_MANIFEST"
assert_file_contains "$POISON_STATUS" "$POISON_MANIFEST_DIR/semantic_frontier_manifest.json"
assert_file_contains "$POISON_STATUS" "dst1_mutator"
assert_file_contains "$POISON_STATUS" "reload_sec"
assert_file_contains "$POISON_STATUS" "retry_limit"

echo "PASS: named poison-stateful semantic profile regression test passed"
