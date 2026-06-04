#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-export-patch.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

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
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

assert_json_field() {
	local path="$1"
	local field="$2"
	local expected="$3"
	python3 - "$path" "$field" "$expected" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
field = sys.argv[2]
expected = sys.argv[3]
actual = payload.get(field)
if str(actual) != expected:
    raise SystemExit(
        f"ASSERT FAIL: JSON 字段 {field}={actual!r} != {expected!r}"
    )
PY
}

BIND9_SUBJECT_ROOT="$WORKDIR/experiments/subjects/bind9/v9.20.22"
BIND9_PATCH_PATH="$WORKDIR/patch/cache/bind9/v9.20.22.patch"
DNSMASQ_SUBJECT_ROOT="$WORKDIR/experiments/subjects/dnsmasq/v2.92"
DNSMASQ_PATCH_PATH="$WORKDIR/patch/cache/dnsmasq/v2.92.patch"
mkdir -p "$BIND9_SUBJECT_ROOT" "$DNSMASQ_SUBJECT_ROOT"

cat >"$WORKDIR/experiments/resolvers.lock.json" <<'EOF'
{
  "generated_at": "2026-05-10T00:00:00Z",
  "generator": "test",
  "resolvers": [
    {
      "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "desired_tag": "v9.20.22",
      "note": "bind9",
      "repo_url": "https://example/bind9.git",
      "resolved_tag": "v9.20.22",
      "resolver": "bind9",
      "status": "locked"
    },
    {
      "commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "desired_tag": "v2.92",
      "note": "dnsmasq",
      "repo_url": "https://example/dnsmasq.git",
      "resolved_tag": "v2.92",
      "resolver": "dnsmasq",
      "status": "locked"
    }
  ]
}
EOF

(
	cd "$BIND9_SUBJECT_ROOT"
	git init -q
	printf 'old\n' > sample.txt
	git add sample.txt
	git -c user.name=test -c user.email=test@example.com -c commit.gpgsign=false commit -qm init
	printf 'new\n' > sample.txt
)

(
	cd "$DNSMASQ_SUBJECT_ROOT"
	git init -q
	printf 'dnsmasq-old\n' > sample.txt
	git add sample.txt
	git -c user.name=test -c user.email=test@example.com -c commit.gpgsign=false commit -qm init
	printf 'dnsmasq-new\n' > sample.txt
)

(
	cd "$ROOT_DIR"
	"$DNSLABCTL_BIN" export-patch \
		--workspace-root "$(python3 - "$ROOT_DIR" "$WORKDIR" <<'PY'
import os
import pathlib
import sys
print(os.path.relpath(pathlib.Path(sys.argv[2]).resolve(), pathlib.Path(sys.argv[1]).resolve()))
PY
		)" \
		--resolver bind9 \
		--purpose cache \
		>"$WORKDIR/export-patch-bind9.json"
)

(
	cd "$ROOT_DIR"
	"$DNSLABCTL_BIN" export-patch \
		--workspace-root "$(python3 - "$ROOT_DIR" "$WORKDIR" <<'PY'
import os
import pathlib
import sys
print(os.path.relpath(pathlib.Path(sys.argv[2]).resolve(), pathlib.Path(sys.argv[1]).resolve()))
PY
)" \
		--resolver dnsmasq \
		--purpose cache \
		>"$WORKDIR/export-patch-dnsmasq.json"
)

assert_file_exists "$BIND9_PATCH_PATH"
assert_file_contains "$BIND9_PATCH_PATH" "diff --git a/sample.txt b/sample.txt"
assert_file_contains "$BIND9_PATCH_PATH" "+new"
assert_json_field "$WORKDIR/export-patch-bind9.json" "resolver" "bind9"
assert_json_field "$WORKDIR/export-patch-bind9.json" "purpose" "cache"
assert_json_field "$WORKDIR/export-patch-bind9.json" "tag" "v9.20.22"
assert_json_field "$WORKDIR/export-patch-bind9.json" "output_path" "$BIND9_PATCH_PATH"

assert_file_exists "$DNSMASQ_PATCH_PATH"
assert_file_contains "$DNSMASQ_PATCH_PATH" "diff --git a/sample.txt b/sample.txt"
assert_file_contains "$DNSMASQ_PATCH_PATH" "+dnsmasq-new"
assert_json_field "$WORKDIR/export-patch-dnsmasq.json" "resolver" "dnsmasq"
assert_json_field "$WORKDIR/export-patch-dnsmasq.json" "purpose" "cache"
assert_json_field "$WORKDIR/export-patch-dnsmasq.json" "tag" "v2.92"
assert_json_field "$WORKDIR/export-patch-dnsmasq.json" "output_path" "$DNSMASQ_PATCH_PATH"

printf 'PASS: dnslabctl export-patch regression test passed\n'
