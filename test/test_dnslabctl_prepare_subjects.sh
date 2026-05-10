#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-prepare-subjects.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

assert_json_array_size() {
	local path="$1"
	local expected="$2"
	python3 - "$path" "$expected" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = int(sys.argv[2])
if not isinstance(payload, list):
    raise SystemExit("ASSERT FAIL: 顶层 JSON 不是数组")
if len(payload) != expected:
    raise SystemExit(
        f"ASSERT FAIL: JSON 数组长度 {len(payload)} != {expected}"
    )
PY
}

assert_json_record() {
	local path="$1"
	local resolver="$2"
	local expected_tag="$3"
	local expected_root="$4"
	python3 - "$path" "$resolver" "$expected_tag" "$expected_root" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
resolver = sys.argv[2]
expected_tag = sys.argv[3]
expected_root = sys.argv[4]
for record in payload:
    if record.get("resolver") != resolver:
        continue
    if record.get("tag") != expected_tag:
        raise SystemExit(
            f"ASSERT FAIL: {resolver}.tag={record.get('tag')!r} != {expected_tag!r}"
        )
    if record.get("subject_root") != expected_root:
        raise SystemExit(
            f"ASSERT FAIL: {resolver}.subject_root={record.get('subject_root')!r} != {expected_root!r}"
        )
    raise SystemExit(0)
raise SystemExit(f"ASSERT FAIL: 缺少 resolver 记录 {resolver}")
PY
}

mkdir -p \
	"$WORKDIR/experiments/subjects/bind9/v9.20.22" \
	"$WORKDIR/experiments/subjects/unbound/release-1.24.2"

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
      "desired_tag": "release-1.24.2",
      "note": "unbound",
      "repo_url": "https://example/unbound.git",
      "resolved_tag": "release-1.24.2",
      "resolver": "unbound",
      "status": "locked"
    }
  ]
}
EOF

(
	cd "$WORKDIR"
	"$DNSLABCTL_BIN" prepare-subjects >"$WORKDIR/prepare-subjects.json"
)

assert_json_array_size "$WORKDIR/prepare-subjects.json" 2
assert_json_record \
	"$WORKDIR/prepare-subjects.json" \
	bind9 \
	v9.20.22 \
	"$WORKDIR/experiments/subjects/bind9/v9.20.22"
assert_json_record \
	"$WORKDIR/prepare-subjects.json" \
	unbound \
	release-1.24.2 \
	"$WORKDIR/experiments/subjects/unbound/release-1.24.2"

(
	cd "$WORKDIR"
	"$DNSLABCTL_BIN" prepare-subjects --resolvers bind9 >"$WORKDIR/prepare-subjects-filtered.json"
)

assert_json_array_size "$WORKDIR/prepare-subjects-filtered.json" 1
assert_json_record \
	"$WORKDIR/prepare-subjects-filtered.json" \
	bind9 \
	v9.20.22 \
	"$WORKDIR/experiments/subjects/bind9/v9.20.22"

printf 'PASS: dnslabctl prepare-subjects regression test passed\n'
