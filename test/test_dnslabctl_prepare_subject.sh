#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-prepare-subject.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

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

mkdir -p "$WORKDIR/experiments/subjects/bind9/v9.20.22"
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
    }
  ]
}
EOF

(
	cd "$WORKDIR"
	"$DNSLABCTL_BIN" prepare-subject \
		--resolver bind9 \
		>"$WORKDIR/prepare-subject.json"
)

assert_json_field "$WORKDIR/prepare-subject.json" "resolver" "bind9"
assert_json_field "$WORKDIR/prepare-subject.json" "tag" "v9.20.22"
assert_json_field "$WORKDIR/prepare-subject.json" "subject_root" "$WORKDIR/experiments/subjects/bind9/v9.20.22"

printf 'PASS: dnslabctl prepare-subject regression test passed\n'
