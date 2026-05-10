#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-lock-defaults.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

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

mkdir -p \
	"$WORKDIR/experiments/subjects/bind9/v9.20.22" \
	"$WORKDIR/build/bind9-afl/bin/named/.libs" \
	"$WORKDIR/named_experiment/runtime" \
	"$WORKDIR/named_experiment/work/response_corpus" \
	"$WORKDIR/run"

cat >"$WORKDIR/experiments/resolvers.lock.json" <<'EOF'
{
  "generated_at": "2026-05-10T00:00:00Z",
  "generator": "test",
  "resolvers": [
    {
      "resolver": "bind9",
      "repo_url": "https://example/bind9.git",
      "desired_tag": "v9.20.22",
      "resolved_tag": "v9.20.22",
      "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "status": "locked",
      "note": "bind9"
    }
  ]
}
EOF

cat >"$WORKDIR/named_experiment/runtime/named.conf" <<'EOF'
directory "__RUNTIME_STATE_DIR__";
EOF

cat >"$WORKDIR/build/bind9-afl/bin/named/.libs/named" <<'EOF'
#!/bin/sh
printf 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0 pwd=%s\n' "$PWD" >&2
printf 'cache\n' > "$NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH"
EOF
chmod +x "$WORKDIR/build/bind9-afl/bin/named/.libs/named"

printf 'DST1\x00\x02\x00\x00' >"$WORKDIR/sample.bin"

(
	cd "$WORKDIR"
	tag="$("$DNSLABCTL_BIN" lock-resolved-tag --resolver bind9)"
	if [ "$tag" != "v9.20.22" ]; then
		printf 'ASSERT FAIL: lock-resolved-tag=%s != v9.20.22\n' "$tag" >&2
		exit 1
	fi
	"$DNSLABCTL_BIN" adapter-replay \
		--resolver bind9 \
		--sample "$WORKDIR/sample.bin" \
		--build-root "$WORKDIR/build/bind9-afl" \
		--run-root "$WORKDIR/run" \
		>"$WORKDIR/adapter-replay.json"
)

assert_json_field "$WORKDIR/adapter-replay.json" "resolver" "bind9"
assert_json_field "$WORKDIR/adapter-replay.json" "run_sample_exit_code" "0"
assert_file_contains "$WORKDIR/run/bind9.stderr" "$WORKDIR/experiments/subjects/bind9/v9.20.22"

printf 'PASS: dnslabctl lock default source-root regression test passed\n'
