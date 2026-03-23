#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-follow-diff-pipeline.XXXXXX")"
QUEUE_DIR="$WORKDIR/work/afl_out/master/queue"
FOLLOW_ROOT="$WORKDIR/work/follow_diff"
export PYTHONDONTWRITEBYTECODE=1

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
	if ! grep -Fq "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

run_cli() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		WORK_DIR="$WORKDIR/work" \
		python3 -m tools.dns_diff.cli "$@"
}

run_cli follow-diff-once >/dev/null
if [ ! -d "$FOLLOW_ROOT" ]; then
	printf 'ASSERT FAIL: follow_diff 根目录未创建\n' >&2
	exit 1
fi

LEGACY_SAMPLE_DIR="$FOLLOW_ROOT/legacy-only"
mkdir -p "$LEGACY_SAMPLE_DIR"
printf '\x01\x02\x03\x04' >"$LEGACY_SAMPLE_DIR/sample.bin"

run_cli follow-diff-once >/dev/null
assert_file_exists "$LEGACY_SAMPLE_DIR/sample.meta.json"
assert_file_exists "$LEGACY_SAMPLE_DIR/state_fingerprint.json"
assert_file_exists "$LEGACY_SAMPLE_DIR/cache_diff.json"
assert_file_exists "$LEGACY_SAMPLE_DIR/triage.json"

mkdir -p "$QUEUE_DIR"
QUEUE_FILE="$QUEUE_DIR/id:000001,orig:seed"
printf '\x09\x08\x07\x06' >"$QUEUE_FILE"

SAMPLE_ID="$(python3 - "$QUEUE_FILE" <<'PY'
import hashlib
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
sha1 = hashlib.sha1(data).hexdigest()
print(f"{path.name}__{sha1[:8]}")
PY
)"

COMPLETED_DIR="$FOLLOW_ROOT/$SAMPLE_ID"
mkdir -p "$COMPLETED_DIR"
cp "$QUEUE_FILE" "$COMPLETED_DIR/sample.bin"

python3 - "$COMPLETED_DIR" "$SAMPLE_ID" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
sample_id = sys.argv[2]

(sample_dir / "sample.meta.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": sample_id,
            "status": "completed",
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

(sample_dir / "triage.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": sample_id,
            "status": "completed_no_diff",
            "diff_class": "no_diff",
            "filter_labels": [],
            "cluster_key": "_",
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": False,
            "notes": [],
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

(sample_dir / "oracle.json").write_text(
    json.dumps(
        {
            "bind9.stderr_parse_status": "ok",
            "unbound.stderr_parse_status": "ok",
            "bind9.parse_ok": True,
            "unbound.parse_ok": True,
            "bind9.resolver_fetch_started": True,
            "unbound.resolver_fetch_started": True,
            "bind9.response_accepted": True,
            "unbound.response_accepted": True,
            "bind9.second_query_hit": False,
            "unbound.second_query_hit": False,
            "bind9.cache_entry_created": False,
            "unbound.cache_entry_created": False,
            "bind9.timeout": False,
            "unbound.timeout": False,
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

(sample_dir / "cache_diff.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": sample_id,
            "cache_delta_triggered": False,
            "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
            "unbound": {"has_cache_diff": False, "interesting_delta_count": 0},
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)

(sample_dir / "state_fingerprint.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "generated_at": "2026-03-23T00:00:00Z",
            "sample_id": sample_id,
            "bind9.forwarding_path": "iterative",
            "bind9.retry_seen": False,
            "bind9.msg_cache_seen": False,
            "bind9.rrset_cache_seen": False,
            "bind9.negative_cache_seen": False,
            "unbound.forwarding_path": "iterative",
            "unbound.retry_seen": False,
            "unbound.msg_cache_seen": False,
            "unbound.rrset_cache_seen": False,
            "unbound.negative_cache_seen": False,
        },
        ensure_ascii=False,
    )
    + "\n",
    encoding="utf-8",
)
PY

run_cli follow-diff-once >/dev/null
run_cli follow-diff-once >/dev/null

python3 - "$COMPLETED_DIR/sample.meta.json" "$SAMPLE_ID" <<'PY'
import json
import pathlib
import sys

meta = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
sample_id = sys.argv[2]
if meta.get("sample_id") != sample_id:
    raise SystemExit("ASSERT FAIL: sample_id 被错误改写")
if meta.get("status") != "completed":
    raise SystemExit("ASSERT FAIL: completed 状态未保持")
PY

run_cli triage-report >/dev/null
assert_file_exists "$FOLLOW_ROOT/cluster_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/status_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/triage_report.md"
assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" "completed_no_diff"

echo "PASS: follow-diff pipeline regression test passed"
