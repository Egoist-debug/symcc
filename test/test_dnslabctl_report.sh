#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dnslabctl-report.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow"
BAD_ROOT="$WORKDIR/bad-follow"
MANIFEST_DIR="$WORKDIR/semantic-export"

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

mkdir -p "$FOLLOW_ROOT" "$BAD_ROOT" "$MANIFEST_DIR"

python3 - "$FOLLOW_ROOT" "$BAD_ROOT" <<'PY'
import json
import pathlib
import sys

follow_root = pathlib.Path(sys.argv[1])
bad_root = pathlib.Path(sys.argv[2])

sample_a = follow_root / "sample-a"
sample_a.mkdir(parents=True, exist_ok=True)
(sample_a / "sample.bin").write_bytes(b"sample-a")
(sample_a / "sample.meta.json").write_text(
    json.dumps(
        {
            "sample_id": "sample-a",
            "source_queue_file": str((sample_a / "sample.bin").resolve()),
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
(sample_a / "triage.json").write_text(
    json.dumps(
        {
            "sample_id": "sample-a",
            "status": "completed_oracle_diff",
            "cluster_key": "cluster-a",
            "analysis_state": "included",
            "semantic_outcome": "oracle_diff",
            "oracle_audit_candidate": True,
            "needs_manual_review": True,
            "filter_labels": [],
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)

sample_b = follow_root / "sample-b"
sample_b.mkdir(parents=True, exist_ok=True)
(sample_b / "transcript").write_bytes(b"sample-b")
(sample_b / "sample.meta.json").write_text(
    json.dumps({"sample_id": "sample-b"}, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
(sample_b / "triage.json").write_text(
    json.dumps(
        {
            "sample_id": "sample-b",
            "status": "completed_no_diff",
            "cluster_key": "_",
            "analysis_state": "excluded",
            "semantic_outcome": "no_diff",
            "oracle_audit_candidate": False,
            "needs_manual_review": True,
            "filter_labels": ["review_only"],
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)

bad_sample = bad_root / "sample-bad"
bad_sample.mkdir(parents=True, exist_ok=True)
(bad_sample / "sample.meta.json").write_text(
    json.dumps({"sample_id": "sample-bad"}, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
(bad_sample / "triage.json").write_text('{"broken":', encoding="utf-8")
PY

env \
	SYMCC_HIGH_VALUE_MANIFEST="$MANIFEST_DIR/high_value_samples.txt" \
	"$DNSLABCTL_BIN" report --root "$FOLLOW_ROOT" >"$WORKDIR/report.json"

assert_file_exists "$FOLLOW_ROOT/cluster_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/status_summary.tsv"
assert_file_exists "$FOLLOW_ROOT/triage_report.md"
assert_file_exists "$MANIFEST_DIR/high_value_samples.txt"
assert_file_exists "$MANIFEST_DIR/semantic_frontier_manifest.json"

assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" $'status\tcount'
assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" $'completed_no_diff\t1'
assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" $'completed_oracle_diff\t1'
assert_file_contains "$FOLLOW_ROOT/status_summary.tsv" $'__total__\t2'
assert_file_contains "$FOLLOW_ROOT/cluster_summary.tsv" $'cluster-a\t1\tsample-a'
assert_file_contains "$FOLLOW_ROOT/cluster_summary.tsv" $'review_only\t1\tsample-b'
assert_file_contains "$FOLLOW_ROOT/cluster_summary.tsv" $'__total__\t2\t-'
assert_file_contains "$FOLLOW_ROOT/triage_report.md" '# DNS Diff Triage Report'

python3 - "$WORKDIR/report.json" "$MANIFEST_DIR/high_value_samples.txt" "$MANIFEST_DIR/semantic_frontier_manifest.json" "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest_lines = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
semantic_manifest = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
follow_root = pathlib.Path(sys.argv[4]).resolve()

if report.get("sample_count") != 2:
    raise SystemExit(f"ASSERT FAIL: sample_count={report.get('sample_count')!r} != 2")
if report.get("semantic_frontier_entry_count") != 2:
    raise SystemExit(
        "ASSERT FAIL: semantic_frontier_entry_count="
        f"{report.get('semantic_frontier_entry_count')!r} != 2"
    )

entries = semantic_manifest.get("entries")
if not isinstance(entries, list) or len(entries) != 2:
    raise SystemExit(f"ASSERT FAIL: semantic_frontier entries={entries!r}")

expected_paths = [
    str((follow_root / "sample-a" / "sample.bin").resolve()),
    str((follow_root / "sample-b" / "transcript").resolve()),
]
actual_paths = [entry.get("sample_path") for entry in entries]
if actual_paths != expected_paths:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier sample_path={actual_paths!r} != {expected_paths!r}"
    )

expected_tiers = [3, 1]
actual_tiers = [entry.get("priority_tier") for entry in entries]
if actual_tiers != expected_tiers:
    raise SystemExit(
        f"ASSERT FAIL: semantic_frontier priority_tier={actual_tiers!r} != {expected_tiers!r}"
    )

if manifest_lines != expected_paths:
    raise SystemExit(
        f"ASSERT FAIL: high_value_samples={manifest_lines!r} != {expected_paths!r}"
    )
PY

if "$DNSLABCTL_BIN" report --root "$BAD_ROOT" >/dev/null 2>"$WORKDIR/bad.stderr"; then
	printf 'ASSERT FAIL: 坏 triage 输入不应成功\n' >&2
	exit 1
fi
assert_file_contains "$WORKDIR/bad.stderr" '样本 semantic truth-source 无效:'
assert_file_contains "$WORKDIR/bad.stderr" 'file=triage.json'

printf 'PASS: dnslabctl report regression test passed\n'
