#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-semantic-frontier.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
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

assert_file_not_exists() {
	local path="$1"
	if [ -e "$path" ]; then
		printf 'ASSERT FAIL: 不期望存在文件 %s\n' "$path" >&2
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

run_cli() {
	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		ENABLE_DST1_MUTATOR=0 \
		ENABLE_CACHE_DELTA=1 \
		ENABLE_TRIAGE=1 \
		ENABLE_SYMCC=1 \
		python3 -m tools.dns_diff.cli "$@"
}

assert_report_fail_closed() {
	local root="$1"
	local stderr_path="$2"
	shift 2

	if run_cli report --root "$root" >/dev/null 2>"$stderr_path"; then
		printf 'ASSERT FAIL: report 对坏 truth-source 输入不应成功: %s\n' "$root" >&2
		exit 1
	fi

	assert_file_contains "$stderr_path" 'dns-diff: report 失败: 样本 semantic truth-source 无效:'
	for expected in "$@"; do
		assert_file_contains "$stderr_path" "$expected"
	done
	assert_file_not_exists "$root/high_value_samples.txt"
	assert_file_not_exists "$root/semantic_frontier_manifest.json"
}

python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_sample(
    sample_id: str,
    *,
    analysis_state: str,
    semantic_outcome: str,
    oracle_audit_candidate: bool,
    needs_manual_review: bool,
    artifact_name,
) -> None:
    sample_dir = root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    write_json(sample_dir / "sample.meta.json", {"sample_id": sample_id})
    write_json(
        sample_dir / "triage.json",
        {
            "schema_version": 1,
            "generated_at": "2026-03-25T00:00:00Z",
            "sample_id": sample_id,
            "status": "completed",
            "diff_class": semantic_outcome,
            "analysis_state": analysis_state,
            "exclude_reason": None,
            "semantic_outcome": semantic_outcome,
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "semantic_diff",
            "failure_bucket_detail": semantic_outcome,
            "oracle_audit_candidate": oracle_audit_candidate,
            "case_study_candidate": oracle_audit_candidate and needs_manual_review,
            "manual_truth_status": "not_started" if oracle_audit_candidate else "not_applicable",
            "filter_labels": [],
            "cluster_key": sample_id,
            "cache_delta_triggered": semantic_outcome == "cache_diff_interesting",
            "interesting_delta_count": 1 if semantic_outcome == "cache_diff_interesting" else 0,
            "needs_manual_review": needs_manual_review,
            "notes": [],
        },
    )
    if artifact_name is not None:
        (sample_dir / artifact_name).write_bytes(sample_id.encode("utf-8"))


write_sample(
    "sample-t3-oracle-cache",
    analysis_state="included",
    semantic_outcome="oracle_and_cache_diff",
    oracle_audit_candidate=True,
    needs_manual_review=True,
    artifact_name="sample.bin",
)
write_sample(
    "sample-t3-oracle",
    analysis_state="included",
    semantic_outcome="oracle_diff",
    oracle_audit_candidate=True,
    needs_manual_review=True,
    artifact_name="transcript",
)
write_sample(
    "sample-t3-cache",
    analysis_state="included",
    semantic_outcome="cache_diff_interesting",
    oracle_audit_candidate=False,
    needs_manual_review=True,
    artifact_name="sample.bin",
)
write_sample(
    "sample-t2-audit",
    analysis_state="excluded",
    semantic_outcome="no_diff",
    oracle_audit_candidate=True,
    needs_manual_review=False,
    artifact_name="sample.bin",
)
write_sample(
    "sample-t1-review",
    analysis_state="excluded",
    semantic_outcome="no_diff",
    oracle_audit_candidate=False,
    needs_manual_review=True,
    artifact_name="sample.bin",
)
write_sample(
    "sample-t0-other",
    analysis_state="included",
    semantic_outcome="no_diff",
    oracle_audit_candidate=False,
    needs_manual_review=False,
    artifact_name="sample.bin",
)
write_sample(
    "sample-missing",
    analysis_state="included",
    semantic_outcome="oracle_diff",
    oracle_audit_candidate=True,
    needs_manual_review=True,
    artifact_name=None,
)
PY

CORRUPT_TRIAGE_ROOT="$WORKDIR/corrupt-triage"
CORRUPT_META_ROOT="$WORKDIR/corrupt-meta"
TYPE_INVALID_TRIAGE_ROOT="$WORKDIR/type-invalid-triage"
MISSING_META_ROOT="$WORKDIR/missing-meta"
INVALID_UTF8_META_ROOT="$WORKDIR/invalid-utf8-meta"
DIRECTORY_META_ROOT="$WORKDIR/directory-meta"

python3 - "$CORRUPT_TRIAGE_ROOT" "$CORRUPT_META_ROOT" "$TYPE_INVALID_TRIAGE_ROOT" "$MISSING_META_ROOT" "$INVALID_UTF8_META_ROOT" "$DIRECTORY_META_ROOT" <<'PY'
import json
import pathlib
import sys

corrupt_triage_root = pathlib.Path(sys.argv[1])
corrupt_meta_root = pathlib.Path(sys.argv[2])
type_invalid_triage_root = pathlib.Path(sys.argv[3])
missing_meta_root = pathlib.Path(sys.argv[4])
invalid_utf8_meta_root = pathlib.Path(sys.argv[5])
directory_meta_root = pathlib.Path(sys.argv[6])


def write_json(path: pathlib.Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_valid_triage(sample_dir: pathlib.Path, sample_id: str) -> None:
    write_json(
        sample_dir / "triage.json",
        {
            "schema_version": 1,
            "generated_at": "2026-03-25T00:00:00Z",
            "sample_id": sample_id,
            "status": "completed",
            "diff_class": "oracle_diff",
            "analysis_state": "included",
            "exclude_reason": None,
            "semantic_outcome": "oracle_diff",
            "failure_taxonomy_version": 1,
            "failure_bucket_primary": "semantic_diff",
            "failure_bucket_detail": "oracle_diff",
            "oracle_audit_candidate": True,
            "case_study_candidate": True,
            "manual_truth_status": "not_started",
            "filter_labels": [],
            "cluster_key": sample_id,
            "cache_delta_triggered": False,
            "interesting_delta_count": 0,
            "needs_manual_review": True,
            "notes": [],
        },
    )


def write_valid_meta(sample_dir: pathlib.Path, sample_id: str) -> None:
    write_json(sample_dir / "sample.meta.json", {"sample_id": sample_id})


sample_dir = corrupt_triage_root / "sample-corrupt-triage"
sample_dir.mkdir(parents=True, exist_ok=True)
write_valid_meta(sample_dir, "sample-corrupt-triage")
(sample_dir / "sample.bin").write_bytes(b"A")
(sample_dir / "triage.json").write_text('{"broken":', encoding="utf-8")

sample_dir = corrupt_meta_root / "sample-corrupt-meta"
sample_dir.mkdir(parents=True, exist_ok=True)
write_valid_triage(sample_dir, "sample-corrupt-meta")
(sample_dir / "sample.bin").write_bytes(b"B")
(sample_dir / "sample.meta.json").write_text('{"broken":', encoding="utf-8")

sample_dir = type_invalid_triage_root / "sample-type-invalid-triage"
sample_dir.mkdir(parents=True, exist_ok=True)
write_valid_meta(sample_dir, "sample-type-invalid-triage")
(sample_dir / "sample.bin").write_bytes(b"C")
(sample_dir / "triage.json").write_text('["not-an-object"]\n', encoding="utf-8")

sample_dir = missing_meta_root / "sample-missing-meta"
sample_dir.mkdir(parents=True, exist_ok=True)
write_valid_triage(sample_dir, "sample-missing-meta")
(sample_dir / "sample.bin").write_bytes(b"D")

sample_dir = invalid_utf8_meta_root / "sample-invalid-utf8-meta"
sample_dir.mkdir(parents=True, exist_ok=True)
write_valid_triage(sample_dir, "sample-invalid-utf8-meta")
(sample_dir / "sample.bin").write_bytes(b"E")
(sample_dir / "sample.meta.json").write_bytes(b"\xff\xfe{not-utf8}")

sample_dir = directory_meta_root / "sample-directory-meta"
sample_dir.mkdir(parents=True, exist_ok=True)
write_valid_triage(sample_dir, "sample-directory-meta")
(sample_dir / "sample.bin").write_bytes(b"F")
(sample_dir / "sample.meta.json").mkdir(parents=True, exist_ok=True)
PY

run_cli report --root "$FOLLOW_ROOT" >/dev/null

assert_file_exists "$FOLLOW_ROOT/high_value_samples.txt"
assert_file_exists "$FOLLOW_ROOT/semantic_frontier_manifest.json"

python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
payload = json.loads((root / "semantic_frontier_manifest.json").read_text(encoding="utf-8"))
expected_top_level_fields = {
    "contract_name",
    "contract_version",
    "generated_at",
    "root",
    "entries",
}
if set(payload.keys()) != expected_top_level_fields:
    raise SystemExit(
        "ASSERT FAIL: semantic_frontier_manifest 顶层字段不符合预期:\n"
        f"actual={set(payload.keys())!r}\nexpected={expected_top_level_fields!r}"
    )
if payload.get("contract_name") != "semantic_frontier_manifest":
    raise SystemExit(
        f"ASSERT FAIL: contract_name={payload.get('contract_name')!r} != 'semantic_frontier_manifest'"
    )
if payload.get("contract_version") != 1:
    raise SystemExit(
        f"ASSERT FAIL: contract_version={payload.get('contract_version')!r} != 1"
    )
generated_at = payload.get("generated_at")
if not isinstance(generated_at, str) or not generated_at:
    raise SystemExit(
        f"ASSERT FAIL: generated_at 应为非空字符串，实际 {generated_at!r}"
    )
if payload.get("root") != str(root):
    raise SystemExit(
        f"ASSERT FAIL: root={payload.get('root')!r} != {str(root)!r}"
    )
entries = payload.get("entries")
if not isinstance(entries, list):
    raise SystemExit("ASSERT FAIL: semantic_frontier_manifest.entries 应为数组")

expected_entries = [
    {
        "sample_path": str((root / "sample-t3-oracle-cache" / "sample.bin").resolve()),
        "sample_id": "sample-t3-oracle-cache",
        "analysis_state": "included",
        "semantic_outcome": "oracle_and_cache_diff",
        "oracle_audit_candidate": True,
        "needs_manual_review": True,
        "priority_tier": 3,
    },
    {
        "sample_path": str((root / "sample-t3-oracle" / "transcript").resolve()),
        "sample_id": "sample-t3-oracle",
        "analysis_state": "included",
        "semantic_outcome": "oracle_diff",
        "oracle_audit_candidate": True,
        "needs_manual_review": True,
        "priority_tier": 3,
    },
    {
        "sample_path": str((root / "sample-t3-cache" / "sample.bin").resolve()),
        "sample_id": "sample-t3-cache",
        "analysis_state": "included",
        "semantic_outcome": "cache_diff_interesting",
        "oracle_audit_candidate": False,
        "needs_manual_review": True,
        "priority_tier": 3,
    },
    {
        "sample_path": str((root / "sample-t2-audit" / "sample.bin").resolve()),
        "sample_id": "sample-t2-audit",
        "analysis_state": "excluded",
        "semantic_outcome": "no_diff",
        "oracle_audit_candidate": True,
        "needs_manual_review": False,
        "priority_tier": 2,
    },
    {
        "sample_path": str((root / "sample-t1-review" / "sample.bin").resolve()),
        "sample_id": "sample-t1-review",
        "analysis_state": "excluded",
        "semantic_outcome": "no_diff",
        "oracle_audit_candidate": False,
        "needs_manual_review": True,
        "priority_tier": 1,
    },
    {
        "sample_path": str((root / "sample-t0-other" / "sample.bin").resolve()),
        "sample_id": "sample-t0-other",
        "analysis_state": "included",
        "semantic_outcome": "no_diff",
        "oracle_audit_candidate": False,
        "needs_manual_review": False,
        "priority_tier": 0,
    },
]

if entries != expected_entries:
    raise SystemExit(
        "ASSERT FAIL: semantic_frontier_manifest entries 不符合预期:\n"
        f"actual={entries!r}\nexpected={expected_entries!r}"
    )

for entry in entries:
    sample_path = pathlib.Path(entry["sample_path"])
    if not sample_path.is_absolute():
        raise SystemExit(f"ASSERT FAIL: sample_path 不是绝对路径: {entry!r}")
    if sample_path != sample_path.resolve():
        raise SystemExit(f"ASSERT FAIL: sample_path 未规范化到 resolve() 结果: {entry!r}")

if any(entry["sample_id"] == "sample-missing" for entry in entries):
    raise SystemExit("ASSERT FAIL: 缺失物理样本的条目应被跳过")

manifest_lines = (root / "high_value_samples.txt").read_text(encoding="utf-8").splitlines()
expected_manifest_lines = [
    entry["sample_path"] for entry in expected_entries if entry["priority_tier"] > 0
]
if manifest_lines != expected_manifest_lines:
    raise SystemExit(
        "ASSERT FAIL: high_value_samples.txt 与 semantic_frontier_manifest Tier1-3 子集不一致:\n"
        f"actual={manifest_lines!r}\nexpected={expected_manifest_lines!r}"
    )
PY

assert_report_fail_closed \
	"$CORRUPT_TRIAGE_ROOT" \
	"$WORKDIR/corrupt-triage.stderr" \
	'file=triage.json' \
	'reason=JSON 损坏'

assert_report_fail_closed \
	"$CORRUPT_META_ROOT" \
	"$WORKDIR/corrupt-meta.stderr" \
	'file=sample.meta.json' \
	'reason=JSON 损坏'

assert_report_fail_closed \
	"$TYPE_INVALID_TRIAGE_ROOT" \
	"$WORKDIR/type-invalid-triage.stderr" \
	'file=triage.json' \
	'reason=JSON 顶层类型无效（期望 object）'

assert_report_fail_closed \
	"$MISSING_META_ROOT" \
	"$WORKDIR/missing-meta.stderr" \
	'file=sample.meta.json' \
	'reason=文件缺失'

assert_report_fail_closed \
	"$INVALID_UTF8_META_ROOT" \
	"$WORKDIR/invalid-utf8-meta.stderr" \
	'file=sample.meta.json' \
	'reason=UTF-8 解码失败'

assert_report_fail_closed \
	"$DIRECTORY_META_ROOT" \
	"$WORKDIR/directory-meta.stderr" \
	'file=sample.meta.json' \
	'reason=文件读取失败'

printf 'PASS: semantic frontier manifest regression test passed\n'
