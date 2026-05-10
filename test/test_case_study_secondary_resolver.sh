#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-case-study-secondary.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
REPORT_DIR="$WORKDIR/report"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

python3 - "$FOLLOW_ROOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
sample_dir = root / "sample-dnsmasq"
sample_dir.mkdir(parents=True, exist_ok=True)

def write_json(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

sample_meta = {
    "schema_version": 1,
    "generated_at": "2026-05-10T00:00:00Z",
    "sample_id": "sample-dnsmasq",
    "status": "completed",
    "artifacts": {
        "sample_bin": "sample.bin",
        "bind9_stderr": "bind9.stderr",
        "dnsmasq_stderr": "dnsmasq.stderr",
        "bind9_before_cache": "bind9.before.cache.txt",
        "bind9_after_cache": "bind9.after.cache.txt",
        "dnsmasq_before_cache": "dnsmasq.before.cache.txt",
        "dnsmasq_after_cache": "dnsmasq.after.cache.txt",
        "oracle": "oracle.json",
    },
}
oracle = {
    "schema_version": 1,
    "generated_at": "2026-05-10T00:00:00Z",
    "sample_id": "sample-dnsmasq",
    "bind9.stderr_parse_status": "ok",
    "dnsmasq.stderr_parse_status": "ok",
    "bind9.parse_ok": True,
    "dnsmasq.parse_ok": True,
    "bind9.resolver_fetch_started": True,
    "dnsmasq.resolver_fetch_started": True,
    "bind9.response_accepted": True,
    "dnsmasq.response_accepted": True,
    "bind9.second_query_hit": False,
    "dnsmasq.second_query_hit": True,
    "bind9.cache_entry_created": False,
    "dnsmasq.cache_entry_created": True,
    "bind9.timeout": False,
    "dnsmasq.timeout": False,
}
cache_diff = {
    "schema_version": 1,
    "generated_at": "2026-05-10T00:00:00Z",
    "sample_id": "sample-dnsmasq",
    "cache_delta_triggered": True,
    "bind9": {"has_cache_diff": False, "interesting_delta_count": 0, "delta_items": []},
    "dnsmasq": {"has_cache_diff": True, "interesting_delta_count": 1, "delta_items": []},
}
triage = {
    "schema_version": 1,
    "generated_at": "2026-05-10T00:00:00Z",
    "sample_id": "sample-dnsmasq",
    "status": "completed_oracle_diff",
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
    "filter_labels": ["oracle_diff"],
    "cluster_key": "completed_oracle_diff|oracle_diff|oracle_diff|fp:iterative->dnsmasq",
    "cache_delta_triggered": True,
    "interesting_delta_count": 1,
    "needs_manual_review": True,
    "notes": ["dnsmasq secondary resolver"],
}
write_json(sample_dir / "sample.meta.json", sample_meta)
write_json(sample_dir / "oracle.json", oracle)
write_json(sample_dir / "cache_diff.json", cache_diff)
write_json(sample_dir / "triage.json", triage)
(sample_dir / "sample.bin").write_bytes(b"\x00\x01")
(sample_dir / "bind9.stderr").write_text("bind9 stderr\n", encoding="utf-8")
(sample_dir / "dnsmasq.stderr").write_text("dnsmasq stderr\n", encoding="utf-8")
PY

PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	python3 -m tools.dns_diff.cli case-study-export \
		--root "$FOLLOW_ROOT" \
		--campaign-report-dir "$REPORT_DIR" \
		--top-n 1 >/dev/null

python3 - "$REPORT_DIR/case_studies/sample-dnsmasq.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
raw = payload["raw_evidence"]
ctx = raw["resolver_context"]
if ctx["secondary"] != "dnsmasq":
    raise SystemExit(f"ASSERT FAIL: secondary={ctx['secondary']!r} != 'dnsmasq'")
paths = raw["paths"]
if "dnsmasq_stderr_path" not in paths:
    raise SystemExit(f"ASSERT FAIL: 缺少 dnsmasq_stderr_path: {paths!r}")
stderr = raw["stderr"]
if "dnsmasq" not in stderr:
    raise SystemExit(f"ASSERT FAIL: 缺少 dnsmasq stderr preview: {stderr!r}")
summary = payload["automated_summary"]
if summary.get("secondary_resolver") != "dnsmasq":
    raise SystemExit(f"ASSERT FAIL: secondary_resolver={summary.get('secondary_resolver')!r}")
if summary.get("dnsmasq_has_cache_diff") is not True:
    raise SystemExit(f"ASSERT FAIL: dnsmasq_has_cache_diff={summary.get('dnsmasq_has_cache_diff')!r} != True")
PY

printf 'PASS: case study secondary resolver regression test passed\n'
