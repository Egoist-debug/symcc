#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-evidence-secondary.XXXXXX")"
FOLLOW_ROOT="$WORKDIR/follow_diff"
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

write_json(
    sample_dir / "sample.meta.json",
    {
        "schema_version": 1,
        "generated_at": "2026-05-10T00:00:00Z",
        "sample_id": "sample-dnsmasq",
        "contract_version": 1,
        "aggregation_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": "poison-stateful",
            "input_model": "DST1 transcript",
            "source_queue_dir": "/tmp/follow/queue",
            "budget_sec": 5,
            "seed_timeout_sec": 1,
            "variant_name": "control",
            "ablation_status": {"mutator": "off", "cache-delta": "on", "triage": "on", "symcc": "on"},
            "contract_version": 1,
        },
        "baseline_compare_key": {
            "resolver_pair": "bind9_vs_unbound",
            "producer_profile": "poison-stateful",
            "input_model": "DST1 transcript",
            "source_queue_dir": "/tmp/follow/queue",
            "budget_sec": 5,
            "seed_timeout_sec": 1,
            "repeat_count": 1,
            "contract_version": 1,
        },
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
    },
)
write_json(
    sample_dir / "triage.json",
    {
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
        "cluster_key": "cluster-x",
        "cache_delta_triggered": False,
        "interesting_delta_count": 0,
        "needs_manual_review": True,
        "notes": ["dnsmasq secondary"],
    },
)
write_json(
    sample_dir / "oracle.json",
    {
        "bind9.parse_ok": True,
        "dnsmasq.parse_ok": False,
        "bind9.response_accepted": True,
        "dnsmasq.response_accepted": True,
        "bind9.second_query_hit": False,
        "dnsmasq.second_query_hit": True,
        "bind9.cache_entry_created": False,
        "dnsmasq.cache_entry_created": True,
        "bind9.stderr_parse_status": "ok",
        "dnsmasq.stderr_parse_status": "ok",
    },
)
write_json(
    sample_dir / "cache_diff.json",
    {
        "cache_delta_triggered": False,
        "bind9": {"has_cache_diff": False, "interesting_delta_count": 0},
        "dnsmasq": {"has_cache_diff": True, "interesting_delta_count": 1},
    },
)
(sample_dir / "sample.bin").write_bytes(b"\x00\x01")
(sample_dir / "bind9.stderr").write_text("bind9\n", encoding="utf-8")
(sample_dir / "dnsmasq.stderr").write_text("dnsmasq\n", encoding="utf-8")
PY

PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
	ROOT_DIR="$ROOT_DIR" \
	python3 -m tools.dns_diff.cli campaign-report --root "$FOLLOW_ROOT" >/dev/null

REPORT_DIR="$(python3 - "$FOLLOW_ROOT/campaign_reports" <<'PY'
from pathlib import Path
import sys
dirs = sorted(path for path in Path(sys.argv[1]).iterdir() if path.is_dir())
print(dirs[-1])
PY
)"

python3 - "$REPORT_DIR/evidence_bundle.json" <<'PY'
import json
import pathlib
import sys

bundle = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
artifacts = bundle["raw_sample_root"]["claim_review_artifacts"]
if "dnsmasq.stderr" not in artifacts:
    raise SystemExit(f"ASSERT FAIL: claim_review_artifacts 缺少 dnsmasq.stderr: {artifacts!r}")
PY

printf 'PASS: publication evidence bundle secondary resolver regression test passed\n'
