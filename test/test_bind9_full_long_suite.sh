#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-bind9-full-long-suite.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

OUT="$(
	env \
		DRY_RUN=1 \
		SUITE_ROOT="$WORKDIR/suite" \
		PRODUCER_LONG_SEC=7200 \
		PRODUCER_SMOKE_SEC=9 \
		RESOLVER_LONG_BUDGET_SEC=600 \
		RESOLVER_REPEAT_COUNT=5 \
		RESOLVER_REPLAY_BACKEND=dnslabctl \
		LIVE_SEED_SYNC_INTERVAL_SEC=300 \
		RESOLVER_FEEDBACK_SCAN_INTERVAL_SEC=300 \
		RESOLVERS="dnsmasq smartdns" \
		"$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" all
)"

printf '%s\n' "$OUT" | grep -F "DRY-RUN producer-smoke duration=9" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未包含 producer-smoke duration\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "DRY-RUN producer-long duration=7200" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未包含 producer-long duration\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "FUZZ_PROFILE=poison-stateful" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未包含 poison-stateful producer profile\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "DST1_MUTATOR_ONLY=1" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未启用 DST1 mutator-only producer 默认值\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS=100000" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未包含 persistent iters producer 默认值\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "DRY-RUN producer-long background=1" >/dev/null || {
	printf 'ASSERT FAIL: all dry-run 未说明 producer-long 后台运行\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "DRY-RUN live-seed-sync interval_sec=300" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未说明 live seed 周期同步\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "source_queue=$WORKDIR/suite/producer/work/afl_out/master/queue" >/dev/null || {
	printf 'ASSERT FAIL: dry-run live seed source queue 不正确\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "target_queue=$WORKDIR/suite/live_handoff/producer_queue" >/dev/null || {
	printf 'ASSERT FAIL: dry-run live seed target queue 不正确\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "DRY-RUN resolver-feedback-sync interval_sec=300" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未说明 resolver feedback 周期扫描\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "feedback_result_root=$WORKDIR/suite/resolver_long_matrix/" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver feedback 结果根目录不正确\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "PRODUCER_QUEUE_DIR=$WORKDIR/suite/live_handoff/producer_queue" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未指向 live handoff queue\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "PRODUCER_PROVENANCE_FILE=$WORKDIR/suite/live_handoff/producer_seed_provenance.json" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未指向 live handoff provenance\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "BUDGET_SEC=600" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未包含长预算\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "REPEAT_COUNT=5" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未包含 repeat=5\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "QUEUE_LIMIT=8" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未包含默认 queue limit\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "RESOLVERS=dnsmasq smartdns" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未保留 resolver 列表\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "DNS_DIFF_REPLAY_BACKEND=dnslabctl" >/dev/null || {
	printf 'ASSERT FAIL: dry-run resolver 未启用 dnslabctl backend\n' >&2
	exit 1
}
printf '%s\n' "$OUT" | grep -F "_resolver_summary" >/dev/null || {
	printf 'ASSERT FAIL: dry-run 未说明 resolver summary 输出\n' >&2
	exit 1
}
if printf '%s\n' "$OUT" | grep -F "background=1" >/dev/null; then
	:
else
	printf 'ASSERT FAIL: all 应后台启动 producer-long 以便 resolver-long 同步消费新 seed\n' >&2
	exit 1
fi
if printf '%s\n' "$OUT" | grep -F "freeze-seeds" >/dev/null; then
	printf 'ASSERT FAIL: all 不应再包含 freeze-seeds\n' >&2
	exit 1
fi
python3 - "$OUT" <<'PY'
import sys

lines = sys.argv[1].splitlines()

def index_of(prefix: str) -> int:
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            return index
    raise SystemExit(f"ASSERT FAIL: 缺少输出行: {prefix}")

producer_long_index = index_of("DRY-RUN producer-long duration=7200")
sync_index = index_of("DRY-RUN live-seed-sync interval_sec=300")
resolver_index = index_of("DRY-RUN resolver-long")
if not producer_long_index < sync_index < resolver_index:
    raise SystemExit(
        "ASSERT FAIL: all 必须启动 producer-long 后建立 live seed handoff，再启动 resolver-long"
    )
PY

"$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" --help | grep -F "producer-long" >/dev/null || {
	printf 'ASSERT FAIL: help 未包含 producer-long\n' >&2
	exit 1
}
if "$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" --help | grep -F "freeze-seeds" >/dev/null; then
	printf 'ASSERT FAIL: help 不应再包含 freeze-seeds\n' >&2
	exit 1
fi
"$ROOT_DIR/scripts/run_bind9_rq3_long_suite.sh" --help | grep -F "run_bind9_full_long_suite.sh" >/dev/null || {
	printf 'ASSERT FAIL: 旧 RQ3 入口未转发到 full long suite\n' >&2
	exit 1
}

PRODUCER_WORK="$WORKDIR/producer-work"
QUEUE_DIR="$PRODUCER_WORK/afl_out/master/queue"
mkdir -p "$QUEUE_DIR"
printf 'seed-a\n' >"$QUEUE_DIR/id:000001,orig:a"
printf 'seed-b\n' >"$QUEUE_DIR/id:000002,orig:b"
printf '{"seed_materialization_method":"cold_start"}\n' >"$PRODUCER_WORK/producer_seed_provenance.json"

SYNC_OUT="$(
	env \
		PRODUCER_WORK_DIR="$PRODUCER_WORK" \
		SUITE_ROOT="$WORKDIR/live-suite" \
		"$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" sync-live-seeds
)"
LIVE_HANDOFF_DIR="$WORKDIR/live-suite/live_handoff"
LIVE_QUEUE_DIR="$LIVE_HANDOFF_DIR/producer_queue"
[ -f "$LIVE_QUEUE_DIR/id:000001,orig:a" ] || {
	printf 'ASSERT FAIL: sync-live-seeds 未复制 queue seed a\n' >&2
	exit 1
}
[ -f "$LIVE_QUEUE_DIR/id:000002,orig:b" ] || {
	printf 'ASSERT FAIL: sync-live-seeds 未复制 queue seed b\n' >&2
	exit 1
}
[ -f "$LIVE_HANDOFF_DIR/producer_seed_provenance.json" ] || {
	printf 'ASSERT FAIL: sync-live-seeds 未复制 provenance\n' >&2
	exit 1
}
[ -f "$LIVE_HANDOFF_DIR/live_seed_manifest.json" ] || {
	printf 'ASSERT FAIL: sync-live-seeds 未写 manifest\n' >&2
	exit 1
}
printf '%s\n' "$SYNC_OUT" | grep -F "live seed handoff: $LIVE_QUEUE_DIR" >/dev/null || {
	printf 'ASSERT FAIL: sync-live-seeds 未输出 live handoff queue\n' >&2
	exit 1
}
python3 - "$LIVE_HANDOFF_DIR/live_seed_manifest.json" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("file_count") != 2:
    raise SystemExit(f"ASSERT FAIL: manifest file_count 非 2: {payload!r}")
if not payload.get("live_seed_batch_id"):
    raise SystemExit(f"ASSERT FAIL: manifest 缺少 live_seed_batch_id: {payload!r}")
PY

printf 'seed-c\n' >"$QUEUE_DIR/id:000003,orig:c"
env \
	PRODUCER_WORK_DIR="$PRODUCER_WORK" \
	SUITE_ROOT="$WORKDIR/live-suite" \
	"$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" sync-live-seeds >/dev/null
[ -f "$LIVE_QUEUE_DIR/id:000003,orig:c" ] || {
	printf 'ASSERT FAIL: sync-live-seeds 未增量复制新 seed c\n' >&2
	exit 1
}

RESOLVER_ONLY_OUT="$(
	env \
		DRY_RUN=1 \
		SUITE_ROOT="$WORKDIR/live-suite" \
		STAMP=resolver-only \
		"$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" resolver-long
)"
printf '%s\n' "$RESOLVER_ONLY_OUT" | grep -F "PRODUCER_QUEUE_DIR=$LIVE_QUEUE_DIR" >/dev/null || {
	printf 'ASSERT FAIL: standalone resolver-long 未使用 live handoff queue\n' >&2
	exit 1
}
printf '%s\n' "$RESOLVER_ONLY_OUT" | grep -F "PRODUCER_PROVENANCE_FILE=$LIVE_HANDOFF_DIR/producer_seed_provenance.json" >/dev/null || {
	printf 'ASSERT FAIL: standalone resolver-long 未使用 live handoff provenance\n' >&2
	exit 1
}

FEEDBACK_SUITE="$WORKDIR/feedback-suite"
FEEDBACK_STAMP=feedback-test
FEEDBACK_ROOT="$FEEDBACK_SUITE/resolver_long_matrix/$FEEDBACK_STAMP"
RUN_ROOT="$FEEDBACK_ROOT/dnsmasq/matrix_runs/full_stack/run-01/follow_diff"
mkdir -p "$RUN_ROOT"
HIGH_SAMPLE="$LIVE_QUEUE_DIR/id:000002,orig:b"
LOW_SAMPLE="$LIVE_QUEUE_DIR/id:000001,orig:a"
python3 - "$RUN_ROOT/semantic_frontier_manifest.json" "$RUN_ROOT/high_value_samples.txt" "$HIGH_SAMPLE" "$LOW_SAMPLE" <<'PY'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
text_manifest = pathlib.Path(sys.argv[2])
high_sample = pathlib.Path(sys.argv[3]).resolve()
low_sample = pathlib.Path(sys.argv[4]).resolve()
payload = {
    "contract_name": "semantic_frontier_manifest",
    "contract_version": 1,
    "generated_at": "2026-06-03T00:00:00Z",
    "root": str(manifest.parent.resolve()),
    "entries": [
        {
            "sample_path": str(low_sample),
            "sample_id": "low",
            "analysis_state": "included",
            "semantic_outcome": "no_diff",
            "oracle_audit_candidate": False,
            "needs_manual_review": False,
            "priority_tier": 0,
        },
        {
            "sample_path": str(high_sample),
            "sample_id": "high",
            "analysis_state": "included",
            "semantic_outcome": "oracle_diff",
            "oracle_audit_candidate": False,
            "needs_manual_review": False,
            "priority_tier": 3,
        },
    ],
}
manifest.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
text_manifest.write_text(str(high_sample) + "\n", encoding="utf-8")
PY
FEEDBACK_OUT="$(
	env \
		PRODUCER_WORK_DIR="$PRODUCER_WORK" \
		SUITE_ROOT="$FEEDBACK_SUITE" \
		STAMP="$FEEDBACK_STAMP" \
		"$ROOT_DIR/scripts/run_bind9_full_long_suite.sh" scan-resolver-feedback
)"
printf '%s\n' "$FEEDBACK_OUT" | grep -F "resolver feedback:" >/dev/null || {
	printf 'ASSERT FAIL: scan-resolver-feedback 未输出反馈结果\n' >&2
	exit 1
}
[ -f "$PRODUCER_WORK/high_value_samples.txt" ] || {
	printf 'ASSERT FAIL: scan-resolver-feedback 未写 producer high_value manifest\n' >&2
	exit 1
}
[ -f "$PRODUCER_WORK/semantic_frontier_manifest.json" ] || {
	printf 'ASSERT FAIL: scan-resolver-feedback 未写 producer semantic frontier manifest\n' >&2
	exit 1
}
python3 - "$PRODUCER_WORK/high_value_samples.txt" "$PRODUCER_WORK/semantic_frontier_manifest.json" "$HIGH_SAMPLE" "$LOW_SAMPLE" <<'PY'
import json
import pathlib
import sys

text_manifest = pathlib.Path(sys.argv[1])
json_manifest = pathlib.Path(sys.argv[2])
high_sample = str(pathlib.Path(sys.argv[3]).resolve())
low_sample = str(pathlib.Path(sys.argv[4]).resolve())
lines = text_manifest.read_text(encoding="utf-8").splitlines()
if lines != [high_sample]:
    raise SystemExit(f"ASSERT FAIL: high_value manifest 内容不正确: {lines!r}")
payload = json.loads(json_manifest.read_text(encoding="utf-8"))
entries = payload.get("entries")
if not isinstance(entries, list) or len(entries) != 1:
    raise SystemExit(f"ASSERT FAIL: semantic frontier entries 不正确: {payload!r}")
entry = entries[0]
if entry.get("sample_path") != high_sample or entry.get("priority_tier") != 3:
    raise SystemExit(f"ASSERT FAIL: semantic frontier entry 不正确: {entry!r}")
if low_sample in json.dumps(payload, ensure_ascii=False):
    raise SystemExit("ASSERT FAIL: semantic frontier 不应包含 priority_tier=0 的 no_diff 样本")
PY

printf 'PASS: bind9 full long suite dry-run contract holds\n'
