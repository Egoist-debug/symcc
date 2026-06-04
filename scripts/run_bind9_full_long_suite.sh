#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/real_experiment_paths.sh"

STAMP="${STAMP:-$(date -u +%Y%m%d_%H%M%S)}"
SUITE_ROOT="${SUITE_ROOT:-$ROOT_DIR/experiments/results/bind9_full_long_suite/$STAMP}"
PRODUCER_RESULT_ROOT="$SUITE_ROOT/producer"
PRODUCER_WORK_DIR="${PRODUCER_WORK_DIR:-$PRODUCER_RESULT_ROOT/work}"
PRODUCER_QUEUE_DIR="$PRODUCER_WORK_DIR/afl_out/master/queue"
PRODUCER_PROVENANCE_FILE="$PRODUCER_WORK_DIR/producer_seed_provenance.json"
PRODUCER_HIGH_VALUE_MANIFEST="$PRODUCER_WORK_DIR/high_value_samples.txt"
PRODUCER_SEMANTIC_FRONTIER_MANIFEST="$PRODUCER_WORK_DIR/semantic_frontier_manifest.json"
LIVE_HANDOFF_DIR="${LIVE_HANDOFF_DIR:-$SUITE_ROOT/live_handoff}"
LIVE_QUEUE_DIR="${LIVE_QUEUE_DIR:-$LIVE_HANDOFF_DIR/producer_queue}"
LIVE_PROVENANCE_FILE="$LIVE_HANDOFF_DIR/producer_seed_provenance.json"
LIVE_SEED_MANIFEST="$LIVE_HANDOFF_DIR/live_seed_manifest.json"

PRODUCER_SMOKE_SEC="${PRODUCER_SMOKE_SEC:-180}"
PRODUCER_LONG_SEC="${PRODUCER_LONG_SEC:-3600}"
RESOLVER_LONG_BUDGET_SEC="${RESOLVER_LONG_BUDGET_SEC:-900}"
RESOLVER_REPEAT_COUNT="${RESOLVER_REPEAT_COUNT:-5}"
RESOLVER_REPLAY_BACKEND="${RESOLVER_REPLAY_BACKEND:-dnslabctl}"
RESOLVER_QUEUE_LIMIT="${RESOLVER_QUEUE_LIMIT:-8}"
RESOLVERS="${RESOLVERS:-unbound dnsmasq smartdns maradns knot-resolver}"
RESOLVER_RESULT_ROOT_BASE="${RESOLVER_RESULT_ROOT_BASE:-$SUITE_ROOT/resolver_long_matrix}"
RESOLVER_FEEDBACK_ROOT="${RESOLVER_FEEDBACK_ROOT:-$RESOLVER_RESULT_ROOT_BASE/$STAMP}"
LIVE_SEED_SYNC_INTERVAL_SEC="${LIVE_SEED_SYNC_INTERVAL_SEC:-300}"
RESOLVER_FEEDBACK_SCAN_INTERVAL_SEC="${RESOLVER_FEEDBACK_SCAN_INTERVAL_SEC:-300}"
LIVE_SEED_WAIT_SEC="${LIVE_SEED_WAIT_SEC:-600}"
DRY_RUN="${DRY_RUN:-0}"

usage() {
	cat <<'EOF'
用法:
  scripts/run_bind9_full_long_suite.sh <命令>

命令:
  preflight        只校验依赖、BIND9 producer 树和 resolver 源/构建树
  producer-smoke   运行短时 BIND9 AFL+SymCC+DST1 producer smoke
  producer-long    运行长时 BIND9 AFL+SymCC+DST1 producer
  sync-live-seeds  将 producer 新增 queue 样本同步到 live handoff 输入
  scan-resolver-feedback 扫描 resolver-long 结果并更新 producer 差异反馈 manifest
  resolver-long    持续同步 live 输入并运行多 resolver/4 变体长预算 campaign matrix
  all              执行 preflight -> producer-smoke -> producer-long(后台) -> resolver-long

常用环境变量:
  SUITE_ROOT=<输出根目录>
  LIVE_HANDOFF_DIR=<producer/resolver live 输入交接目录>
  LIVE_SEED_SYNC_INTERVAL_SEC=300
  RESOLVER_FEEDBACK_SCAN_INTERVAL_SEC=300
  PRODUCER_SMOKE_SEC=180
  PRODUCER_LONG_SEC=3600
  RESOLVER_LONG_BUDGET_SEC=900
  RESOLVER_REPEAT_COUNT=5
  RESOLVER_REPLAY_BACKEND=dnslabctl
  RESOLVER_QUEUE_LIMIT=8
  RESOLVERS="unbound dnsmasq smartdns maradns knot-resolver"
  DRY_RUN=1
EOF
}

is_dry_run() {
	[ "$DRY_RUN" = "1" ]
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		printf '缺少命令: %s\n' "$1" >&2
		exit 1
	}
}

require_dir() {
	[ -d "$1" ] || {
		printf '缺少目录: %s\n' "$1" >&2
		exit 1
	}
}

require_file() {
	[ -e "$1" ] || {
		printf '缺少文件: %s\n' "$1" >&2
		exit 1
	}
}

preflight() {
	local cmd resolver build_root

	if is_dry_run; then
		printf 'DRY-RUN preflight suite_root=%s\n' "$SUITE_ROOT"
		return 0
	fi

	for cmd in python3 timeout make xmake; do
		require_cmd "$cmd"
	done

	require_file "$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
	require_file "$ROOT_DIR/experiments/resolvers.lock.json"
	require_dir "$(resolver_src_root bind9)"
	require_dir "$(bind9_afl_tree)"
	require_dir "$(bind9_symcc_tree)"

	for resolver in $RESOLVERS; do
		require_dir "$(resolver_src_root "$resolver")"
		if [ "$(resolver_normalize_name "$resolver")" = "unbound" ]; then
			build_root="$(unbound_afl_tree)"
		else
			build_root="$(resolver_build_root "$resolver")"
		fi
		require_dir "$build_root"
	done

	printf '%s\n' "$SUITE_ROOT"
}

dry_run_producer() {
	local label="$1" duration="$2"
	printf 'DRY-RUN %s duration=%s\n' "$label" "$duration"
	printf 'FUZZ_PROFILE=poison-stateful\n'
	printf 'ENABLE_DST1_MUTATOR=1\n'
	printf 'DST1_MUTATOR_ONLY=1\n'
	printf 'NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS=100000\n'
	printf 'SYMCC_HIGH_VALUE_MANIFEST=%s\n' "$PRODUCER_HIGH_VALUE_MANIFEST"
	printf 'SYMCC_SEMANTIC_FRONTIER_MANIFEST=%s\n' "$PRODUCER_SEMANTIC_FRONTIER_MANIFEST"
	printf 'WORK_DIR=%s\n' "$PRODUCER_WORK_DIR"
	printf 'SRC_TREE=%s\n' "$(resolver_src_root bind9)"
	printf 'AFL_TREE=%s\n' "$(bind9_afl_tree)"
	printf 'SYMCC_TREE=%s\n' "$(bind9_symcc_tree)"
	printf 'RESPONSE_CORPUS_DIR=%s\n' "$(default_response_corpus_dir)"
	printf 'command=%s prepare\n' "$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
	printf 'command=%s run %s\n' "$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" "$duration"
}

ensure_producer_feedback_files() {
	mkdir -p "$PRODUCER_WORK_DIR"
	[ -f "$PRODUCER_HIGH_VALUE_MANIFEST" ] || : >"$PRODUCER_HIGH_VALUE_MANIFEST"
	[ -f "$PRODUCER_SEMANTIC_FRONTIER_MANIFEST" ] && return 0
	python3 - "$PRODUCER_SEMANTIC_FRONTIER_MANIFEST" "$PRODUCER_WORK_DIR" <<'PY'
import datetime
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]).resolve()
payload = {
    "contract_name": "semantic_frontier_manifest",
    "contract_version": 1,
    "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    "root": str(root),
    "entries": [],
}
manifest_path.write_text(
    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

run_producer() {
	local label="$1" duration="$2"

	if is_dry_run; then
		dry_run_producer "$label" "$duration"
		return 0
	fi

	mkdir -p "$PRODUCER_RESULT_ROOT"
	ensure_producer_feedback_files
	env \
		FUZZ_PROFILE=poison-stateful \
		ENABLE_DST1_MUTATOR=1 \
		DST1_MUTATOR_ONLY="${DST1_MUTATOR_ONLY:-1}" \
		NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS="${NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS:-100000}" \
		SYMCC_HIGH_VALUE_MANIFEST="$PRODUCER_HIGH_VALUE_MANIFEST" \
		SYMCC_SEMANTIC_FRONTIER_MANIFEST="$PRODUCER_SEMANTIC_FRONTIER_MANIFEST" \
		WORK_DIR="$PRODUCER_WORK_DIR" \
		SRC_TREE="$(resolver_src_root bind9)" \
		AFL_TREE="$(bind9_afl_tree)" \
		SYMCC_TREE="$(bind9_symcc_tree)" \
		RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
		"$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" prepare
	env \
		FUZZ_PROFILE=poison-stateful \
		ENABLE_DST1_MUTATOR=1 \
		DST1_MUTATOR_ONLY="${DST1_MUTATOR_ONLY:-1}" \
		NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS="${NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS:-100000}" \
		SYMCC_HIGH_VALUE_MANIFEST="$PRODUCER_HIGH_VALUE_MANIFEST" \
		SYMCC_SEMANTIC_FRONTIER_MANIFEST="$PRODUCER_SEMANTIC_FRONTIER_MANIFEST" \
		WORK_DIR="$PRODUCER_WORK_DIR" \
		SRC_TREE="$(resolver_src_root bind9)" \
		AFL_TREE="$(bind9_afl_tree)" \
		SYMCC_TREE="$(bind9_symcc_tree)" \
		RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
		"$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" run "$duration"
	printf '%s\n' "$PRODUCER_WORK_DIR"
}

producer_smoke() {
	run_producer "producer-smoke" "$PRODUCER_SMOKE_SEC"
}

sync_live_seeds() {
	if is_dry_run; then
		printf 'DRY-RUN live-seed-sync interval_sec=%s\n' "$LIVE_SEED_SYNC_INTERVAL_SEC"
		printf 'source_queue=%s\n' "$PRODUCER_QUEUE_DIR"
		printf 'source_provenance=%s\n' "$PRODUCER_PROVENANCE_FILE"
		printf 'target_queue=%s\n' "$LIVE_QUEUE_DIR"
		printf 'target_provenance=%s\n' "$LIVE_PROVENANCE_FILE"
		printf 'manifest=%s\n' "$LIVE_SEED_MANIFEST"
		return 0
	fi

	mkdir -p "$LIVE_QUEUE_DIR"
	python3 - "$LIVE_SEED_MANIFEST" "$PRODUCER_QUEUE_DIR" "$PRODUCER_PROVENANCE_FILE" "$LIVE_QUEUE_DIR" "$LIVE_PROVENANCE_FILE" <<'PY'
import datetime
import hashlib
import json
import pathlib
import shutil
import sys

manifest_path = pathlib.Path(sys.argv[1])
source_queue = pathlib.Path(sys.argv[2])
source_provenance = pathlib.Path(sys.argv[3])
target_queue = pathlib.Path(sys.argv[4])
target_provenance = pathlib.Path(sys.argv[5])

target_queue.mkdir(parents=True, exist_ok=True)
target_provenance.parent.mkdir(parents=True, exist_ok=True)

copied = 0
if source_queue.is_dir():
    for source_file in sorted(source_queue.iterdir()):
        if not source_file.is_file():
            continue
        target_file = target_queue / source_file.name
        if target_file.exists():
            continue
        tmp_file = target_file.with_name(target_file.name + ".tmp")
        shutil.copy2(source_file, tmp_file)
        tmp_file.replace(target_file)
        copied += 1

if source_provenance.is_file():
    tmp_provenance = target_provenance.with_name(target_provenance.name + ".tmp")
    shutil.copy2(source_provenance, tmp_provenance)
    tmp_provenance.replace(target_provenance)

digest = hashlib.sha1()
files = []
for path in sorted(target_queue.iterdir()):
    if not path.is_file():
        continue
    data = path.read_bytes()
    digest.update(path.name.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(len(data)).encode("ascii"))
    digest.update(b"\0")
    digest.update(hashlib.sha1(data).hexdigest().encode("ascii"))
    digest.update(b"\0")
    files.append({"name": path.name, "size": len(data)})

payload = {
    "source_queue_dir": str(source_queue.resolve()),
    "source_provenance_file": str(source_provenance.resolve()),
    "target_queue_dir": str(target_queue.resolve()),
    "target_provenance_file": str(target_provenance.resolve()),
    "live_seed_batch_id": digest.hexdigest() if files else None,
    "file_count": len(files),
    "copied_count": copied,
    "files": files,
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
}
tmp_manifest = manifest_path.with_name(manifest_path.name + ".tmp")
tmp_manifest.write_text(
    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
tmp_manifest.replace(manifest_path)
PY
	printf 'live seed handoff: %s\n' "$LIVE_QUEUE_DIR"
}

wait_for_live_queue() {
	local deadline=$((SECONDS + LIVE_SEED_WAIT_SEC))

	while true; do
		sync_live_seeds >/dev/null || true
		if [ -d "$LIVE_QUEUE_DIR" ] && \
		   find "$LIVE_QUEUE_DIR" -maxdepth 1 -type f -print -quit | grep -q .; then
			return 0
		fi
		if (( SECONDS >= deadline )); then
			printf '等待 live handoff queue 超时: %s\n' "$LIVE_QUEUE_DIR" >&2
			return 1
		fi
		sleep 1
	done
}

live_seed_sync_loop() {
	while true; do
		sync_live_seeds
		sleep "$LIVE_SEED_SYNC_INTERVAL_SEC"
	done
}

scan_resolver_feedback() {
	if is_dry_run; then
		printf 'DRY-RUN resolver-feedback-sync interval_sec=%s\n' "$RESOLVER_FEEDBACK_SCAN_INTERVAL_SEC"
		printf 'feedback_result_root=%s\n' "$RESOLVER_FEEDBACK_ROOT"
		printf 'producer_high_value_manifest=%s\n' "$PRODUCER_HIGH_VALUE_MANIFEST"
		printf 'producer_semantic_frontier_manifest=%s\n' "$PRODUCER_SEMANTIC_FRONTIER_MANIFEST"
		return 0
	fi

	ensure_producer_feedback_files
	python3 - "$RESOLVER_FEEDBACK_ROOT" "$PRODUCER_HIGH_VALUE_MANIFEST" "$PRODUCER_SEMANTIC_FRONTIER_MANIFEST" "$PRODUCER_WORK_DIR" <<'PY'
import datetime
import json
import pathlib
import sys

feedback_root = pathlib.Path(sys.argv[1])
text_manifest = pathlib.Path(sys.argv[2])
json_manifest = pathlib.Path(sys.argv[3])
producer_root = pathlib.Path(sys.argv[4]).resolve()

def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

def coerce_tier(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(value, 3))

def normalize_entry(entry: dict, source_manifest: pathlib.Path) -> dict | None:
    sample_path = entry.get("sample_path")
    if not isinstance(sample_path, str) or not sample_path.strip():
        return None
    resolved_sample = pathlib.Path(sample_path).expanduser().resolve()
    if not resolved_sample.is_file():
        return None
    priority_tier = coerce_tier(entry.get("priority_tier"))
    if priority_tier <= 0:
        return None
    return {
        "sample_path": str(resolved_sample),
        "sample_id": str(entry.get("sample_id") or resolved_sample.name),
        "analysis_state": str(entry.get("analysis_state") or "unknown"),
        "semantic_outcome": str(entry.get("semantic_outcome") or "unknown"),
        "oracle_audit_candidate": bool(entry.get("oracle_audit_candidate")),
        "needs_manual_review": bool(entry.get("needs_manual_review")),
        "priority_tier": priority_tier,
        "source_manifest": str(source_manifest.resolve()),
    }

entries_by_path: dict[str, dict] = {}
if feedback_root.is_dir():
    for manifest_path in sorted(feedback_root.rglob("semantic_frontier_manifest.json")):
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        raw_entries = payload.get("entries")
        if not isinstance(raw_entries, list):
            continue
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                continue
            entry = normalize_entry(raw_entry, manifest_path)
            if entry is None:
                continue
            existing = entries_by_path.get(entry["sample_path"])
            if existing is None or entry["priority_tier"] > existing["priority_tier"]:
                entries_by_path[entry["sample_path"]] = entry

def sort_key(entry: dict) -> tuple[int, str, str]:
    return (-int(entry["priority_tier"]), entry["semantic_outcome"], entry["sample_path"])

entries = sorted(entries_by_path.values(), key=sort_key)
text_manifest.parent.mkdir(parents=True, exist_ok=True)
json_manifest.parent.mkdir(parents=True, exist_ok=True)

tmp_text = text_manifest.with_name(text_manifest.name + ".tmp")
tmp_text.write_text(
    "".join(f"{entry['sample_path']}\n" for entry in entries),
    encoding="utf-8",
)
tmp_text.replace(text_manifest)

payload = {
    "contract_name": "semantic_frontier_manifest",
    "contract_version": 1,
    "generated_at": utc_now(),
    "root": str(producer_root),
    "feedback_result_root": str(feedback_root.resolve()),
    "entries": entries,
}
tmp_json = json_manifest.with_name(json_manifest.name + ".tmp")
tmp_json.write_text(
    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
tmp_json.replace(json_manifest)
print(f"entries={len(entries)}")
PY
	printf 'resolver feedback: %s\n' "$PRODUCER_SEMANTIC_FRONTIER_MANIFEST"
}

resolver_feedback_scan_loop() {
	while true; do
		scan_resolver_feedback
		sleep "$RESOLVER_FEEDBACK_SCAN_INTERVAL_SEC"
	done
}

producer_long() {
	local feedback_pid=""
	local producer_status=0

	if is_dry_run; then
		run_producer "producer-long" "$PRODUCER_LONG_SEC"
		scan_resolver_feedback
		return 0
	fi

	resolver_feedback_scan_loop &
	feedback_pid="$!"
	cleanup_feedback_loop() {
		if [ -n "$feedback_pid" ]; then
			kill "$feedback_pid" 2>/dev/null || true
			wait "$feedback_pid" 2>/dev/null || true
		fi
	}
	trap cleanup_feedback_loop INT TERM
	set +e
	run_producer "producer-long" "$PRODUCER_LONG_SEC"
	producer_status="$?"
	set -e
	cleanup_feedback_loop
	trap - INT TERM
	return "$producer_status"
}

resolver_summary_dir() {
	printf '%s/%s/_resolver_summary\n' "$RESOLVER_RESULT_ROOT_BASE" "$STAMP"
}

resolver_long() {
	local summary_dir sync_pid=""
	local resolver_status=0
	summary_dir="$(resolver_summary_dir)"

	if is_dry_run; then
		printf 'DRY-RUN resolver-long\n'
		printf 'RESULT_ROOT_BASE=%s\n' "$RESOLVER_RESULT_ROOT_BASE"
		printf 'STAMP=%s\n' "$STAMP"
		printf 'PRODUCER_QUEUE_DIR=%s\n' "$LIVE_QUEUE_DIR"
		printf 'PRODUCER_PROVENANCE_FILE=%s\n' "$LIVE_PROVENANCE_FILE"
		printf 'RESPONSE_CORPUS_DIR=%s\n' "$(default_response_corpus_dir)"
		printf 'BUDGET_SEC=%s\n' "$RESOLVER_LONG_BUDGET_SEC"
		printf 'REPEAT_COUNT=%s\n' "$RESOLVER_REPEAT_COUNT"
		printf 'QUEUE_LIMIT=%s\n' "$RESOLVER_QUEUE_LIMIT"
		printf 'RESOLVERS=%s\n' "$RESOLVERS"
		printf 'REPLAY_BACKEND=%s\n' "$RESOLVER_REPLAY_BACKEND"
		printf 'DNS_DIFF_REPLAY_BACKEND=%s\n' "$RESOLVER_REPLAY_BACKEND"
		printf 'command=%s\n' "$ROOT_DIR/scripts/run_real_campaign_matrix_multi_resolver.sh"
		printf 'summary=%s\n' "$summary_dir"
		return 0
	fi

	live_seed_sync_loop &
	sync_pid="$!"
	cleanup_live_seed_loop() {
		if [ -n "$sync_pid" ]; then
			kill "$sync_pid" 2>/dev/null || true
			wait "$sync_pid" 2>/dev/null || true
		fi
	}
	trap cleanup_live_seed_loop INT TERM
	set +e
	wait_for_live_queue
	resolver_status="$?"
	if [ "$resolver_status" -eq 0 ]; then
		env \
				RESULT_ROOT_BASE="$RESOLVER_RESULT_ROOT_BASE" \
				STAMP="$STAMP" \
				REPLAY_BACKEND="$RESOLVER_REPLAY_BACKEND" \
				DNS_DIFF_REPLAY_BACKEND="$RESOLVER_REPLAY_BACKEND" \
				PRODUCER_QUEUE_DIR="$LIVE_QUEUE_DIR" \
				PRODUCER_PROVENANCE_FILE="$LIVE_PROVENANCE_FILE" \
				RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
				BUDGET_SEC="$RESOLVER_LONG_BUDGET_SEC" \
				REPEAT_COUNT="$RESOLVER_REPEAT_COUNT" \
				QUEUE_LIMIT="$RESOLVER_QUEUE_LIMIT" \
				RESOLVERS="$RESOLVERS" \
				"$ROOT_DIR/scripts/run_real_campaign_matrix_multi_resolver.sh"
		resolver_status="$?"
	fi
	set -e
	cleanup_live_seed_loop
	trap - INT TERM
	if [ "$resolver_status" -ne 0 ]; then
		return "$resolver_status"
	fi
	printf 'resolver summary: %s\n' "$summary_dir"
}

run_all() {
	local producer_pid=""
	local producer_status=0

	if is_dry_run; then
		preflight
		producer_smoke
		dry_run_producer "producer-long" "$PRODUCER_LONG_SEC"
		printf 'DRY-RUN producer-long background=1\n'
		sync_live_seeds
		scan_resolver_feedback
		resolver_long
		return 0
	fi

	preflight
	producer_smoke
	producer_long &
	producer_pid="$!"
	cleanup_all() {
		if [ -n "$producer_pid" ] && kill -0 "$producer_pid" 2>/dev/null; then
			kill "$producer_pid" 2>/dev/null || true
			wait "$producer_pid" 2>/dev/null || true
		fi
	}
	trap cleanup_all EXIT INT TERM

	resolver_long
	set +e
	wait "$producer_pid"
	producer_status="$?"
	set -e
	producer_pid=""
	scan_resolver_feedback
	trap - EXIT INT TERM
	return "$producer_status"
}

main() {
	local cmd="${1:-help}"
	case "$cmd" in
		preflight) preflight ;;
		producer-smoke) producer_smoke ;;
		producer-long) producer_long ;;
		sync-live-seeds) sync_live_seeds ;;
		scan-resolver-feedback) scan_resolver_feedback ;;
		resolver-long) resolver_long ;;
		all) run_all ;;
		""|-h|--help|help)
			usage
			;;
		*)
			printf '未知命令: %s\n' "$cmd" >&2
			usage >&2
			exit 1
			;;
	esac
}

main "${1:-help}"
