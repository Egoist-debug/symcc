#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/real_experiment_paths.sh"

REPLAY_BACKEND_RAW="${REPLAY_BACKEND:-${DNS_DIFF_REPLAY_BACKEND:-python}}"
case "$REPLAY_BACKEND_RAW" in
	python|"")
		REPLAY_BACKEND="python"
		;;
	dnslabctl)
		REPLAY_BACKEND="dnslabctl"
		;;
	*)
		printf '未知 REPLAY_BACKEND: %s\n' "$REPLAY_BACKEND_RAW" >&2
		exit 1
		;;
esac

STAMP="${STAMP:-$(date -u +%Y%m%d_%H%M%S)}"
if [ "$REPLAY_BACKEND" = "dnslabctl" ]; then
	DEFAULT_RESULT_ROOT_BASE="$ROOT_DIR/experiments/results/real_campaign_matrix_batch_dnslabctl"
else
	DEFAULT_RESULT_ROOT_BASE="$ROOT_DIR/experiments/results/real_campaign_matrix_batch"
fi
RESULT_ROOT_BASE="${RESULT_ROOT_BASE:-$DEFAULT_RESULT_ROOT_BASE}"
BASE_DIR="$RESULT_ROOT_BASE/$STAMP"
STATUS_TSV="$BASE_DIR/matrix_run_status.tsv"
SUCCESSFUL_ROOTS=()

REPEAT_COUNT="${REPEAT_COUNT:-2}"
BUDGET_SEC="${BUDGET_SEC:-5}"
QUEUE_LIMIT="${QUEUE_LIMIT:-0}"
RESOLVERS="${RESOLVERS:-unbound dnsmasq smartdns maradns knot-resolver}"
PRODUCER_QUEUE_DIR="${PRODUCER_QUEUE_DIR:-}"
PRODUCER_PROVENANCE_FILE="${PRODUCER_PROVENANCE_FILE:-}"
TRANSCRIPT_SOURCE_DIR="${TRANSCRIPT_SOURCE_DIR:-}"
RESPONSE_CORPUS_DIR="${RESPONSE_CORPUS_DIR:-$(default_response_corpus_dir)}"
BIND9_SRC_TREE="${BIND9_SRC_TREE:-$(resolver_src_root bind9)}"
BIND9_AFL_TREE="${BIND9_AFL_TREE:-$(bind9_afl_tree)}"

mkdir -p "$BASE_DIR"
cat >"$STATUS_TSV" <<'EOF'
resolver	status	work_root	matrix_file
EOF

matrix_file_for() {
	case "$(resolver_normalize_name "$1")" in
		unbound) printf '%s\n' "$ROOT_DIR/tools/dns_diff/config/poison_stateful_longbudget_matrix.json" ;;
		dnsmasq) printf '%s\n' "$ROOT_DIR/tools/dns_diff/config/poison_stateful_dnsmasq_matrix.json" ;;
		smartdns) printf '%s\n' "$ROOT_DIR/tools/dns_diff/config/poison_stateful_smartdns_matrix.json" ;;
		maradns) printf '%s\n' "$ROOT_DIR/tools/dns_diff/config/poison_stateful_maradns_matrix.json" ;;
		knot-resolver) printf '%s\n' "$ROOT_DIR/tools/dns_diff/config/poison_stateful_knot_matrix.json" ;;
		*)
			printf '未知 resolver: %s\n' "$1" >&2
			return 1
			;;
	esac
}

prepare_work_root() {
	local work_root="$1"
	env \
		PRODUCER_QUEUE_DIR="$PRODUCER_QUEUE_DIR" \
		PRODUCER_PROVENANCE_FILE="$PRODUCER_PROVENANCE_FILE" \
		TRANSCRIPT_SOURCE_DIR="$TRANSCRIPT_SOURCE_DIR" \
		QUEUE_LIMIT="$QUEUE_LIMIT" \
		python3 - "$work_root" <<'PY'
from pathlib import Path
import json
import os
import shutil
import sys

root = Path(sys.argv[1])
queue_dir = root / "afl_out" / "master" / "queue"
queue_dir.mkdir(parents=True, exist_ok=True)

queue_limit = int(os.environ.get("QUEUE_LIMIT", "0"))
producer_queue_dir_raw = os.environ.get("PRODUCER_QUEUE_DIR", "").strip()
transcript_source_dir_raw = os.environ.get("TRANSCRIPT_SOURCE_DIR", "").strip()
provenance_path = Path(os.environ.get("PRODUCER_PROVENANCE_FILE", "")).expanduser()
copied = 0

def _valid_source_dir(raw: str) -> Path | None:
    """空字符串的 Path('') 会解析为 '.'（cwd），必须显式拒绝。"""
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    return candidate if candidate.is_dir() else None

def iter_source_files() -> list[Path]:
    producer_dir = _valid_source_dir(producer_queue_dir_raw)
    if producer_dir is not None:
        files = sorted(path for path in producer_dir.iterdir() if path.is_file())
        return files[:queue_limit] if queue_limit > 0 else files
    transcript_dir = _valid_source_dir(transcript_source_dir_raw)
    if transcript_dir is not None:
        files = sorted(path for path in transcript_dir.iterdir() if path.is_file())
        return files[:queue_limit] if queue_limit > 0 else files
    return []

for index, source_file in enumerate(iter_source_files(), start=1):
    target = queue_dir / f"id:{index:06d},orig:{source_file.name}"
    shutil.copyfile(source_file, target)
    copied += 1

if copied == 0:
    qname = b'\x07example\x03com\x00'
    query = bytes.fromhex('123401000001000000000000') + qname + bytes.fromhex('00010001')
    response = bytes.fromhex('567881800001000100000000') + qname + bytes.fromhex('00010001c00c000100010000003c000401020304')
    post = bytes.fromhex('9abc01000001000000000000') + qname + bytes.fromhex('00010001')
    wire = bytearray(b'DST1')
    wire += bytes([1, 0])
    wire += len(query).to_bytes(2, 'little')
    wire += len(post).to_bytes(2, 'little')
    wire += len(response).to_bytes(2, 'little')
    wire += query + response + post
    (queue_dir / 'id:000001,orig:matrix-seed').write_bytes(wire)
    copied = 1

if provenance_path.is_file():
    shutil.copyfile(provenance_path, root / "producer_seed_provenance.json")
else:
    payload = {
        "cold_start": False,
        "seed_source_dir": str(queue_dir.resolve()),
        "seed_materialization_method": "reused_filtered_corpus",
        "seed_snapshot_id": "matrixseed000000000000000000000000000000000000",
        "regen_seeds": False,
        "refilter_queries": False,
        "stable_input_dir": str(queue_dir.resolve()),
        "transcript_format_version": 2,
        "transcript_max_responses": 16,
        "response_preserve": 20,
        "recorded_at": "2026-05-25T00:00:00Z",
    }
    (root / "producer_seed_provenance.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

print(copied)
PY
}

run_matrix() {
	local resolver="$1"
	local normalized_resolver
	local matrix_file
	local work_root
	local secondary_src
	local secondary_build

	normalized_resolver="$(resolver_normalize_name "$resolver")"
	matrix_file="$(matrix_file_for "$normalized_resolver")"
	work_root="$BASE_DIR/$normalized_resolver"
	secondary_src="$(resolver_src_root "$normalized_resolver")"
	if [ "$normalized_resolver" = "unbound" ]; then
		secondary_build="${AFL_TREE:-$(unbound_afl_tree)}"
	else
		secondary_build="$(resolver_build_root "$normalized_resolver")"
	fi

	prepare_work_root "$work_root" >/dev/null
	if env \
		ROOT_DIR="$ROOT_DIR" \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		DNS_DIFF_REPLAY_BACKEND="$REPLAY_BACKEND" \
		BIND9_AFL_TREE="$BIND9_AFL_TREE" \
		BIND9_SRC_TREE="$BIND9_SRC_TREE" \
		BIND9_NAMED_CONF_TEMPLATE="$ROOT_DIR/named_experiment/runtime/named.conf" \
		RESPONSE_CORPUS_DIR="$RESPONSE_CORPUS_DIR" \
		UNBOUND_SRC_TREE="$secondary_src" \
		DNSMASQ_SRC_TREE="$secondary_src" \
		SMARTDNS_SRC_TREE="$secondary_src" \
		MARADNS_SRC_TREE="$secondary_src" \
		KNOT_RESOLVER_SRC_TREE="$secondary_src" \
		AFL_TREE="$secondary_build" \
		DNSMASQ_BUILD_TREE="$secondary_build" \
		SMARTDNS_BUILD_TREE="$secondary_build" \
		MARADNS_BUILD_TREE="$secondary_build" \
		KNOT_RESOLVER_BUILD_TREE="$secondary_build" \
		CAMPAIGN_MATRIX_LIVE_SOURCE_QUEUE_DIR="$PRODUCER_QUEUE_DIR" \
		CAMPAIGN_MATRIX_LIVE_SOURCE_QUEUE_LIMIT="$QUEUE_LIMIT" \
		python3 -m tools.dns_diff.cli campaign-matrix \
			--matrix-file "$matrix_file" \
			--budget-sec "$BUDGET_SEC" \
			--repeat "$REPEAT_COUNT" \
			--work-root "$work_root"; then
		printf '%s\tpass\t%s\t%s\n' "$normalized_resolver" "$work_root" "$matrix_file" >>"$STATUS_TSV"
		SUCCESSFUL_ROOTS+=("$work_root")
	else
		printf '%s\tfail\t%s\t%s\n' "$normalized_resolver" "$work_root" "$matrix_file" >>"$STATUS_TSV"
	fi
}

for resolver in $RESOLVERS; do
	run_matrix "$resolver"
done

if [ "${#SUCCESSFUL_ROOTS[@]}" -eq 0 ]; then
	printf 'ASSERT FAIL: 没有任何 resolver matrix 成功落盘\n' >&2
	exit 1
fi

AGGREGATE_ARGS=()
for work_root in "${SUCCESSFUL_ROOTS[@]}"; do
	AGGREGATE_ARGS+=(--matrix-root "$work_root")
done

python3 -m tools.dns_diff.cli resolver-matrix-aggregate \
	"${AGGREGATE_ARGS[@]}" \
	--output-dir "$BASE_DIR/_resolver_summary"

printf '%s\n' "$BASE_DIR"
