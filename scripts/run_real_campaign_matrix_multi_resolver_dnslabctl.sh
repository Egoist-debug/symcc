#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
BASE_DIR="$ROOT_DIR/experiments/results/real_campaign_matrix_batch_dnslabctl/$STAMP"
mkdir -p "$BASE_DIR"

STATUS_TSV="$BASE_DIR/matrix_run_status.tsv"
SUCCESSFUL_ROOTS=()
REPEAT_COUNT="${REPEAT_COUNT:-2}"
BUDGET_SEC="${BUDGET_SEC:-5}"

cat >"$STATUS_TSV" <<'EOF'
resolver	status	work_root	matrix_file
EOF

prepare_work_root() {
	local work_root="$1"
	TRANSCRIPT_SOURCE_DIR="${TRANSCRIPT_SOURCE_DIR:-}" \
	QUEUE_LIMIT="${QUEUE_LIMIT:-0}" \
	python3 - "$work_root" <<'PY'
from pathlib import Path
import json
import os
import shutil
import sys

root = Path(sys.argv[1])
queue_dir = root / "afl_out" / "master" / "queue"
queue_dir.mkdir(parents=True, exist_ok=True)

transcript_source_raw = os.environ.get("TRANSCRIPT_SOURCE_DIR", "").strip()
transcript_source_dir = (
    Path(transcript_source_raw).expanduser() if transcript_source_raw else None
)
queue_limit = int(os.environ.get("QUEUE_LIMIT", "0"))
copied = 0

if transcript_source_dir is not None and transcript_source_dir.is_dir():
    source_files = sorted(path for path in transcript_source_dir.iterdir() if path.is_file())
    if queue_limit > 0:
        source_files = source_files[:queue_limit]
    for index, source_file in enumerate(source_files, start=1):
        target = queue_dir / f"id:{index:06d},orig:{source_file.name}"
        shutil.copyfile(source_file, target)
    copied = len(source_files)

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

seed = {
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
    "recorded_at": "2026-05-14T07:20:00Z",
}
(root / "producer_seed_provenance.json").write_text(
    json.dumps(seed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
print(f"prepared {copied} queue seeds under {queue_dir}")
PY
}

run_matrix() {
	local resolver="$1"
	local matrix_file="$2"
	local work_root="$BASE_DIR/$resolver"
	local secondary_build=""
	local secondary_src=""

	case "$resolver" in
		unbound)
			secondary_build="$ROOT_DIR/experiments/subjects/unbound/release-1.24.2-build/unbound-afl"
			secondary_src="$ROOT_DIR/experiments/subjects/unbound/release-1.24.2"
			;;
		dnsmasq)
			secondary_build="$ROOT_DIR/experiments/subjects/dnsmasq/v2.92-build"
			secondary_src="$ROOT_DIR/experiments/subjects/dnsmasq/v2.92"
			;;
		smartdns)
			secondary_build="$ROOT_DIR/experiments/subjects/smartdns/Release47.1-build"
			secondary_src="$ROOT_DIR/experiments/subjects/smartdns/Release47.1"
			;;
		maradns)
			secondary_build="$ROOT_DIR/experiments/subjects/maradns/deadwood-3.3.02-build"
			secondary_src="$ROOT_DIR/experiments/subjects/maradns/deadwood-3.3.02"
			;;
		knot)
			secondary_build="$ROOT_DIR/experiments/subjects/knot-resolver/v6.2.0-build"
			secondary_src="$ROOT_DIR/experiments/subjects/knot-resolver/v6.2.0"
			;;
		*)
			printf 'ASSERT FAIL: 未知 resolver %s\n' "$resolver" >&2
			exit 1
			;;
	esac

	prepare_work_root "$work_root"
	if env \
		ROOT_DIR="$ROOT_DIR" \
		DNS_DIFF_REPLAY_BACKEND=dnslabctl \
		BIND9_AFL_TREE="$ROOT_DIR/experiments/subjects/bind9/v9.20.22-build/bind9-afl" \
		BIND9_SRC_TREE="$ROOT_DIR/experiments/subjects/bind9/v9.20.22" \
		BIND9_NAMED_CONF_TEMPLATE="$ROOT_DIR/named_experiment/runtime/named.conf" \
		RESPONSE_CORPUS_DIR="$ROOT_DIR/named_experiment/work/response_corpus" \
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
		python3 -m tools.dns_diff.cli campaign-matrix \
			--matrix-file "$matrix_file" \
			--budget-sec "$BUDGET_SEC" \
			--repeat "$REPEAT_COUNT" \
			--work-root "$work_root"; then
		printf '%s\tpass\t%s\t%s\n' "$resolver" "$work_root" "$matrix_file" >>"$STATUS_TSV"
		SUCCESSFUL_ROOTS+=("$work_root")
	else
		printf '%s\tfail\t%s\t%s\n' "$resolver" "$work_root" "$matrix_file" >>"$STATUS_TSV"
	fi
}

run_matrix "unbound" "$ROOT_DIR/tools/dns_diff/config/poison_stateful_longbudget_matrix.json"
run_matrix "dnsmasq" "$ROOT_DIR/tools/dns_diff/config/poison_stateful_dnsmasq_matrix.json"
run_matrix "smartdns" "$ROOT_DIR/tools/dns_diff/config/poison_stateful_smartdns_matrix.json"
run_matrix "maradns" "$ROOT_DIR/tools/dns_diff/config/poison_stateful_maradns_matrix.json"
run_matrix "knot" "$ROOT_DIR/tools/dns_diff/config/poison_stateful_knot_matrix.json"

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

printf 'PASS: real multi-resolver dnslabctl backend campaign matrix generated at %s\n' "$BASE_DIR"
