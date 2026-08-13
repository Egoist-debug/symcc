#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/real_experiment_paths.sh"

STAMP="${STAMP:-$(date -u +%Y%m%d_%H%M%S)}"
RESULT_ROOT_BASE="${RESULT_ROOT_BASE:-$ROOT_DIR/experiments/results/real_resolver_replay_matrix}"
OUT_DIR="$RESULT_ROOT_BASE/$STAMP"
LOG_DIR="$OUT_DIR/logs"
TSV_PATH="$OUT_DIR/matrix.tsv"
MANIFEST_PATH="$OUT_DIR/manifest.json"
DNSLABCTL_BIN="${DNSLABCTL_BIN:-$ROOT_DIR/build/linux/x86_64/release/dnslabctl}"

mkdir -p "$LOG_DIR"

run_check() {
	local resolver="$1"
	local capability="$2"
	local command_type="$3"
	local value="$4"
	local log_path="$LOG_DIR/${resolver}_${capability}.log"
	local started_at
	started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

	if [ "$command_type" = "script" ]; then
		if bash "$ROOT_DIR/$value" >"$log_path" 2>&1; then
			printf '%s\t%s\tpass\t%s\t%s\t%s\n' \
				"$resolver" "$capability" "$started_at" \
				"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$value" >>"$TSV_PATH"
			return 0
		fi
	else
		if eval "$value" >"$log_path" 2>&1; then
			printf '%s\t%s\tpass\t%s\t%s\t%s\n' \
				"$resolver" "$capability" "$started_at" \
				"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$value" >>"$TSV_PATH"
			return 0
		fi
	fi

	tail -n 20 "$log_path" >&2 || true
	printf '%s\t%s\tfail\t%s\t%s\t%s\n' \
		"$resolver" "$capability" "$started_at" \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$value" >>"$TSV_PATH"
	return 1
}

build_command_for() {
	local resolver
	local normalized
	local source_root
	local build_root

	normalized="$(resolver_normalize_name "$1")"
	source_root="$(resolver_src_root "$normalized")"
	# adapter-build 的 --build-root 是构建根：unbound 适配器在其下
	# 挂 unbound-afl/ 目标树（与 unbound_afl_tree() 一致）。传
	# unbound_afl_tree() 会导致 unbound-afl/unbound-afl 双重嵌套，
	# 产物路径与 registry/tests 期望不符。
	if [ "$normalized" = "unbound" ]; then
		build_root="$(resolver_build_root "$normalized")"
	else
		build_root="$(resolver_build_root "$normalized")"
	fi
	printf '%q ' "$DNSLABCTL_BIN" adapter-build --resolver "$normalized" --source-root "$source_root" --build-root "$build_root"
	printf '\n'
}

cat >"$TSV_PATH" <<'EOF'
resolver	capability	status	started_at	finished_at	script
EOF

run_check "unbound" "build_real" "eval" "$(build_command_for unbound)"
run_check "unbound" "replay_real" "script" "test/test_dns_diff_replay_unbound_smoke.sh"
run_check "dnsmasq" "build_real" "eval" "$(build_command_for dnsmasq)"
run_check "dnsmasq" "replay_real" "script" "test/test_dnslabctl_dnsmasq_replay_smoke.sh"
run_check "smartdns" "build_real" "eval" "$(build_command_for smartdns)"
run_check "smartdns" "replay_real" "script" "test/test_dnslabctl_smartdns_replay_smoke.sh"
run_check "maradns" "build_real" "eval" "$(build_command_for maradns)"
run_check "maradns" "replay_real" "script" "test/test_dnslabctl_maradns_replay_smoke.sh"
run_check "knot-resolver" "build_real" "eval" "$(build_command_for knot-resolver)"
run_check "knot-resolver" "replay_real" "script" "test/test_dnslabctl_knot_resolver_replay_smoke.sh"
run_check "knot-resolver" "sync_secondary_real" "script" "test/test_dnslabctl_sync_replay_secondary_knot.sh"

python3 - "$TSV_PATH" "$MANIFEST_PATH" "$OUT_DIR" <<'PY'
import csv
import json
import pathlib
import sys

tsv_path = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
out_dir = pathlib.Path(sys.argv[3])
rows = list(csv.DictReader(tsv_path.open(encoding="utf-8"), delimiter="\t"))
payload = {
    "generated_at": rows[0]["started_at"] if rows else None,
    "output_dir": str(out_dir),
    "record_count": len(rows),
    "all_passed": all(row["status"] == "pass" for row in rows),
    "rows": rows,
}
manifest_path.write_text(
    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
PY

printf '%s\n' "$OUT_DIR"
