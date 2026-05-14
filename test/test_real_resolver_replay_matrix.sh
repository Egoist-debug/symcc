#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
OUT_DIR="/home/ubuntu/tmp/real_resolver_replay_matrix/$STAMP"
mkdir -p "$OUT_DIR/logs"
TSV_PATH="$OUT_DIR/matrix.tsv"
MANIFEST_PATH="$OUT_DIR/manifest.json"

run_check() {
	local resolver="$1"
	local capability="$2"
	local script_path="$3"
	local log_path="$OUT_DIR/logs/${resolver}_${capability}.log"
	local started_at
	started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	if bash "$ROOT_DIR/$script_path" >"$log_path" 2>&1; then
		printf '%s\t%s\tpass\t%s\t%s\t%s\n' \
			"$resolver" "$capability" "$started_at" \
			"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$script_path" >>"$TSV_PATH"
	else
		tail -n 20 "$log_path" >&2 || true
		printf '%s\t%s\tfail\t%s\t%s\t%s\n' \
			"$resolver" "$capability" "$started_at" \
			"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$script_path" >>"$TSV_PATH"
		return 1
	fi
}

cat >"$TSV_PATH" <<'EOF'
resolver	capability	status	started_at	finished_at	script
EOF

run_check "unbound" "replay_real" "test/test_dns_diff_replay_unbound_smoke.sh"
run_check "unbound" "build_real" "test/test_dnslabctl_unbound_build_smoke.sh"
run_check "dnsmasq" "build_real" "test/test_dnslabctl_dnsmasq_build_smoke.sh"
run_check "dnsmasq" "replay_real" "test/test_dnslabctl_dnsmasq_replay_smoke.sh"
run_check "smartdns" "build_real" "test/test_dnslabctl_smartdns_build_smoke.sh"
run_check "smartdns" "replay_real" "test/test_dnslabctl_smartdns_replay_smoke.sh"
run_check "maradns" "build_real" "test/test_dnslabctl_maradns_build_smoke.sh"
run_check "maradns" "replay_real" "test/test_dnslabctl_maradns_replay_smoke.sh"
run_check "knot-resolver" "build_real" "test/test_dnslabctl_knot_resolver_build_smoke.sh"
run_check "knot-resolver" "replay_real" "test/test_dnslabctl_knot_resolver_replay_smoke.sh"
run_check "knot-resolver" "sync_secondary_real" "test/test_dnslabctl_sync_replay_secondary_knot.sh"

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

printf 'PASS: real resolver replay matrix generated at %s\n' "$OUT_DIR"
