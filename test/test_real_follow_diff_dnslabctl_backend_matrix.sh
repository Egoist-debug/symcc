#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 默认路径使用本仓库 subjects 布局（可 env 覆盖）；RUN_ROOT_BASE 默认系统临时目录。
RUN_ROOT_BASE="${REAL_FOLLOW_DIFF_RUN_ROOT_BASE:-${TMPDIR:-/tmp}}"
UNBOUND_AFL_TREE="${UNBOUND_AFL_TREE_OVERRIDE:-$ROOT_DIR/experiments/subjects/unbound/release-1.24.2-build}"
UNBOUND_SRC_TREE="${UNBOUND_SRC_TREE_OVERRIDE:-$ROOT_DIR/experiments/subjects/unbound/release-1.24.2}"
BIND9_AFL_TREE="${BIND9_AFL_TREE_OVERRIDE:-$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl}"
BIND9_SRC_TREE="${BIND9_SRC_TREE_OVERRIDE:-$ROOT_DIR/experiments/subjects/bind9/v9.20.22}"
RESPONSE_CORPUS_DIR="${RESPONSE_CORPUS_DIR_OVERRIDE:-$ROOT_DIR/named_experiment/work/response_corpus}"
WORKDIR="$(mktemp -d "$RUN_ROOT_BASE/follow-diff-dnslabctl-real.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export SEED_TIMEOUT_SEC="${SEED_TIMEOUT_SEC:-15}"

cleanup() {
	if [ "${KEEP_WORKDIR:-0}" = "1" ]; then
		return
	fi
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

RESULT_TSV="$WORKDIR/result.tsv"
cat >"$RESULT_TSV" <<'EOF'
resolver	meta_status	triage_status
EOF

write_sample() {
	local path="$1"
	python3 - "$path" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
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
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(wire)
PY
}

assert_file_exists() {
	local path="$1"
	if [ ! -f "$path" ]; then
		printf 'ASSERT FAIL: 缺少文件 %s\n' "$path" >&2
		exit 1
	fi
}

run_probe() {
	local resolver="$1"
	local work_root="$WORKDIR/$resolver"
	local queue_dir="$work_root/bind9-work/afl_out/master/queue"
	local work_dir="$work_root/work"
	local sample_file="$queue_dir/id:000001,orig:real-seed"
	local secondary_build=""
	local secondary_src=""

	mkdir -p "$queue_dir"
	write_sample "$sample_file"

	case "$resolver" in
		unbound)
			secondary_build="$UNBOUND_AFL_TREE"
			secondary_src="$UNBOUND_SRC_TREE"
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
		knot-resolver)
			secondary_build="$ROOT_DIR/experiments/subjects/knot-resolver/v6.2.0-build"
			secondary_src="$ROOT_DIR/experiments/subjects/knot-resolver/v6.2.0"
			;;
		*)
			printf 'ASSERT FAIL: 未知 resolver %s\n' "$resolver" >&2
			exit 1
			;;
	esac

	env \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
		ROOT_DIR="$ROOT_DIR" \
		WORK_DIR="$work_dir" \
		BIND9_WORK_DIR="$work_root/bind9-work" \
		DNS_DIFF_SECONDARY_RESOLVER="$resolver" \
		DNS_DIFF_REPLAY_BACKEND=dnslabctl \
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
		python3 -m tools.dns_diff.cli follow-diff-once >/dev/null

	local sample_dir
	sample_dir="$(find "$work_dir/follow_diff" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
	assert_file_exists "$sample_dir/sample.meta.json"
	assert_file_exists "$sample_dir/oracle.json"
	assert_file_exists "$sample_dir/cache_diff.json"
	assert_file_exists "$sample_dir/triage.json"

	local meta_status
	local triage_status
	meta_status="$(python3 - "$sample_dir/sample.meta.json" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(payload.get('status', ''))
PY
)"
	triage_status="$(python3 - "$sample_dir/triage.json" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
print(payload.get('status', ''))
PY
)"

	if [ "$meta_status" != "completed" ]; then
		printf 'ASSERT FAIL: resolver=%s meta_status=%s\n' "$resolver" "$meta_status" >&2
		exit 1
	fi
	case "$triage_status" in
		failed_*|'')
			printf 'ASSERT FAIL: resolver=%s triage_status=%s\n' "$resolver" "$triage_status" >&2
			exit 1
			;;
	esac

	printf '%s\t%s\t%s\n' "$resolver" "$meta_status" "$triage_status" >>"$RESULT_TSV"
}

run_probe unbound
run_probe dnsmasq
run_probe smartdns
run_probe maradns
run_probe knot-resolver

printf 'PASS: real follow diff dnslabctl backend matrix passed (%s)\n' "$RESULT_TSV"
