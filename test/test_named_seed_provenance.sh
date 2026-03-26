#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMED_WRAPPER="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-seed-provenance.XXXXXX")"
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

assert_seed_provenance_payload() {
	local path="$1"
	local expected_cold_start="$2"
	local expected_source_dir="$3"
	local expected_stable_input_dir="$4"
	local expected_method="$5"
	python3 - "$path" "$expected_cold_start" "$expected_source_dir" "$expected_stable_input_dir" "$expected_method" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_cold_start = sys.argv[2] == "true"
expected_source_dir = pathlib.Path(sys.argv[3]).resolve()
expected_stable_input_dir = pathlib.Path(sys.argv[4]).resolve()
expected_method = sys.argv[5]

payload = json.loads(path.read_text(encoding="utf-8"))
required_fields = {
    "cold_start",
    "seed_source_dir",
    "seed_materialization_method",
    "seed_snapshot_id",
    "regen_seeds",
    "refilter_queries",
    "stable_input_dir",
    "recorded_at",
}
missing = required_fields - set(payload.keys())
if missing:
    raise SystemExit(f"ASSERT FAIL: seed provenance 缺少字段 {sorted(missing)!r}")

if payload.get("cold_start") is not expected_cold_start:
    raise SystemExit(
        f"ASSERT FAIL: cold_start={payload.get('cold_start')!r} != {expected_cold_start!r}"
    )
if pathlib.Path(payload.get("seed_source_dir", "")).resolve() != expected_source_dir:
    raise SystemExit(
        "ASSERT FAIL: seed_source_dir="
        f"{payload.get('seed_source_dir')!r} != {str(expected_source_dir)!r}"
    )
if pathlib.Path(payload.get("stable_input_dir", "")).resolve() != expected_stable_input_dir:
    raise SystemExit(
        "ASSERT FAIL: stable_input_dir="
        f"{payload.get('stable_input_dir')!r} != {str(expected_stable_input_dir)!r}"
    )
if payload.get("seed_materialization_method") != expected_method:
    raise SystemExit(
        "ASSERT FAIL: seed_materialization_method="
        f"{payload.get('seed_materialization_method')!r} != {expected_method!r}"
    )
if payload.get("regen_seeds") is not False:
    raise SystemExit("ASSERT FAIL: regen_seeds 应为 false")
if payload.get("refilter_queries") is not False:
    raise SystemExit("ASSERT FAIL: refilter_queries 应为 false")
snapshot_id = payload.get("seed_snapshot_id")
if not isinstance(snapshot_id, str) or len(snapshot_id) != 40:
    raise SystemExit(f"ASSERT FAIL: seed_snapshot_id 非法: {snapshot_id!r}")
recorded_at = payload.get("recorded_at")
if not isinstance(recorded_at, str) or not recorded_at:
    raise SystemExit(f"ASSERT FAIL: recorded_at 非法: {recorded_at!r}")
PY
}

SCENARIO_WORK="$WORKDIR/work"
STABLE_INPUT_DIR="$SCENARIO_WORK/stable_transcript_corpus"
SOURCE_DIR="$SCENARIO_WORK/transcript_corpus"
RESPONSE_DIR="$SCENARIO_WORK/response_corpus"
SIDE_CAR="$SCENARIO_WORK/producer_seed_provenance.json"
STATUS_OUT="$WORKDIR/status.txt"

mkdir -p "$STABLE_INPUT_DIR" "$SOURCE_DIR" "$RESPONSE_DIR"
printf '\x01\x02\x03\x04' >"$STABLE_INPUT_DIR/id_000000_seed"
printf '\xaa\xbb\xcc\xdd' >"$SOURCE_DIR/source-seed"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$SCENARIO_WORK" \
	FUZZ_PROFILE=poison-stateful \
	REGEN_SEEDS=0 \
	REFILTER_QUERIES=0 \
	bash "$NAMED_WRAPPER" filter-seeds >/dev/null

assert_file_exists "$SIDE_CAR"
assert_seed_provenance_payload \
	"$SIDE_CAR" \
	false \
	"$STABLE_INPUT_DIR" \
	"$STABLE_INPUT_DIR" \
	"reused_filtered_corpus"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$SCENARIO_WORK" \
	FUZZ_PROFILE=poison-stateful \
	bash "$NAMED_WRAPPER" status >"$STATUS_OUT"

grep -Fq -- "$SIDE_CAR" "$STATUS_OUT" || {
	printf 'ASSERT FAIL: status 输出未包含 provenance sidecar 路径\n' >&2
	cat "$STATUS_OUT" >&2
	exit 1
}
grep -Fq -- 'reused_filtered_corpus' "$STATUS_OUT" || {
	printf 'ASSERT FAIL: status 输出未包含 provenance materialization method\n' >&2
	cat "$STATUS_OUT" >&2
	exit 1
}

printf 'PASS: named seed provenance regression test passed\n'
