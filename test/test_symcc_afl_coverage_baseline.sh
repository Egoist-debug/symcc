#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_helper_bin() {
	python3 - "$ROOT_DIR" <<'PY'
import pathlib
import os
import sys

root = pathlib.Path(sys.argv[1])
candidates = [
    root / "build/linux/x86_64/release/symcc_fuzzing_helper",
    root / "util/symcc_fuzzing_cpp/build/linux/x86_64/release/symcc_fuzzing_helper",
]
existing = [path for path in candidates if path.is_file() and path.stat().st_mode & 0o111]
if not existing:
    raise SystemExit(1)
print(max(existing, key=lambda path: path.stat().st_mtime))
PY
}

ensure_helper_bin() {
	xmake f -P "$ROOT_DIR/util/symcc_fuzzing_cpp" -m release >/dev/null
	xmake b -P "$ROOT_DIR/util/symcc_fuzzing_cpp" symcc_fuzzing_helper >/dev/null
	local helper_bin=""
	helper_bin="$(resolve_helper_bin || true)"
	if [ -z "$helper_bin" ]; then
		printf 'ASSERT FAIL: 未找到 symcc_fuzzing_helper\n' >&2
		exit 1
	fi
	printf '%s\n' "$helper_bin"
}

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含 %s\n' "$path" "$expected" >&2
		cat "$path" >&2
		exit 1
	fi
}

assert_no_symcc_feedback() {
	local queue_dir="$1"
	if find "$queue_dir" -maxdepth 1 -type f -name '*,symcc' -print -quit | grep -q .; then
		printf 'ASSERT FAIL: AFL 已知覆盖不应作为 SymCC 新覆盖回流\n' >&2
		find "$queue_dir" -maxdepth 1 -type f -print >&2
		exit 1
	fi
}

write_fixture_tools() {
	local bin_dir="$1"
	mkdir -p "$bin_dir"

	cat >"$bin_dir/afl-fuzz" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
	cat >"$bin_dir/afl-showmap" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
bitmap_out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "-o" ]; then
		bitmap_out="$2"
		shift 2
		continue
	fi
	last="$1"
	shift
done
printf '%s\n' "$last" >>"$SHOWMAP_LOG"
python3 - "$bitmap_out" "$last" <<'PY'
import os
import pathlib
import sys

bitmap_path = pathlib.Path(sys.argv[1])
testcase_path = pathlib.Path(sys.argv[2])
data = testcase_path.read_bytes()
response_tail_path = os.environ.get("TEST_RESPONSE_TAIL", "")
if response_tail_path:
    data = pathlib.Path(response_tail_path).read_bytes()
bitmap = bytearray(64)
bitmap[sum(data) % len(bitmap)] = 1
bitmap_path.write_bytes(bitmap)
PY
EOF
	cat >"$bin_dir/symcc-target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${LD_LIBRARY_PATH-}" >"$LD_PATH_LOG"
mkdir -p "$SYMCC_OUTPUT_DIR/not-a-testcase"
if [ "${OUTPUT_INVALID_DST1:-0}" = "1" ]; then
	printf 'not-a-dst1-transcript\n' >"$SYMCC_OUTPUT_DIR/id:000001"
elif [ "${OUTPUT_FROM_RESPONSE_TAIL:-0}" = "1" ]; then
	cp "$TEST_RESPONSE_TAIL" "$SYMCC_OUTPUT_DIR/id:000001"
elif [ "${ADD_RUNTIME_QUEUE:-0}" = "1" ]; then
	printf 'new\n' >"$AFL_QUEUE_DIR/id:000002,src:000001,+cov"
	printf 'new\n' >"$SYMCC_OUTPUT_DIR/id:000001"
else
	cp "$1" "$SYMCC_OUTPUT_DIR/id:000001"
fi
EOF
	chmod +x "$bin_dir/afl-fuzz" "$bin_dir/afl-showmap" "$bin_dir/symcc-target"
}

write_valid_dst1() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import struct
import sys


def question(name: str, flags: int) -> bytes:
    encoded_name = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    ) + b"\0"
    return (
        struct.pack(">HHHHHH", 0x1234, flags, 1, 0, 0, 0)
        + encoded_name
        + struct.pack(">HH", 1, 1)
    )


query = question("cache.example.test", 0x0100)
response = question("cache.example.test", 0x8180)
post_check = query
transcript = (
    b"DST1"
    + bytes([1, 0])
    + struct.pack("<HHH", len(query), len(post_check), len(response))
    + query
    + response
    + post_check
)
pathlib.Path(sys.argv[1]).write_bytes(transcript)
PY
}

run_helper_poison_contract() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$3"
	local queue_dir="$work_root/afl_out/exp/master/queue"

	env \
		LD_PATH_LOG="$work_root/ld-path.log" \
		SHOWMAP_LOG="$work_root/showmap.log" \
		AFL_QUEUE_DIR="$queue_dir" \
		OUTPUT_INVALID_DST1=1 \
		timeout -k 1 2 "$helper_bin" \
			-a master -o "$work_root/afl_out" -n exp -v \
			--require-poison-eligible -- \
			"$bin_dir/symcc-target" @@ >"$work_root/helper.log" 2>&1 || true
}

prepare_fixture() {
	local work_root="$1"
	local bin_dir="$2"
	local queue_dir="$work_root/afl_out/exp/master/queue"
	mkdir -p "$queue_dir"
	printf 'command_line : %s -i in -o out -- %s @@\n' \
		"$bin_dir/afl-fuzz" "$bin_dir/symcc-target" \
		>"$work_root/afl_out/exp/master/fuzzer_stats"
	printf '%s\n' "$queue_dir"
}

run_helper() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$3"
	local add_runtime_queue="$4"
	local queue_dir="$work_root/afl_out/exp/master/queue"

	env \
		LD_LIBRARY_PATH="$work_root/runtime-libs" \
		LD_PATH_LOG="$work_root/ld-path.log" \
		SHOWMAP_LOG="$work_root/showmap.log" \
		AFL_QUEUE_DIR="$queue_dir" \
		ADD_RUNTIME_QUEUE="$add_runtime_queue" \
		timeout -k 1 2 "$helper_bin" \
			-a master -o "$work_root/afl_out" -n exp -v -- \
			"$bin_dir/symcc-target" @@ >"$work_root/helper.log" 2>&1 || true
}

run_helper_with_response_tails() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$3"
	local queue_dir="$work_root/afl_out/exp/master/queue"
	local response_dir="$work_root/response-tails"

	env \
		LD_PATH_LOG="$work_root/ld-path.log" \
		SHOWMAP_LOG="$work_root/showmap.log" \
		AFL_QUEUE_DIR="$queue_dir" \
		OUTPUT_FROM_RESPONSE_TAIL=1 \
		timeout -k 1 2 "$helper_bin" \
			-a master -o "$work_root/afl_out" -n exp -v \
			-r "$response_dir" -e TEST_RESPONSE_TAIL -- \
			"$bin_dir/symcc-target" @@ >"$work_root/helper.log" 2>&1 || true
}

scenario_initial_afl_baseline() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$work_root/bin"
	local queue_dir=""

	write_fixture_tools "$bin_dir"
	queue_dir="$(prepare_fixture "$work_root" "$bin_dir")"
	printf 'new\n' >"$queue_dir/id:000001,orig:seed"
	run_helper "$helper_bin" "$work_root" "$bin_dir" 0

	assert_file_contains "$work_root/helper.log" 'Merged AFL queue coverage baseline: scanned=1 coverage_updates=1 total_scanned=1'
	assert_file_contains "$work_root/helper.log" 'Generated 1 test cases, copied 0 to AFL queue'
	assert_no_symcc_feedback "$queue_dir"
	if grep -Fq 'not-a-testcase' "$work_root/showmap.log"; then
		printf 'ASSERT FAIL: SymCC 输出目录不应作为 testcase 交给 showmap\n' >&2
		cat "$work_root/showmap.log" >&2
		exit 1
	fi
	if [ "$(cat "$work_root/ld-path.log")" != "$work_root/runtime-libs" ]; then
		printf 'ASSERT FAIL: SymCC target 未完整继承调用方 LD_LIBRARY_PATH\n' >&2
		cat "$work_root/ld-path.log" >&2
		exit 1
	fi
}

scenario_runtime_afl_queue_merge() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$work_root/bin"
	local queue_dir=""

	write_fixture_tools "$bin_dir"
	queue_dir="$(prepare_fixture "$work_root" "$bin_dir")"
	printf 'old\n' >"$queue_dir/id:000001,orig:seed"
	run_helper "$helper_bin" "$work_root" "$bin_dir" 1

	assert_file_contains "$work_root/helper.log" 'total_scanned=1'
	assert_file_contains "$work_root/helper.log" 'Merged AFL queue coverage baseline: scanned=1 coverage_updates=1 total_scanned=2'
	assert_file_contains "$work_root/helper.log" 'Generated 1 test cases, copied 0 to AFL queue'
	assert_no_symcc_feedback "$queue_dir"
}

scenario_response_tail_is_part_of_baseline_identity() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$work_root/bin"
	local queue_dir=""

	write_fixture_tools "$bin_dir"
	queue_dir="$(prepare_fixture "$work_root" "$bin_dir")"
	printf 'request-one\n' >"$queue_dir/id:000001,orig:seed"
	printf 'request-two\n' >"$queue_dir/id:000002,orig:seed"
	mkdir -p "$work_root/response-tails"
	printf 'tail-one\n' >"$work_root/response-tails/01.bin"
	printf 'tail-two\n' >"$work_root/response-tails/02.bin"

	run_helper_with_response_tails "$helper_bin" "$work_root" "$bin_dir"

	assert_file_contains "$work_root/helper.log" 'total_scanned=2 response_tail='
	assert_file_contains "$work_root/helper.log" 'total_scanned=4 response_tail='
	assert_file_contains "$work_root/helper.log" 'Generated 1 test cases, copied 0 to AFL queue'
	assert_no_symcc_feedback "$queue_dir"
}

scenario_poison_ineligible_output_rejected() {
	local helper_bin="$1"
	local work_root="$2"
	local bin_dir="$work_root/bin"
	local queue_dir=""

	write_fixture_tools "$bin_dir"
	queue_dir="$(prepare_fixture "$work_root" "$bin_dir")"
	write_valid_dst1 "$queue_dir/id:000001,orig:seed"
	run_helper_poison_contract "$helper_bin" "$work_root" "$bin_dir"

	assert_file_contains "$work_root/helper.log" \
		'Rejected poison-ineligible SymCC output'
	assert_file_contains "$work_root/helper.log" 'invalid_magic'
	assert_file_contains "$work_root/helper.log" \
		'Generated 1 test cases, copied 0 to AFL queue'
	assert_no_symcc_feedback "$queue_dir"
}

main() {
	local helper_bin=""
	local work_root=""
	helper_bin="$(ensure_helper_bin)"
	work_root="$(mktemp -d "${TMPDIR:-/tmp}/symcc-afl-baseline.XXXXXX")"
	trap 'rm -rf "${work_root:-}"' EXIT

	scenario_initial_afl_baseline "$helper_bin" "$work_root/initial"
	scenario_runtime_afl_queue_merge "$helper_bin" "$work_root/runtime"
	scenario_response_tail_is_part_of_baseline_identity "$helper_bin" "$work_root/response-tail"
	scenario_poison_ineligible_output_rejected "$helper_bin" "$work_root/poison-contract"
	printf 'PASS: SymCC AFL-relative coverage regression test passed\n'
}

main "$@"
