#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FILE="$ROOT_DIR/patch/cache/bind9/bin/named/resolver_afl_symcc_orchestrator.c"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-postcheck.XXXXXX")"
CASE="happy"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		exit 1
	fi
}

assert_file_not_contains() {
	local path="$1"
	local unexpected="$2"
	if grep -Fq -- "$unexpected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 不包含: %s\n' "$path" "$unexpected" >&2
		exit 1
	fi
}

if [ "$#" -gt 0 ]; then
	if [ "$#" -eq 2 ] && [ "$1" = "--case" ]; then
		CASE="$2"
	else
		printf '用法: %s [--case happy|short-query]\n' "$0" >&2
		exit 1
	fi
fi

case "$CASE" in
	happy|short-query)
		;;
	*)
		printf '不支持的 case: %s\n' "$CASE" >&2
		exit 1
		;;
esac

python3 - "$SOURCE_FILE" "$WORKDIR/harness.c" <<'PY'
import pathlib
import re
import sys

source_path = pathlib.Path(sys.argv[1])
harness_path = pathlib.Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")

required_snippets = [
    "NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION 2",
    "build_second_query_from_client_query",
    "if (transcript.client_query_len < 2)",
    "result = execute_legacy_request(orchestrator, second_query,",
    "input[5] != NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION",
]
for snippet in required_snippets:
    if snippet not in source:
        raise SystemExit(f"ASSERT FAIL: orchestrator 缺少关键片段: {snippet}")

for forbidden in ("post_check_query_len", "post_check_query"):
    if forbidden in source:
        raise SystemExit(f"ASSERT FAIL: orchestrator 仍残留旧字段: {forbidden}")

def extract_define(name: str) -> str:
    pattern = re.compile(rf"^#define\s+{re.escape(name)}\s+.+$", re.MULTILINE)
    match = pattern.search(source)
    if match is None:
        raise SystemExit(f"ASSERT FAIL: 缺少宏 {name}")
    return match.group(0)

def extract_block(start_marker: str, end_marker: str) -> str:
    start = source.find(start_marker)
    if start == -1:
        raise SystemExit(f"ASSERT FAIL: 缺少块起点 {start_marker}")
    end = source.find(end_marker, start)
    if end == -1:
        raise SystemExit(f"ASSERT FAIL: 缺少块终点 {end_marker}")
    end += len(end_marker)
    return source[start:end]

def extract_function(signature: str) -> str:
    start = source.find(signature)
    if start == -1:
        raise SystemExit(f"ASSERT FAIL: 缺少函数签名 {signature}")
    brace_start = source.find("{", start)
    if brace_start == -1:
        raise SystemExit(f"ASSERT FAIL: 函数 {signature} 缺少函数体")
    depth = 1
    index = brace_start + 1
    while index < len(source) and depth > 0:
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    if depth != 0:
        raise SystemExit(f"ASSERT FAIL: 函数 {signature} 大括号不匹配")
    return source[start:index]

defines = "\n".join([
    extract_define("NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAGIC"),
    extract_define("NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION"),
    extract_define("NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES"),
])

transcript_struct = extract_block(
    "typedef struct named_resolver_afl_symcc_transcript {",
    "} named_resolver_afl_symcc_transcript_t;",
)

functions = "\n\n".join([
    extract_function("static uint16_t\nread_u16le"),
    extract_function("static bool\nbuild_second_query_from_client_query"),
    extract_function("static bool\nlooks_like_transcript"),
    extract_function("static bool\nparse_transcript_input"),
])

harness = f'''#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{defines}

{transcript_struct}

{functions}

static void require_true(bool value, const char *message) {{
    if (!value) {{
        fprintf(stderr, "ASSERT FAIL: %s\\n", message);
        exit(1);
    }}
}}

static uint16_t read_u16be(const uint8_t *buffer) {{
    return (uint16_t)(((uint16_t)buffer[0] << 8) | (uint16_t)buffer[1]);
}}

static void print_hex_bytes(const uint8_t *bytes, size_t len) {{
    for (size_t index = 0; index < len; ++index) {{
        printf("%02x", bytes[index]);
    }}
}}

static void test_happy(void) {{
    static const uint8_t transcript_bytes[] = {{
        'D', 'S', 'T', '1',
        2,
        NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION,
        0x06, 0x00,
        0x03, 0x00,
        0x02, 0x00,
        0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd,
        0x01, 0x02, 0x03,
        0x04, 0x05,
    }};
    static const uint8_t expected_second_query[] = {{0x13, 0x35, 0xaa, 0xbb, 0xcc, 0xdd}};
    named_resolver_afl_symcc_transcript_t transcript;
    uint8_t second_query[sizeof(expected_second_query)];

    require_true(parse_transcript_input(transcript_bytes, sizeof(transcript_bytes), &transcript),
                 "happy transcript 应被成功解析");
    require_true(transcript.response_count == 2, "response_count 应为 2");
    require_true(transcript.client_query_len == sizeof(expected_second_query), "client_query 长度错误");
    require_true(transcript.response_lens[0] == 3, "第一个 response 长度错误");
    require_true(transcript.response_lens[1] == 2, "第二个 response 长度错误");
    require_true(memcmp(transcript.client_query, expected_second_query, 2) != 0,
                 "second query 必须修改 TxID");
    require_true(build_second_query_from_client_query(transcript.client_query, transcript.client_query_len, second_query),
                 "happy transcript 必须能生成 second query");
    require_true(memcmp(second_query, expected_second_query, sizeof(expected_second_query)) == 0,
                 "second query 字节结果不符合 +0x0101 语义");
    require_true(memcmp(second_query + 2, transcript.client_query + 2, transcript.client_query_len - 2) == 0,
                 "TxID 以外的 query 字节必须保持不变");
    printf("EVIDENCE_T2 case=happy txid_delta=0x0101 original_txid=0x%04x derived_txid=0x%04x client_query_hex=",
           (unsigned)read_u16be(transcript.client_query),
           (unsigned)read_u16be(second_query));
    print_hex_bytes(transcript.client_query, transcript.client_query_len);
    printf(" second_query_hex=");
    print_hex_bytes(second_query, sizeof(expected_second_query));
    printf(" response_count=%u response_lens=%u,%u\\n",
           (unsigned)transcript.response_count,
           (unsigned)transcript.response_lens[0],
           (unsigned)transcript.response_lens[1]);
    puts("PASS: happy path 自动生成 second query 通过");
}}

static void test_short_query(void) {{
    static const uint8_t transcript_bytes[] = {{
        'D', 'S', 'T', '1',
        0,
        NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION,
        0x01, 0x00,
        0x7a,
    }};
    named_resolver_afl_symcc_transcript_t transcript;
    uint8_t second_query[1] = {{0}};

    require_true(parse_transcript_input(transcript_bytes, sizeof(transcript_bytes), &transcript),
                 "short-query transcript 结构上应可解析");
    require_true(transcript.client_query_len == 1, "short-query 长度应为 1");
    require_true(!build_second_query_from_client_query(transcript.client_query, transcript.client_query_len, second_query),
                 "short-query 必须被 second query helper 拒绝");
    printf("EVIDENCE_T2 case=short-query client_query_len=%u helper_result=rejected client_query_hex=",
           (unsigned)transcript.client_query_len);
    print_hex_bytes(transcript.client_query, transcript.client_query_len);
    putchar('\\n');
    puts("PASS: short-query 被安全拒绝");
}}

int main(int argc, char **argv) {{
    if (argc != 2) {{
        fprintf(stderr, "用法: %s <happy|short-query>\\n", argv[0]);
        return 1;
    }}
    if (strcmp(argv[1], "happy") == 0) {{
        test_happy();
        return 0;
    }}
    if (strcmp(argv[1], "short-query") == 0) {{
        test_short_query();
        return 0;
    }}
    fprintf(stderr, "未知 case: %s\\n", argv[1]);
    return 1;
}}
'''

harness_path.write_text(harness, encoding="utf-8")
PY

cc -std=c11 -Wall -Wextra -Werror "$WORKDIR/harness.c" -o "$WORKDIR/harness"

"$WORKDIR/harness" "$CASE"

assert_file_contains "$SOURCE_FILE" "NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION 2"
assert_file_contains "$SOURCE_FILE" "build_second_query_from_client_query"
assert_file_contains "$SOURCE_FILE" "result = execute_legacy_request(orchestrator, second_query,"
assert_file_not_contains "$SOURCE_FILE" "post_check_query_len"
assert_file_not_contains "$SOURCE_FILE" "post_check_query"

printf 'PASS: named transcript postcheck generation regression test passed (%s)\n' "$CASE"
