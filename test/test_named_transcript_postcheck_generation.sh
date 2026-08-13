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
		printf '用法: %s [--case happy|empty-postcheck]\n' "$0" >&2
		exit 1
	fi
fi

case "$CASE" in
	happy|empty-postcheck)
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

# 现行 DST1 契约：10-byte header + 显式 post-check，reserved byte 不是版本字段。
required_snippets = [
    "header_len = 10 + transcript->response_count * 2",
    "transcript->post_check_query_len = read_u16le(input + 8)",
    "transcript->post_check_query = input + cursor",
]
for snippet in required_snippets:
    if snippet not in source:
        raise SystemExit(f"ASSERT FAIL: orchestrator 缺少显式 post-check 解析片段: {snippet}")

# v2 迁移曾把 reserved byte 当版本字段并要求 ==2，且删除 wire post-check，
# 与 producer 的 10-byte 显式 post-check 格式脱节，必须回归拒绝。
for forbidden in ("NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION",):
    if forbidden in source:
        raise SystemExit(f"ASSERT FAIL: orchestrator 仍残留 v2 版本字段校验: {forbidden}")

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
    extract_define("NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_MAX_RESPONSES"),
])

transcript_struct = extract_block(
    "typedef struct named_resolver_afl_symcc_transcript {",
    "} named_resolver_afl_symcc_transcript_t;",
)

functions = "\n\n".join([
    extract_function("static uint16_t\nread_u16le"),
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

static void print_hex_bytes(const uint8_t *bytes, size_t len) {{
    for (size_t index = 0; index < len; ++index) {{
        printf("%02x", bytes[index]);
    }}
}}

static void test_happy(void) {{
    static const uint8_t transcript_bytes[] = {{
        'D', 'S', 'T', '1',
        1,
        0,
        0x06, 0x00,
        0x03, 0x00,
        0x02, 0x00,
        0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd,
        0x56, 0x78,
        0x9a, 0xbc, 0x01,
    }};
    static const uint8_t expected_client_query[] = {{0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd}};
    static const uint8_t expected_response[] = {{0x56, 0x78}};
    static const uint8_t expected_post_check[] = {{0x9a, 0xbc, 0x01}};
    named_resolver_afl_symcc_transcript_t transcript;

    require_true(parse_transcript_input(transcript_bytes, sizeof(transcript_bytes), &transcript),
                 "happy transcript 应被成功解析");
    require_true(transcript.response_count == 1, "response_count 应为 1");
    require_true(transcript.client_query_len == sizeof(expected_client_query),
                 "client_query 长度错误");
    require_true(memcmp(transcript.client_query, expected_client_query, sizeof(expected_client_query)) == 0,
                 "client_query 字节错误");
    require_true(transcript.response_lens[0] == sizeof(expected_response),
                 "第一个 response 长度错误");
    require_true(memcmp(transcript.responses[0], expected_response, sizeof(expected_response)) == 0,
                 "第一个 response 字节错误");
    require_true(transcript.post_check_query_len == sizeof(expected_post_check),
                 "post_check_query 长度错误");
    require_true(transcript.post_check_query != NULL, "post_check_query 不应为 NULL");
    require_true(memcmp(transcript.post_check_query, expected_post_check, sizeof(expected_post_check)) == 0,
                 "post_check_query 字节错误");
    printf("EVIDENCE_T2 case=happy response_count=%u client_query_len=%zu post_check_len=%zu client_query_hex=",
           (unsigned)transcript.response_count,
           transcript.client_query_len,
           transcript.post_check_query_len);
    print_hex_bytes(transcript.client_query, transcript.client_query_len);
    printf(" post_check_hex=");
    print_hex_bytes(transcript.post_check_query, transcript.post_check_query_len);
    putchar('\\n');
    puts("PASS: happy path 显式 post-check 解析通过");
}}

static void test_empty_postcheck(void) {{
    static const uint8_t transcript_bytes[] = {{
        'D', 'S', 'T', '1',
        1,
        0,
        0x02, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0xaa, 0xbb,
        0xcc,
    }};
    named_resolver_afl_symcc_transcript_t transcript;

    require_true(parse_transcript_input(transcript_bytes, sizeof(transcript_bytes), &transcript),
                 "empty-postcheck transcript 结构上应可解析");
    require_true(transcript.response_count == 1, "response_count 应为 1");
    require_true(transcript.client_query_len == 2, "client_query 长度应为 2");
    require_true(transcript.post_check_query_len == 0, "post_check_query 长度应为 0");
    require_true(transcript.post_check_query == NULL, "空 post-check 时 post_check_query 应为 NULL");
    require_true(transcript.response_lens[0] == 1, "第一个 response 长度错误");
    printf("EVIDENCE_T2 case=empty-postcheck client_query_len=%zu post_check_len=%zu\\n",
           transcript.client_query_len, transcript.post_check_query_len);
    puts("PASS: empty-postcheck 被安全解析为无 post-check");
}}

int main(int argc, char **argv) {{
    if (argc != 2) {{
        fprintf(stderr, "用法: %s <happy|empty-postcheck>\\n", argv[0]);
        return 1;
    }}
    if (strcmp(argv[1], "happy") == 0) {{
        test_happy();
        return 0;
    }}
    if (strcmp(argv[1], "empty-postcheck") == 0) {{
        test_empty_postcheck();
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

assert_file_contains "$SOURCE_FILE" "header_len = 10 + transcript->response_count * 2"
assert_file_contains "$SOURCE_FILE" "transcript->post_check_query_len = read_u16le(input + 8)"
assert_file_not_contains "$SOURCE_FILE" "NAMED_RESOLVER_AFL_SYMCC_TRANSCRIPT_VERSION"

printf 'PASS: named transcript explicit post-check format regression test passed (%s)\n' "$CASE"
