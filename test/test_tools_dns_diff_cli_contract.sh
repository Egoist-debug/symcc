#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRAPPER="$ROOT_DIR/unbound_experiment/run_unbound_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-tools-dns-diff-cli.XXXXXX")"
PYTHONPATH_VALUE="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
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

assert_file_contains() {
	local path="$1"
	local expected="$2"
	if ! grep -Fq -- "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 包含: %s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

assert_file_not_contains() {
	local path="$1"
	local unexpected="$2"
	if grep -Fq -- "$unexpected" "$path"; then
		printf 'ASSERT FAIL: 期望 %s 不包含: %s\n' "$path" "$unexpected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

write_fake_unbound_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import os
import pathlib
import sys

dump_path = os.environ.get("UNBOUND_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH")
if not dump_path:
    sys.stderr.write("missing dump path\\n")
    sys.exit(9)

stdin_data = sys.stdin.buffer.read()
content = "START_RRSET_CACHE\\n;rrset 300 1 0 1 0\\nexample.com. 300 IN A 1.2.3.4\\nEND_RRSET_CACHE\\nEOF\\n"
pathlib.Path(dump_path).write_text(content, encoding="utf-8")
log_path = os.environ.get("FAKE_UNBOUND_INVOCATION_LOG")
if log_path:
    pathlib.Path(log_path).write_text(
        f"stdin={len(stdin_data)} response_dir={os.environ.get('UNBOUND_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR', '_')}\\n",
        encoding="utf-8",
    )
sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
sys.exit(0)
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_dnsmasq_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_dnsmasq_harness() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--dnsmasq-stderr-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--dnsmasq-bin')
args = parser.parse_args()
Path(args.cache_dump_path).write_text(
    'May 10 05:49:01 dnsmasq[250875]: Host                           Address                                  Flags      Expires                  Source\\n'
    'May 10 05:49:01 dnsmasq[250875]: ------------------------------ ---------------------------------------- ---------- ------------------------ ------------\\n'
    'May 10 05:49:01 dnsmasq[250875]: example.com                    1.2.3.4                                  4F         Sun May 10 05:50:01 2026\\n',
    encoding='utf-8',
)
Path(args.dnsmasq_stderr_path).write_text('dnsmasq-native\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_smartdns_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_smartdns_harness() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import struct
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--smartdns-log-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--smartdns-bin')
args = parser.parse_args()
packet = (
    b'\\x56\\x78\\x81\\x80\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00'
    b'\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'
    b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x02\\x58\\x00\\x04\\x01\\x02\\x03\\x04'
)
info = bytearray(344)
info[0:len(b'example.com')] = b'example.com'
struct.pack_into('<i', info, 256, 1)
struct.pack_into('<I', info, 292, 0)
struct.pack_into('<i', info, 296, 600)
struct.pack_into('<i', info, 300, 0)
struct.pack_into('<i', info, 304, 6)
struct.pack_into('<i', info, 308, -1)
struct.pack_into('<q', info, 328, 111)
struct.pack_into('<q', info, 336, 222)
payload = struct.pack('<Q32sI4x', 0x6548634163536E44, b'cache ver 1.3\\0', 1)
payload += struct.pack('<I4x', 0x64526352)
payload += bytes(info)
payload += struct.pack('<i4xqI4x', 1, len(packet), 0x61546144)
payload += packet
Path(args.cache_dump_path).write_bytes(payload)
Path(args.smartdns_log_path).write_text('smartdns-native\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_maradns_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_maradns_harness() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--mode', required=True)
parser.add_argument('--cache-dump-path', required=True)
parser.add_argument('--maradns-log-path', required=True)
parser.add_argument('--transcript')
parser.add_argument('--deadwood-bin')
args = parser.parse_args()
Path(args.cache_dump_path).write_text('MARADNS_CACHE_DUMP\\nCACHE_ENTRY\\texample.com\\tA\\t_\\n', encoding='utf-8')
Path(args.maradns_log_path).write_text('maradns-native\\n', encoding='utf-8')
print('ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0')
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

write_fake_dnslabctl() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    """#!/usr/bin/env python3
import os
import pathlib
import sys

log_path = os.environ.get("FAKE_DNSLABCTL_LOG")
if log_path:
    pathlib.Path(log_path).write_text(" ".join(sys.argv[1:]) + "\\n", encoding="utf-8")
if sys.argv[1:3] == ["prepare-subject", "--resolver"] and len(sys.argv) >= 4:
    print('{"resolver": "%s"}' % sys.argv[3])
    sys.exit(0)
sys.exit(9)
""",
    encoding="utf-8",
)
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

HELP_OUT="$WORKDIR/python-help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli --help >"$HELP_OUT"
assert_file_contains "$HELP_OUT" "fetch"
assert_file_contains "$HELP_OUT" "dump-cache"
assert_file_contains "$HELP_OUT" "parse-cache"
assert_file_contains "$HELP_OUT" "replay-diff-cache"
assert_file_contains "$HELP_OUT" "follow-diff-window"
assert_file_contains "$HELP_OUT" "campaign-close"

WINDOW_HELP_OUT="$WORKDIR/window-help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli follow-diff-window --help >"$WINDOW_HELP_OUT"
assert_file_contains "$WINDOW_HELP_OUT" "--budget-sec"

CLOSE_HELP_OUT="$WORKDIR/close-help.txt"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli campaign-close --help >"$CLOSE_HELP_OUT"
assert_file_contains "$CLOSE_HELP_OUT" "--budget-sec"

FETCH_UNKNOWN_ERR="$WORKDIR/fetch-unknown.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli fetch --target not-registered >/dev/null 2>"$FETCH_UNKNOWN_ERR"; then
	printf 'ASSERT FAIL: 未注册 target 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$FETCH_UNKNOWN_ERR" "dns-diff: fetch 失败"
assert_file_contains "$FETCH_UNKNOWN_ERR" "未注册 target: 'not-registered'"
assert_file_contains "$FETCH_UNKNOWN_ERR" "dnsmasq"
assert_file_contains "$FETCH_UNKNOWN_ERR" "unbound"

PARSE_UNKNOWN_ERR="$WORKDIR/parse-unknown.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	python3 -m tools.dns_diff.cli parse-cache not-registered "$WORKDIR/missing.dump" >/dev/null 2>"$PARSE_UNKNOWN_ERR"; then
	printf 'ASSERT FAIL: 未注册 resolver 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$PARSE_UNKNOWN_ERR" "dns-diff: parse-cache 失败"
assert_file_contains "$PARSE_UNKNOWN_ERR" "未注册 resolver: 'not-registered'"
assert_file_contains "$PARSE_UNKNOWN_ERR" "bind9"
assert_file_contains "$PARSE_UNKNOWN_ERR" "dnsmasq"
assert_file_contains "$PARSE_UNKNOWN_ERR" "unbound"

FAKE_AFL_TREE="$WORKDIR/unbound-afl"
FAKE_TARGET="$FAKE_AFL_TREE/.libs/unbound-fuzzme"
write_fake_unbound_binary "$FAKE_TARGET"
mkdir -p "$FAKE_AFL_TREE/libworker/.libs" "$WORKDIR/work/response_corpus"
FAKE_DNSMASQ_BUILD_TREE="$WORKDIR/dnsmasq-build"
FAKE_DNSMASQ_TARGET="$FAKE_DNSMASQ_BUILD_TREE/dnsmasq"
FAKE_DNSMASQ_HARNESS="$WORKDIR/dnsmasq-harness.py"
FAKE_SMARTDNS_BUILD_TREE="$WORKDIR/smartdns-build"
FAKE_SMARTDNS_TARGET="$FAKE_SMARTDNS_BUILD_TREE/src/smartdns"
FAKE_SMARTDNS_HARNESS="$WORKDIR/smartdns-harness.py"
FAKE_MARADNS_BUILD_TREE="$WORKDIR/maradns-build"
FAKE_MARADNS_TARGET="$FAKE_MARADNS_BUILD_TREE/deadwood-build/deadwood-github/src/Deadwood"
FAKE_MARADNS_HARNESS="$WORKDIR/maradns-harness.py"
FAKE_DNSLABCTL="$WORKDIR/fake-dnslabctl.py"
FAKE_DNSLABCTL_LOG="$WORKDIR/fake-dnslabctl.log"
write_fake_dnsmasq_binary "$FAKE_DNSMASQ_TARGET"
write_fake_dnsmasq_harness "$FAKE_DNSMASQ_HARNESS"
write_fake_smartdns_binary "$FAKE_SMARTDNS_TARGET"
write_fake_smartdns_harness "$FAKE_SMARTDNS_HARNESS"
write_fake_maradns_binary "$FAKE_MARADNS_TARGET"
write_fake_maradns_harness "$FAKE_MARADNS_HARNESS"
write_fake_dnslabctl "$FAKE_DNSLABCTL"
mkdir -p "$WORKDIR/dnsmasq-source"
mkdir -p "$WORKDIR/smartdns-source"
mkdir -p "$WORKDIR/maradns-source"
SAMPLE_FILE="$WORKDIR/sample.bin"
DIRECT_DUMP_OUT="$WORKDIR/direct.cache.txt"
WRAPPER_DUMP_OUT="$WORKDIR/wrapper.cache.txt"
DIRECT_LOG="$WORKDIR/direct.log"
WRAPPER_LOG="$WORKDIR/wrapper.log"
DNSMASQ_DUMP_OUT="$WORKDIR/dnsmasq.cache.txt"
DNSMASQ_WRAPPER_DUMP_OUT="$WORKDIR/dnsmasq.wrapper.cache.txt"
SMARTDNS_DUMP_OUT="$WORKDIR/smartdns.cache.bin"
SMARTDNS_WRAPPER_DUMP_OUT="$WORKDIR/smartdns.wrapper.cache.bin"
MARADNS_DUMP_OUT="$WORKDIR/maradns.cache.txt"
MARADNS_WRAPPER_DUMP_OUT="$WORKDIR/maradns.wrapper.cache.txt"
printf '\x01\x02\x03\x04' >"$SAMPLE_FILE"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ROOT_DIR" \
	AFL_TREE="$FAKE_AFL_TREE" \
	WORK_DIR="$WORKDIR/work" \
	RESPONSE_CORPUS_DIR="$WORKDIR/work/response_corpus" \
	FAKE_UNBOUND_INVOCATION_LOG="$DIRECT_LOG" \
	python3 -m tools.dns_diff.cli dump-cache --target unbound "$SAMPLE_FILE" "$DIRECT_DUMP_OUT" >/dev/null
assert_file_exists "$DIRECT_DUMP_OUT"
assert_file_contains "$DIRECT_DUMP_OUT" "START_RRSET_CACHE"
assert_file_contains "$DIRECT_LOG" "stdin=4"
assert_file_contains "$DIRECT_LOG" "response_dir=$WORKDIR/work/response_corpus"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	AFL_TREE="$FAKE_AFL_TREE" \
	WORK_DIR="$WORKDIR/work" \
	RESPONSE_CORPUS_DIR="$WORKDIR/work/response_corpus" \
	FAKE_UNBOUND_INVOCATION_LOG="$WRAPPER_LOG" \
	"$WRAPPER" dump-cache "$SAMPLE_FILE" "$WRAPPER_DUMP_OUT" >/dev/null
assert_file_exists "$WRAPPER_DUMP_OUT"
assert_file_contains "$WRAPPER_DUMP_OUT" "START_RRSET_CACHE"
assert_file_contains "$WRAPPER_LOG" "stdin=4"
assert_file_contains "$WRAPPER_LOG" "response_dir=$WORKDIR/work/response_corpus"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	DNSLABCTL_BIN="$FAKE_DNSLABCTL" \
	FAKE_DNSLABCTL_LOG="$FAKE_DNSLABCTL_LOG" \
	python3 -m tools.dns_diff.cli fetch --target dnsmasq >/dev/null
assert_file_contains "$FAKE_DNSLABCTL_LOG" "prepare-subject --resolver dnsmasq"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	DNSLABCTL_BIN="$FAKE_DNSLABCTL" \
	FAKE_DNSLABCTL_LOG="$FAKE_DNSLABCTL_LOG" \
	python3 -m tools.dns_diff.cli fetch --target smartdns >/dev/null
assert_file_contains "$FAKE_DNSLABCTL_LOG" "prepare-subject --resolver smartdns"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	DNSLABCTL_BIN="$FAKE_DNSLABCTL" \
	FAKE_DNSLABCTL_LOG="$FAKE_DNSLABCTL_LOG" \
	python3 -m tools.dns_diff.cli fetch --target maradns >/dev/null
assert_file_contains "$FAKE_DNSLABCTL_LOG" "prepare-subject --resolver maradns"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	DNSLABCTL_BIN="$FAKE_DNSLABCTL" \
	FAKE_DNSLABCTL_LOG="$FAKE_DNSLABCTL_LOG" \
	python3 -m tools.dns_diff.cli fetch --target knot-resolver >/dev/null
assert_file_contains "$FAKE_DNSLABCTL_LOG" "prepare-subject --resolver knot-resolver"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ROOT_DIR" \
	DNSMASQ_BUILD_TREE="$FAKE_DNSMASQ_BUILD_TREE" \
	DNSMASQ_SRC_TREE="$WORKDIR/dnsmasq-source" \
	DNSMASQ_HARNESS_SCRIPT="$FAKE_DNSMASQ_HARNESS" \
	python3 -m tools.dns_diff.cli dump-cache --target dnsmasq "$SAMPLE_FILE" "$DNSMASQ_DUMP_OUT" >/dev/null
assert_file_exists "$DNSMASQ_DUMP_OUT"
assert_file_contains "$DNSMASQ_DUMP_OUT" "example.com"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	DNSMASQ_BUILD_TREE="$FAKE_DNSMASQ_BUILD_TREE" \
	DNSMASQ_SRC_TREE="$WORKDIR/dnsmasq-source" \
	DNSMASQ_HARNESS_SCRIPT="$FAKE_DNSMASQ_HARNESS" \
	"$WRAPPER" dump-cache --target dnsmasq "$SAMPLE_FILE" "$DNSMASQ_WRAPPER_DUMP_OUT" >/dev/null
assert_file_exists "$DNSMASQ_WRAPPER_DUMP_OUT"
assert_file_contains "$DNSMASQ_WRAPPER_DUMP_OUT" "example.com"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ROOT_DIR" \
	SMARTDNS_BUILD_TREE="$FAKE_SMARTDNS_BUILD_TREE" \
	SMARTDNS_SRC_TREE="$WORKDIR/smartdns-source" \
	SMARTDNS_HARNESS_SCRIPT="$FAKE_SMARTDNS_HARNESS" \
	python3 -m tools.dns_diff.cli dump-cache --target smartdns "$SAMPLE_FILE" "$SMARTDNS_DUMP_OUT" >/dev/null
assert_file_exists "$SMARTDNS_DUMP_OUT"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	SMARTDNS_BUILD_TREE="$FAKE_SMARTDNS_BUILD_TREE" \
	SMARTDNS_SRC_TREE="$WORKDIR/smartdns-source" \
	SMARTDNS_HARNESS_SCRIPT="$FAKE_SMARTDNS_HARNESS" \
	"$WRAPPER" dump-cache --target smartdns "$SAMPLE_FILE" "$SMARTDNS_WRAPPER_DUMP_OUT" >/dev/null
assert_file_exists "$SMARTDNS_WRAPPER_DUMP_OUT"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ROOT_DIR" \
	MARADNS_BUILD_TREE="$FAKE_MARADNS_BUILD_TREE" \
	MARADNS_SRC_TREE="$WORKDIR/maradns-source" \
	MARADNS_HARNESS_SCRIPT="$FAKE_MARADNS_HARNESS" \
	python3 -m tools.dns_diff.cli dump-cache --target maradns "$SAMPLE_FILE" "$MARADNS_DUMP_OUT" >/dev/null
assert_file_exists "$MARADNS_DUMP_OUT"
assert_file_contains "$MARADNS_DUMP_OUT" "CACHE_ENTRY"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	MARADNS_BUILD_TREE="$FAKE_MARADNS_BUILD_TREE" \
	MARADNS_SRC_TREE="$WORKDIR/maradns-source" \
	MARADNS_HARNESS_SCRIPT="$FAKE_MARADNS_HARNESS" \
	"$WRAPPER" dump-cache --target maradns "$SAMPLE_FILE" "$MARADNS_WRAPPER_DUMP_OUT" >/dev/null
assert_file_exists "$MARADNS_WRAPPER_DUMP_OUT"
assert_file_contains "$MARADNS_WRAPPER_DUMP_OUT" "CACHE_ENTRY"

BIND_DUMP="$WORKDIR/bind.cache.txt"
BIND_TSV="$WORKDIR/bind.norm.tsv"
printf '%s\n' \
	';' \
	"; Cache dump of view '_default' (cache _default)" \
	';' \
	'example.com. 300 IN A 1.2.3.4' >"$BIND_DUMP"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" parse-cache bind9 "$BIND_DUMP" "$BIND_TSV" >/dev/null
assert_file_exists "$BIND_TSV"
assert_file_contains "$BIND_TSV" $'bind9\t_default\texample.com.\tA\tA\tRRSET\trrset\t300\t1.2.3.4\tclass=IN'

DNSMASQ_PARSE_TSV="$WORKDIR/dnsmasq.norm.tsv"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" parse-cache dnsmasq "$DNSMASQ_DUMP_OUT" "$DNSMASQ_PARSE_TSV" >/dev/null
assert_file_exists "$DNSMASQ_PARSE_TSV"
assert_file_contains "$DNSMASQ_PARSE_TSV" $'dnsmasq\t_\texample.com\tA\tA\tCACHE\trrset\t_\t1.2.3.4\tflags=4F expires=Sun May 10 05:50:01 2026'

SMARTDNS_PARSE_TSV="$WORKDIR/smartdns.norm.tsv"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" parse-cache smartdns "$SMARTDNS_DUMP_OUT" "$SMARTDNS_PARSE_TSV" >/dev/null
assert_file_exists "$SMARTDNS_PARSE_TSV"
assert_file_contains "$SMARTDNS_PARSE_TSV" $'smartdns\t_\texample.com\tA\tA\tCACHE\tpacket\t600\t1.2.3.4\tclass=1 rcode=0 hitnum=6 speed=-1 query_flag=0 insert_time=111 replace_time=222'

MARADNS_PARSE_TSV="$WORKDIR/maradns.norm.tsv"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" parse-cache maradns "$MARADNS_DUMP_OUT" "$MARADNS_PARSE_TSV" >/dev/null
assert_file_exists "$MARADNS_PARSE_TSV"
assert_file_contains "$MARADNS_PARSE_TSV" $'maradns\t_\texample.com\tA\tA\tCACHE\trrset\t_\t_\tsource=deadwood-log'

WINDOW_GUARD_ERR="$WORKDIR/window.guard.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	DNS_DIFF_CLI_TIMEOUT_SEC=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" follow-diff-window --budget-sec 0.1 >/dev/null 2>"$WINDOW_GUARD_ERR"; then
	printf 'ASSERT FAIL: follow-diff-window 设置 DNS_DIFF_CLI_TIMEOUT_SEC 时应被 wrapper 拒绝\n' >&2
	exit 1
fi
assert_file_contains "$WINDOW_GUARD_ERR" "DNS_DIFF_CLI_TIMEOUT_SEC"
assert_file_contains "$WINDOW_GUARD_ERR" "follow-diff-window --budget-sec"
assert_file_not_contains "$WINDOW_GUARD_ERR" "dns-diff: follow-diff-window 失败"

REMOVED_ERR="$WORKDIR/removed.err"
if env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORKDIR/work" \
	"$WRAPPER" run >/dev/null 2>"$REMOVED_ERR"; then
	printf 'ASSERT FAIL: 已移除厚命令 run 不应成功\n' >&2
	exit 1
fi
assert_file_contains "$REMOVED_ERR" "命令 'run'"
assert_file_contains "$REMOVED_ERR" "已从 thin wrapper 中移除"

echo "PASS: tools dns-diff CLI contract test passed"
