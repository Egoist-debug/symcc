#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-follow-diff-self-exec.XXXXXX")"
ROOT_ENV="$WORKDIR/root"
QUEUE_DIR="$WORKDIR/bind9-work/afl_out/master/queue"
WORK_STATEFUL="$WORKDIR/work"
READLINK_BLOCKER_C="$WORKDIR/readlink_blocker.c"
READLINK_BLOCKER_SO="$WORKDIR/readlink_blocker.so"
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

assert_dir_exists() {
	local path="$1"
	if [ ! -d "$path" ]; then
		printf 'ASSERT FAIL: 缺少目录 %s\n' "$path" >&2
		exit 1
	fi
}

write_fake_bind9_binary() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
script = """#!/usr/bin/env python3
import os
import pathlib
import sys
dump_path = os.environ.get("NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH")
has_input = any("input=" in arg for arg in sys.argv[1:])
ttl = "299" if has_input else "300"
pathlib.Path(dump_path).write_text(
    "\\n".join([
        ";",
        "; Cache dump of view '_default' (cache _default)",
        ";",
        f"example.com. {ttl} IN A 1.2.3.4",
    ]) + "\\n",
    encoding="utf-8",
)
sys.stderr.write("ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n")
sys.exit(0)
"""
path.write_text(script, encoding="utf-8")
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

write_readlink_blocker() {
	cat >"$READLINK_BLOCKER_C" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static ssize_t (*real_readlink_fn)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat_fn)(int, const char *, char *, size_t) = NULL;

static int should_block(const char *path) {
  return path != NULL && strcmp(path, "/proc/self/exe") == 0;
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
  if (should_block(path)) {
    errno = ENOENT;
    return -1;
  }
  if (real_readlink_fn == NULL) {
    real_readlink_fn = (ssize_t (*)(const char *, char *, size_t))dlsym(RTLD_NEXT, "readlink");
  }
  return real_readlink_fn(path, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
  if (should_block(path)) {
    errno = ENOENT;
    return -1;
  }
  if (real_readlinkat_fn == NULL) {
    real_readlinkat_fn =
        (ssize_t (*)(int, const char *, char *, size_t))dlsym(RTLD_NEXT, "readlinkat");
  }
  return real_readlinkat_fn(dirfd, path, buf, bufsiz);
}
EOF
	cc -shared -fPIC -o "$READLINK_BLOCKER_SO" "$READLINK_BLOCKER_C" -ldl
}

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
BIND9_SRC="$WORKDIR/bind9-src"
DNSMASQ_BUILD="$WORKDIR/dnsmasq-build"
DNSMASQ_BIN="$DNSMASQ_BUILD/dnsmasq"
DNSMASQ_SRC="$WORKDIR/dnsmasq-src"
DNSMASQ_HARNESS="$WORKDIR/dnsmasq-harness.py"
NAMED_CONF_TEMPLATE="$ROOT_ENV/named_experiment/runtime/named.conf"
RESPONSE_CORPUS_DIR="$ROOT_ENV/named_experiment/work/response_corpus"
SAMPLE_FILE="$QUEUE_DIR/id:000001,orig:seed"

mkdir -p \
	"$QUEUE_DIR" \
	"$BIND9_SRC" \
	"$DNSMASQ_SRC" \
	"$RESPONSE_CORPUS_DIR" \
	"$ROOT_ENV/named_experiment/runtime"
printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
printf 'seed\n' >"$RESPONSE_CORPUS_DIR/seed.txt"
write_fake_bind9_binary "$BIND9_BIN"
write_fake_dnsmasq_binary "$DNSMASQ_BIN"
write_fake_dnsmasq_harness "$DNSMASQ_HARNESS"
write_readlink_blocker

python3 - "$SAMPLE_FILE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
response = (
    b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
    b'\x07example\x03com\x00\x00\x01\x00\x01'
    b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04'
)
post = b'\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
wire = bytearray(b'DST1')
wire += bytes([1, 2])
wire += len(query).to_bytes(2, 'little')
wire += len(response).to_bytes(2, 'little')
wire += query + response + post
path.write_bytes(wire)
PY

if ! (
	cd /tmp
	env \
		LD_PRELOAD="$READLINK_BLOCKER_SO" \
		ROOT_DIR="$ROOT_ENV" \
		WORK_DIR="$WORK_STATEFUL" \
		BIND9_WORK_DIR="$WORKDIR/bind9-work" \
		DNS_DIFF_SECONDARY_RESOLVER=dnsmasq \
		BIND9_AFL_TREE="$BIND9_TREE" \
		BIND9_SRC_TREE="$BIND9_SRC" \
		DNSMASQ_BUILD_TREE="$DNSMASQ_BUILD" \
		DNSMASQ_SRC_TREE="$DNSMASQ_SRC" \
		DNSMASQ_HARNESS_SCRIPT="$DNSMASQ_HARNESS" \
		"$DNSLABCTL_BIN" follow-diff-once >"$WORKDIR/follow-diff.json" 2>"$WORKDIR/follow-diff.stderr"
); then
	printf 'ASSERT FAIL: dnslabctl follow-diff-once 在 /proc/self/exe 不可用时仍应成功\n' >&2
	cat "$WORKDIR/follow-diff.stderr" >&2
	exit 1
fi

SAMPLE_META="$(find "$WORK_STATEFUL/follow_diff" -maxdepth 2 -mindepth 2 -type f -name sample.meta.json | sort | head -n 1)"
assert_file_exists "$WORKDIR/follow-diff.json"
assert_file_exists "$SAMPLE_META"
SAMPLE_DIR="$(dirname "$SAMPLE_META")"
assert_file_exists "$SAMPLE_DIR/sample.meta.json"
assert_file_exists "$SAMPLE_DIR/oracle.json"
assert_file_exists "$SAMPLE_DIR/cache_diff.json"
assert_file_exists "$SAMPLE_DIR/triage.json"
assert_file_exists "$SAMPLE_DIR/bind9/bind9.before.cache.txt"
assert_file_exists "$SAMPLE_DIR/bind9/bind9.after.cache.txt"
assert_file_exists "$SAMPLE_DIR/dnsmasq/dnsmasq.before.cache.txt"
assert_file_exists "$SAMPLE_DIR/dnsmasq/dnsmasq.after.cache.txt"
assert_dir_exists "$SAMPLE_DIR/bind9"
assert_dir_exists "$SAMPLE_DIR/dnsmasq"

python3 - "$SAMPLE_DIR" "$DNSLABCTL_BIN" <<'PY'
import json
import pathlib
import sys

sample_dir = pathlib.Path(sys.argv[1])
dnslabctl_bin = pathlib.Path(sys.argv[2]).resolve()
meta = json.loads((sample_dir / "sample.meta.json").read_text(encoding="utf-8"))
triage = json.loads((sample_dir / "triage.json").read_text(encoding="utf-8"))
artifacts = meta.get("artifacts", {})
if artifacts.get("dnsmasq_stderr") != "dnsmasq/dnsmasq.stderr":
    raise SystemExit(f"ASSERT FAIL: artifacts 未保留 dnsmasq_stderr: {artifacts!r}")
if meta.get("status") != "completed":
    raise SystemExit(f"ASSERT FAIL: sample.meta.status={meta.get('status')!r}")
executed = meta.get("executed_resolvers")
if not isinstance(executed, list) or "dnsmasq" not in executed or "bind9" not in executed:
    raise SystemExit(f"ASSERT FAIL: sample.meta.executed_resolvers={executed!r}")
if meta.get("diff_detected") is not True:
    raise SystemExit(f"ASSERT FAIL: sample.meta.diff_detected={meta.get('diff_detected')!r}")
resolver_diffs = meta.get("resolver_diffs")
if not isinstance(resolver_diffs, list) or not resolver_diffs:
    raise SystemExit(f"ASSERT FAIL: sample.meta.resolver_diffs={resolver_diffs!r}")
if triage.get("status") != "completed_oracle_diff":
    raise SystemExit(f"ASSERT FAIL: triage.status={triage.get('status')!r}")
failure = meta.get("failure")
if failure not in (None, {}):
    raise SystemExit(f"ASSERT FAIL: 成功样本不应保留 failure: {failure!r}")
PY

printf 'PASS: dnslabctl follow-diff self executable fallback regression test passed\n'
