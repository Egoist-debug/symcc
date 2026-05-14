#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-input-model-eval.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

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

BIND9_TREE="$WORKDIR/bind9-afl"
BIND9_BIN="$BIND9_TREE/bin/named/.libs/named"
NAMED_CONF_TEMPLATE="$WORKDIR/named.conf.template"
LEGACY_RESPONSE_DIR="$WORKDIR/legacy_responses"
OUTPUT_DIR="$WORKDIR/out"

mkdir -p "$BIND9_TREE/bin/named/.libs" "$LEGACY_RESPONSE_DIR"

python3 - "$BIND9_BIN" <<'PY'
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
script = """#!/usr/bin/env python3
import os
import pathlib
import sys

sample_path = None
for arg in sys.argv[1:]:
    if 'input=' in arg:
        sample_path = pathlib.Path(arg.split('input=', 1)[1])
        break
if sample_path is None:
    raise SystemExit('missing input path')
data = sample_path.read_bytes()
has_response_dir = bool(os.environ.get('NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR'))
if data.startswith(b'DST1'):
    summary = 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=1 cache_entry_created=1 timeout=0\\n'
elif data.startswith(b'\\x12\\x34'):
    if has_response_dir:
        summary = 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 second_query_hit=0 cache_entry_created=0 timeout=0\\n'
    else:
        summary = 'ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=0 second_query_hit=0 cache_entry_created=0 timeout=0\\n'
else:
    summary = 'ORACLE_SUMMARY parse_ok=0 resolver_fetch_started=0 response_accepted=0 second_query_hit=0 cache_entry_created=0 timeout=0\\n'
dump_path = os.environ.get('NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH')
if dump_path:
    pathlib.Path(dump_path).write_text('cache\\n', encoding='utf-8')
sys.stderr.write(summary)
sys.exit(0)
"""
path.write_text(script, encoding="utf-8")
path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY

printf 'options { directory "__RUNTIME_STATE_DIR__"; };\n' >"$NAMED_CONF_TEMPLATE"
printf '\xaa\xbb\xcc\xdd' >"$LEGACY_RESPONSE_DIR/resp.bin"

python3 - "$WORKDIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
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
(root / 'dst1.bin').write_bytes(wire)
(root / 'query.bin').write_bytes(query)
(root / 'legacy.bin').write_bytes(query)
(root / 'random.bin').write_bytes(b'\x99\x88\x77\x66\x55')
PY

python3 -m tools.dns_diff.cli input-model-eval \
  --output-dir "$OUTPUT_DIR" \
  --bind9-tree "$BIND9_TREE" \
  --named-conf-template "$NAMED_CONF_TEMPLATE" \
  --dst1-input "$WORKDIR/dst1.bin" \
  --query-only-input "$WORKDIR/query.bin" \
  --random-input "$WORKDIR/random.bin" \
  --legacy-input "$WORKDIR/legacy.bin" \
  --legacy-response-dir "$LEGACY_RESPONSE_DIR" >/dev/null

assert_file_exists "$OUTPUT_DIR/summary.tsv"
assert_file_exists "$OUTPUT_DIR/summary.json"

python3 - "$OUTPUT_DIR/summary.tsv" <<'PY'
import csv
import pathlib
import sys

rows = {row["model_name"]: row for row in csv.DictReader(pathlib.Path(sys.argv[1]).open(encoding="utf-8"), delimiter="\t")}
if rows["dst1_transcript"]["parse_accept_rate"] != "1.000000":
    raise SystemExit("ASSERT FAIL: dst1 parse_accept_rate 非 1")
if rows["dst1_transcript"]["effective_post_check_rate"] != "1.000000":
    raise SystemExit("ASSERT FAIL: dst1 effective_post_check_rate 非 1")
if rows["query_only"]["response_accept_rate"] != "0.000000":
    raise SystemExit("ASSERT FAIL: query_only response_accept_rate 非 0")
if rows["legacy_response_tail"]["response_accept_rate"] != "1.000000":
    raise SystemExit("ASSERT FAIL: legacy_response_tail response_accept_rate 非 1")
if rows["random_packet"]["parse_accept_rate"] != "0.000000":
    raise SystemExit("ASSERT FAIL: random_packet parse_accept_rate 非 0")
PY

printf 'PASS: input model eval smoke test passed\n'
