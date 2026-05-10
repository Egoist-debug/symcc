#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARSER_SCRIPT="$ROOT_DIR/unbound_experiment/run_unbound_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-cache-parser.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

write_lines() {
	local path="$1"
	shift

	: >"$path"
	for line in "$@"; do
		printf '%s\n' "$line" >>"$path"
	done
}

assert_has_line() {
	local path="$1"
	local expected="$2"

	if ! grep -Fqx "$expected" "$path"; then
		printf 'ASSERT FAIL: 期望在 %s 中找到行:\n%s\n' "$path" "$expected" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

assert_empty_file() {
	local path="$1"

	if [ -s "$path" ]; then
		printf 'ASSERT FAIL: 期望文件为空: %s\n' "$path" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

compare_tsv() {
	local before_file="$1"
	local after_file="$2"
	local added_file="$3"
	local removed_file="$4"
	python3 - "$before_file" "$after_file" "$added_file" "$removed_file" <<'PY'
from pathlib import Path
import sys


def load(path_str: str) -> dict[tuple[str, ...], str]:
    mapping: dict[tuple[str, ...], str] = {}
    path = Path(path_str)
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line:
            continue
        fields = raw_line.split("\t")
        if len(fields) != 10:
            raise SystemExit(f"ASSERT FAIL: {path}:{lineno} 列数不是 10，而是 {len(fields)}")
        key = tuple(fields[:7] + fields[8:])
        mapping.setdefault(key, raw_line)
    return mapping


before = load(sys.argv[1])
after = load(sys.argv[2])
added = [after[key] for key in sorted(after.keys() - before.keys())]
removed = [before[key] for key in sorted(before.keys() - after.keys())]
Path(sys.argv[3]).write_text("\n".join(added) + ("\n" if added else ""), encoding="utf-8")
Path(sys.argv[4]).write_text("\n".join(removed) + ("\n" if removed else ""), encoding="utf-8")
PY
}

bind_negative_dump="$WORKDIR/bind_negative.cache.txt"
bind_negative_norm="$WORKDIR/bind_negative.norm.tsv"
write_lines "$bind_negative_dump" \
	";" \
	"; Cache dump of view '_default' (cache _default)" \
	";" \
	"example.com. 300 IN \\-A ;-\$NXDOMAIN" \
	"300 NSEC example.com. A NS SOA RRSIG NSEC DNSKEY"
"$PARSER_SCRIPT" parse-cache bind9 "$bind_negative_dump" "$bind_negative_norm" >/dev/null
assert_has_line "$bind_negative_norm" $'bind9\t_default\texample.com.\t\\-A\t\\-A\tRRSET\tnegative\t300\t;-$NXDOMAIN\tclass=IN'
assert_has_line "$bind_negative_norm" $'bind9\t_default\texample.com.\tNSEC\tNSEC\tRRSET\trrset\t300\texample.com. A NS SOA RRSIG NSEC DNSKEY\tclass=IN'

bind_before_dump="$WORKDIR/bind_before.cache.txt"
bind_after_dump="$WORKDIR/bind_after.cache.txt"
bind_before_norm="$WORKDIR/bind_before.norm.tsv"
bind_after_norm="$WORKDIR/bind_after.norm.tsv"
bind_added="$WORKDIR/bind_added.tsv"
bind_removed="$WORKDIR/bind_removed.tsv"
write_lines "$bind_before_dump" \
	";" \
	"; Cache dump of view '_default' (cache _default)" \
	";" \
	"example.com. 300 IN A 1.2.3.4"
write_lines "$bind_after_dump" \
	";" \
	"; Cache dump of view '_default' (cache _default)" \
	";" \
	"example.com. 299 IN A 1.2.3.4"
"$PARSER_SCRIPT" parse-cache bind9 "$bind_before_dump" "$bind_before_norm" >/dev/null
"$PARSER_SCRIPT" parse-cache bind9 "$bind_after_dump" "$bind_after_norm" >/dev/null
compare_tsv "$bind_before_norm" "$bind_after_norm" "$bind_added" "$bind_removed"
assert_empty_file "$bind_added"
assert_empty_file "$bind_removed"

unbound_before_dump="$WORKDIR/unbound_before.cache.txt"
unbound_after_dump="$WORKDIR/unbound_after.cache.txt"
unbound_before_norm="$WORKDIR/unbound_before.norm.tsv"
unbound_after_norm="$WORKDIR/unbound_after.norm.tsv"
unbound_added="$WORKDIR/unbound_added.tsv"
unbound_removed="$WORKDIR/unbound_removed.tsv"
write_lines "$unbound_before_dump" \
	"START_RRSET_CACHE" \
	";rrset 300 2 0 2 1" \
	"example.com. 300 IN A 1.2.3.4" \
	"300 AAAA 2001:db8::1" \
	"END_RRSET_CACHE" \
	"START_MSG_CACHE" \
	"msg example.com. IN A 33152 1 300 0 1 0 0 -1" \
	"END_MSG_CACHE" \
	"EOF"
write_lines "$unbound_after_dump" \
	"START_RRSET_CACHE" \
	";rrset 299 2 0 2 1" \
	"example.com. 299 IN A 1.2.3.4" \
	"299 AAAA 2001:db8::1" \
	"END_RRSET_CACHE" \
	"START_MSG_CACHE" \
	"msg example.com. IN A 33152 1 299 0 1 0 0 -1" \
	"END_MSG_CACHE" \
	"EOF"
"$PARSER_SCRIPT" parse-cache unbound "$unbound_before_dump" "$unbound_before_norm" >/dev/null
"$PARSER_SCRIPT" parse-cache unbound "$unbound_after_dump" "$unbound_after_norm" >/dev/null
assert_has_line "$unbound_before_norm" $'unbound\t_\texample.com.\tA\tA\tRRSET\trrset\t300\t1.2.3.4\tclass=IN'
assert_has_line "$unbound_before_norm" $'unbound\t_\texample.com.\tAAAA\tAAAA\tRRSET\trrset\t300\t2001:db8::1\tclass=IN'
assert_has_line "$unbound_before_norm" $'unbound\t_\texample.com.\tA\t_\tMSG\tmessage\t300\t_\tclass=IN flags=33152 qd=1 sec=0 an=1 ns=0 ar=0 bogus=-1 reason=_'
compare_tsv "$unbound_before_norm" "$unbound_after_norm" "$unbound_added" "$unbound_removed"
assert_empty_file "$unbound_added"
assert_empty_file "$unbound_removed"

dnsmasq_dump="$WORKDIR/dnsmasq.cache.txt"
dnsmasq_norm="$WORKDIR/dnsmasq.norm.tsv"
write_lines "$dnsmasq_dump" \
	"May 10 05:49:01 dnsmasq[250875]: Host                           Address                                  Flags      Expires                  Source" \
	"May 10 05:49:01 dnsmasq[250875]: ------------------------------ ---------------------------------------- ---------- ------------------------ ------------" \
	"May 10 05:49:01 dnsmasq[250875]: bind                                                                    !F I    C" \
	"May 10 05:49:01 dnsmasq[250875]: example.com                    1.2.3.4                                  4F         Sun May 10 05:50:01 2026" \
	"May 10 05:49:02 dnsmasq[250875]: exiting on receipt of SIGTERM"
"$PARSER_SCRIPT" parse-cache dnsmasq "$dnsmasq_dump" "$dnsmasq_norm" >/dev/null
assert_has_line "$dnsmasq_norm" $'dnsmasq\t_\texample.com\tA\tA\tCACHE\trrset\t_\t1.2.3.4\tflags=4F expires=Sun May 10 05:50:01 2026'

smartdns_dump="$WORKDIR/smartdns.cache"
smartdns_norm="$WORKDIR/smartdns.norm.tsv"
python3 - "$smartdns_dump" <<'PY'
from pathlib import Path
import struct
import sys

path = Path(sys.argv[1])
packet = (
    b"\x56\x78\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
    b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x58\x00\x04\x01\x02\x03\x04"
)
info = bytearray(344)
info[0 : len(b"example.com")] = b"example.com"
struct.pack_into("<i", info, 256, 1)
struct.pack_into("<I", info, 292, 0)
struct.pack_into("<i", info, 296, 600)
struct.pack_into("<i", info, 300, 0)
struct.pack_into("<i", info, 304, 6)
struct.pack_into("<i", info, 308, -1)
struct.pack_into("<q", info, 328, 111)
struct.pack_into("<q", info, 336, 222)
file_header = struct.pack("<Q32sI4x", 0x6548634163536E44, b"cache ver 1.3\0", 1)
record_header = struct.pack("<I4x", 0x64526352)
data_head = struct.pack("<i4xqI4x", 1, len(packet), 0x61546144)
path.write_bytes(file_header + record_header + info + data_head + packet)
PY
"$PARSER_SCRIPT" parse-cache smartdns "$smartdns_dump" "$smartdns_norm" >/dev/null
assert_has_line "$smartdns_norm" $'smartdns\t_\texample.com\tA\tA\tCACHE\tpacket\t600\t1.2.3.4\tclass=1 rcode=0 hitnum=6 speed=-1 query_flag=0 insert_time=111 replace_time=222'

maradns_dump="$WORKDIR/maradns.cache.txt"
maradns_norm="$WORKDIR/maradns.norm.tsv"
write_lines "$maradns_dump" \
	"MARADNS_CACHE_DUMP" \
	"Fetching \\007example\\003com\\000\\000\\001 from cache"
"$PARSER_SCRIPT" parse-cache maradns "$maradns_dump" "$maradns_norm" >/dev/null
assert_has_line "$maradns_norm" $'maradns\t_\texample.com\tA\tA\tCACHE\trrset\t_\t_\tsource=deadwood-log'

echo "PASS: cache dump parser regression test passed"
