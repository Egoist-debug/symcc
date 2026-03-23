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

echo "PASS: cache dump parser regression test passed"
