#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMED_WRAPPER="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-named-transcript-current.XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

SAMPLE_PATH="$WORKDIR/id:000001,orig:current-dst1"

python3 - "$SAMPLE_PATH" <<'PY'
from pathlib import Path
import struct
import sys

output = Path(sys.argv[1])
qname = b'\x07example\x03com\x00'
query = bytes.fromhex('123401000001000000000000') + qname + bytes.fromhex('00010001')
response = bytes.fromhex('567881800001000100000000') + qname + bytes.fromhex('00010001c00c000100010000003c000401020304')
post_check = bytes.fromhex('9abc01000001000000000000') + qname + bytes.fromhex('00010001')

payload = bytearray()
payload += b"DST1"
payload += bytes([1])
payload += bytes([0])
payload += struct.pack("<H", len(query))
payload += struct.pack("<H", len(post_check))
payload += struct.pack("<H", len(response))
payload += query
payload += response
payload += post_check
output.write_bytes(payload)
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	bash -c '
		set -euo pipefail
		source "$1"
		validate_transcript_seed_v2_two_part "$2"
	' _ "$NAMED_WRAPPER" "$SAMPLE_PATH"

printf 'PASS: named current DST1 transcript acceptance test passed\n'
