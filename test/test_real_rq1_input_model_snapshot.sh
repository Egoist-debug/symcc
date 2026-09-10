#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%d_%H%M%S)"
# 默认路径保持 CI 宿主机布局；本地/其他环境用 env 覆盖。
OUT_BASE="${REAL_RQ1_OUT_BASE:-${TMPDIR:-/tmp}/rq1_input_model_snapshot}"
BIND9_TREE="${REAL_RQ1_BIND9_TREE:-$ROOT_DIR/experiments/subjects/bind9/v9.20.22-afl}"
OUT_DIR="$OUT_BASE/$STAMP"
RESP_DIR="$OUT_DIR/legacy_responses"
mkdir -p "$RESP_DIR"

python3 - "$OUT_DIR" <<'PY'
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
(root / 'random.bin').write_bytes(b'\x99\x88\x77\x66\x55\x44\x33\x22')
(root / 'legacy_responses' / 'resp.bin').write_bytes(response)
PY

python3 -m tools.dns_diff.cli input-model-eval \
  --output-dir "$OUT_DIR/out" \
  --bind9-tree "$BIND9_TREE" \
  --named-conf-template "$ROOT_DIR/named_experiment/runtime/named.conf" \
  --dst1-input "$OUT_DIR/dst1.bin" \
  --query-only-input "$OUT_DIR/query.bin" \
  --random-input "$OUT_DIR/random.bin" \
  --legacy-input "$OUT_DIR/legacy.bin" \
  --legacy-response-dir "$RESP_DIR"

printf 'PASS: real RQ1 input model snapshot generated at %s\n' "$OUT_DIR"
