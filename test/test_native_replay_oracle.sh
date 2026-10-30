#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/a3-native-XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
BIND="$ROOT/experiments/subjects/bind9/v9.20.22-afl"
UB="$ROOT/experiments/subjects/unbound/release-1.24.2-build/unbound-afl"
COMMON=(-std=gnu11 -ffunction-sections -fdata-sections -I"$ROOT" -pthread)
read -r -a EXTRA_FLAGS <<< "${CFLAGS:-}"
COMMON+=("${EXTRA_FLAGS[@]}")
LIBPATH="$BIND/lib/dns/.libs:$BIND/lib/isc/.libs"
run_native() {
    if ! "$@" >"$TMP/oracle.log" 2>&1; then
        cat "$TMP/oracle.log"
        return 1
    fi
    PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -B - "$TMP/oracle.log" <<'PY'
import sys
from pathlib import Path
from tools.dns_diff.oracle import parse_oracle_summary

lines = Path(sys.argv[1]).read_text().splitlines()
oracle = None
checks = 0
for line in lines:
    if line.startswith("ORACLE_SUMMARY "):
        oracle = parse_oracle_summary(line, "native")
    elif line.startswith("ORACLE_EXPECT "):
        assert oracle is not None
        assert oracle["native.stderr_parse_status"] == "ok"
        assert isinstance(oracle["native.fake_reply_dispatched"], bool)
        for token in line.split()[1:]:
            key, value = token.split("=")
            assert oracle["native." + key] == bool(int(value)), (line, oracle)
        assert oracle["native.cache_entry_created"] == oracle["native.second_query_hit"]
        oracle = None
        checks += 1
assert checks > 0
assert lines[-1] == f"PASS: native replay oracle ({checks} checks)"
print(lines[-1] + "；最终 summary 解析一致")
PY
}
for variant in cache fuzz; do
    "${CC:-gcc}" "${COMMON[@]}" -DTEST_BIND \
        "-DNATIVE_SOURCE=\"patch/$variant/bind9/bin/named/resolver_afl_symcc_orchestrator.c\"" \
        -include "$BIND/config.h" -I"$BIND" -I"$BIND/include" \
        -I"$ROOT/patch/$variant/bind9/include" -I"$BIND/bin/named/include" \
        -I"$BIND/lib/isc/include" -I"$BIND/lib/dns/include" -I"$BIND/lib/ns/include" \
        -I"$BIND/lib/isccfg/include" -I"$BIND/lib/isccc/include" \
        "$ROOT/test/test_native_replay_oracle.c" \
        -Wl,--gc-sections -Wl,-rpath,"$BIND/lib/dns/.libs" -Wl,-rpath,"$BIND/lib/isc/.libs" \
        -L"$BIND/lib/dns/.libs" -L"$BIND/lib/isc/.libs" -ldns -lisc \
        /usr/local/lib/afl/afl-compiler-rt.o -lurcu -lurcu-common -luv -lcrypto \
        -o "$TMP/bind-$variant"
    LD_LIBRARY_PATH="$LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" run_native "$TMP/bind-$variant"
done
"${CC:-gcc}" "${COMMON[@]}" -I"$ROOT/patch/cache/unbound" -I"$UB" \
    "$ROOT/test/test_native_replay_oracle.c" -Wl,--gc-sections \
    "$UB/.libs/libunbound.a" -lssl -lcrypto -lexpat -ldl -lm \
    -o "$TMP/unbound"
run_native "$TMP/unbound"
