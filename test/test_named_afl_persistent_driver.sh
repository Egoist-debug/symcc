#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FILE="$ROOT_DIR/patch/fuzz/bind9/bin/named/resolver_afl_symcc_orchestrator.c"

if ! grep -Fq "load_persistent_loop_limit" "$SOURCE_FILE"; then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must load a configurable loop limit\n' >&2
	exit 1
fi

if ! grep -Fq "NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS" "$SOURCE_FILE"; then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must expose persistent iteration tuning\n' >&2
	exit 1
fi

if ! grep -Fq "__AFL_LOOP(persistent_loop_limit)" "$SOURCE_FILE"; then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must pass the configured limit to __AFL_LOOP\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"for \(int loop = 0; __AFL_LOOP\(persistent_loop_limit\); loop\+\+\) \{.*?\n\t\t\}",
    source,
    re.S,
)
if not match:
    raise SystemExit(1)

after_loop = source[match.end():match.end() + 256]
if "print_stats_and_exit(orchestrator);" not in after_loop:
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must exit cleanly when the AFL loop ends\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
execute = source.find("result = execute_input_case(orchestrator, afl_request")
if execute < 0:
    raise SystemExit(1)

match = re.search(
    r"if \(result == ISC_R_TIMEDOUT\) \{(?P<body>.*?)\n\t\t\t\}",
    source[execute:],
    re.S,
)
if not match:
    raise SystemExit(1)

body = match.group("body")
if "shutdown_named()" in body or "return NULL" in body:
    raise SystemExit(1)
if "continue;" not in body:
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc per-case timeout must continue the AFL loop instead of shutting down named\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"resolver_afl_symcc_request_connected\(isc_nmhandle_t \*handle,.*?\n\}",
    source,
    re.S,
)
if not match:
    raise SystemExit(1)

body = match.group(0)
timeout_check = body.find("timed_out = ctx->timed_out;")
handle_data = body.find("isc_nmhandle_getdata(handle)")
if timeout_check < 0 or handle_data < 0 or timeout_check > handle_data:
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc connect callback must check timeout before attaching ns_client state\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"resolver_afl_symcc_request_connected\(isc_nmhandle_t \*handle,.*?\n\}",
    source,
    re.S,
)
if not match:
    raise SystemExit(1)

body = match.group(0)
setup = body.find("ns__client_setup")
ready = body.find("client->state = NS_CLIENTSTATE_READY;")
request = body.find("ns_client_request")
if setup < 0 or ready < 0 or request < 0 or not (setup < ready < request):
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc connect callback must mark ns_client READY before request/cancel paths\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"resolver_afl_symcc_request_done_notify\(void\) \{(?P<body>.*?)\n\}",
    source,
    re.S,
)
if not match:
    raise SystemExit(1)

body = match.group("body")
if "get_request_context" in body or "finish_request_context" in body:
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc done notify must not finish the global request context\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"resolver_afl_symcc_client_sendcb\(isc_buffer_t \*buffer\) \{(?P<body>.*?)\n\}",
    source,
    re.S,
)
if not match:
    raise SystemExit(1)

body = match.group("body")
reply_sent = body.find("ctx->reply_sent = true;")
finish = body.find("finish_request_context(ctx, ISC_R_SUCCESS);")
if reply_sent < 0 or finish < 0 or reply_sent > finish:
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc sendcb must complete successful request contexts\n' >&2
	exit 1
fi

if ! python3 - "$SOURCE_FILE" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(
    r"if \(rc == ETIMEDOUT\) \{(?P<body>.*?)\n\t\t\}",
    source,
    re.S,
)
if not match:
    raise SystemExit(1)

body = match.group("body")
if "ctx->result = ISC_R_TIMEDOUT;" not in body:
    raise SystemExit(1)
if "if (ctx->result == ISC_R_UNSET)" in body:
    raise SystemExit(1)
PY
then
	printf 'ASSERT FAIL: resolver-afl-symcc timedwait timeout must force ISC_R_TIMEDOUT\n' >&2
	exit 1
fi

if grep -Fq "raise(SIGSTOP)" "$SOURCE_FILE"; then
	printf 'ASSERT FAIL: resolver-afl-symcc persistent driver must not hand-roll SIGSTOP\n' >&2
	exit 1
fi

printf 'PASS: named AFL persistent driver uses AFL loop handshake\n'
