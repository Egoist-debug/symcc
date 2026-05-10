#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-bind9-bootstrap.XXXXXX")"

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

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

source "$SCRIPT_PATH"

TREE="$WORKDIR/bind9-git-tree"
FAKEBIN="$WORKDIR/fakebin"
AUTORECONF_LOG="$WORKDIR/autoreconf.log"

mkdir -p "$TREE" "$FAKEBIN"
touch "$TREE/configure.ac"

cat >"$FAKEBIN/autoreconf" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s::%s\n' "\$PWD" "\$*" >"$AUTORECONF_LOG"
cat > configure <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x configure
EOF
chmod +x "$FAKEBIN/autoreconf"

PATH="$FAKEBIN:$PATH"
ensure_bind9_configure_ready "$TREE"

[ -x "$TREE/configure" ] || {
	printf 'ASSERT FAIL: 期望生成可执行 configure: %s\n' "$TREE/configure" >&2
	exit 1
}
assert_file_contains "$AUTORECONF_LOG" "$TREE"
assert_file_contains "$AUTORECONF_LOG" "-fi"

printf 'PASS: named bind9 git bootstrap regression test passed\n'
