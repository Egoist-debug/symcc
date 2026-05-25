#!/usr/bin/env bash

resolver_normalize_name() {
	case "$1" in
		knot) printf 'knot-resolver' ;;
		*) printf '%s' "$1" ;;
	esac
}

resolver_locked_tag() {
	local resolver
	local fallback="$2"
	local dnslabctl_bin="${DNSLABCTL_BIN:-$ROOT_DIR/build/linux/x86_64/release/dnslabctl}"
	local lock_file="${RESOLVERS_LOCK_FILE:-$ROOT_DIR/experiments/resolvers.lock.json}"
	resolver="$(resolver_normalize_name "$1")"

	if [ -x "$dnslabctl_bin" ] && [ -f "$lock_file" ]; then
		if "$dnslabctl_bin" lock-resolved-tag --lock-file "$lock_file" --resolver "$resolver" 2>/dev/null; then
			return 0
		fi
	fi

	python3 - "$lock_file" "$resolver" "$fallback" <<'PY'
import json
import pathlib
import sys

lock_file = pathlib.Path(sys.argv[1])
resolver = sys.argv[2]
fallback = sys.argv[3]
if lock_file.is_file():
    try:
        payload = json.loads(lock_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        payload = {}
    for entry in payload.get("resolvers", []):
        if entry.get("resolver") != resolver:
            continue
        tag = (entry.get("resolved_tag") or entry.get("desired_tag") or "").strip()
        if tag:
            print(tag)
            raise SystemExit(0)
print(fallback)
PY
}

resolver_src_root() {
	local resolver
	local tag
	resolver="$(resolver_normalize_name "$1")"
	case "$resolver" in
		bind9)
			tag="${BIND9_TAG:-$(resolver_locked_tag bind9 v9.20.22)}"
			printf '%s\n' "${BIND9_SRC_TREE:-$ROOT_DIR/experiments/subjects/bind9/$tag}"
			;;
		unbound)
			tag="${UNBOUND_TAG:-$(resolver_locked_tag unbound release-1.24.2)}"
			printf '%s\n' "${UNBOUND_SRC_TREE:-$ROOT_DIR/experiments/subjects/unbound/$tag}"
			;;
		dnsmasq)
			tag="${DNSMASQ_TAG:-$(resolver_locked_tag dnsmasq v2.92)}"
			printf '%s\n' "${DNSMASQ_SRC_TREE:-$ROOT_DIR/experiments/subjects/dnsmasq/$tag}"
			;;
		smartdns)
			tag="${SMARTDNS_TAG:-$(resolver_locked_tag smartdns Release47.1)}"
			printf '%s\n' "${SMARTDNS_SRC_TREE:-$ROOT_DIR/experiments/subjects/smartdns/$tag}"
			;;
		maradns)
			tag="${MARADNS_TAG:-$(resolver_locked_tag maradns deadwood-3.3.02)}"
			printf '%s\n' "${MARADNS_SRC_TREE:-$ROOT_DIR/experiments/subjects/maradns/$tag}"
			;;
		knot-resolver)
			tag="${KNOT_RESOLVER_TAG:-$(resolver_locked_tag knot-resolver v6.2.0)}"
			printf '%s\n' "${KNOT_RESOLVER_SRC_TREE:-$ROOT_DIR/experiments/subjects/knot-resolver/$tag}"
			;;
		*)
			printf '未知 resolver: %s\n' "$resolver" >&2
			return 1
			;;
	esac
}

resolver_build_root() {
	local resolver
	local tag
	resolver="$(resolver_normalize_name "$1")"
	case "$resolver" in
		unbound)
			tag="${UNBOUND_TAG:-$(resolver_locked_tag unbound release-1.24.2)}"
			printf '%s\n' "${UNBOUND_BUILD_ROOT:-$ROOT_DIR/experiments/subjects/unbound/${tag}-build}"
			;;
		dnsmasq)
			tag="${DNSMASQ_TAG:-$(resolver_locked_tag dnsmasq v2.92)}"
			printf '%s\n' "${DNSMASQ_BUILD_TREE:-$ROOT_DIR/experiments/subjects/dnsmasq/${tag}-build}"
			;;
		smartdns)
			tag="${SMARTDNS_TAG:-$(resolver_locked_tag smartdns Release47.1)}"
			printf '%s\n' "${SMARTDNS_BUILD_TREE:-$ROOT_DIR/experiments/subjects/smartdns/${tag}-build}"
			;;
		maradns)
			tag="${MARADNS_TAG:-$(resolver_locked_tag maradns deadwood-3.3.02)}"
			printf '%s\n' "${MARADNS_BUILD_TREE:-$ROOT_DIR/experiments/subjects/maradns/${tag}-build}"
			;;
		knot-resolver)
			tag="${KNOT_RESOLVER_TAG:-$(resolver_locked_tag knot-resolver v6.2.0)}"
			printf '%s\n' "${KNOT_RESOLVER_BUILD_TREE:-$ROOT_DIR/experiments/subjects/knot-resolver/${tag}-build}"
			;;
		*)
			printf '未知 resolver: %s\n' "$resolver" >&2
			return 1
			;;
	esac
}

bind9_afl_tree() {
	local tag="${BIND9_TAG:-$(resolver_locked_tag bind9 v9.20.22)}"
	local preferred="${ROOT_DIR}/experiments/subjects/bind9/${tag}-build/bind9-afl"
	local legacy="${ROOT_DIR}/experiments/subjects/bind9/${tag}-afl"
	if [ -n "${BIND9_AFL_TREE:-}" ]; then
		printf '%s\n' "$BIND9_AFL_TREE"
	elif [ -d "$preferred" ]; then
		printf '%s\n' "$preferred"
	else
		printf '%s\n' "$legacy"
	fi
}

bind9_symcc_tree() {
	local tag="${BIND9_TAG:-$(resolver_locked_tag bind9 v9.20.22)}"
	local preferred="${ROOT_DIR}/experiments/subjects/bind9/${tag}-build/bind9-symcc"
	local legacy="${ROOT_DIR}/experiments/subjects/bind9/${tag}-symcc"
	if [ -n "${BIND9_SYMCC_TREE:-}" ]; then
		printf '%s\n' "$BIND9_SYMCC_TREE"
	elif [ -d "$preferred" ]; then
		printf '%s\n' "$preferred"
	else
		printf '%s\n' "$legacy"
	fi
}

unbound_afl_tree() {
	local tag="${UNBOUND_TAG:-$(resolver_locked_tag unbound release-1.24.2)}"
	local preferred="${ROOT_DIR}/experiments/subjects/unbound/${tag}-build/unbound-afl"
	local legacy="${ROOT_DIR}/experiments/subjects/unbound/${tag}-afl"
	if [ -n "${AFL_TREE:-}" ]; then
		printf '%s\n' "$AFL_TREE"
	elif [ -d "$preferred" ]; then
		printf '%s\n' "$preferred"
	else
		printf '%s\n' "$legacy"
	fi
}

default_response_corpus_dir() {
	local named_dir="$ROOT_DIR/named_experiment/work/response_corpus"
	local unbound_dir="$ROOT_DIR/unbound_experiment/work_stateful/response_corpus"
	if [ -d "$named_dir" ]; then
		printf '%s\n' "$named_dir"
	else
		printf '%s\n' "$unbound_dir"
	fi
}
