#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONPATH_VALUE="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
UNBOUND_WRAPPER="$ROOT_DIR/unbound_experiment/run_unbound_afl_symcc.sh"
NAMED_WRAPPER="$ROOT_DIR/named_experiment/run_named_afl_symcc.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/symcc-dns-diff-defaults.XXXXXX")"
ISOLATED_ROOT="$WORKDIR/isolated-root"
export PYTHONDONTWRITEBYTECODE=1

cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

locked_tag_for() {
	local resolver="$1"

	python3 - "$ROOT_DIR/experiments/resolvers.lock.json" "$resolver" <<'PY'
import json
import pathlib
import sys

lock_path = pathlib.Path(sys.argv[1])
resolver = sys.argv[2]
payload = json.loads(lock_path.read_text(encoding="utf-8"))
for entry in payload.get("resolvers", []):
    if entry.get("resolver") != resolver:
        continue
    print(entry.get("resolved_tag") or entry.get("desired_tag") or "")
    raise SystemExit(0)
raise SystemExit(1)
PY
}

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

assert_file_empty() {
	local path="$1"
	assert_file_exists "$path"
	if [ -s "$path" ]; then
		printf 'ASSERT FAIL: 期望空文件 %s\n' "$path" >&2
		printf '实际内容:\n' >&2
		cat "$path" >&2
		exit 1
	fi
}

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

assert_path_absent() {
	local path="$1"
	if [ -e "$path" ]; then
		printf 'ASSERT FAIL: 路径本不应存在 %s\n' "$path" >&2
		exit 1
	fi
}

BIND9_TAG="$(locked_tag_for bind9)"
UNBOUND_TAG="$(locked_tag_for unbound)"
EXPECTED_BIND9_AFL_TREE="$ROOT_DIR/experiments/subjects/bind9/${BIND9_TAG}-afl"
EXPECTED_UNBOUND_SRC_TREE="$ROOT_DIR/experiments/subjects/unbound/$UNBOUND_TAG"
EXPECTED_UNBOUND_AFL_TREE="$ROOT_DIR/experiments/subjects/unbound/${UNBOUND_TAG}-afl"

mkdir -p "$ISOLATED_ROOT"

PATH_HELPER_ROOT="$WORKDIR/path-helper-root"
mkdir -p "$PATH_HELPER_ROOT"

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PYTHONPATH_VALUE" python3 - "$PATH_HELPER_ROOT" <<'PY'
import stat
import sys
from pathlib import Path

from tools.dns_diff.path_defaults import (
    resolve_cache_dump_dir,
    resolve_dnsmasq_build_tree,
    resolve_dnslabctl_bin,
    resolve_knot_resolver_build_tree,
    resolve_maradns_binary,
    resolve_maradns_build_tree,
    resolve_response_corpus_dir,
    resolve_smartdns_binary,
    resolve_smartdns_build_tree,
)

root = Path(sys.argv[1]).resolve()
smart_tag = "smartdns-test-tag"
maradns_tag = "maradns-test-tag"
dnsmasq_tag = "dnsmasq-test-tag"
knot_tag = "knot-test-tag"

expected_smartdns_build = (
    root / "experiments" / "subjects" / "smartdns" / f"{smart_tag}-build"
).resolve()
expected_maradns_build = (
    root / "experiments" / "subjects" / "maradns" / f"{maradns_tag}-build"
).resolve()
expected_dnsmasq_build = (
    root / "experiments" / "subjects" / "dnsmasq" / f"{dnsmasq_tag}-build"
).resolve()
expected_knot_build = (
    root / "experiments" / "subjects" / "knot-resolver" / f"{knot_tag}-build"
).resolve()

checks = {
    "resolve_smartdns_build_tree(tag_override)": resolve_smartdns_build_tree(
        root, environ={"SMARTDNS_TAG": smart_tag}
    )
    == expected_smartdns_build,
    "resolve_maradns_build_tree(tag_override)": resolve_maradns_build_tree(
        root, environ={"MARADNS_TAG": maradns_tag}
    )
    == expected_maradns_build,
    "resolve_dnsmasq_build_tree(tag_override)": resolve_dnsmasq_build_tree(
        root, environ={"DNSMASQ_TAG": dnsmasq_tag}
    )
    == expected_dnsmasq_build,
    "resolve_knot_resolver_build_tree(tag_override)": resolve_knot_resolver_build_tree(
        root, environ={"KNOT_RESOLVER_TAG": knot_tag}
    )
    == expected_knot_build,
}

smartdns_override = (root / "override-smartdns-build").resolve()
maradns_override = (root / "override-maradns-build").resolve()
dnslabctl_override = (root / "override-bin" / "dnslabctl").resolve()
checks["resolve_smartdns_build_tree(env_override)"] = resolve_smartdns_build_tree(
    root,
    environ={"SMARTDNS_BUILD_TREE": str(smartdns_override)},
) == smartdns_override
checks["resolve_maradns_build_tree(env_override)"] = resolve_maradns_build_tree(
    root,
    environ={"MARADNS_BUILD_TREE": str(maradns_override)},
) == maradns_override
checks["resolve_dnslabctl_bin(default)"] = resolve_dnslabctl_bin(root) == (
    root / "build" / "linux" / "x86_64" / "release" / "dnslabctl"
).resolve()
checks["resolve_dnslabctl_bin(env_override)"] = resolve_dnslabctl_bin(
    root,
    environ={"DNSLABCTL_BIN": str(dnslabctl_override)},
) == dnslabctl_override

expected_work = (root / "unbound_experiment" / "work_stateful").resolve()
expected_response_corpus = (expected_work / "response_corpus").resolve()
expected_cache_dump_dir = (expected_work / "cache_dumps").resolve()
response_override = (root / "override-response-corpus").resolve()
checks["resolve_response_corpus_dir(default)"] = resolve_response_corpus_dir(
    expected_work,
    environ={},
) == expected_response_corpus
checks["resolve_response_corpus_dir(env_override)"] = resolve_response_corpus_dir(
    expected_work,
    environ={"RESPONSE_CORPUS_DIR": str(response_override)},
) == response_override
checks["resolve_cache_dump_dir(default)"] = resolve_cache_dump_dir(expected_work) == expected_cache_dump_dir

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit(f"ASSERT FAIL: path_defaults build tree helper 校验失败 {failed}")

smartdns_candidate = expected_smartdns_build / "smartdns-build" / "src" / "smartdns"
smartdns_candidate.parent.mkdir(parents=True, exist_ok=True)
smartdns_candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
smartdns_candidate.chmod(
    smartdns_candidate.stat().st_mode
    | stat.S_IXUSR
    | stat.S_IXGRP
    | stat.S_IXOTH
)
if resolve_smartdns_binary(expected_smartdns_build) != smartdns_candidate.resolve():
    raise SystemExit(
        "ASSERT FAIL: resolve_smartdns_binary 未命中兼容 smartdns-build/src/smartdns"
    )

maradns_candidate = expected_maradns_build / "deadwood-github" / "src" / "Deadwood"
maradns_candidate.parent.mkdir(parents=True, exist_ok=True)
maradns_candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
maradns_candidate.chmod(
    maradns_candidate.stat().st_mode
    | stat.S_IXUSR
    | stat.S_IXGRP
    | stat.S_IXOTH
)
if resolve_maradns_binary(expected_maradns_build) != maradns_candidate.resolve():
    raise SystemExit(
        "ASSERT FAIL: resolve_maradns_binary 未命中兼容 deadwood-github/src/Deadwood"
    )

smartdns_fallback_root = (root / "smartdns-fallback").resolve()
maradns_fallback_root = (root / "maradns-fallback").resolve()
if resolve_smartdns_binary(smartdns_fallback_root) != (
    smartdns_fallback_root / "src" / "smartdns"
):
    raise SystemExit("ASSERT FAIL: resolve_smartdns_binary fallback 路径不符合预期")
if resolve_maradns_binary(maradns_fallback_root) != (
    maradns_fallback_root / "deadwood-github" / "src" / "Deadwood"
):
    raise SystemExit("ASSERT FAIL: resolve_maradns_binary fallback 路径不符合预期")
PY

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PYTHONPATH_VALUE" python3 - "$ISOLATED_ROOT" <<'PY'
import sys
from pathlib import Path

from tools.dns_diff.follow_diff import (
    default_bind9_work_dir,
    default_follow_diff_output_root,
    default_follow_diff_source_dir,
    default_follow_diff_work_dir,
    resolve_bind9_work_dir,
    resolve_follow_diff_source_dir,
    resolve_follow_diff_work_dir,
)
from tools.dns_diff.report import (
    default_follow_diff_root,
    default_high_value_manifest_path,
    resolve_high_value_manifest_path,
)

root = Path(sys.argv[1]).resolve()
expected_work = (root / "unbound_experiment" / "work_stateful").resolve()
expected_bind9_work = (root / "named_experiment" / "work").resolve()
expected_source = (expected_bind9_work / "afl_out" / "master" / "queue").resolve()
isolated_work = (root / "isolated-work").resolve()
explicit_bind9_work = (root / "explicit-bind9-work").resolve()
expected_follow_root = (expected_work / "follow_diff").resolve()
expected_manifest = (expected_work / "high_value_samples.txt").resolve()
custom_root = (root / "custom-follow-diff").resolve()

checks = {
    "default_follow_diff_work_dir": default_follow_diff_work_dir(root) == expected_work,
    "resolve_follow_diff_work_dir": resolve_follow_diff_work_dir(
        root_dir=root, environ={}
    )
    == expected_work,
    "default_bind9_work_dir": default_bind9_work_dir(root) == expected_bind9_work,
    "resolve_bind9_work_dir": resolve_bind9_work_dir(root_dir=root, environ={})
    == expected_bind9_work,
    "resolve_bind9_work_dir(work_dir_override)": resolve_bind9_work_dir(
        root_dir=root,
        environ={"WORK_DIR": str(isolated_work)},
    )
    == isolated_work,
    "resolve_bind9_work_dir(bind9_override)": resolve_bind9_work_dir(
        root_dir=root,
        environ={
            "WORK_DIR": str(isolated_work),
            "BIND9_WORK_DIR": str(explicit_bind9_work),
        },
    )
    == explicit_bind9_work,
    "default_follow_diff_source_dir": default_follow_diff_source_dir(expected_bind9_work)
    == expected_source,
    "resolve_follow_diff_source_dir": resolve_follow_diff_source_dir(
        root_dir=root, environ={}
    )
    == expected_source,
    "resolve_follow_diff_source_dir(work_dir_override)": resolve_follow_diff_source_dir(
        root_dir=root,
        environ={"WORK_DIR": str(isolated_work)},
    )
    == (isolated_work / "afl_out" / "master" / "queue").resolve(),
    "resolve_follow_diff_source_dir(bind9_override)": resolve_follow_diff_source_dir(
        root_dir=root,
        environ={
            "WORK_DIR": str(isolated_work),
            "BIND9_WORK_DIR": str(explicit_bind9_work),
        },
    )
    == (explicit_bind9_work / "afl_out" / "master" / "queue").resolve(),
    "default_follow_diff_output_root": default_follow_diff_output_root(expected_work)
    == expected_follow_root,
    "report.default_follow_diff_root": default_follow_diff_root(work_dir=expected_work)
    == expected_follow_root,
    "default_high_value_manifest_path(default_root)": default_high_value_manifest_path(
        expected_follow_root, work_dir=expected_work
    )
    == expected_manifest,
    "resolve_high_value_manifest_path(default_root)": resolve_high_value_manifest_path(
        expected_follow_root, work_dir=expected_work, environ={}
    )
    == expected_manifest,
    "default_high_value_manifest_path(custom_root)": default_high_value_manifest_path(
        custom_root, work_dir=expected_work
    )
    == (custom_root / "high_value_samples.txt").resolve(),
    "resolve_high_value_manifest_path(custom_root)": resolve_high_value_manifest_path(
        custom_root, work_dir=expected_work, environ={}
    )
    == (custom_root / "high_value_samples.txt").resolve(),
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit(f"ASSERT FAIL: 默认路径 helper 校验失败 {failed}")
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ISOLATED_ROOT" \
	DNS_DIFF_CLI_BACKEND=python \
	python3 -m tools.dns_diff.cli follow-diff-once >/dev/null
assert_dir_exists "$ISOLATED_ROOT/unbound_experiment/work_stateful/follow_diff"
assert_file_exists "$ISOLATED_ROOT/unbound_experiment/work_stateful/follow_diff.state.json"
assert_path_absent "$ISOLATED_ROOT/unbound_experiment/work_stateful/afl_out/master/queue"

WORK_OVERRIDE="$WORKDIR/work-override"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ISOLATED_ROOT" \
	WORK_DIR="$WORK_OVERRIDE" \
	DNS_DIFF_CLI_BACKEND=python \
	python3 -m tools.dns_diff.cli follow-diff-once >/dev/null
assert_dir_exists "$WORK_OVERRIDE/follow_diff"
assert_file_exists "$WORK_OVERRIDE/follow_diff.state.json"
assert_path_absent "$WORK_OVERRIDE/afl_out/master/queue"

UNBOUND_DEFAULT_TRACE="$WORKDIR/unbound-default.trace"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORK_OVERRIDE" \
	bash -x "$UNBOUND_WRAPPER" follow-diff-once >/dev/null 2>"$UNBOUND_DEFAULT_TRACE"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "WORK_DIR=$WORK_OVERRIDE"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "BIND9_WORK_DIR=$WORK_OVERRIDE"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "FOLLOW_DIFF_SOURCE_DIR=$WORK_OVERRIDE/afl_out/master/queue"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "SRC_TREE=$EXPECTED_UNBOUND_SRC_TREE"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "AFL_TREE=$EXPECTED_UNBOUND_AFL_TREE"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "BIND9_AFL_TREE=$EXPECTED_BIND9_AFL_TREE"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "REPORT_HIGH_VALUE_MANIFEST=$WORK_OVERRIDE/high_value_samples.txt"
assert_file_contains "$UNBOUND_DEFAULT_TRACE" "SYMCC_HIGH_VALUE_MANIFEST=$WORK_OVERRIDE/high_value_samples.txt"

BIND9_WORK_OVERRIDE="$WORKDIR/bind9-work-override"
UNBOUND_BIND9_TRACE="$WORKDIR/unbound-bind9.trace"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$WORK_OVERRIDE" \
	BIND9_WORK_DIR="$BIND9_WORK_OVERRIDE" \
	bash -x "$UNBOUND_WRAPPER" follow-diff-once >/dev/null 2>"$UNBOUND_BIND9_TRACE"
assert_file_contains "$UNBOUND_BIND9_TRACE" "WORK_DIR=$WORK_OVERRIDE"
assert_file_contains "$UNBOUND_BIND9_TRACE" "BIND9_WORK_DIR=$BIND9_WORK_OVERRIDE"
assert_file_contains "$UNBOUND_BIND9_TRACE" "FOLLOW_DIFF_SOURCE_DIR=$BIND9_WORK_OVERRIDE/afl_out/master/queue"

SOURCE_WORK="$WORKDIR/source-work"
DEFAULT_SOURCE_WORK="$WORKDIR/default-named-work"
DEFAULT_QUEUE="$DEFAULT_SOURCE_WORK/afl_out/master/queue"
OVERRIDE_QUEUE="$WORKDIR/override-queue"
mkdir -p "$DEFAULT_QUEUE" "$OVERRIDE_QUEUE"
printf '\x10\x20\x30\x40' >"$DEFAULT_QUEUE/id:000001,orig:default"
printf '\xaa\xbb\xcc\xdd' >"$OVERRIDE_QUEUE/id:000002,orig:override"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ISOLATED_ROOT" \
	WORK_DIR="$SOURCE_WORK" \
	BIND9_WORK_DIR="$DEFAULT_SOURCE_WORK" \
	FOLLOW_DIFF_SOURCE_DIR="$OVERRIDE_QUEUE" \
	DNS_DIFF_CLI_BACKEND=python \
	python3 -m tools.dns_diff.cli follow-diff-once >/dev/null

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PYTHONPATH_VALUE" python3 - "$SOURCE_WORK/follow_diff" "$DEFAULT_QUEUE/id:000001,orig:default" "$OVERRIDE_QUEUE/id:000002,orig:override" <<'PY'
import hashlib
import sys
from pathlib import Path

follow_root = Path(sys.argv[1]).resolve()
default_queue_file = Path(sys.argv[2]).resolve()
override_queue_file = Path(sys.argv[3]).resolve()

def sample_id(queue_file: Path) -> str:
    digest = hashlib.sha1(queue_file.read_bytes()).hexdigest()
    return f"{queue_file.name}__{digest[:8]}"

default_sample_dir = follow_root / sample_id(default_queue_file)
override_sample_dir = follow_root / sample_id(override_queue_file)

if default_sample_dir.exists():
    raise SystemExit(
        f"ASSERT FAIL: FOLLOW_DIFF_SOURCE_DIR override 未生效，错误消费默认 queue {default_sample_dir}"
    )
if not override_sample_dir.is_dir():
    raise SystemExit(
        f"ASSERT FAIL: FOLLOW_DIFF_SOURCE_DIR override 样本未落盘 {override_sample_dir}"
    )
PY

UNBOUND_SOURCE_TRACE="$WORKDIR/unbound-source.trace"
env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$SOURCE_WORK" \
	BIND9_WORK_DIR="$DEFAULT_SOURCE_WORK" \
	FOLLOW_DIFF_SOURCE_DIR="$OVERRIDE_QUEUE" \
	bash -x "$UNBOUND_WRAPPER" follow-diff-once >/dev/null 2>"$UNBOUND_SOURCE_TRACE"
assert_file_contains "$UNBOUND_SOURCE_TRACE" "FOLLOW_DIFF_SOURCE_DIR=$OVERRIDE_QUEUE"

REPORT_WORK="$WORKDIR/report-work"
DEFAULT_MANIFEST_OVERRIDE="$WORKDIR/default-override.manifest"
CUSTOM_REPORT_ROOT="$WORKDIR/custom-follow-root"
CUSTOM_MANIFEST_OVERRIDE="$WORKDIR/custom-override.manifest"
mkdir -p "$CUSTOM_REPORT_ROOT"

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PYTHONPATH_VALUE" python3 - "$REPORT_WORK" "$CUSTOM_REPORT_ROOT" "$DEFAULT_MANIFEST_OVERRIDE" "$CUSTOM_MANIFEST_OVERRIDE" <<'PY'
import sys
from pathlib import Path

from tools.dns_diff.report import default_follow_diff_root, resolve_high_value_manifest_path

work_dir = Path(sys.argv[1]).resolve()
custom_root = Path(sys.argv[2]).resolve()
default_manifest = Path(sys.argv[3]).resolve()
custom_manifest = Path(sys.argv[4]).resolve()
default_root = default_follow_diff_root(work_dir=work_dir)

if resolve_high_value_manifest_path(
    default_root,
    work_dir=work_dir,
    environ={"SYMCC_HIGH_VALUE_MANIFEST": str(default_manifest)},
) != default_manifest:
    raise SystemExit("ASSERT FAIL: default root manifest env override 未生效")

if resolve_high_value_manifest_path(
    custom_root,
    work_dir=work_dir,
    environ={"SYMCC_HIGH_VALUE_MANIFEST": str(custom_manifest)},
) != custom_manifest:
    raise SystemExit("ASSERT FAIL: custom root manifest env override 未生效")
PY

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ISOLATED_ROOT" \
	WORK_DIR="$REPORT_WORK" \
	SYMCC_HIGH_VALUE_MANIFEST="$DEFAULT_MANIFEST_OVERRIDE" \
	DNS_DIFF_CLI_BACKEND=python \
	python3 -m tools.dns_diff.cli triage-report >/dev/null
assert_file_empty "$DEFAULT_MANIFEST_OVERRIDE"
assert_path_absent "$REPORT_WORK/high_value_samples.txt"

env \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH="$PYTHONPATH_VALUE" \
	ROOT_DIR="$ISOLATED_ROOT" \
	WORK_DIR="$REPORT_WORK" \
	SYMCC_HIGH_VALUE_MANIFEST="$CUSTOM_MANIFEST_OVERRIDE" \
	DNS_DIFF_CLI_BACKEND=python \
	python3 -m tools.dns_diff.cli report --root "$CUSTOM_REPORT_ROOT" >/dev/null
assert_file_empty "$CUSTOM_MANIFEST_OVERRIDE"
assert_path_absent "$CUSTOM_REPORT_ROOT/high_value_samples.txt"

NAMED_TRACE="$WORKDIR/named.trace"
NAMED_WORK_GENERIC="$WORKDIR/named-work-generic"
NAMED_WORK_SPECIFIC="$WORKDIR/named-work-specific"
NAMED_MANIFEST_OVERRIDE="$WORKDIR/named-override.manifest"
if ! env \
	PYTHONDONTWRITEBYTECODE=1 \
	WORK_DIR="$NAMED_WORK_GENERIC" \
	BIND9_WORK_DIR="$NAMED_WORK_SPECIFIC" \
	SYMCC_HIGH_VALUE_MANIFEST="$NAMED_MANIFEST_OVERRIDE" \
	bash -x "$NAMED_WRAPPER" help >/dev/null 2>"$NAMED_TRACE"
then
	:
fi
assert_file_contains "$NAMED_TRACE" "WORK_DIR=$NAMED_WORK_SPECIFIC"
assert_file_contains "$NAMED_TRACE" "BIND9_WORK_DIR=$NAMED_WORK_SPECIFIC"
assert_file_contains "$NAMED_TRACE" "NAMED_HIGH_VALUE_MANIFEST=$NAMED_WORK_SPECIFIC/high_value_samples.txt"
assert_file_contains "$NAMED_TRACE" "SYMCC_HIGH_VALUE_MANIFEST=$NAMED_MANIFEST_OVERRIDE"

echo "PASS: dns-diff defaults regression test passed"
