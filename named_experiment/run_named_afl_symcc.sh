#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_DIR="$ROOT_DIR/named_experiment"
PROFILE_DIR="$EXP_DIR/profiles"
DEFAULT_BIND9_WORK_DIR="$EXP_DIR/work"
BIND9_WORK_DIR="${BIND9_WORK_DIR:-${WORK_DIR:-$DEFAULT_BIND9_WORK_DIR}}"
WORK_DIR="$BIND9_WORK_DIR"
UNBOUND_REPORT_WORK_DIR="$ROOT_DIR/unbound_experiment/work_stateful"
NAMED_HIGH_VALUE_MANIFEST="$WORK_DIR/high_value_samples.txt"
UNBOUND_REPORT_HIGH_VALUE_MANIFEST="$UNBOUND_REPORT_WORK_DIR/high_value_samples.txt"
DEFAULT_SYMCC_HIGH_VALUE_MANIFEST="$NAMED_HIGH_VALUE_MANIFEST"
PATCH_ROOT="$ROOT_DIR/patch"
PATCH_VARIANT="${PATCH_VARIANT:-fuzz}"
RESOLVERS_LOCK_FILE="${RESOLVERS_LOCK_FILE:-$ROOT_DIR/experiments/resolvers.lock.json}"
LEGACY_SRC_TREE="$ROOT_DIR/bind-9.18.46"
LEGACY_AFL_TREE="$ROOT_DIR/bind-9.18.46-afl"
LEGACY_SYMCC_TREE="$ROOT_DIR/bind-9.18.46-symcc"
SRC_TREE="${SRC_TREE:-}"
AFL_TREE="${AFL_TREE:-}"
SYMCC_TREE="${SYMCC_TREE:-}"

HELPER_BIN="$ROOT_DIR/build/linux/x86_64/release/symcc_fuzzing_helper"
GEN_INPUT_BIN="$ROOT_DIR/build/linux/x86_64/release/gen_input"
DNSLABCTL_BIN="$ROOT_DIR/build/linux/x86_64/release/dnslabctl"
DST1_MUTATOR_LIBRARY="${DST1_MUTATOR_LIBRARY:-$ROOT_DIR/build/linux/x86_64/release/libafl_dst1_mutator.so}"
AFL_FUZZ_BIN="${AFL_FUZZ_BIN:-/usr/local/bin/afl-fuzz}"
AFL_CC_BIN="${AFL_CC_BIN:-/usr/local/bin/afl-clang-fast}"
SYMCC_CC_BIN="${SYMCC_CC_BIN:-$ROOT_DIR/build/linux/x86_64/release/symcc}"
SYMCC_CXX_BIN="${SYMCC_CXX_BIN:-$ROOT_DIR/build/linux/x86_64/release/sym++}"

BIN_DIR="$WORK_DIR/bin"
RUNTIME_STATE_DIR="$WORK_DIR/runtime"
NAMED_CONF_TEMPLATE="$EXP_DIR/runtime/named.conf"
NAMED_CONF="$RUNTIME_STATE_DIR/named.conf"
QUERY_CORPUS_DIR="$WORK_DIR/query_corpus"
STABLE_QUERY_CORPUS_DIR="$WORK_DIR/stable_query_corpus"
RESPONSE_CORPUS_DIR="$WORK_DIR/response_corpus"
TRANSCRIPT_CORPUS_DIR="$WORK_DIR/transcript_corpus"
STABLE_TRANSCRIPT_CORPUS_DIR="$WORK_DIR/stable_transcript_corpus"
TRANSCRIPT_SEED_MIX_DIR="$WORK_DIR/transcript_seed_mix"
QUERY_DRIVER="$WORK_DIR/driver_query.bin"
QUERY_PARSER_BIN="$BIN_DIR/dns_parser_sym"
RESPONSE_PARSER_BIN="$BIN_DIR/dns_response_parser_sym"
QUERY_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_parser.c"
RESPONSE_PARSER_SRC="$ROOT_DIR/gen_input/test/dns_response_parser.c"
LOG_DIR="$WORK_DIR/logs"
PID_DIR="$WORK_DIR/pids"
AFL_OUT_DIR="$WORK_DIR/afl_out"
SYMCC_OUTPUT_DIR="$WORK_DIR/symcc_output"
CACHE_DUMP_DIR="$WORK_DIR/cache_dumps"
QUERY_GEN_LOG="$WORK_DIR/query_gen.log"
RESPONSE_GEN_LOG="$WORK_DIR/response_gen.log"
TRANSCRIPT_GEN_LOG="$WORK_DIR/transcript_gen.log"
SEED_PROVENANCE_FILE="$WORK_DIR/producer_seed_provenance.json"
EXECUTION_MANIFEST_FILE="$WORK_DIR/producer_execution_manifest.json"

MASTER_LOG="$LOG_DIR/afl_master_persistent.log"
SECONDARY_LOG="$LOG_DIR/afl_secondary_persistent.log"
HELPER_LOG="$LOG_DIR/helper_persistent.log"
MASTER_PID="$PID_DIR/afl_master.pid"
SECONDARY_PID="$PID_DIR/afl_secondary.pid"
HELPER_PID="$PID_DIR/helper.pid"

MUTATOR_ADDR="${MUTATOR_ADDR:-127.0.0.1:55300}"
TARGET_ADDR="${TARGET_ADDR:-127.0.0.1:55301}"
REPLY_TIMEOUT_MS="${REPLY_TIMEOUT_MS:-}"
JOBS="${JOBS:-2}"
AFL_TIMEOUT_MS="${AFL_TIMEOUT_MS:-}"
SEED_TIMEOUT_SEC="${SEED_TIMEOUT_SEC:-15}"
ENABLE_SECONDARY="${ENABLE_SECONDARY:-}"
ENABLE_DST1_MUTATOR="${ENABLE_DST1_MUTATOR:-}"
ENABLE_SYMCC="${ENABLE_SYMCC:-}"
ENABLE_CACHE_DELTA="${ENABLE_CACHE_DELTA:-1}"
ENABLE_TRIAGE="${ENABLE_TRIAGE:-1}"
DST1_MUTATOR_ONLY="${DST1_MUTATOR_ONLY:-}"
SYMCC_FRONTIER_RELOAD_SEC="${SYMCC_FRONTIER_RELOAD_SEC:-}"
SYMCC_FRONTIER_RETRY_LIMIT="${SYMCC_FRONTIER_RETRY_LIMIT:-}"
SYMCC_SEMANTIC_FRONTIER_MANIFEST="${SYMCC_SEMANTIC_FRONTIER_MANIFEST:-}"
REGEN_SEEDS="${REGEN_SEEDS:-0}"
REFILTER_QUERIES="${REFILTER_QUERIES:-0}"
RESET_OUTPUT="${RESET_OUTPUT:-1}"
QUERY_MAX_ITER="${QUERY_MAX_ITER:-}"
RESPONSE_MAX_ITER="${RESPONSE_MAX_ITER:-}"
RESPONSE_QUERY_SEEDS="${RESPONSE_QUERY_SEEDS:-}"
TRANSCRIPT_MAX_ITER="${TRANSCRIPT_MAX_ITER:-}"
TRANSCRIPT_RESPONSE_SEEDS="${TRANSCRIPT_RESPONSE_SEEDS:-}"
TRANSCRIPT_MAX_RESPONSES="${TRANSCRIPT_MAX_RESPONSES:-3}"
RESPONSE_PRESERVE="${RESPONSE_PRESERVE:-20}"
TRANSCRIPT_FORMAT_VERSION="${TRANSCRIPT_FORMAT_VERSION:-2}"
RUN_DURATION_SEC="${RUN_DURATION_SEC:-180}"
FUZZ_PROFILE="${FUZZ_PROFILE:-poison-stateful}"
TRANSCRIPT_GEN_TARGET="${TRANSCRIPT_GEN_TARGET:-}"
HELPER_NAME="${HELPER_NAME:-symcc}"
HELPER_RUN_ROOT="${HELPER_RUN_ROOT:-$WORK_DIR}"
HELPER_RUN_NAME="${HELPER_RUN_NAME:-$(basename "$AFL_OUT_DIR")}"
USE_TMUX="${USE_TMUX:-1}"
SHOW_AFL_UI="${SHOW_AFL_UI:-1}"
MASTER_SESSION="${MASTER_SESSION:-named_afl_master}"
SECONDARY_SESSION="${SECONDARY_SESSION:-named_afl_secondary}"
HELPER_SESSION="${HELPER_SESSION:-named_symcc_helper}"
QUERY_CORPUS_GENERATED_THIS_RUN=0
RESPONSE_CORPUS_GENERATED_THIS_RUN=0
TRANSCRIPT_CORPUS_GENERATED_THIS_RUN=0
PRODUCER_RUN_ID="${PRODUCER_RUN_ID:-}"
PRODUCER_RANDOM_SEED="${PRODUCER_RANDOM_SEED:-}"
PRODUCER_VARIANT_NAME="${PRODUCER_VARIANT_NAME:-${VARIANT_NAME:-}}"
PRODUCER_REPEAT_INDEX="${PRODUCER_REPEAT_INDEX:-${REPEAT_INDEX:-}}"
AFL_MASTER_STARTED=""
AFL_SECONDARY_STARTED=""
SYMCC_HELPER_STARTED=""
if [ ! -r "$DEFAULT_SYMCC_HIGH_VALUE_MANIFEST" ]; then
	DEFAULT_SYMCC_HIGH_VALUE_MANIFEST="$UNBOUND_REPORT_HIGH_VALUE_MANIFEST"
fi
SYMCC_HIGH_VALUE_MANIFEST="${SYMCC_HIGH_VALUE_MANIFEST:-$DEFAULT_SYMCC_HIGH_VALUE_MANIFEST}"
export SYMCC_HIGH_VALUE_MANIFEST

usage() {
	cat <<'EOF'
用法:
  named_experiment/run_named_afl_symcc.sh <命令>

命令:
  build         同步 patch，并构建 helper、AFL 持久模式 named、SymCC named
  gen-seeds     按 profile 生成 query/response/transcript 语料
  filter-seeds  按 profile 筛选稳定输入语料
  prepare       执行 build + gen-seeds(按需) + filter-seeds
  start         以持久模式启动 AFL++ master/secondary + SymCC helper
  dump-cache <样本> [输出文件] 以干净实例回放单个样本并导出 BIND9 cache dump
  run [秒数]    启动实验并持续运行指定秒数，结束后自动输出状态并停止
  stop          停止当前实验进程
  status        查看当前实验状态与关键统计

默认约定:
  1. AFL++ 目标使用 shared-memory testcase 持久模式，仍由 target 内部注入线程驱动执行。
  2. patch/ 按 PATCH_VARIANT(cache|fuzz) + resolver 分层；named 默认同步到 experiments/subjects/bind9/<tag>、<tag>-afl、<tag>-symcc，缺少 lock/subjects 时回落到旧 bind-9.18.46* 路径。
  3. 运行产物默认写入 named_experiment/work/，可通过 WORK_DIR 覆盖。
  4. start 默认清理旧的 afl_out 和当前日志；如需保留可设置 RESET_OUTPUT=0。
  5. FUZZ_PROFILE 支持 legacy-response-tail 与 poison-stateful，默认 poison-stateful。
  6. 本脚本保持 producer-only；差分跟随、解析与汇总入口统一留在 unbound 外壳 / Python CLI。

常用环境变量:
  FUZZ_PROFILE=poison-stateful
  PATCH_VARIANT=cache|fuzz (兼容旧值 diff->cache；producer 默认 fuzz)
  JOBS=2
  ENABLE_SECONDARY=1
  AFL_TIMEOUT_MS=7000
  REPLY_TIMEOUT_MS=80
  REGEN_SEEDS=0
  REFILTER_QUERIES=0
  RESET_OUTPUT=1
  SHOW_AFL_UI=1
  ENABLE_DST1_MUTATOR=1 (poison-stateful 默认)
  ENABLE_SYMCC=1
  DST1_MUTATOR_LIBRARY=build/linux/x86_64/release/libafl_dst1_mutator.so
  DST1_MUTATOR_ONLY=1
  NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS=100000
  SYMCC_FRONTIER_RELOAD_SEC=15
  SYMCC_FRONTIER_RETRY_LIMIT=1
  SYMCC_SEMANTIC_FRONTIER_MANIFEST=<dirname(SYMCC_HIGH_VALUE_MANIFEST)>/semantic_frontier_manifest.json
  RESPONSE_QUERY_SEEDS=8
  TRANSCRIPT_MAX_ITER=4
  TRANSCRIPT_RESPONSE_SEEDS=24
  TRANSCRIPT_FORMAT_VERSION=2
  TRANSCRIPT_MAX_RESPONSES=3
  RESPONSE_PRESERVE=20
  TRANSCRIPT_GEN_TARGET=<AFL_TREE>/bin/named/.libs/named
  RUN_DURATION_SEC=180
  MUTATOR_ADDR=127.0.0.1:55300
  TARGET_ADDR=127.0.0.1:55301
EOF
}

log() {
	printf '[named-exp] %s\n' "$*"
}

warn() {
	printf '[named-exp][warn] %s\n' "$*" >&2
}

die() {
	printf '[named-exp][error] %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

require_file() {
	[ -e "$1" ] || die "缺少文件: $1"
}

require_dir() {
	[ -d "$1" ] || die "缺少目录: $1"
}

locked_tag_for() {
	local resolver="$1"

	[ -f "$RESOLVERS_LOCK_FILE" ] || return 1
	if [ -x "$DNSLABCTL_BIN" ]; then
		if "$DNSLABCTL_BIN" lock-resolved-tag \
			--lock-file "$RESOLVERS_LOCK_FILE" \
			--resolver "$resolver"
		then
			return 0
		fi
	fi

	command -v python3 >/dev/null 2>&1 || return 1

	python3 - "$RESOLVERS_LOCK_FILE" "$resolver" <<'PY'
import json
import pathlib
import sys

lock_path = pathlib.Path(sys.argv[1])
resolver = sys.argv[2]
payload = json.loads(lock_path.read_text(encoding="utf-8"))
for entry in payload.get("resolvers", []):
    if entry.get("resolver") != resolver:
        continue
    tag = entry.get("resolved_tag") or entry.get("desired_tag")
    if not isinstance(tag, str) or not tag:
        raise SystemExit(1)
    print(tag)
    raise SystemExit(0)
raise SystemExit(1)
PY
}

resolve_bind9_tree_layout_defaults() {
	local locked_tag=""
	local subject_root=""

	if [ -z "$SRC_TREE" ] || [ -z "$AFL_TREE" ] || [ -z "$SYMCC_TREE" ]; then
		if locked_tag="$(locked_tag_for bind9 2>/dev/null)"; then
			subject_root="$ROOT_DIR/experiments/subjects/bind9/$locked_tag"
			[ -n "$SRC_TREE" ] || SRC_TREE="$subject_root"
			[ -n "$AFL_TREE" ] || AFL_TREE="$ROOT_DIR/experiments/subjects/bind9/${locked_tag}-afl"
			[ -n "$SYMCC_TREE" ] || SYMCC_TREE="$ROOT_DIR/experiments/subjects/bind9/${locked_tag}-symcc"
		fi
	fi

	[ -n "$SRC_TREE" ] || SRC_TREE="$LEGACY_SRC_TREE"
	[ -n "$AFL_TREE" ] || AFL_TREE="$LEGACY_AFL_TREE"
	[ -n "$SYMCC_TREE" ] || SYMCC_TREE="$LEGACY_SYMCC_TREE"
}

ensure_src_tree_materialized() {
	if [ -d "$SRC_TREE" ]; then
		return 0
	fi

	if [ "$SRC_TREE" != "$LEGACY_SRC_TREE" ] && [ -x "$DNSLABCTL_BIN" ]; then
		if "$DNSLABCTL_BIN" prepare-subject --resolver bind9 >/dev/null 2>&1; then
			[ -d "$SRC_TREE" ] && return 0
		fi
	fi

	if [ "$SRC_TREE" != "$LEGACY_SRC_TREE" ] && [ -d "$LEGACY_SRC_TREE" ]; then
		log "lock/subjects 源树缺失，使用旧树初始化: $SRC_TREE <- $LEGACY_SRC_TREE"
		mkdir -p "$(dirname "$SRC_TREE")"
		cp -a "$LEGACY_SRC_TREE" "$SRC_TREE"
		return 0
	fi

	die "缺少目录: $SRC_TREE"
}

resolve_semantic_frontier_manifest_default() {
	local manifest_dir="$SYMCC_HIGH_VALUE_MANIFEST"

	case "$manifest_dir" in
	*/*)
		manifest_dir="${manifest_dir%/*}"
		;;
	*)
		manifest_dir='.'
		;;
	esac

	printf '%s/semantic_frontier_manifest.json' "$manifest_dir"
}

apply_profile_semantic_defaults() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		ENABLE_DST1_MUTATOR="${ENABLE_DST1_MUTATOR:-1}"
		DST1_MUTATOR_ONLY="${DST1_MUTATOR_ONLY:-1}"
		NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS="${NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS:-100000}"
		SYMCC_FRONTIER_RELOAD_SEC="${SYMCC_FRONTIER_RELOAD_SEC:-15}"
		SYMCC_FRONTIER_RETRY_LIMIT="${SYMCC_FRONTIER_RETRY_LIMIT:-1}"
		SYMCC_SEMANTIC_FRONTIER_MANIFEST="${SYMCC_SEMANTIC_FRONTIER_MANIFEST:-$(resolve_semantic_frontier_manifest_default)}"
		export ENABLE_DST1_MUTATOR="$ENABLE_DST1_MUTATOR"
		export DST1_MUTATOR_ONLY="$DST1_MUTATOR_ONLY"
		export NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS="$NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS"
		export SYMCC_FRONTIER_RELOAD_SEC="$SYMCC_FRONTIER_RELOAD_SEC"
		export SYMCC_FRONTIER_RETRY_LIMIT="$SYMCC_FRONTIER_RETRY_LIMIT"
		export SYMCC_SEMANTIC_FRONTIER_MANIFEST="$SYMCC_SEMANTIC_FRONTIER_MANIFEST"
		return 0
	fi

	ENABLE_DST1_MUTATOR="${ENABLE_DST1_MUTATOR:-0}"
	DST1_MUTATOR_ONLY="${DST1_MUTATOR_ONLY:-0}"
	NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS="${NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS:-100000}"
}

validate_component_switches() {
	local name=""
	local value=""
	for name in ENABLE_SECONDARY ENABLE_DST1_MUTATOR DST1_MUTATOR_ONLY ENABLE_SYMCC ENABLE_CACHE_DELTA ENABLE_TRIAGE; do
		value="${!name}"
		case "$value" in
		0|1) ;;
		*) die "$name 仅允许 0 或 1（当前: ${value:-<空>}）" ;;
		esac
	done
}

show_semantic_config_summary() {
	local semantic_manifest="${SYMCC_SEMANTIC_FRONTIER_MANIFEST:-<unset>}"
	local frontier_reload_sec="${SYMCC_FRONTIER_RELOAD_SEC:-<unset>}"
	local frontier_retry_limit="${SYMCC_FRONTIER_RETRY_LIMIT:-<unset>}"

	printf '\nProducer semantic 配置:\n'
	printf '  %-14s %s\n' "high_value" "$SYMCC_HIGH_VALUE_MANIFEST"
	printf '  %-14s %s\n' "semantic_json" "$semantic_manifest"
	printf '  %-14s %s\n' "dst1_mutator" "$ENABLE_DST1_MUTATOR"
	printf '  %-14s %s\n' "symcc" "$ENABLE_SYMCC"
	printf '  %-14s %s\n' "mutator_only" "$DST1_MUTATOR_ONLY"
	printf '  %-14s %s\n' "reload_sec" "$frontier_reload_sec"
	printf '  %-14s %s\n' "retry_limit" "$frontier_retry_limit"
	printf '  %-28s %s\n' "transcript_format_version" "$TRANSCRIPT_FORMAT_VERSION"
	printf '  %-28s %s\n' "transcript_max_responses" "$TRANSCRIPT_MAX_RESPONSES"
	printf '  %-28s %s\n' "response_preserve" "$RESPONSE_PRESERVE"
}

active_source_generated_this_run() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		printf '%s' "$TRANSCRIPT_CORPUS_GENERATED_THIS_RUN"
	else
		printf '%s' "$QUERY_CORPUS_GENERATED_THIS_RUN"
	fi
}

write_seed_provenance_sidecar() {
	local cold_start="$1"
	local source_dir="$2"
	local stable_input_dir="$3"
	local materialization_method="$4"

	command -v python3 >/dev/null 2>&1 || die "缺少命令: python3"
	mkdir -p "$(dirname "$SEED_PROVENANCE_FILE")"

	env \
		SEED_PROVENANCE_OUT="$SEED_PROVENANCE_FILE" \
		SEED_PROVENANCE_COLD_START="$cold_start" \
		SEED_PROVENANCE_SOURCE_DIR="$source_dir" \
		SEED_PROVENANCE_STABLE_INPUT_DIR="$stable_input_dir" \
		SEED_PROVENANCE_METHOD="$materialization_method" \
		SEED_PROVENANCE_REGEN_SEEDS="$REGEN_SEEDS" \
		SEED_PROVENANCE_REFILTER_QUERIES="$REFILTER_QUERIES" \
		SEED_PROVENANCE_TRANSCRIPT_FORMAT_VERSION="$TRANSCRIPT_FORMAT_VERSION" \
		SEED_PROVENANCE_TRANSCRIPT_MAX_RESPONSES="$TRANSCRIPT_MAX_RESPONSES" \
		SEED_PROVENANCE_RESPONSE_PRESERVE="$RESPONSE_PRESERVE" \
		python3 - <<'PY'
import datetime
import hashlib
import json
import os
from pathlib import Path


def env_bool(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def optional_path(name: str):
    value = os.environ.get(name, "").strip()
    return str(Path(value).resolve()) if value else None


def env_int(name: str):
    value = os.environ.get(name, "").strip()
    if value == "":
        return None
    return int(value)


def snapshot_dir(path_text: str | None):
    if not path_text:
        return None
    path = Path(path_text)
    if not path.is_dir():
        return None
    digest = hashlib.sha1()
    file_count = 0
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file():
            continue
        file_count += 1
        rel_path = candidate.relative_to(path).as_posix()
        data = candidate.read_bytes()
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha1(data).hexdigest().encode("ascii"))
        digest.update(b"\0")
    if file_count == 0:
        return None
    return digest.hexdigest()


stable_input_dir = optional_path("SEED_PROVENANCE_STABLE_INPUT_DIR")
payload = {
    "cold_start": env_bool("SEED_PROVENANCE_COLD_START"),
    "seed_source_dir": optional_path("SEED_PROVENANCE_SOURCE_DIR"),
    "seed_materialization_method": os.environ.get("SEED_PROVENANCE_METHOD", "").strip() or None,
    "seed_snapshot_id": snapshot_dir(stable_input_dir),
    "regen_seeds": env_bool("SEED_PROVENANCE_REGEN_SEEDS"),
    "refilter_queries": env_bool("SEED_PROVENANCE_REFILTER_QUERIES"),
    "stable_input_dir": stable_input_dir,
    "transcript_format_version": env_int("SEED_PROVENANCE_TRANSCRIPT_FORMAT_VERSION"),
    "transcript_max_responses": env_int("SEED_PROVENANCE_TRANSCRIPT_MAX_RESPONSES"),
    "response_preserve": env_int("SEED_PROVENANCE_RESPONSE_PRESERVE"),
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
}

output_path = Path(os.environ["SEED_PROVENANCE_OUT"])
output_path.write_text(
    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

	log "producer seed provenance 已写出: $SEED_PROVENANCE_FILE"
}

show_seed_provenance_summary() {
	printf '\nSeed provenance:\n'
	printf '  %-14s %s\n' "sidecar" "$SEED_PROVENANCE_FILE"
	if [ ! -f "$SEED_PROVENANCE_FILE" ]; then
		printf '  %-14s %s\n' "status" "missing"
		return 0
	fi

	if ! command -v python3 >/dev/null 2>&1; then
		printf '  %-14s %s\n' "status" "python3-missing"
		return 0
	fi

	python3 - "$SEED_PROVENANCE_FILE" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

print(f"  {'status':14s} ready")
print(f"  {'method':14s} {payload.get('seed_materialization_method') or '<unset>'}")
print(f"  {'cold_start':14s} {payload.get('cold_start')}")
print(f"  {'seed_source':14s} {payload.get('seed_source_dir') or '<unset>'}")
print(f"  {'stable_input':14s} {payload.get('stable_input_dir') or '<unset>'}")
print(f"  {'snapshot_id':14s} {payload.get('seed_snapshot_id') or '<unset>'}")
print(f"  {'transcript_format_version':28s} {payload.get('transcript_format_version')}")
print(f"  {'transcript_max_responses':28s} {payload.get('transcript_max_responses')}")
print(f"  {'response_preserve':28s} {payload.get('response_preserve')}")
PY
}

initialize_execution_identity() {
	local identity=""
	identity="$(python3 - <<'PY'
import secrets
import uuid

print(uuid.uuid4().hex, secrets.randbelow(2**31 - 1) + 1)
PY
)"
	read -r PRODUCER_RUN_ID PRODUCER_RANDOM_SEED <<<"$identity"
	AFL_MASTER_STARTED=0
	AFL_SECONDARY_STARTED=0
	SYMCC_HELPER_STARTED=0
	rm -f "$EXECUTION_MANIFEST_FILE"
}

component_pid() {
	local pidfile="$1"
	local session="$2"
	if tmux_session_alive "$session"; then
		tmux list-panes -t "$session" -F '#{pane_pid}' 2>/dev/null | head -n 1
	elif pid_is_alive "$pidfile"; then
		cat "$pidfile"
	fi
}

write_execution_manifest() {
	local status="$1"
	local exit_code="${2:-}"
	local queue_dir="$AFL_OUT_DIR/master/queue"
	local master_pid=""
	local secondary_pid=""
	local symcc_pid=""

	mkdir -p "$(dirname "$EXECUTION_MANIFEST_FILE")"
	master_pid="$(component_pid "$MASTER_PID" "$MASTER_SESSION" || true)"
	secondary_pid="$(component_pid "$SECONDARY_PID" "$SECONDARY_SESSION" || true)"
	symcc_pid="$(component_pid "$HELPER_PID" "$HELPER_SESSION" || true)"

	env \
		EXECUTION_MANIFEST_OUT="$EXECUTION_MANIFEST_FILE" \
		EXECUTION_MANIFEST_STATUS="$status" \
		EXECUTION_MANIFEST_EXIT_CODE="$exit_code" \
		EXECUTION_MANIFEST_WORK_DIR="$WORK_DIR" \
		EXECUTION_MANIFEST_QUEUE_DIR="$queue_dir" \
		EXECUTION_MANIFEST_PROFILE="$FUZZ_PROFILE" \
		EXECUTION_MANIFEST_VARIANT="$PRODUCER_VARIANT_NAME" \
		EXECUTION_MANIFEST_REPEAT_INDEX="$PRODUCER_REPEAT_INDEX" \
		EXECUTION_MANIFEST_RUN_ID="$PRODUCER_RUN_ID" \
		EXECUTION_MANIFEST_RANDOM_SEED="$PRODUCER_RANDOM_SEED" \
		EXECUTION_MANIFEST_ENABLE_SECONDARY="$ENABLE_SECONDARY" \
		EXECUTION_MANIFEST_ENABLE_DST1_MUTATOR="$ENABLE_DST1_MUTATOR" \
		EXECUTION_MANIFEST_ENABLE_CACHE_DELTA="$ENABLE_CACHE_DELTA" \
		EXECUTION_MANIFEST_ENABLE_TRIAGE="$ENABLE_TRIAGE" \
		EXECUTION_MANIFEST_ENABLE_SYMCC="$ENABLE_SYMCC" \
		EXECUTION_MANIFEST_MASTER_STARTED="$AFL_MASTER_STARTED" \
		EXECUTION_MANIFEST_SECONDARY_STARTED="$AFL_SECONDARY_STARTED" \
		EXECUTION_MANIFEST_SYMCC_STARTED="$SYMCC_HELPER_STARTED" \
		EXECUTION_MANIFEST_MASTER_PID="$master_pid" \
		EXECUTION_MANIFEST_SECONDARY_PID="$secondary_pid" \
		EXECUTION_MANIFEST_SYMCC_PID="$symcc_pid" \
		EXECUTION_MANIFEST_MASTER_COMMAND="$AFL_FUZZ_BIN -M master" \
		EXECUTION_MANIFEST_SECONDARY_COMMAND="$AFL_FUZZ_BIN -S secondary" \
		EXECUTION_MANIFEST_SYMCC_COMMAND="$HELPER_BIN -a master" \
		python3 - <<'PY'
import datetime
import hashlib
import json
import os
import re
from pathlib import Path


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def env_bool(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def env_int(name: str):
    value = os.environ.get(name, "").strip()
    return int(value) if value else None


def queue_snapshot(queue_dir: Path) -> dict:
    digest = hashlib.sha256()
    file_count = 0
    size_bytes = 0
    if queue_dir.is_dir():
        files = sorted(path for path in queue_dir.rglob("*") if path.is_file())
    else:
        files = []
    for path in files:
        relative_path = path.relative_to(queue_dir).as_posix()
        size = path.stat().st_size
        file_count += 1
        size_bytes += size
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        digest.update(b"\0")
    sha256 = digest.hexdigest()
    return {
        "path": str(queue_dir.resolve()),
        "snapshot_id": sha256,
        "algorithm": "sha256-relative-path-size-content-v1",
        "file_count": file_count,
        "size_bytes": size_bytes,
        "sha256": sha256,
    }


def inferred_variant(toggles: dict) -> str:
    configured = os.environ.get("EXECUTION_MANIFEST_VARIANT", "").strip()
    if configured:
        return configured
    signature = tuple(toggles[name] for name in (
        "ENABLE_DST1_MUTATOR", "ENABLE_CACHE_DELTA", "ENABLE_TRIAGE", "ENABLE_SYMCC"
    ))
    return {
        ("1", "1", "1", "1"): "full_stack",
        ("1", "1", "1", "0"): "afl_only",
        ("0", "1", "1", "1"): "no_mutator",
        ("1", "0", "1", "1"): "no_cache_delta",
    }.get(signature, "custom")


def inferred_repeat_index(work_dir: Path) -> int:
    configured = env_int("EXECUTION_MANIFEST_REPEAT_INDEX")
    if configured is not None:
        return configured
    match = re.fullmatch(r"run-(\d+)", work_dir.name)
    return int(match.group(1)) if match else 1


def component(existing: dict, *, enabled: bool, started_env: str, pid_env: str, command: str, status: str, exit_code):
    started_value = os.environ.get(started_env, "").strip()
    started = started_value == "1" if started_value else bool(existing.get("started", False))
    pid_value = env_int(pid_env)
    pid = pid_value if pid_value is not None else existing.get("pid")
    if not enabled:
        started = False
        pid = None
    if status == "running":
        component_exit_status = None
    elif started:
        component_exit_status = exit_code
    else:
        component_exit_status = None
    return {
        "enabled": enabled,
        "started": started,
        "pid": pid,
        "exit_status": component_exit_status,
        "command_summary": command if enabled else None,
    }


output_path = Path(os.environ["EXECUTION_MANIFEST_OUT"])
work_dir = Path(os.environ["EXECUTION_MANIFEST_WORK_DIR"]).resolve()
queue_dir = Path(os.environ["EXECUTION_MANIFEST_QUEUE_DIR"])
status = os.environ["EXECUTION_MANIFEST_STATUS"]
exit_code = env_int("EXECUTION_MANIFEST_EXIT_CODE")
existing = {}
if output_path.is_file():
    try:
        existing = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        existing = {}

new_toggles = {
    "ENABLE_DST1_MUTATOR": os.environ["EXECUTION_MANIFEST_ENABLE_DST1_MUTATOR"],
    "ENABLE_CACHE_DELTA": os.environ["EXECUTION_MANIFEST_ENABLE_CACHE_DELTA"],
    "ENABLE_TRIAGE": os.environ["EXECUTION_MANIFEST_ENABLE_TRIAGE"],
    "ENABLE_SYMCC": os.environ["EXECUTION_MANIFEST_ENABLE_SYMCC"],
}
toggles = existing.get("toggles", new_toggles) if status != "running" else new_toggles
run_id = os.environ.get("EXECUTION_MANIFEST_RUN_ID", "").strip() or existing.get("producer_run_id")
random_seed = env_int("EXECUTION_MANIFEST_RANDOM_SEED")
if random_seed is None:
    random_seed = existing.get("random_seed")
variant_name = existing.get("variant_name") if status != "running" else None
repeat_index = existing.get("repeat_index") if status != "running" else None
variant_name = variant_name or inferred_variant(toggles)
repeat_index = repeat_index or inferred_repeat_index(work_dir)
started_at = existing.get("started_at") or now_utc()
components_existing = existing.get("components", {}) if isinstance(existing.get("components"), dict) else {}

payload = {
    "contract_name": "rq3_producer_execution_manifest",
    "contract_version": 1,
    "status": status,
    "exit_code": exit_code,
    "producer_run_id": run_id,
    "random_seed": random_seed,
    "variant_name": variant_name,
    "repeat_index": repeat_index,
    "producer_profile": os.environ["EXECUTION_MANIFEST_PROFILE"],
    "run_dir": str(work_dir),
    "started_at": started_at,
    "finished_at": None if status == "running" else now_utc(),
    "toggles": toggles,
    "queue_snapshot": queue_snapshot(queue_dir),
    "components": {
        "afl_master": component(
            components_existing.get("afl_master", {}), enabled=True,
            started_env="EXECUTION_MANIFEST_MASTER_STARTED", pid_env="EXECUTION_MANIFEST_MASTER_PID",
            command=os.environ["EXECUTION_MANIFEST_MASTER_COMMAND"], status=status, exit_code=exit_code,
        ),
        "afl_secondary": component(
            components_existing.get("afl_secondary", {}),
            enabled=env_bool("EXECUTION_MANIFEST_ENABLE_SECONDARY"),
            started_env="EXECUTION_MANIFEST_SECONDARY_STARTED", pid_env="EXECUTION_MANIFEST_SECONDARY_PID",
            command=os.environ["EXECUTION_MANIFEST_SECONDARY_COMMAND"], status=status, exit_code=exit_code,
        ),
        "symcc": component(
            components_existing.get("symcc", {}), enabled=env_bool("EXECUTION_MANIFEST_ENABLE_SYMCC"),
            started_env="EXECUTION_MANIFEST_SYMCC_STARTED", pid_env="EXECUTION_MANIFEST_SYMCC_PID",
            command=os.environ["EXECUTION_MANIFEST_SYMCC_COMMAND"], status=status, exit_code=exit_code,
        ),
    },
}
output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

execution_manifest_is_running() {
	[ -f "$EXECUTION_MANIFEST_FILE" ] || return 1
	python3 - "$EXECUTION_MANIFEST_FILE" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(0 if payload.get("status") == "running" else 1)
PY
}

finish_execution_manifest() {
	local status="$1"
	local exit_code="$2"
	execution_manifest_is_running || return 0
	write_execution_manifest "$status" "$exit_code"
}

validate_transcript_seed_v2_two_part() {
	local sample="$1"

	python3 - "$sample" <<'PY'
from pathlib import Path
import struct
import sys

sample_path = Path(sys.argv[1])
data = sample_path.read_bytes()

if len(data) < 10:
    raise SystemExit(f"{sample_path}: transcript seed 太短，无法解析现行 DST1 header")

if data[:4] != b"DST1":
    raise SystemExit(f"{sample_path}: transcript magic 非 DST1，拒绝作为现行 DST1 seed")

response_count = data[4]
reserved_or_version = data[5]
query_len = struct.unpack_from("<H", data, 6)[0]
post_check_len = struct.unpack_from("<H", data, 8)[0]
max_responses = 16

if response_count > max_responses:
    raise SystemExit(
        f"{sample_path}: response_count={response_count} 超出上限 {max_responses}"
    )

offset = 10
length_table_bytes = response_count * 2
if len(data) < offset + length_table_bytes:
    raise SystemExit(f"{sample_path}: transcript seed 不完整，缺少 response length 表")

response_lengths = []
for _ in range(response_count):
    response_lengths.append(struct.unpack_from("<H", data, offset)[0])
    offset += 2

expected_total = offset + query_len + sum(response_lengths) + post_check_len
actual_total = len(data)
if (
    reserved_or_version == 0
    and query_len > 0
    and expected_total == actual_total
):
    raise SystemExit(0)

if reserved_or_version == 0:
    raise SystemExit(
        f"{sample_path}: transcript version=0，布局不符合现行 DST1 两段式格式"
    )

raise SystemExit(
    f"{sample_path}: transcript header[5]={reserved_or_version}，布局不符合现行 DST1 两段式格式"
)
PY
}

validate_transcript_corpus_dir_or_die() {
	local dir_path="$1"
	local context_tag="$2"
	local sample

	[ -d "$dir_path" ] || return 0
	for sample in "$dir_path"/*; do
		[ -f "$sample" ] || continue
		if ! validate_transcript_seed_v2_two_part "$sample"; then
			die "$context_tag 检测到旧格式/损坏 transcript seed: $sample。请删除旧语料后重新生成 transcript corpus（例如设置 REGEN_SEEDS=1 重新跑 gen-seeds/prepare）。"
		fi
	done
}

prepare_transcript_seed_mix() {
	local seed_index
	local sample

	validate_transcript_corpus_dir_or_die "$TRANSCRIPT_CORPUS_DIR" "prepare_transcript_seed_mix"

	rm -rf "$TRANSCRIPT_SEED_MIX_DIR"
	mkdir -p "$TRANSCRIPT_SEED_MIX_DIR"

	seed_index=0
	for sample in "$QUERY_CORPUS_DIR"/*; do
		[ -f "$sample" ] || continue
		cp "$sample" \
			"$TRANSCRIPT_SEED_MIX_DIR/query_$(printf '%04d' "$seed_index")_$(basename "$sample")"
		seed_index=$((seed_index + 1))
	done

	seed_index=0
	while IFS= read -r sample; do
		[ -f "$sample" ] || continue
		cp "$sample" \
			"$TRANSCRIPT_SEED_MIX_DIR/response_$(printf '%04d' "$seed_index")_$(basename "$sample")"
		seed_index=$((seed_index + 1))
	done <<EOF
$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f | LC_ALL=C sort | head -n "$TRANSCRIPT_RESPONSE_SEEDS")
EOF
}

ensure_dirs() {
	mkdir -p "$WORK_DIR" "$BIN_DIR" "$LOG_DIR" "$PID_DIR" "$SYMCC_OUTPUT_DIR" \
		"$RUNTIME_STATE_DIR" "$EXP_DIR/runtime" "$CACHE_DUMP_DIR"
	prepare_named_conf
}

load_profile() {
	local profile_file

	profile_file="$PROFILE_DIR/${FUZZ_PROFILE}.env"
	if [ -f "$profile_file" ]; then
		log "加载 profile: $profile_file"
		# shellcheck disable=SC1090
		. "$profile_file"
	fi
	case "$FUZZ_PROFILE" in
	legacy-response-tail|poison-stateful)
		;;
	*)
		die "未知 FUZZ_PROFILE: $FUZZ_PROFILE"
		;;
	esac
	: "${REPLY_TIMEOUT_MS:=50}"
	: "${AFL_TIMEOUT_MS:=3000+}"
	: "${ENABLE_SECONDARY:=1}"
	: "${ENABLE_SYMCC:=1}"
	: "${QUERY_MAX_ITER:=40}"
	: "${RESPONSE_MAX_ITER:=4}"
	: "${RESPONSE_QUERY_SEEDS:=8}"
	: "${TRANSCRIPT_MAX_ITER:=4}"
	: "${TRANSCRIPT_RESPONSE_SEEDS:=24}"
	if [ "$FUZZ_PROFILE" = "poison-stateful" ] && [ -z "$TRANSCRIPT_GEN_TARGET" ]; then
		TRANSCRIPT_GEN_TARGET="$AFL_TREE/bin/named/.libs/named"
	fi
	apply_profile_semantic_defaults
	if [ "$TRANSCRIPT_FORMAT_VERSION" != "2" ]; then
		die "仅支持两段式 transcript 格式版本：TRANSCRIPT_FORMAT_VERSION 必须为 2（当前: $TRANSCRIPT_FORMAT_VERSION）"
	fi
}

active_input_corpus_dir() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		printf '%s' "$STABLE_TRANSCRIPT_CORPUS_DIR"
	else
		printf '%s' "$STABLE_QUERY_CORPUS_DIR"
	fi
}

sample_source_dir() {
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		printf '%s' "$TRANSCRIPT_CORPUS_DIR"
	else
		printf '%s' "$QUERY_CORPUS_DIR"
	fi
}

prepare_named_conf() {
	local runtime_dir_escaped

	require_file "$NAMED_CONF_TEMPLATE"
	runtime_dir_escaped="$(printf '%s' "$RUNTIME_STATE_DIR" | sed 's/[&|]/\\&/g')"
	sed "s|__RUNTIME_STATE_DIR__|$runtime_dir_escaped|g" \
		"$NAMED_CONF_TEMPLATE" >"$NAMED_CONF"
}

afl_ld_library_path() {
	local dirs=()
	mapfile -t dirs < <(find "$AFL_TREE" -type d -path '*/.libs' | sort)
	[ "${#dirs[@]}" -gt 0 ] || die "未找到 AFL named 依赖库目录，请先构建 $AFL_TREE"
	(
		IFS=:
		printf '%s' "${dirs[*]}"
	)
}

ensure_tree_exists() {
	local tree="$1"
	ensure_src_tree_materialized
	if [ ! -d "$tree" ]; then
		log "创建构建树: $tree"
		cp -a "$SRC_TREE" "$tree"
	fi
}

validate_patch_variant() {
	local variant="$1"
	case "$variant" in
	cache|diff|fuzz)
		;;
	*)
		die "未知 PATCH_VARIANT: $variant（仅支持 cache、fuzz，兼容旧值 diff）"
		;;
	esac
}

normalize_patch_variant() {
	local variant="$1"
	validate_patch_variant "$variant"
	case "$variant" in
	diff)
		printf '%s' cache
		;;
	*)
		printf '%s' "$variant"
		;;
	esac
}

bind9_patch_variant_root() {
	local variant="$1"
	local normalized_variant=""

	normalized_variant="$(normalize_patch_variant "$variant")"
	printf '%s/%s/bind9' "$PATCH_ROOT" "$normalized_variant"
}

patch_variant_mappings() {
	local variant="$1"
	local normalized_variant=""

	normalized_variant="$(normalize_patch_variant "$variant")"
	case "$normalized_variant" in
	cache)
		printf '%s\n' \
			"bin/named/main.c:bin/named/main.c" \
			"bin/named/Makefile.am:bin/named/Makefile.am" \
			"bin/named/resolver_afl_symcc_orchestrator.c:bin/named/resolver_afl_symcc_orchestrator.c" \
			"bin/named/resolver_afl_symcc_mutator_server.c:bin/named/resolver_afl_symcc_mutator_server.c" \
			"include/named/resolver_afl_symcc_orchestrator.h:bin/named/include/named/resolver_afl_symcc_orchestrator.h" \
			"include/named/resolver_afl_symcc_mutator_server.h:bin/named/include/named/resolver_afl_symcc_mutator_server.h" \
			"lib/isc/managers.c:lib/isc/managers.c" \
			"lib/dns/dispatch.c:lib/dns/dispatch.c" \
			"lib/dns/include/dns/dispatch.h:lib/dns/include/dns/dispatch.h"
		;;
	fuzz)
		printf '%s\n' \
			"bin/named/Makefile.am:bin/named/Makefile.am" \
			"bin/named/main.c:bin/named/main.c" \
			"bin/named/resolver_afl_symcc_orchestrator.c:bin/named/resolver_afl_symcc_orchestrator.c" \
			"bin/named/resolver_afl_symcc_mutator_server.c:bin/named/resolver_afl_symcc_mutator_server.c" \
			"include/named/resolver_afl_symcc_orchestrator.h:bin/named/include/named/resolver_afl_symcc_orchestrator.h" \
			"include/named/resolver_afl_symcc_mutator_server.h:bin/named/include/named/resolver_afl_symcc_mutator_server.h" \
			"lib/isc/managers.c:lib/isc/managers.c" \
			"lib/dns/dispatch.c:lib/dns/dispatch.c" \
			"lib/dns/include/dns/dispatch.h:lib/dns/include/dns/dispatch.h"
		;;
	esac
}

patch_source_mappings() {
	local variant="$1"
	patch_variant_mappings "$variant"
}

copy_if_different() {
	local src="$1"
	local dst="$2"
	mkdir -p "$(dirname "$dst")"
	if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
		return 0
	fi
	cp "$src" "$dst"
}

apply_bind9_tree_compat_fixes() {
	local tree="$1"
	local qp_file="$tree/lib/dns/qp.c"
	local baseline_root="$tree/.symcc_patch_baseline/files"
	local full_restore_files=(
		"bin/named/fuzz.c"
		"lib/ns/client.c"
	)
	local legacy_print_include_files=(
		"$tree/lib/dns/dispatch.c"
		"$tree/lib/ns/client.c"
		"$tree/bin/named/main.c"
	)
	local dispatchmgr_call_fixups=(
		"$tree/lib/dns/client.c|dns_dispatchmgr_create\\(mctx,\\s*nm,\\s*(&client->dispatchmgr)\\)|dns_dispatchmgr_create(mctx, loopmgr, nm, \$1)"
		"$tree/tests/dns/dispatch_test.c|dns_dispatchmgr_create\\(mctx,\\s*connect_nm,\\s*(&[^)]+)\\)|dns_dispatchmgr_create(mctx, loopmgr, connect_nm, \$1)"
		"$tree/tests/libtest/dns.c|dns_dispatchmgr_create\\(mctx,\\s*netmgr,\\s*(&dispatchmgr)\\)|dns_dispatchmgr_create(mctx, loopmgr, netmgr, \$1)"
		"$tree/tests/libtest/ns.c|dns_dispatchmgr_create\\(mctx,\\s*netmgr,\\s*(&dispatchmgr)\\)|dns_dispatchmgr_create(mctx, loopmgr, netmgr, \$1)"
		"$tree/bin/nsupdate/nsupdate.c|dns_dispatchmgr_create\\(gmctx,\\s*netmgr,\\s*(&dispatchmgr)\\)|dns_dispatchmgr_create(gmctx, loopmgr, netmgr, \$1)"
		"$tree/bin/tools/mdig.c|dns_dispatchmgr_create\\(mctx,\\s*netmgr,\\s*(&dispatchmgr)\\)|dns_dispatchmgr_create(mctx, loopmgr, netmgr, \$1)"
		"$tree/bin/named/server.c|dns_dispatchmgr_create\\(named_g_mctx,\\s*named_g_netmgr,\\s*(&named_g_dispatchmgr)\\)|dns_dispatchmgr_create(named_g_mctx, named_g_loopmgr, named_g_netmgr, \$1)"
		"$tree/bin/tests/system/pipelined/pipequeries.c|dns_dispatchmgr_create\\(mctx,\\s*netmgr,\\s*(&dispatchmgr)\\)|dns_dispatchmgr_create(mctx, loopmgr, netmgr, \$1)"
		"$tree/bin/delv/delv.c|dns_dispatchmgr_create\\(mctx,\\s*netmgr,\\s*(&dispatchmgr)\\)|dns_dispatchmgr_create(mctx, loopmgr, netmgr, \$1)"
	)
	local legacy_print_file=""
	local dispatchmgr_fixup=""
	local dispatchmgr_fixup_file=""
	local dispatchmgr_fixup_pattern=""
	local dispatchmgr_fixup_replacement=""
	local full_restore_rel=""

	if [ -f "$qp_file" ] && grep -Fq 'chunk_get_raw(dns_qp_t *qp) {' "$qp_file"; then
		perl -0pi -e 's/chunk_get_raw\(dns_qp_t \*qp\) \{/chunk_get_raw(dns_qp_t *qp, size_t bytes) {/g' "$qp_file"
		perl -0pi -e 's/size_t size = chunk_size_raw\(\);\n\t\tvoid \*ptr = mmap/size_t size = chunk_size_raw();\n\t\tINSIST(bytes <= size);\n\t\tvoid *ptr = mmap/g' "$qp_file"
		perl -0pi -e 's/return isc_mem_allocate\(qp->mctx, QP_CHUNK_BYTES\);/return isc_mem_allocate(qp->mctx, bytes);/g' "$qp_file"
	fi

	for full_restore_rel in "${full_restore_files[@]}"; do
		if [ -f "$baseline_root/$full_restore_rel" ]; then
			copy_if_different \
				"$baseline_root/$full_restore_rel" \
				"$tree/$full_restore_rel"
		fi
	done

	for dispatchmgr_fixup in "${dispatchmgr_call_fixups[@]}"; do
		dispatchmgr_fixup_file="${dispatchmgr_fixup%%|*}"
		dispatchmgr_fixup="${dispatchmgr_fixup#*|}"
		dispatchmgr_fixup_pattern="${dispatchmgr_fixup%%|*}"
		dispatchmgr_fixup_replacement="${dispatchmgr_fixup#*|}"
		if [ -f "$dispatchmgr_fixup_file" ] && grep -Fq 'dns_dispatchmgr_create(' "$dispatchmgr_fixup_file"; then
			perl -0pi -e "s/${dispatchmgr_fixup_pattern}/${dispatchmgr_fixup_replacement}/gs" "$dispatchmgr_fixup_file"
		fi
	done

	if [ ! -f "$tree/lib/isc/include/isc/print.h" ]; then
		for legacy_print_file in "${legacy_print_include_files[@]}"; do
			if [ -f "$legacy_print_file" ] && grep -Fq '#include <isc/print.h>' "$legacy_print_file"; then
				perl -0pi -e 's/^#include <isc\/print\.h>\n//m' "$legacy_print_file"
			fi
		done
	fi
}

snapshot_patch_tree_variant_baselines() {
	local tree="$1"
	local baseline_root="$tree/.symcc_patch_baseline"
	local files_root="$baseline_root/files"
	local absent_root="$baseline_root/absent"
	local variant=""
	local src_rel=""
	local dst_rel=""
	local baseline_path=""
	local absent_path=""

	[ -d "$tree" ] || return 0
	mkdir -p "$files_root" "$absent_root"

	for variant in cache fuzz; do
		while IFS=: read -r src_rel dst_rel; do
			[ -n "$dst_rel" ] || continue
			baseline_path="$files_root/$dst_rel"
			absent_path="$absent_root/$dst_rel"
			if [ -f "$baseline_path" ] || [ -e "$absent_path" ]; then
				continue
			fi
			mkdir -p "$(dirname "$baseline_path")" "$(dirname "$absent_path")"
			if [ -e "$tree/$dst_rel" ]; then
				cp "$tree/$dst_rel" "$baseline_path"
			else
				: >"$absent_path"
			fi
		done < <(patch_variant_mappings "$variant")
	done
}

restore_inactive_patch_variant_files() {
	local tree="$1"
	local active_variant="$2"
	local normalized_active_variant=""
	local baseline_root="$tree/.symcc_patch_baseline"
	local files_root="$baseline_root/files"
	local absent_root="$baseline_root/absent"
	local variant=""
	local src_rel=""
	local dst_rel=""
	local baseline_path=""
	local absent_path=""

	normalized_active_variant="$(normalize_patch_variant "$active_variant")"
	for variant in cache fuzz; do
		[ "$variant" = "$normalized_active_variant" ] && continue
		while IFS=: read -r src_rel dst_rel; do
			[ -n "$dst_rel" ] || continue
			baseline_path="$files_root/$dst_rel"
			absent_path="$absent_root/$dst_rel"
			if [ -f "$baseline_path" ]; then
				copy_if_different "$baseline_path" "$tree/$dst_rel"
			elif [ -e "$absent_path" ]; then
				rm -f "$tree/$dst_rel"
			fi
		done < <(patch_variant_mappings "$variant")
	done
}

sync_patch_tree() {
	local tree="$1"
	local variant="${2:-$PATCH_VARIANT}"
	local patch_variant_root=""
	local src_rel=""
	local dst_rel=""
	validate_patch_variant "$variant"
	[ -d "$tree" ] || return 0

	patch_variant_root="$(bind9_patch_variant_root "$variant")"
	snapshot_patch_tree_variant_baselines "$tree"
	restore_inactive_patch_variant_files "$tree" "$variant"

	while IFS=: read -r src_rel dst_rel; do
		[ -n "$src_rel" ] || continue
		copy_if_different "$patch_variant_root/$src_rel" "$tree/$dst_rel"
	done < <(patch_source_mappings "$variant")
	apply_bind9_tree_compat_fixes "$tree"
}

sync_patch() {
	local variant="${1:-$PATCH_VARIANT}"
	local patch_variant_root=""
	local src_rel=""
	local dst_rel=""
	validate_patch_variant "$variant"
	ensure_src_tree_materialized

	patch_variant_root="$(bind9_patch_variant_root "$variant")"
	while IFS=: read -r src_rel dst_rel; do
		[ -n "$src_rel" ] || continue
		require_file "$patch_variant_root/$src_rel"
	done < <(patch_source_mappings "$variant")

	sync_patch_tree "$SRC_TREE" "$variant"
	ensure_tree_exists "$AFL_TREE"
	ensure_tree_exists "$SYMCC_TREE"
	sync_patch_tree "$AFL_TREE" "$variant"
	sync_patch_tree "$SYMCC_TREE" "$variant"
}

build_helper_and_gen_input() {
	require_cmd xmake
	validate_component_switches
	log "构建 gen_input 与 SymCC 编译工具链"
	(
		cd "$ROOT_DIR"
		HOME="$ROOT_DIR/.xmake-home" \
		XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
		xmake f -c --backend=qsym -m release >/dev/null
		if [ "$ENABLE_SYMCC" = "1" ]; then
			HOME="$ROOT_DIR/.xmake-home" \
			XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
			xmake b symcc_fuzzing_helper
		fi
		HOME="$ROOT_DIR/.xmake-home" \
		XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
		xmake b gen_input
		HOME="$ROOT_DIR/.xmake-home" \
		XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
		xmake b SymCC
		if [ "$ENABLE_DST1_MUTATOR" = "1" ] && \
		   [ "$DST1_MUTATOR_LIBRARY" = "$ROOT_DIR/build/linux/x86_64/release/libafl_dst1_mutator.so" ]; then
			HOME="$ROOT_DIR/.xmake-home" \
			XMAKE_GLOBALDIR="$ROOT_DIR/.xmake-global" \
			xmake b afl_dst1_mutator
		fi
	)
	if [ "$ENABLE_SYMCC" = "1" ]; then
		require_file "$HELPER_BIN"
	fi
	require_file "$GEN_INPUT_BIN"
	require_file "$SYMCC_CC_BIN"
	require_file "$SYMCC_CXX_BIN"
	if [ "$ENABLE_DST1_MUTATOR" = "1" ]; then
		require_file "$DST1_MUTATOR_LIBRARY"
	fi
}

build_seed_parsers() {
	require_file "$SYMCC_CC_BIN"
	require_file "$QUERY_PARSER_SRC"
	require_file "$RESPONSE_PARSER_SRC"
	ensure_dirs

	if [ ! -x "$QUERY_PARSER_BIN" ]; then
		log "构建 query DNS parser"
		"$SYMCC_CC_BIN" "$QUERY_PARSER_SRC" -O2 -o "$QUERY_PARSER_BIN"
	fi

	if [ ! -x "$RESPONSE_PARSER_BIN" ]; then
		log "构建 response DNS parser"
		"$SYMCC_CC_BIN" "$RESPONSE_PARSER_SRC" -O2 -o "$RESPONSE_PARSER_BIN"
	fi
}

ensure_bind9_configure_ready() {
	local tree="$1"
	local configure_path="$tree/configure"

	[ -d "$tree" ] || die "缺少目录: $tree"

	if [ -x "$configure_path" ]; then
		return 0
	fi

	if [ -f "$configure_path" ]; then
		chmod +x "$configure_path" 2>/dev/null || true
		if [ -x "$configure_path" ]; then
			return 0
		fi
	fi

	require_file "$tree/configure.ac"
	require_cmd autoreconf
	log "检测到 BIND9 git 源码树缺少 configure，执行 autoreconf -fi: $tree"
	(
		cd "$tree"
		autoreconf -fi
	)
	require_file "$configure_path"
	chmod +x "$configure_path" 2>/dev/null || true
	[ -x "$configure_path" ] || die "autoreconf 未生成可执行 configure: $configure_path"
}

bind9_named_makefile_needs_autoreconf() {
	local tree="$1"
	local named_makefile_am="$tree/bin/named/Makefile.am"
	local named_makefile_in="$tree/bin/named/Makefile.in"

	[ -f "$named_makefile_am" ] || return 1
	grep -q 'resolver_afl_symcc_orchestrator.c' "$named_makefile_am" || return 1
	grep -q 'resolver_afl_symcc_mutator_server.c' "$named_makefile_am" || return 1
	grep -q 'resolver_afl_symcc_orchestrator.c' "$named_makefile_in" 2>/dev/null || return 0
	grep -q 'resolver_afl_symcc_mutator_server.c' "$named_makefile_in" 2>/dev/null || return 0
	return 1
}

build_afl_named() {
	local reconfigure=0

	require_file "$AFL_CC_BIN"
	ensure_tree_exists "$AFL_TREE"
	sync_patch_tree "$AFL_TREE" "$PATCH_VARIANT"
	if bind9_named_makefile_needs_autoreconf "$AFL_TREE"; then
		log "检测到 named Makefile.in 未同步 patch，刷新 autotools 产物: $AFL_TREE"
		ensure_bind9_configure_ready "$AFL_TREE"
		reconfigure=1
	elif [ ! -x "$AFL_TREE/configure" ]; then
		ensure_bind9_configure_ready "$AFL_TREE"
		reconfigure=1
	fi

	if [ ! -f "$AFL_TREE/config.status" ]; then
		reconfigure=1
	elif grep -q 'NAMED_AFL_NO_PERSISTENT_MODE' "$AFL_TREE/config.status"; then
		reconfigure=1
	fi

	if [ "$reconfigure" -eq 1 ]; then
		log "配置 AFL named（开启持久模式）"
		(
			cd "$AFL_TREE"
			make distclean >/dev/null 2>&1 || true
			CC="$AFL_CC_BIN" \
			CPPFLAGS= \
			./configure \
				--enable-fuzzing=afl \
				--without-libxml2 \
				--without-json-c \
				--without-libidn2 \
				--without-lmdb
		)
	fi

	log "编译 AFL named"
	(
		cd "$AFL_TREE"
		make bind.keys.h
		make -C lib -j"$JOBS"
		make -C bin/named -j"$JOBS" named
	)
	require_file "$AFL_TREE/bin/named/.libs/named"
}

build_symcc_named() {
	local reconfigure=0

	require_file "$SYMCC_CC_BIN"
	require_file "$SYMCC_CXX_BIN"
	ensure_tree_exists "$SYMCC_TREE"
	sync_patch_tree "$SYMCC_TREE" "$PATCH_VARIANT"
	if bind9_named_makefile_needs_autoreconf "$SYMCC_TREE"; then
		log "检测到 named Makefile.in 未同步 patch，刷新 autotools 产物: $SYMCC_TREE"
		ensure_bind9_configure_ready "$SYMCC_TREE"
		reconfigure=1
	elif [ ! -x "$SYMCC_TREE/configure" ]; then
		ensure_bind9_configure_ready "$SYMCC_TREE"
		reconfigure=1
	fi

	if [ ! -f "$SYMCC_TREE/config.status" ]; then
		reconfigure=1
	elif ! grep -q -- '-DENABLE_AFL' "$SYMCC_TREE/config.status"; then
		reconfigure=1
	fi

	mkdir -p "$SYMCC_OUTPUT_DIR/build"

	if [ "$reconfigure" -eq 1 ]; then
		log "配置 SymCC named"
		(
			cd "$SYMCC_TREE"
			make distclean >/dev/null 2>&1 || true
			SYMCC_NO_SYMBOLIC_INPUT=1 \
			SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
			CC="$SYMCC_CC_BIN" \
			CXX="$SYMCC_CXX_BIN" \
			CPPFLAGS='-DENABLE_AFL' \
			./configure \
				--without-libxml2 \
				--without-json-c \
				--without-libidn2 \
				--without-lmdb
		)
	fi

	log "编译 SymCC named"
	(
		cd "$SYMCC_TREE"
		make bind.keys.h
		SYMCC_NO_SYMBOLIC_INPUT=1 \
		SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
		make -C lib -j"$JOBS"
		SYMCC_NO_SYMBOLIC_INPUT=1 \
		SYMCC_OUTPUT_DIR="$SYMCC_OUTPUT_DIR/build" \
		make -C bin/named -j"$JOBS" named
	)
	require_file "$SYMCC_TREE/bin/named/named"
}

generate_seeds() {
	ensure_dirs
	build_helper_and_gen_input
	build_seed_parsers

	if [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$QUERY_CORPUS_DIR" ] || \
		[ -z "$(find "$QUERY_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		QUERY_CORPUS_GENERATED_THIS_RUN=1
		require_file "$QUERY_PARSER_BIN"
		rm -rf "$QUERY_CORPUS_DIR"
		mkdir -p "$QUERY_CORPUS_DIR"
		log "生成 query 语料"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns \
			-i "$QUERY_MAX_ITER" \
			-o "$QUERY_CORPUS_DIR" \
			"$QUERY_PARSER_BIN" \
			>"$QUERY_GEN_LOG" 2>&1
	fi

	if [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$RESPONSE_CORPUS_DIR" ] || \
		[ -z "$(find "$RESPONSE_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		RESPONSE_CORPUS_GENERATED_THIS_RUN=1
		require_file "$RESPONSE_PARSER_BIN"
		rm -rf "$RESPONSE_CORPUS_DIR"
		mkdir -p "$RESPONSE_CORPUS_DIR"
		log "生成 response 综合语料（模板 + 语法变异 + hybrid payload）"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns-poison-response \
			--hybrid \
			--preserve "$RESPONSE_PRESERVE" \
			-i "$RESPONSE_MAX_ITER" \
			--seed-dir "$QUERY_CORPUS_DIR" \
			--seed-dir-limit "$RESPONSE_QUERY_SEEDS" \
			-o "$RESPONSE_CORPUS_DIR" \
			"$RESPONSE_PARSER_BIN" \
			>"$RESPONSE_GEN_LOG" 2>&1
	fi

	if [ "$FUZZ_PROFILE" = "poison-stateful" ] && [ "$REGEN_SEEDS" -eq 0 ] && \
		[ -d "$TRANSCRIPT_CORPUS_DIR" ] && \
		[ -n "$(find "$TRANSCRIPT_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		validate_transcript_corpus_dir_or_die "$TRANSCRIPT_CORPUS_DIR" "generate_seeds"
	fi

	if [ "$FUZZ_PROFILE" = "poison-stateful" ] && \
		{ [ "$REGEN_SEEDS" -eq 1 ] || [ ! -d "$TRANSCRIPT_CORPUS_DIR" ] || \
			[ -z "$(find "$TRANSCRIPT_CORPUS_DIR" -maxdepth 1 -type f 2>/dev/null)" ]; }
	then
		TRANSCRIPT_CORPUS_GENERATED_THIS_RUN=1
		if [ "$TRANSCRIPT_GEN_TARGET" = "$AFL_TREE/bin/named/.libs/named" ]; then
			build_afl_named
		fi
		require_file "$TRANSCRIPT_GEN_TARGET"
		rm -rf "$TRANSCRIPT_CORPUS_DIR"
		mkdir -p "$TRANSCRIPT_CORPUS_DIR"
		prepare_transcript_seed_mix
		log "生成 stateful transcript 语料"
		"$GEN_INPUT_BIN" \
			-v \
			-f dns-stateful-transcript \
			--seed-dir "$TRANSCRIPT_SEED_MIX_DIR" \
			-i "$TRANSCRIPT_MAX_ITER" \
			-o "$TRANSCRIPT_CORPUS_DIR" \
			"$TRANSCRIPT_GEN_TARGET" \
			>"$TRANSCRIPT_GEN_LOG" 2>&1
	fi
}

sample_is_stable() {
	local sample="$1"
	local stderr_file
	local ld_path

	stderr_file="$(mktemp "$LOG_DIR/filter.XXXXXX.stderr")"
	ld_path="$(afl_ld_library_path)"

	if env \
		LD_LIBRARY_PATH="$ld_path" \
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
		NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
		timeout -k 5 "$SEED_TIMEOUT_SEC" \
		"$AFL_TREE/bin/named/.libs/named" \
		-g \
		-c "$NAMED_CONF" \
		-A "resolver-afl-symcc:${MUTATOR_ADDR},input=$sample" \
		>/dev/null 2>"$stderr_file"
	then
		if grep -q 'Requests sent: 1' "$stderr_file" && \
			grep -q 'Replies received: 1' "$stderr_file"
		then
			rm -f "$stderr_file"
			return 0
		fi
	fi

	rm -f "$stderr_file"
	return 1
}

sample_is_stateful_stable() {
	local sample="$1"
	local stderr_file=""
	local ld_path=""
	require_file "$DNSLABCTL_BIN"
	require_file "$AFL_TREE/bin/named/.libs/named"

	if ! "$DNSLABCTL_BIN" transcript-summary --input "$sample" >/dev/null 2>&1; then
		return 1
	fi

	stderr_file="$(mktemp "$LOG_DIR/stateful-filter.XXXXXX.stderr")"
	ld_path="$(afl_ld_library_path)"
	if ! env \
		LD_LIBRARY_PATH="$ld_path" \
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
		timeout -k 5 "$SEED_TIMEOUT_SEC" \
		"$AFL_TREE/bin/named/.libs/named" \
		-g \
		-c "$NAMED_CONF" \
		-A "resolver-afl-symcc:${MUTATOR_ADDR},input=$sample" \
		>/dev/null 2>"$stderr_file"
	then
		warn "stateful stable harness 异常退出，拒绝样本: $sample"
		rm -f "$stderr_file"
		return 1
	fi

	local counter=""
	for counter in \
		'Transcript cases' \
		'Oracle parse_ok' \
		'Oracle resolver_fetch_started' \
		'Oracle response_accepted' \
		'Oracle second_query_hit'
	do
		if ! grep -Eq "^[[:space:]]*${counter}: 1[[:space:]]*$" "$stderr_file"; then
			warn "stateful stable harness 缺少 ${counter}=1，拒绝样本: $sample"
			rm -f "$stderr_file"
			return 1
		fi
	done

	rm -f "$stderr_file"
	return 0
}

validate_stateful_stable_corpus_or_die() {
	local dir_path="$1"
	local context_tag="$2"
	local sample=""

	for sample in "$dir_path"/*; do
		[ -f "$sample" ] || continue
		if ! sample_is_stateful_stable "$sample"; then
			die "$context_tag 的已有 stateful corpus 未通过真实 named 五计数器门槛: $sample。请设置 REFILTER_QUERIES=1 重新筛选。"
		fi
	done
}

filter_seeds() {
	local tmp_dir
	local seed_count=0
	local next_id=0
	local source_dir
	local target_dir

	source_dir="$(sample_source_dir)"
	target_dir="$(active_input_corpus_dir)"
	ensure_dirs
	[ -d "$source_dir" ] || die "输入语料目录不存在: $source_dir"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "response 语料目录不存在: $RESPONSE_CORPUS_DIR"
	# 先验证输入协议，避免旧格式在依赖构建前被吞成无关的工具缺失错误。
	if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
		validate_transcript_corpus_dir_or_die "$source_dir" "filter_seeds(source)"
	fi
	build_afl_named

	if [ "$REFILTER_QUERIES" -eq 0 ] && [ -d "$target_dir" ] && \
		[ -n "$(find "$target_dir" -maxdepth 1 -type f 2>/dev/null)" ]
	then
		if [ "$FUZZ_PROFILE" = "poison-stateful" ]; then
			validate_transcript_corpus_dir_or_die "$target_dir" "filter_seeds(reuse)"
			validate_stateful_stable_corpus_or_die "$target_dir" "filter_seeds(reuse)"
		fi
		write_seed_provenance_sidecar \
			0 \
			"$target_dir" \
			"$target_dir" \
			"reused_filtered_corpus"
		log "复用已有稳定输入语料: $target_dir"
		return 0
	fi

	tmp_dir="$(mktemp -d "$WORK_DIR/.stable_query_tmp.XXXXXX")"

	if [ "$FUZZ_PROFILE" != "poison-stateful" ]; then
		require_file "$QUERY_DRIVER"
		cp "$QUERY_DRIVER" "$tmp_dir/$(printf 'id_%06d_driver' "$next_id")"
		next_id=$((next_id + 1))
		seed_count=$((seed_count + 1))
	fi

	log "筛选稳定输入语料 ($FUZZ_PROFILE)"
	for sample in "$source_dir"/*; do
		[ -f "$sample" ] || continue
		if { [ "$FUZZ_PROFILE" = "poison-stateful" ] && sample_is_stateful_stable "$sample"; } || \
			{ [ "$FUZZ_PROFILE" != "poison-stateful" ] && sample_is_stable "$sample"; }
		then
			cp "$sample" "$tmp_dir/$(printf 'id_%06d_%s' "$next_id" "$(basename "$sample")")"
			next_id=$((next_id + 1))
			seed_count=$((seed_count + 1))
		fi
	done

	if [ "$seed_count" -le 0 ]; then
		rm -rf "$tmp_dir"
		die "没有筛出任何稳定输入语料"
	fi

	rm -rf "$target_dir"
	mv "$tmp_dir" "$target_dir"
	write_seed_provenance_sidecar \
		"$(active_source_generated_this_run)" \
		"$source_dir" \
		"$target_dir" \
		"filtered_from_source_corpus"
	log "稳定输入语料已生成，目录: $target_dir，样本数: $seed_count"
}

prepare_all() {
	ensure_dirs
	sync_patch
	build_helper_and_gen_input
	build_afl_named
	if [ "$ENABLE_SYMCC" = "1" ]; then
		build_symcc_named
	fi
	generate_seeds
	filter_seeds
}

pid_is_alive() {
	local pidfile="$1"
	[ -f "$pidfile" ] || return 1
	local pid
	pid="$(cat "$pidfile" 2>/dev/null || true)"
	[ -n "$pid" ] || return 1
	kill -0 "$pid" 2>/dev/null
}

tmux_enabled() {
	[ "$USE_TMUX" -eq 1 ] && command -v tmux >/dev/null 2>&1
}

tmux_session_alive() {
	local session="$1"
	tmux_enabled || return 1
	tmux has-session -t "$session" 2>/dev/null
}

quote_cmd() {
	printf '%q ' "$@"
}

stop_pidfile() {
	local pidfile="$1"
	local name="$2"

	if ! pid_is_alive "$pidfile"; then
		rm -f "$pidfile"
		return 0
	fi

	local pid
	pid="$(cat "$pidfile")"
	log "停止 $name (pid=$pid)"
	kill "$pid" 2>/dev/null || true
	for _ in $(seq 1 10); do
		if ! kill -0 "$pid" 2>/dev/null; then
			break
		fi
		sleep 1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$pidfile"
}

stop_all() {
	if tmux_enabled; then
		if [ "$ENABLE_SYMCC" = "1" ]; then
			tmux kill-session -t "$HELPER_SESSION" 2>/dev/null || true
		fi
		tmux kill-session -t "$SECONDARY_SESSION" 2>/dev/null || true
		tmux kill-session -t "$MASTER_SESSION" 2>/dev/null || true
	fi
	if [ "$ENABLE_SYMCC" = "1" ]; then
		stop_pidfile "$HELPER_PID" "helper"
	fi
	stop_pidfile "$SECONDARY_PID" "afl-secondary"
	stop_pidfile "$MASTER_PID" "afl-master"
	pkill -f "$AFL_TREE/bin/named/.libs/named -g -c $NAMED_CONF -A resolver-afl-symcc:${MUTATOR_ADDR}" \
		2>/dev/null || true
	pkill -f "$SYMCC_TREE/bin/named/named -g -c $NAMED_CONF -A resolver-afl-symcc:${MUTATOR_ADDR}" \
		2>/dev/null || true
}

cleanup_output() {
	if [ "$RESET_OUTPUT" -eq 1 ]; then
		rm -rf "$AFL_OUT_DIR"
		rm -f "$MASTER_LOG" "$SECONDARY_LOG" "$HELPER_LOG"
	fi
	mkdir -p "$AFL_OUT_DIR" "$LOG_DIR" "$PID_DIR"
}

wait_for_master_queue() {
	local stats_file="$AFL_OUT_DIR/master/fuzzer_stats"
	for _ in $(seq 1 30); do
		if [ -f "$stats_file" ]; then
			return 0
		fi
		sleep 1
	done
	die "等待 AFL master 初始化超时: $stats_file"
}

launch_in_background() {
	local logfile="$1"
	local pidfile="$2"
	local pid
	shift 2

	nohup "$@" >>"$logfile" 2>&1 </dev/null &
	pid="$!"
	disown "$pid" 2>/dev/null || true
	echo "$pid" >"$pidfile"
}

launch_in_tmux() {
	local session="$1"
	local logfile="$2"
	shift 2

	local root_quoted logfile_quoted cmd_quoted
	root_quoted="$(printf '%q' "$ROOT_DIR")"
	logfile_quoted="$(printf '%q' "$logfile")"
	cmd_quoted="$(quote_cmd "$@")"

	tmux kill-session -t "$session" 2>/dev/null || true
	tmux new-session -d -s "$session" \
		"cd ${root_quoted} && exec ${cmd_quoted}"
	tmux pipe-pane -o -t "${session}:0.0" "cat >>${logfile_quoted}"
}

launch_shell_in_tmux() {
	local session="$1"
	local logfile="$2"
	local command_text="$3"
	local logfile_quoted

	logfile_quoted="$(printf '%q' "$logfile")"

	tmux kill-session -t "$session" 2>/dev/null || true
	tmux new-session -d -s "$session" "$command_text"
	tmux pipe-pane -o -t "${session}:0.0" "cat >>${logfile_quoted}"
}

attach_master_ui() {
	[ "$SHOW_AFL_UI" -eq 1 ] || return 0

	if ! tmux_enabled; then
		warn "SHOW_AFL_UI=1 需要 USE_TMUX=1 且已安装 tmux，当前仅保留日志: $MASTER_LOG"
		return 0
	fi

	if ! tmux_session_alive "$MASTER_SESSION"; then
		warn "AFL master session 未启动，无法显示 UI: $MASTER_SESSION"
		return 0
	fi

	if [ -n "${TMUX:-}" ]; then
		log "切换到 AFL++ UI 页面: $MASTER_SESSION（返回原 session 可执行 tmux switch-client -l）"
		tmux switch-client -t "$MASTER_SESSION" || \
			warn "切换到 AFL++ UI 失败，请手动执行: tmux switch-client -t $MASTER_SESSION"
	else
		log "附着到 AFL++ UI 页面: $MASTER_SESSION（离开界面可按 Ctrl-b d）"
		tmux attach-session -t "$MASTER_SESSION" || \
			warn "附着到 AFL++ UI 失败，请手动执行: tmux attach-session -t $MASTER_SESSION"
	fi
}

start_all() {
	local ld_path
	local helper_target_csv
	local -a master_no_ui=()
	local -a master_seed_args=()
	local -a afl_env=()
	local -a helper_env=()
	local -a helper_extra=()
	local input_dir

	prepare_all
	stop_all
	cleanup_output
	initialize_execution_identity
	write_execution_manifest "running" ""
	master_seed_args=(-s "$PRODUCER_RANDOM_SEED")
	ld_path="$(afl_ld_library_path)"
	input_dir="$(active_input_corpus_dir)"
	helper_target_csv="${AFL_TREE}/bin/named/.libs/named,-g,-c,${NAMED_CONF},-A,resolver-afl-symcc:${MUTATOR_ADDR}"
	afl_env=(
		LD_LIBRARY_PATH="$ld_path"
		AFL_NO_AFFINITY=1
		AFL_SKIP_CPUFREQ=1
		AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
		AFL_OLD_CHILD_SYNC=1
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR"
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS"
		NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS="$NAMED_RESOLVER_AFL_SYMCC_PERSISTENT_ITERS"
	)
	if [ "$ENABLE_DST1_MUTATOR" = "1" ]; then
		afl_env+=(
			AFL_CUSTOM_MUTATOR_LIBRARY="$DST1_MUTATOR_LIBRARY"
		)
		if [ "$DST1_MUTATOR_ONLY" = "1" ]; then
			afl_env+=(AFL_CUSTOM_MUTATOR_ONLY=1)
		fi
	fi
	if [ "$FUZZ_PROFILE" != "poison-stateful" ]; then
		afl_env+=(
			NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR"
		)
		helper_extra=(
			-r "$RESPONSE_CORPUS_DIR"
			-e NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL
		)
	else
		helper_extra=(--require-poison-eligible)
	fi
	helper_env=(
		LD_LIBRARY_PATH="$ld_path"
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR"
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS"
		SYMCC_HIGH_VALUE_MANIFEST="$SYMCC_HIGH_VALUE_MANIFEST"
	)
	if [ "$FUZZ_PROFILE" != "poison-stateful" ]; then
		helper_env+=(RESPONSE_PRESERVE="$RESPONSE_PRESERVE")
	fi
	if [ -n "$SYMCC_FRONTIER_RELOAD_SEC" ]; then
		helper_env+=(SYMCC_FRONTIER_RELOAD_SEC="$SYMCC_FRONTIER_RELOAD_SEC")
	fi
	if [ -n "$SYMCC_FRONTIER_RETRY_LIMIT" ]; then
		helper_env+=(SYMCC_FRONTIER_RETRY_LIMIT="$SYMCC_FRONTIER_RETRY_LIMIT")
	fi
	if [ -n "$SYMCC_SEMANTIC_FRONTIER_MANIFEST" ]; then
		helper_env+=(SYMCC_SEMANTIC_FRONTIER_MANIFEST="$SYMCC_SEMANTIC_FRONTIER_MANIFEST")
	fi

	if [ "$SHOW_AFL_UI" -ne 1 ] || ! tmux_enabled; then
		master_no_ui=(AFL_NO_UI=1)
	fi

	log "启动 AFL master（持久模式）"
	if tmux_enabled; then
		launch_in_tmux \
			"$MASTER_SESSION" \
			"$MASTER_LOG" \
			env \
			"${afl_env[@]}" \
			"${master_no_ui[@]}" \
			"$AFL_FUZZ_BIN" \
			-M master \
			"${master_seed_args[@]}" \
			-i "$input_dir" \
			-o "$AFL_OUT_DIR" \
			-m none \
			-t "$AFL_TIMEOUT_MS" \
			-- \
			"$AFL_TREE/bin/named/.libs/named" \
			-g \
			-c "$NAMED_CONF" \
			-A "resolver-afl-symcc:${MUTATOR_ADDR}"
	else
		launch_in_background \
			"$MASTER_LOG" \
			"$MASTER_PID" \
			env \
			"${afl_env[@]}" \
			"${master_no_ui[@]}" \
			"$AFL_FUZZ_BIN" \
			-M master \
			"${master_seed_args[@]}" \
			-i "$input_dir" \
			-o "$AFL_OUT_DIR" \
			-m none \
			-t "$AFL_TIMEOUT_MS" \
			-- \
			"$AFL_TREE/bin/named/.libs/named" \
			-g \
			-c "$NAMED_CONF" \
			-A "resolver-afl-symcc:${MUTATOR_ADDR}"
	fi
	AFL_MASTER_STARTED=1

	if [ "$ENABLE_SECONDARY" -eq 1 ]; then
		log "启动 AFL secondary（持久模式）"
		if tmux_enabled; then
			launch_in_tmux \
				"$SECONDARY_SESSION" \
				"$SECONDARY_LOG" \
				env \
				"${afl_env[@]}" \
				AFL_NO_UI=1 \
				"$AFL_FUZZ_BIN" \
				-S secondary \
				-i "$input_dir" \
				-o "$AFL_OUT_DIR" \
				-m none \
				-t "$AFL_TIMEOUT_MS" \
				-- \
				"$AFL_TREE/bin/named/.libs/named" \
				-g \
				-c "$NAMED_CONF" \
				-A "resolver-afl-symcc:${MUTATOR_ADDR}"
		else
			launch_in_background \
				"$SECONDARY_LOG" \
				"$SECONDARY_PID" \
				env \
				"${afl_env[@]}" \
				AFL_NO_UI=1 \
				"$AFL_FUZZ_BIN" \
				-S secondary \
				-i "$input_dir" \
				-o "$AFL_OUT_DIR" \
				-m none \
				-t "$AFL_TIMEOUT_MS" \
				-- \
				"$AFL_TREE/bin/named/.libs/named" \
				-g \
				-c "$NAMED_CONF" \
				-A "resolver-afl-symcc:${MUTATOR_ADDR}"
		fi
		AFL_SECONDARY_STARTED=1
	fi

	if [ -d "$AFL_OUT_DIR/$HELPER_NAME" ]; then
		rm -rf "$AFL_OUT_DIR/$HELPER_NAME"
	fi
	if [ -d "$HELPER_RUN_ROOT/$HELPER_RUN_NAME/${HELPER_RUN_NAME}_symcc" ]; then
		rm -rf "$HELPER_RUN_ROOT/$HELPER_RUN_NAME/${HELPER_RUN_NAME}_symcc"
	fi

	if [ "$ENABLE_SYMCC" = "1" ]; then
		log "启动 SymCC helper"
		if tmux_enabled; then
			launch_shell_in_tmux \
				"$HELPER_SESSION" \
				"$HELPER_LOG" \
				"cd $(printf '%q' "$ROOT_DIR") && while [ ! -f $(printf '%q' "$AFL_OUT_DIR/master/fuzzer_stats") ]; do sleep 1; done && exec $(quote_cmd env "${helper_env[@]}" "$HELPER_BIN" -o "$HELPER_RUN_ROOT" -n "$HELPER_RUN_NAME" -a master -v "${helper_extra[@]}" -t "$helper_target_csv" -- "$SYMCC_TREE/bin/named/named" -g -c "$NAMED_CONF" -A "resolver-afl-symcc:${MUTATOR_ADDR}")"
		else
			wait_for_master_queue
			launch_in_background \
				"$HELPER_LOG" \
				"$HELPER_PID" \
				env \
				"${helper_env[@]}" \
				"$HELPER_BIN" \
				-o "$HELPER_RUN_ROOT" \
				-n "$HELPER_RUN_NAME" \
				-a master \
				-v \
				"${helper_extra[@]}" \
				-t "$helper_target_csv" \
				-- \
				"$SYMCC_TREE/bin/named/named" \
				-g \
				-c "$NAMED_CONF" \
				-A "resolver-afl-symcc:${MUTATOR_ADDR}"
		fi
		SYMCC_HELPER_STARTED=1
	else
		log "ENABLE_SYMCC=0，跳过 SymCC helper 构建/启动"
	fi
	write_execution_manifest "running" ""

	log "实验已启动"
	status_all
	attach_master_ui
}

show_pid_status() {
	local name="$1"
	local pidfile="$2"
	if [ "$name" = "afl-master" ] && tmux_session_alive "$MASTER_SESSION"; then
		printf '  %-14s running (tmux:%s)\n' "$name" "$MASTER_SESSION"
	elif [ "$name" = "afl-secondary" ] && tmux_session_alive "$SECONDARY_SESSION"; then
		printf '  %-14s running (tmux:%s)\n' "$name" "$SECONDARY_SESSION"
	elif [ "$name" = "helper" ] && tmux_session_alive "$HELPER_SESSION"; then
		printf '  %-14s running (tmux:%s)\n' "$name" "$HELPER_SESSION"
	elif pid_is_alive "$pidfile"; then
		printf '  %-14s running (pid=%s)\n' "$name" "$(cat "$pidfile")"
	else
		printf '  %-14s stopped\n' "$name"
	fi
}

show_fuzzer_stats() {
	local stats_file="$1"
	local edges_found=""
	local total_edges=""
	[ -f "$stats_file" ] || return 0
	printf '  %s\n' "$stats_file"
	grep -E '^(execs_done|cycles_done|corpus_count|saved_crashes|saved_hangs|bitmap_cvg|pending_total|last_find|edges_found|total_edges)' \
		"$stats_file" | sed 's/^/    /'

	edges_found="$(awk -F: '$1 ~ /^edges_found/ { gsub(/ /, "", $2); print $2 }' "$stats_file")"
	total_edges="$(awk -F: '$1 ~ /^total_edges/ { gsub(/ /, "", $2); print $2 }' "$stats_file")"
	if [ -n "$edges_found" ] && [ -n "$total_edges" ] && [ "$total_edges" -gt 0 ]; then
		awk -v found="$edges_found" -v total="$total_edges" \
			'BEGIN { printf "    edge_coverage    : %d/%d (%.2f%%)\n", found, total, (found * 100.0) / total }'
	fi
}

show_tmux_pane() {
	local session="$1"
	tmux_session_alive "$session" || return 0
	tmux capture-pane -p -t "${session}:0.0" | sed 's/^/    /'
}

status_all() {
	printf '进程状态:\n'
	printf '  %-14s %s\n' "profile" "$FUZZ_PROFILE"
	show_pid_status "afl-master" "$MASTER_PID"
	show_pid_status "afl-secondary" "$SECONDARY_PID"
	if [ "$ENABLE_SYMCC" = "1" ]; then
		show_pid_status "helper" "$HELPER_PID"
	else
		printf '  %-14s disabled (ENABLE_SYMCC=0)\n' "helper"
	fi

	printf '\nAFL 统计:\n'
	show_fuzzer_stats "$AFL_OUT_DIR/master/fuzzer_stats"
	show_fuzzer_stats "$AFL_OUT_DIR/secondary/fuzzer_stats"
	show_semantic_config_summary
	show_seed_provenance_summary

	if tmux_session_alive "$MASTER_SESSION"; then
		printf '\nAFL UI:\n'
		printf '  master session: %s\n' "$MASTER_SESSION"
		printf '  手动查看: tmux attach-session -t %s\n' "$MASTER_SESSION"
		printf '  当前页面:\n'
		show_tmux_pane "$MASTER_SESSION"
	fi

	printf '\n日志尾部:\n'
	for log_file in "$MASTER_LOG" "$SECONDARY_LOG" "$HELPER_LOG"; do
		[ -f "$log_file" ] || continue
		printf '  %s\n' "$log_file"
		tail -n 5 "$log_file" | sed 's/^/    /'
	done
}

dump_named_cache() {
	local sample="$1"
	local output_path="${2:-$CACHE_DUMP_DIR/$(basename "$sample").named.cache.txt}"
	local stderr_file="$WORK_DIR/named_dump_cache.stderr"
	local ld_path
	local rc=0
	local -a named_args=()

	require_file "$AFL_TREE/bin/named/.libs/named"
	[ -d "$RESPONSE_CORPUS_DIR" ] || die "response 语料目录不存在: $RESPONSE_CORPUS_DIR"
	if [ -n "$sample" ]; then
		require_file "$sample"
	fi

	ensure_dirs
	ld_path="$(afl_ld_library_path)"
	mkdir -p "$(dirname "$output_path")"
	rm -f "$output_path" "$stderr_file"

	if [ -n "$sample" ]; then
		log "dump-cache: 回放 $(basename "$sample")"
		named_args=(
			-g
			-c "$NAMED_CONF"
			-A "resolver-afl-symcc:${MUTATOR_ADDR},input=$sample"
		)
	else
		log "dump-cache: 导出空实例 cache"
		named_args=(
			-g
			-c "$NAMED_CONF"
			-A "resolver-afl-symcc:${MUTATOR_ADDR}"
		)
	fi
	set +e
	env \
		LD_LIBRARY_PATH="$ld_path" \
		NAMED_RESOLVER_AFL_SYMCC_TARGET="$TARGET_ADDR" \
		NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR="$RESPONSE_CORPUS_DIR" \
		NAMED_RESOLVER_AFL_SYMCC_REPLY_TIMEOUT_MS="$REPLY_TIMEOUT_MS" \
		NAMED_RESOLVER_AFL_SYMCC_CACHE_DUMP_PATH="$output_path" \
		timeout -k 2 "$SEED_TIMEOUT_SEC" \
		"$AFL_TREE/bin/named/.libs/named" \
		"${named_args[@]}" \
		< /dev/null \
		>/dev/null 2>"$stderr_file"
	rc=$?
	set -e

	case "$rc" in
	0)
		;;
	124|137)
		die "dump-cache 超时: rc=$rc"
		;;
	*)
		die "dump-cache 异常退出: rc=$rc"
		;;
	esac

	[ -s "$output_path" ] || die "cache dump 为空，stderr: $stderr_file"
	log "cache dump 已写出: $output_path"
}

run_for_duration() {
	local duration="${1:-$RUN_DURATION_SEC}"

	case "$duration" in
	""|*[!0-9]*)
		die "run 持续时间必须是正整数秒: $duration"
		;;
	esac
	[ "$duration" -gt 0 ] || die "run 持续时间必须大于 0: $duration"

	cleanup_run_for_duration() {
		local rc="$?"
		stop_all >/dev/null 2>&1 || true
		finish_execution_manifest "failed" "$rc" >/dev/null 2>&1 || true
	}

	trap cleanup_run_for_duration EXIT
	trap 'exit 130' INT TERM

	start_all
	log "开始定时运行: ${duration}s"
	sleep "$duration"
	log "定时运行结束，输出当前状态"
	status_all

	trap - EXIT INT TERM
	stop_all
	finish_execution_manifest "success" 0
}

handle_execution_error() {
	local rc="$1"
	trap - ERR
	if execution_manifest_is_running; then
		stop_all >/dev/null 2>&1 || true
		finish_execution_manifest "failed" "$rc" >/dev/null 2>&1 || true
	fi
	return "$rc"
}

main() {
	local cmd="${1:-}"

	if [ "$#" -gt 0 ]; then
		shift
	fi

	case "$cmd" in
	build)
		ensure_dirs
		sync_patch
		build_helper_and_gen_input
		build_afl_named
		if [ "$ENABLE_SYMCC" = "1" ]; then
			build_symcc_named
		fi
		;;
	gen-seeds)
		generate_seeds
		;;
	filter-seeds)
		filter_seeds
		;;
	prepare)
		prepare_all
		;;
	start)
		start_all
		;;
	dump-cache)
		dump_named_cache "${1:-}" "${2:-}"
		;;
	run)
		run_for_duration "${1:-}"
		;;
	stop)
		stop_all
		finish_execution_manifest "success" 0
		;;
	status)
		status_all
		;;
	""|-h|--help|help)
		usage
		;;
	*)
		usage
		die "未知命令: $cmd"
		;;
	esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	require_cmd timeout
	require_cmd make
	require_cmd grep
	require_cmd sed
	require_cmd find
	require_cmd awk
	validate_patch_variant "$PATCH_VARIANT"
	require_file "$PATCH_ROOT"
	require_file "$NAMED_CONF_TEMPLATE"
	resolve_bind9_tree_layout_defaults
	load_profile
	validate_component_switches
	export -n AFL_TREE 2>/dev/null || true
	export -n AFL_CC_BIN 2>/dev/null || true
	export -n AFL_FUZZ_BIN 2>/dev/null || true
	export -n AFL_TIMEOUT_MS 2>/dev/null || true

	trap 'handle_execution_error "$?"' ERR
	main "$@"
	trap - ERR
fi
