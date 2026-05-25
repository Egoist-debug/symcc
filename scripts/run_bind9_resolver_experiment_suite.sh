#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/real_experiment_paths.sh"

STAMP="${STAMP:-$(date -u +%Y%m%d_%H%M%S)}"
SUITE_ROOT="${SUITE_ROOT:-$ROOT_DIR/experiments/results/bind9_resolver_experiment_suite/$STAMP}"
PRODUCER_RESULT_ROOT="$SUITE_ROOT/producer"
PRODUCER_WORK_DIR="${PRODUCER_WORK_DIR:-$PRODUCER_RESULT_ROOT/work}"
PRODUCER_SMOKE_SEC="${PRODUCER_SMOKE_SEC:-180}"
PRODUCER_DURATION_SEC="${PRODUCER_DURATION_SEC:-3600}"
RESOLVER_VARIANT_BUDGET_SEC="${RESOLVER_VARIANT_BUDGET_SEC:-900}"
RESOLVER_REPEAT_COUNT="${RESOLVER_REPEAT_COUNT:-1}"
RESOLVER_REPLAY_BACKEND="${RESOLVER_REPLAY_BACKEND:-python}"
RESOLVERS="${RESOLVERS:-unbound dnsmasq smartdns maradns knot-resolver}"
CAPABILITY_OUTPUT_DIR="$SUITE_ROOT/_resolver_capability"

usage() {
	cat <<'EOF'
用法:
  scripts/run_bind9_resolver_experiment_suite.sh <命令>

命令:
  preflight             校验依赖、resolver 源树与构建树
  producer-smoke        运行一次短时 producer smoke
  producer-1h           运行一次 3600 秒 producer 正式实验
  replay-matrix         生成全 resolver build/replay 能力矩阵
  resolver-smoke        运行全 resolver 小预算 campaign matrix
  resolver-1h-each      运行每个 resolver 总计约 1 小时的 4 变体矩阵
  capability-report     汇总 replay matrix 与 resolver matrix 为能力总表
  all                   执行 preflight -> producer-smoke -> producer-1h -> replay-matrix -> resolver-1h-each -> capability-report
EOF
}

latest_run_dir() {
	local base="$1"
	find "$base" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

preflight() {
	local cmd
	for cmd in python3 timeout make xmake; do
		command -v "$cmd" >/dev/null 2>&1 || {
			printf '缺少命令: %s\n' "$cmd" >&2
			exit 1
		}
	done

	[ -x "$ROOT_DIR/build/linux/x86_64/release/dnslabctl" ] || {
		printf '缺少可执行文件: %s\n' "$ROOT_DIR/build/linux/x86_64/release/dnslabctl" >&2
		exit 1
	}
	[ -f "$ROOT_DIR/experiments/resolvers.lock.json" ] || {
		printf '缺少 lock 文件: %s\n' "$ROOT_DIR/experiments/resolvers.lock.json" >&2
		exit 1
	}
	[ -d "$(resolver_src_root bind9)" ] || {
		printf '缺少 bind9 源树: %s\n' "$(resolver_src_root bind9)" >&2
		exit 1
	}

	for resolver in $RESOLVERS; do
		[ -d "$(resolver_src_root "$resolver")" ] || {
			printf '缺少 resolver 源树: %s -> %s\n' "$resolver" "$(resolver_src_root "$resolver")" >&2
			exit 1
		}
		if [ "$resolver" = "unbound" ]; then
			[ -d "$(unbound_afl_tree)" ] || {
				printf '缺少 unbound AFL 构建树: %s\n' "$(unbound_afl_tree)" >&2
				exit 1
			}
		else
			[ -d "$(resolver_build_root "$resolver")" ] || {
				printf '缺少 resolver 构建树: %s -> %s\n' "$resolver" "$(resolver_build_root "$resolver")" >&2
				exit 1
			}
		fi
	done

	printf '%s\n' "$SUITE_ROOT"
}

run_producer() {
	local duration="$1"
	mkdir -p "$PRODUCER_RESULT_ROOT"
	env \
		FUZZ_PROFILE=poison-stateful \
		WORK_DIR="$PRODUCER_WORK_DIR" \
		SRC_TREE="$(resolver_src_root bind9)" \
		AFL_TREE="$(bind9_afl_tree)" \
		SYMCC_TREE="$(bind9_symcc_tree)" \
		RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
		"$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" prepare
	env \
		FUZZ_PROFILE=poison-stateful \
		WORK_DIR="$PRODUCER_WORK_DIR" \
		SRC_TREE="$(resolver_src_root bind9)" \
		AFL_TREE="$(bind9_afl_tree)" \
		SYMCC_TREE="$(bind9_symcc_tree)" \
		RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
		"$ROOT_DIR/named_experiment/run_named_afl_symcc.sh" run "$duration"
	printf '%s\n' "$PRODUCER_WORK_DIR"
}

producer_smoke() {
	run_producer "$PRODUCER_SMOKE_SEC"
}

producer_1h() {
	run_producer "$PRODUCER_DURATION_SEC"
}

replay_matrix() {
	env RESULT_ROOT_BASE="$SUITE_ROOT/replay_matrix" "$ROOT_DIR/scripts/run_real_resolver_replay_matrix.sh"
}

run_matrix() {
	local result_root_base="$1"
	local budget_sec="$2"
	local repeat_count="$3"
	env \
		RESULT_ROOT_BASE="$result_root_base" \
		REPLAY_BACKEND="$RESOLVER_REPLAY_BACKEND" \
		PRODUCER_QUEUE_DIR="$PRODUCER_WORK_DIR/afl_out/master/queue" \
		PRODUCER_PROVENANCE_FILE="$PRODUCER_WORK_DIR/producer_seed_provenance.json" \
		RESPONSE_CORPUS_DIR="$(default_response_corpus_dir)" \
		BUDGET_SEC="$budget_sec" \
		REPEAT_COUNT="$repeat_count" \
		RESOLVERS="$RESOLVERS" \
		"$ROOT_DIR/scripts/run_real_campaign_matrix_multi_resolver.sh"
}

resolver_smoke() {
	run_matrix "$SUITE_ROOT/resolver_smoke_matrix" "${SMOKE_MATRIX_BUDGET_SEC:-5}" "${SMOKE_MATRIX_REPEAT_COUNT:-1}"
}

resolver_1h_each() {
	run_matrix "$SUITE_ROOT/resolver_matrix_1h_each" "$RESOLVER_VARIANT_BUDGET_SEC" "$RESOLVER_REPEAT_COUNT"
}

capability_report() {
	local replay_matrix_root="${REPLAY_MATRIX_DIR:-$(latest_run_dir "$SUITE_ROOT/replay_matrix")}"
	local resolver_matrix_root="${RESOLVER_MATRIX_DIR:-$(latest_run_dir "$SUITE_ROOT/resolver_matrix_1h_each")}"
	[ -n "$replay_matrix_root" ] || {
		printf '缺少 replay matrix 目录\n' >&2
		exit 1
	}
	[ -n "$resolver_matrix_root" ] || {
		printf '缺少 resolver matrix 目录\n' >&2
		exit 1
	}
	mkdir -p "$CAPABILITY_OUTPUT_DIR"
	python3 -m tools.dns_diff.cli resolver-capability-report \
		--replay-matrix-dir "$replay_matrix_root" \
		--matrix-batch-dir "$resolver_matrix_root" \
		--output-dir "$CAPABILITY_OUTPUT_DIR"
	printf '%s\n' "$CAPABILITY_OUTPUT_DIR"
}

main() {
	local cmd="${1:-help}"
	case "$cmd" in
		preflight) preflight ;;
		producer-smoke) producer_smoke ;;
		producer-1h) producer_1h ;;
		replay-matrix) replay_matrix ;;
		resolver-smoke) resolver_smoke ;;
		resolver-1h-each) resolver_1h_each ;;
		capability-report) capability_report ;;
		all)
			preflight >/dev/null
			producer_smoke >/dev/null
			producer_1h >/dev/null
			replay_matrix >/dev/null
			resolver_1h_each >/dev/null
			capability_report
			;;
		""|-h|--help|help)
			usage
			;;
		*)
			printf '未知命令: %s\n' "$cmd" >&2
			usage >&2
			exit 1
			;;
	esac
}

main "${1:-help}"
