#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1

python3 - "$ROOT_DIR" <<'PY'
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from tools.dns_diff import publication_audit

# 只替换外部 producer 可执行文件与构建/展示边界，不运行 resolver 或 fuzzing。
stub_source = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import sys

args = sys.argv[1:]
role = "master" if "-M" in args else "secondary" if "-S" in args else "symcc"
work = Path(os.environ["WORK_DIR"])
(work / (role + ".json")).write_text(json.dumps({
    "argv": args, "pid": os.getpid(),
    "mutator": os.environ.get("AFL_CUSTOM_MUTATOR_LIBRARY"),
    "mutator_only": os.environ.get("AFL_CUSTOM_MUTATOR_ONLY"),
    "symcc_random_seed": os.environ.get("SYMCC_RANDOM_SEED"),
    "feedback": {key: os.environ.get(key) for key in (
        "SYMCC_HIGH_VALUE_MANIFEST", "SYMCC_SEMANTIC_FRONTIER_MANIFEST",
        "SYMCC_FRONTIER_RELOAD_SEC", "SYMCC_FRONTIER_RETRY_LIMIT")},
}))
if role == "master":
    queue = work / "afl_out/master/queue"
    queue.mkdir(parents=True, exist_ok=True)
    (queue / "id:000000").write_bytes(b"DST1-fixture")
    (queue / "id:000000.meta.json").write_text('{"run": 1}')
    if os.environ.get("FAIL_COMPONENT") != "master-no-stats":
        (queue.parent / "fuzzer_stats").write_text("fixture\\n")
signal.pause()
"""

driver = r'''
set -euo pipefail
source "$1/named_experiment/run_named_afl_symcc.sh"
AFL_FUZZ_BIN="$WORK_DIR/component"
HELPER_BIN="$WORK_DIR/component"
AFL_TREE="$WORK_DIR/afl"
SYMCC_TREE="$WORK_DIR/symcc"
DST1_MUTATOR_LIBRARY="$WORK_DIR/dst1-mutator.so"
prepare_all() {
    mkdir -p "$LOG_DIR" "$PID_DIR" "$STABLE_TRANSCRIPT_CORPUS_DIR"
    printf seed >"$STABLE_TRANSCRIPT_CORPUS_DIR/seed"
}
afl_ld_library_path() { printf '%s' "$WORK_DIR/libs"; }
status_all() { :; }
attach_master_ui() { :; }
stop_all() {
    local file pid
    for file in "$HELPER_PID" "$SECONDARY_PID" "$MASTER_PID"; do
        if [ -f "$file" ]; then
            pid="$(cat "$file")"
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            rm -f "$file"
        fi
    done
}
trap stop_all EXIT
trap 'handle_execution_error "$?"' ERR
if [ -n "${FAIL_COMPONENT:-}" ]; then
    eval "$(declare -f launch_in_background | sed '1s/launch_in_background/launch_component/')"
    launch_in_background() {
        if [ "$2" = "$PID_DIR/$FAIL_COMPONENT" ]; then
            return 23
        fi
        launch_component "$@"
    }
fi
# 用临时子进程模拟 tmux 传输，仍执行实际组装的命令及 shell quoting。
tmux_enabled() { [ "$USE_TMUX" = 1 ]; }
tmux_session_alive() { return 1; }
launch_in_tmux() {
    local session="$1" logfile="$2" pidfile
    shift 2
    case "$session" in
        "$MASTER_SESSION") pidfile="$MASTER_PID" ;;
        "$SECONDARY_SESSION") pidfile="$SECONDARY_PID" ;;
        "$HELPER_SESSION") pidfile="$HELPER_PID" ;;
    esac
    launch_in_background "$logfile" "$pidfile" bash -c "exec $(quote_cmd "$@")"
}
wait_for_master_queue() {
    local i
    for i in $(seq 1 200); do
        [ ! -f "$AFL_OUT_DIR/master/fuzzer_stats" ] || return 0
        sleep 0.01
    done
    return 1
}
load_profile
validate_component_switches
start_all
for role in master secondary symcc; do
    [ "$role" != secondary ] || [ "$ENABLE_SECONDARY" = 1 ] || continue
    [ "$role" != symcc ] || [ "$ENABLE_SYMCC" = 1 ] || continue
    for i in $(seq 1 200); do
        [ ! -f "$WORK_DIR/$role.json" ] || break
        sleep 0.01
    done
    [ -f "$WORK_DIR/$role.json" ]
done
write_execution_manifest running ""
cp "$EXECUTION_MANIFEST_FILE" "$WORK_DIR/running.json"
printf '{"run": 2}\n' >"$AFL_OUT_DIR/master/queue/id:000000.meta.json"
write_execution_manifest running ""
cp "$EXECUTION_MANIFEST_FILE" "$WORK_DIR/metadata-change.json"
stop_all
finish_execution_manifest success 0
'''

with tempfile.TemporaryDirectory(prefix="symcc-named-execution-") as temp:
    run_ids = set()
    queue_hashes = set()
    command_sets = {}
    feedback_sets = {}
    audit_ids = {"producer_run_ids": set(), "random_seeds": set()}
    for name, tmux, symcc, secondary, mutator, only, failure in [
        ("full", 0, 1, 1, 1, 1, ""),
        ("afl-only", 0, 0, 0, 1, 0, ""),
        ("no-mutator", 0, 1, 1, 0, 1, ""),
        ("tmux-full", 1, 1, 1, 1, 1, ""),
        ("no-cache-delta", 0, 1, 1, 1, 1, ""),
        ("no-triage", 0, 1, 1, 1, 1, ""),
        ("wide-seed", 0, 1, 1, 1, 1, ""),
        ("zero-seed", 0, 1, 1, 1, 1, ""),
        ("leading-zero-seed", 0, 1, 1, 1, 1, ""),
        ("failed-master", 0, 1, 1, 1, 1, "afl_master.pid"),
        ("failed-helper", 1, 1, 1, 1, 1, "helper.pid"),
        ("master-not-ready", 1, 0, 1, 1, 1, "master-no-stats"),
    ]:
        work = Path(temp) / (name + " quoted path")
        work.mkdir()
        stub = work / "component"
        stub.write_text(stub_source)
        stub.chmod(0o755)
        producer_seed = {
            "wide-seed": "4294967296", "zero-seed": "0", "leading-zero-seed": "0007",
        }.get(name, "4294967295")
        env = dict(os.environ, WORK_DIR=str(work), BIND9_WORK_DIR=str(work),
                   PRODUCER_RANDOM_SEED=producer_seed, USE_TMUX=str(tmux),
                   SYMCC_RANDOM_SEED="19",
                   SYMCC_HIGH_VALUE_MANIFEST=str(work / "high_value_samples.txt"),
                   SYMCC_SEMANTIC_FRONTIER_MANIFEST=str(work / "semantic_frontier_manifest.json"),
                   PRODUCER_REPEAT_INDEX="1", PRODUCER_VARIANT_NAME="", VARIANT_NAME="",
                   ENABLE_SYMCC=str(symcc), ENABLE_SECONDARY=str(secondary),
                   ENABLE_DST1_MUTATOR=str(mutator), DST1_MUTATOR_ONLY=str(only),
                   ENABLE_CACHE_DELTA="0" if name == "no-cache-delta" else "1",
                   ENABLE_TRIAGE="0" if name == "no-triage" else "1", SHOW_AFL_UI="0",
                   RESET_OUTPUT="1", FUZZ_PROFILE="poison-stateful",
                   FAIL_COMPONENT=failure,
                   AFL_CUSTOM_MUTATOR_LIBRARY="/must-not-leak.so",
                   AFL_CUSTOM_MUTATOR_ONLY="1")
        result = subprocess.run(["bash", "-c", driver, "_", str(root)],
                                env=env, capture_output=True, text=True, timeout=15)
        if failure:
            expected_rc = 1 if failure == "master-no-stats" else 23
            assert result.returncode == expected_rc, (name, result.stdout, result.stderr)
            failed = json.loads((work / "producer_execution_manifest.json").read_text())
            assert failed["status"] == "failed", (name, failed)
            assert failed["exit_code"] == expected_rc
            assert failed["components"]["symcc"]["started"] is False
            assert failed["components"]["afl_master"]["started"] is (failure != "afl_master.pid")
            print("PASS:", name)
            continue
        assert result.returncode == 0, (name, result.stdout, result.stderr)
        if name in {"no-cache-delta", "no-triage"}:
            assert "不是生成消融" in result.stderr
        running = json.loads((work / "running.json").read_text())
        for role, key, enabled in [
            ("master", "afl_master", True),
            ("secondary", "afl_secondary", bool(secondary)),
            ("symcc", "symcc", bool(symcc)),
        ]:
            component = running["components"][key]
            assert component["enabled"] is enabled, (name, key, component)
            assert component["started"] is enabled, (name, key, component)
            record_path = work / (role + ".json")
            assert record_path.exists() is enabled, (name, role)
            if not enabled:
                assert component["pid"] is None and component["command_summary"] is None
                continue
            record = json.loads(record_path.read_text())
            assert component["pid"] == record["pid"], (name, key, component, record)
            if role != "symcc":
                args = record["argv"]
                assert "-s" in args, (name, role, "缺少 -s", args)
                assert args[args.index("-s") + 1] == producer_seed, (name, role, args)
                assert record["mutator"] == (str(work / "dst1-mutator.so") if mutator else None)
                assert record["mutator_only"] == ("1" if mutator and only else None)
            else:
                expected_solver_seed = {
                    "wide-seed": "0", "zero-seed": "0", "leading-zero-seed": "7",
                }.get(name, "4294967295")
                assert record["symcc_random_seed"] == expected_solver_seed, (name, record)
                feedback_sets[name] = {
                    key: value.replace(str(work), "<work>") if value else value
                    for key, value in record["feedback"].items()
                }
            command = shlex.split(component["command_summary"])
            assert command[command.index(str(stub)) + 1:] == record["argv"], (name, role, command)
        command_sets[name] = {
            key: [arg.replace(str(work), "<work>") for arg in shlex.split(component["command_summary"])]
            if component["command_summary"] else None
            for key, component in running["components"].items()
        }
        assert running["execution_mode"] == "independent_producer_generation"
        assert running["random_seed"] == int(producer_seed)
        assert running["producer_run_id"] not in run_ids
        run_ids.add(running["producer_run_id"])
        snapshot = running["queue_snapshot"]
        assert snapshot["algorithm"] == "sha256-relative-path-size-content-v2"
        assert snapshot["file_count"] == 1 and snapshot["size_bytes"] == len(b"DST1-fixture")
        queue_hashes.add(snapshot["sha256"])
        changed = json.loads((work / "metadata-change.json").read_text())
        assert changed["queue_snapshot"] == snapshot
        final = json.loads((work / "producer_execution_manifest.json").read_text())
        assert final["status"] == "success" and final["finished_at"]
        assert final["producer_run_id"] == running["producer_run_id"]
        for key, component in running["components"].items():
            assert final["components"][key]["command_summary"] == component["command_summary"]
            assert final["components"][key]["exit_status"] is None
        # 喂给 B2 的是真实 writer 输出，但进程/队列来自替身，绝不是实验结果。
        manifest_path = work / "producer_execution_manifest.json"
        before_audit = manifest_path.read_bytes()
        issues = []
        expected_variant = {
            "afl-only": "afl_only", "no-mutator": "no_mutator",
            "no-cache-delta": "no_cache_delta", "no-triage": "custom",
        }.get(name, "full_stack")
        publication_audit._audit_producer_execution_manifest(
            run={}, expected_run_dir=work, variant_name=expected_variant,
            repeat_index=1,
            expected_env={key: env[key] for key in (
                "ENABLE_DST1_MUTATOR", "ENABLE_CACHE_DELTA", "ENABLE_TRIAGE", "ENABLE_SYMCC")},
            matrix_root=Path(temp), scope=name, issues=issues,
            **(audit_ids if name in {"full", "wide-seed"}
               else {"producer_run_ids": set(), "random_seeds": set()}))
        assert not issues, (name, issues)
        assert manifest_path.read_bytes() == before_audit
        # stop 可以在另一个 shell 运行；其默认开关/seed 不能改写原执行事实。
        (work / "producer_execution_manifest.json").write_text(json.dumps(running))
        stop = subprocess.run(
            ["bash", "-c", 'source "$1/named_experiment/run_named_afl_symcc.sh"; '
             'load_profile; finish_execution_manifest success 0', "_", str(root)],
            env=dict(env, ENABLE_SYMCC="0" if symcc else "1",
                     ENABLE_SECONDARY="0", PRODUCER_RANDOM_SEED="17"),
            capture_output=True, text=True, timeout=5)
        assert stop.returncode == 0, stop.stderr
        stopped = json.loads((work / "producer_execution_manifest.json").read_text())
        assert stopped["random_seed"] == running["random_seed"]
        assert stopped["components"] == final["components"], (name, stopped, final)
        legacy = dict(running)
        legacy.pop("execution_mode")
        legacy["queue_snapshot"] = dict(snapshot, algorithm="sha256-relative-path-size-content-v1")
        legacy_text = json.dumps(legacy)
        (work / "producer_execution_manifest.json").write_text(legacy_text)
        legacy_stop = subprocess.run(
            ["bash", "-c", 'source "$1/named_experiment/run_named_afl_symcc.sh"; '
             'load_profile; finish_execution_manifest success 0', "_", str(root)],
            env=env, capture_output=True, text=True, timeout=5)
        assert legacy_stop.returncode == 0, legacy_stop.stderr
        assert (work / "producer_execution_manifest.json").read_text() == legacy_text
        print("PASS:", name)

    assert len(run_ids) == 9 and len(queue_hashes) == 1
    for variant in ("no-cache-delta", "no-triage"):
        assert command_sets[variant] == command_sets["full"], variant
        assert feedback_sets[variant] == feedback_sets["full"], variant
    print("PASS: 等价生成配置的命令/反馈参数；writer → B2（仅替身合同联调）")
    shutdown_work = Path(temp) / "shutdown"
    shutdown = subprocess.run(["bash", "-c", r'''
        source "$1/named_experiment/run_named_afl_symcc.sh"
        AFL_TREE="$WORK_DIR/afl"
        SYMCC_TREE="$WORK_DIR/symcc"
        mkdir -p "$PID_DIR"
        sleep 60 &
        old_helper=$!
        trap 'kill "$old_helper" 2>/dev/null || true; wait "$old_helper" 2>/dev/null || true' EXIT
        echo "$old_helper" >"$HELPER_PID"
        stop_all
        if kill -0 "$old_helper" 2>/dev/null; then
            printf 'ASSERT FAIL: ENABLE_SYMCC=0 遗留上一轮 helper\n' >&2
            exit 1
        fi
    ''', "_", str(root)], env=dict(os.environ, WORK_DIR=str(shutdown_work),
                                  BIND9_WORK_DIR=str(shutdown_work), USE_TMUX="0",
                                  ENABLE_SYMCC="0"),
        capture_output=True, text=True, timeout=15)
    assert shutdown.returncode == 0, (shutdown.stdout, shutdown.stderr)
    print("PASS: disabled-symcc-stops-old-helper")
PY
