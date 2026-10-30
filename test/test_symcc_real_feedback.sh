#!/usr/bin/env bash
set -euo pipefail

# 只使用现有工具链；这是小目标诊断，不是 DNS 实验或 producer 来源夹具。
if ! command -v python3 >/dev/null; then
	printf 'SKIP: 缺少 python3\n' >&2
	exit 77
fi
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 -B - "$ROOT_DIR" <<'PY'
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


root = Path(sys.argv[1])
build = root / "build/linux/x86_64/release"
tools = {
    "symcc": build / "symcc",
    "pass": build / "libsymcc.so",
    "runtime": build / "libsymcc-rt.so",
    "helper": build / "symcc_fuzzing_helper",
    "clang": Path("/usr/lib/llvm-21/bin/clang"),
    "afl_cc": Path("/usr/local/bin/afl-clang-fast"),
    "afl_fuzz": Path("/usr/local/bin/afl-fuzz"),
    "showmap": Path("/usr/local/bin/afl-showmap"),
    "timeout": Path("/usr/bin/timeout"),
    "ldd": Path("/usr/bin/ldd"),
}
missing = [str(p) for key, p in tools.items()
           if not p.is_file() or (key not in ("pass", "runtime") and not os.access(p, os.X_OK))]
if sys.platform != "linux" or missing:
    print("SKIP: 需要 Linux 和现有 LLVM21/QSYM/C++ helper/AFL 工具：" + ", ".join(missing))
    sys.exit(77)
if os.environ.get("B3_OUTPUT_ROOT") != "/tmp":
    print("FAIL: 必须显式设置 B3_OUTPUT_ROOT=/tmp；不允许写历史结果目录", file=sys.stderr)
    sys.exit(1)

# subreaper 收养另建进程组的孙进程，不能只 kill 外层 timeout。
require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
        "无法启用 PR_SET_CHILD_SUBREAPER")
cpu = min(os.sched_getaffinity(0))
os.sched_setaffinity(0, {cpu})
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
work = Path(tempfile.mkdtemp(prefix="symcc-real-feedback.", dir="/tmp"))
started = time.monotonic()
for name in ("tmp", "solve", "seed", "logs"):
    (work / name).mkdir()
print(f"B3_OUTPUT={work}", flush=True)
env = {key: val for key, val in os.environ.items()
       if not key.startswith(("SYMCC_", "AFL_")) and key not in ("LD_PRELOAD", "LD_LIBRARY_PATH")}
env.update(PATH="/usr/local/bin:/usr/bin:/bin", TMPDIR=str(work / "tmp"),
           LC_ALL="C", SYMCC_RANDOM_SEED="1", SYMCC_ENABLE_LINEARIZATION="1",
           AFL_NO_UI="1", AFL_NO_AFFINITY="1")
report = {
    "status": "failed", "execution_mode": "bounded_symbolic_feedback_diagnostic",
    "dns_b3_verified": False, "helper_fuzzer_stats_is_fixture": True,
    "cpu": cpu, "budget_seconds": 180, "output_limit_bytes": 64 * 1024 * 1024,
    "output_limit_files": 256, "commands": [], "binaries": {},
    "environment": {k: v for k, v in env.items()
                    if k.startswith(("SYMCC_", "AFL_")) or k in ("PATH", "TMPDIR", "LC_ALL")},
    "removed_environment_keys": sorted(set(os.environ) - set(env)),
}
peak_bytes = peak_files = 0


def descendants(pid=None):
    children = set()
    for task in Path(f"/proc/{pid or os.getpid()}/task").glob("*"):
        try:
            children.update(map(int, (task / "children").read_text().split()))
        except FileNotFoundError:
            pass
    result = list(children)
    for child in children:
        result.extend(descendants(child))
    return result


def terminate_children(proc=None):
    # 只回收本诊断的子孙，绝不按进程名匹配其他 worker。
    killed = set()
    deadline = time.monotonic() + 1
    while True:
        pids = descendants()
        for pid in reversed(pids):
            try:
                os.kill(pid, signal.SIGKILL)
                killed.add(pid)
            except ProcessLookupError:
                pass
        if proc is not None:
            proc.poll()
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        if not descendants():
            return sorted(killed)
        require(time.monotonic() < deadline, "子孙进程未能在清理时限内退出")
        time.sleep(0.01)


def guard():
    global peak_bytes, peak_files
    size = count = 0
    for path in work.rglob("*"):
        try:
            stat = path.lstat()
        except FileNotFoundError:
            continue
        if not path.is_dir():
            count += 1
            size += max(stat.st_size, stat.st_blocks * 512)
    peak_bytes, peak_files = max(peak_bytes, size), max(peak_files, count)
    require(size <= report["output_limit_bytes"] and count <= report["output_limit_files"],
            f"输出超限：{size} bytes / {count} files")
    require(time.monotonic() - started < 178, "总诊断时限已到，预留 2 秒回收")


def interrupted(signum, frame):
    raise RuntimeError(f"收到信号 {signum}，停止并回收本测试")


for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
    signal.signal(sig, interrupted)
signal.alarm(178)


def run(label, argv, seconds, stdin=None, extra=None, ready=None):
    guard()
    command = list(map(str, argv))
    out, err = work / "logs" / (label + ".stdout"), work / "logs" / (label + ".stderr")
    record = {"label": label, "argv": command, "command": shlex.join(command),
              "timeout_seconds": seconds, "stdin": str(stdin) if stdin else None,
              "environment_delta": extra or {}, "stdout": str(out), "stderr": str(err)}
    report["commands"].append(record)
    begin = time.monotonic()
    with open(stdin or os.devnull, "rb") as inp, out.open("wb") as stdout, err.open("wb") as stderr:
        proc = subprocess.Popen(command, stdin=inp, stdout=stdout, stderr=stderr,
                                cwd=work, env=env | (extra or {}), start_new_session=True)
        record["pid"] = proc.pid
        try:
            while proc.poll() is None:
                guard()
                if ready is not None and ready():
                    record["stop_reason"] = "feedback_observed"
                    proc.terminate()
                    try:
                        proc.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
                    break
                require(time.monotonic() - begin < seconds, f"{label} 超时（不能当 PASS）")
                time.sleep(0.05)
        finally:
            record["killed_descendants"] = terminate_children(proc)
            record["returncode"] = proc.wait()
            record["elapsed_seconds"] = round(time.monotonic() - begin, 3)
    if ready is None:
        require(record["returncode"] == 0, f"{label} 退出 {record['returncode']}，见 {err}")
    else:
        require(record.get("stop_reason") == "feedback_observed", "helper 未完成回流即退出")
    return out.read_text(errors="replace"), err.read_text(errors="replace")


def identity(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "resolved_path": str(path.resolve()),
            "size_bytes": path.stat().st_size, "sha256": digest}


def concrete(path, label):
    data = path.read_bytes()
    require(len(data) == 4, f"{path} 不是完整的 4 字节整数")
    x = int.from_bytes(data, "little", signed=True)
    double = (2 * x + 2**31) % 2**32 - 2**31
    expected = x if double < 7 else (7 if x % 7 else (x + 7 + 2**31) % 2**32 - 2**31)
    _, stderr = run(label, [work / "if.afl"], 2, stdin=path)
    require(stderr.splitlines() == [str(x), str(expected)], f"{label} 具体分支结果不符：{stderr!r}")
    return identity(path) | {"hex": data.hex(), "input_int": x, "foo_result": expected}


try:
    report["source"] = identity(root / "test/if.c")
    report["script"] = identity(root / "test/test_symcc_real_feedback.sh")
    for key, path in tools.items():
        report["binaries"][key] = identity(path)
    linked, _ = run("runtime-linkage", [tools["ldd"], tools["runtime"]], 3)
    require("not found" not in linked, "runtime 共享库依赖缺失")
    for key, pattern in (("z3", r"libz3\.so\S*\s+=>\s+(\S+)"),
                         ("llvm", r"libLLVM\S*\s+=>\s+(\S+)")):
        match = re.search(pattern, linked)
        require(match is not None, f"runtime 缺少真实 {key} 依赖")
        report["binaries"][key] = identity(Path(match[1]))
    for label, compiler, target in (("compile-sym", tools["symcc"], "if.sym"),
                                    ("compile-afl", tools["afl_cc"], "if.afl")):
        run(label, [compiler, "-O0", "-fwrapv", root / "test/if.c", "-o", work / target], 20)
        report["binaries"][target] = identity(work / target)
    seed = work / "seed/five"
    seed.write_bytes(bytes.fromhex("05000000"))
    report["seed"] = concrete(seed, "baseline")
    require(report["seed"]["foo_result"] == 7, "基线必须进入返回 7 的分支")
    _, solver = run("solver", [work / "if.sym"], 5, stdin=seed,
                    extra={"SYMCC_OUTPUT_DIR": str(work / "solve")})
    require("QSYM backend" in solver and "[STAT] SMT:" in solver, "缺少 QSYM/SMT 事实")
    report["solver_stats"] = [json.loads(line.split("SMT:", 1)[1])
                              for line in solver.splitlines() if line.startswith("[STAT] SMT:")]
    require(any(item.get("solving_time", 0) > 0 for item in report["solver_stats"]),
            "没有实际求解耗时记录")
    require(re.findall(r"(?m)^-?\d+$", solver) == ["5", "7"], "符号基线具体结果不符")
    candidates = sorted((work / "solve").iterdir())
    require(0 < len(candidates) <= 32, "solver 未产生候选或超出小目标预算")
    report["solver_candidates"] = []
    for i, path in enumerate(candidates):
        require(path.is_file() and f"New testcase: {path}" in solver, "候选缺少 solver 来源")
        report["solver_candidates"].append(concrete(path, f"candidate-{i}"))
    changed = [item for item in report["solver_candidates"] if item["foo_result"] != 7]
    require(changed, "solver 候选未改变具体 foo 分支")
    candidate_hashes = {item["sha256"] for item in changed}
    base = work / "afl_out/exp/master"
    base.joinpath("queue").mkdir(parents=True)
    base.joinpath("queue/id:000000,orig:seed").write_bytes(seed.read_bytes())
    # 这份手写 stats 只用于 helper 接口准备；真实 AFL 证据只读 live-afl。
    base.joinpath("fuzzer_stats").write_text(
        f"command_line : {tools['afl_fuzz']} -i {work / 'seed'} -o {work / 'afl_out/exp'}"
        f" -- {work / 'if.afl'}\n")
    helper_queue = work / "afl_out/exp/exp_symcc/queue"

    def feedback_ready():
        log = work / "logs/helper.stderr"
        if not log.exists() or not re.search(r"Generated \d+ test cases, copied [1-9]\d* to AFL queue",
                                             log.read_text(errors="replace")):
            return False
        return (any(helper_queue.glob("id:*")) and any((base / "queue").glob("*,symcc")))

    run("helper", [tools["helper"], "-o", work / "afl_out", "-n", "exp", "-a", "master",
                   "-t", work / "if.afl", "--", tools["timeout"], "-k", "1", "5", work / "if.sym"],
        10, ready=feedback_ready)
    helper_log = (work / "logs/helper.stderr").read_text()
    require("SymCC Fuzzing Helper (C++ version)" in helper_log, "未执行预期 C++ helper")
    require("scanned=1 coverage_updates=1 total_scanned=1" in helper_log, "缺少真实 AFL 基线合并")
    require("The target process was killed" not in helper_log, "helper 内部 solver 被杀，不能当 PASS")
    report["queues"] = {}
    for name, paths in (("helper", sorted(helper_queue.glob("id:*"))),
                        ("master", sorted((base / "queue").glob("*,symcc")))):
        require(0 < len(paths) <= 32, f"{name} 队列候选数量不符")
        items = [concrete(path, f"{name}-replay-{i}") for i, path in enumerate(paths)]
        require(any(item["sha256"] in candidate_hashes for item in items),
                f"{name} 未包含已验证的 solver 分支变化候选")
        report["queues"][name] = items
    helper_hashes = {item["sha256"] for item in report["queues"]["helper"]}
    require(helper_hashes == {item["sha256"] for item in report["queues"]["master"]},
            "helper 与 master 的回流内容哈希不一致")
    selected = next(item for item in report["queues"]["helper"] if item["sha256"] in candidate_hashes)
    for name, path in (("seed", seed), ("candidate", Path(selected["path"]))):
        run("showmap-" + name, [tools["showmap"], "-q", "-e", "-m", "none", "-t", "1000",
                               "-o", work / (name + ".map"), "--", work / "if.afl"], 3, stdin=path)
    known = set((work / "seed.map").read_text().splitlines())
    new_edges = set((work / "candidate.map").read_text().splitlines()) - known
    require(known and new_edges, "真实候选未提供相对基线的新 edge")
    report["new_edges"] = sorted(new_edges)
    # 本机 core_pattern 使用管道；只验证导入，不据此测试崩溃检测或修改系统配置。
    afl_log, _ = run("afl-import", [tools["afl_fuzz"], "-M", "master", "-F", helper_queue,
                                  "-i", work / "seed", "-o", work / "live-afl", "-s", "1",
                                  "-V", "3", "-m", "none", "-t", "1000", "--", work / "if.afl"],
        8, extra={"AFL_IMPORT_FIRST": "1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"})
    live = work / "live-afl/master"
    stats = dict(line.split(":", 1) for line in (live / "fuzzer_stats").read_text().splitlines()
                 if ":" in line)
    stats = {key.strip(): val.strip() for key, val in stats.items()}
    report["afl_stats"] = stats
    require(int(stats.get("corpus_imported", "0")) > 0, "真实 AFL 没有记录导入")
    require(f"-F {helper_queue}" in stats.get("command_line", ""), "真实 AFL 命令缺少 helper 来源")
    require("Syncing queues from other fuzzer instances first" in afl_log
            and "Time limit was reached" in afl_log, "缺少真实 AFL 先导入和限时退出日志")
    imported = [p for p in sorted((live / "queue").glob("id:*"))
                if ",sync:foreign_0,src:" in p.name and identity(p)["sha256"] in helper_hashes]
    require(imported, "没有带 sync 来源且匹配 helper 哈希的真实 AFL 队列项")
    # 本次唯一 -F 对应 foreign_0；还要核对 src 文件名，排除 AFL 自己变出相同字节。
    for path in imported:
        source = path.name.split(",sync:foreign_0,src:", 1)[1]
        require(any((source == p.name or source.startswith(p.name + ","))
                    and p.read_bytes() == path.read_bytes() for p in helper_queue.glob("id:*")),
                f"真实 AFL 导入的 src 无法对应 helper 原件：{path.name}")
    report["afl_imports"] = [concrete(p, f"import-replay-{i}") for i, p in enumerate(imported)]
    require(any(item["sha256"] in candidate_hashes for item in report["afl_imports"]),
            "真实 AFL 未导入改变分支的 solver 候选")
    report["status"] = "passed"
except Exception as exc:
    report["error"] = str(exc)
    print(f"FAIL: {exc}", file=sys.stderr)
finally:
    signal.alarm(0)
    try:
        report["final_cleanup_killed"] = terminate_children()
        report["remaining_descendants"] = descendants()
        guard()
    except Exception as exc:
        report["status"] = "failed"
        report["cleanup_error"] = str(exc)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["peak_output_bytes"] = peak_bytes
    report["peak_output_files"] = peak_files
    (work / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"{'PASS' if report['status'] == 'passed' else 'FAIL'}: {work / 'result.json'}", flush=True)
sys.exit(0 if report["status"] == "passed" else 1)
PY
