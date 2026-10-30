#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1

python3 - "$ROOT_DIR" <<'PY'
import csv
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from tools.dns_diff.matrix import _queue_snapshot_digest
from tools.dns_diff.schema import QUEUE_SNAPSHOT_DIGEST_ALGORITHM

# 只有 campaign CLI 是替身；实际执行复制后的生产脚本及其中的 provenance/汇总代码。
cli_stub = f"""#!{sys.executable}
import json
import os
from pathlib import Path
import sys
if sys.argv[1:3] != ["-m", "tools.dns_diff.cli"]:
    os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])
command = sys.argv[3]
with open(os.environ["CLI_CALLS"], "a") as log:
    log.write(command + "\\n")
if command == "campaign-close":
    path = Path(os.environ["WORK_DIR"]) / "campaign_reports/fixture/summary.json"
    payload = {{"semantic_counts": {{"no_diff": 1}}}}
elif command == "campaign-aggregate":
    path = Path(sys.argv[sys.argv.index("--output-dir") + 1]) / "campaign_aggregates/fixture/summary.json"
    payload = {{"aggregation_key": {{"resolver_pair": "bind9_vs_dnsmasq"}},
               "run_count": 1, "variance_status": "insufficient_runs", "aggregates": {{}}}}
else:
    raise SystemExit("不允许真实 CLI 调用: " + command)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload))
"""

with tempfile.TemporaryDirectory(prefix="symcc-rq3-replay-") as temp:
    temp = Path(temp)
    source = temp / "source"
    source.mkdir()
    digests = []
    for index, (content, limit) in enumerate((
        (b"same payload", "1"), (b"same payload", "1"), (b"changed payload", "1"),
        (b"payload", "0"), (b"payload", "-1"), (None, "1"),
    )):
        isolated = temp / str(index)
        (isolated / "scripts/lib").mkdir(parents=True)
        (isolated / "bin").mkdir()
        for name in ("run_real_rq3_multi_resolver_ablation.sh", "lib/cleanup_run_root.sh"):
            shutil.copyfile(root / "scripts" / name, isolated / "scripts" / name)
        wrapper = isolated / "bin/python3"
        wrapper.write_text(cli_stub)
        wrapper.chmod(0o755)
        if content is None:
            (source / "seed.bin").unlink()
        else:
            (source / "seed.bin").write_bytes(content)
        (source / "0.meta.json").write_text(json.dumps({"metadata": index}))
        source_before = {p.name: p.read_bytes() for p in source.iterdir()}
        calls = isolated / "cli-calls"
        before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        result = subprocess.run(
            ["bash", "scripts/run_real_rq3_multi_resolver_ablation.sh"], cwd=isolated,
            env=dict(os.environ, PATH=str(isolated / "bin") + os.pathsep + os.environ["PATH"],
                     PYTHONPATH=str(root), TRANSCRIPT_SOURCE_DIR=str(source),
                     QUEUE_LIMIT=limit, REPEAT_COUNT="1", BUDGET_SEC="1", RESOLVERS="dnsmasq",
                     CLI_CALLS=str(calls)), capture_output=True, text=True, timeout=15)
        if index >= 3:
            assert result.returncode != 0
            assert ("没有 payload" if content is None else "QUEUE_LIMIT") in result.stderr
            assert not calls.exists()
            continue
        assert result.returncode == 0, (result.stdout, result.stderr)
        after = datetime.datetime.now(datetime.timezone.utc)
        bases = list((isolated / "experiments/results/real_rq3_multi_resolver_ablation").iterdir())
        assert len(bases) == 1
        base = bases[0]
        queue = base / "dnsmasq/afl_out/master/queue"
        provenance = json.loads((base / "dnsmasq/producer_seed_provenance.json").read_text())
        recorded = datetime.datetime.fromisoformat(provenance["recorded_at"].replace("Z", "+00:00"))
        assert before <= recorded <= after, provenance
        assert provenance["seed_source_dir"] == str(source.resolve()), provenance
        assert provenance["stable_input_dir"] == str(queue.resolve())
        assert provenance["execution_mode"] == "shared_queue_replay"
        assert provenance["generation_evidence"] is False
        assert provenance["seed_snapshot_algorithm"] == QUEUE_SNAPSHOT_DIGEST_ALGORITHM
        digest, count, size = _queue_snapshot_digest(queue)
        assert provenance["seed_snapshot_id"] == digest
        assert count == 1 and size == len(content)
        assert (queue / "id:000001,orig:seed.bin").read_bytes() == content
        digests.append(digest)
        summary = json.loads((base / "resolver_variant_summary.json").read_text())
        assert summary["execution_mode"] == "shared_queue_replay"
        assert summary["generation_evidence"] is False
        assert len(summary["rows"]) == 4
        for row in summary["rows"]:
            assert row["execution_mode"] == "shared_queue_replay"
            assert row["generation_evidence"] is False
            assert row["source_queue_dir"] == str(queue.resolve())
            assert row["total_samples_mean"] == "NA"
        for name in ("resolver_variant_summary.tsv", "status.tsv"):
            with (base / name).open() as handle:
                rows = list(csv.DictReader(handle, delimiter="\t"))
            assert len(rows) == 4
            for row in rows:
                assert row["execution_mode"] == "shared_queue_replay", row
                assert row["generation_evidence"] == "false", row
        assert not list(base.rglob("producer_execution_manifest.json"))
        assert calls.read_text().splitlines().count("campaign-close") == 4
        assert calls.read_text().splitlines().count("campaign-aggregate") == 4
        assert {p.name: p.read_bytes() for p in source.iterdir()} == source_before
        # 强制同名批次冲突，确认旧目录中的字节不会被第二次运行覆盖。
        existing = {p.relative_to(base): p.read_bytes() for p in base.rglob("*") if p.is_file()}
        date_stub = isolated / "bin/date"
        date_stub.write_text("#!/bin/sh\nprintf '%s\\n' " + base.name + "\n")
        date_stub.chmod(0o755)
        collision = subprocess.run(
            ["bash", "scripts/run_real_rq3_multi_resolver_ablation.sh"], cwd=isolated,
            env=dict(os.environ, PATH=str(isolated / "bin") + os.pathsep + os.environ["PATH"],
                     PYTHONPATH=str(root), TRANSCRIPT_SOURCE_DIR=str(source), RESOLVERS="dnsmasq"),
            capture_output=True, text=True, timeout=5)
        assert collision.returncode != 0
        assert {p.relative_to(base): p.read_bytes() for p in base.rglob("*") if p.is_file()} == existing
    assert digests[0] == digests[1] and digests[1] != digests[2]
print("PASS: RQ3 replay 来源、内容身份与非生成标签（仅离线 CLI 替身）")
PY
