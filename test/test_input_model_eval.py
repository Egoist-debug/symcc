import csv
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.dns_diff import input_model_eval as evaluation
from tools.dns_diff.oracle import parse_oracle_summary


QUERY = bytes.fromhex("123401000001000000000000") + b"\x01a\x00\x00\x01\x00\x01"
RESPONSE = bytes.fromhex("123481830001000000000000") + QUERY[12:]
ORACLE = (
    "ORACLE_SUMMARY parse_ok=1 resolver_fetch_started=1 response_accepted=1 "
    "second_query_hit=0 cache_entry_created=0 timeout=0\n"
)


def transcript(post=QUERY):
    return (
        b"DST1\x01\x00" + len(QUERY).to_bytes(2, "little")
        + len(post).to_bytes(2, "little") + len(RESPONSE).to_bytes(2, "little")
        + QUERY + RESPONSE + post
    )


class InputModelEvalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tree = self.root / "bind9"
        binary = self.tree / "bin/named/.libs/named"
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        self.conf = self.root / "named.conf"
        self.conf.write_text('directory "__RUNTIME_STATE_DIR__";\n')
        self.response_dir = self.root / "responses"
        self.response_dir.mkdir()
        (self.response_dir / "response.bin").write_bytes(RESPONSE)
        for name, data in (
            ("dst1", transcript()), ("query", QUERY), ("legacy", QUERY),
            ("random", b"random"),
        ):
            (self.root / f"{name}.bin").write_bytes(data)

    def run_sample(self, work_root=None, response_dir=None):
        return evaluation._run_single_sample(
            bind9_tree=self.tree, named_conf_template=self.conf,
            work_root=work_root or self.root / "sample",
            sample_path=self.root / "query.bin", response_dir=response_dir,
            seed_timeout_sec=1, reply_timeout_ms=1,
        )

    def run_eval(self, output_name="out"):
        return evaluation.run_input_model_eval(
            output_dir=self.root / output_name, bind9_tree=self.tree,
            named_conf_template=self.conf, dst1_input=self.root / "dst1.bin",
            query_only_input=self.root / "query.bin",
            random_input=self.root / "random.bin", legacy_input=self.root / "legacy.bin",
            legacy_response_dir=self.response_dir,
        )

    def test_freezes_executed_query_and_response_before_subprocess(self):
        (self.response_dir / ".ignored").write_bytes(b"hidden")
        (self.response_dir / "nested").mkdir()

        def run(command, **kwargs):
            (self.root / "query.bin").write_bytes(b"changed")
            (self.response_dir / "response.bin").write_bytes(b"changed")
            executed = Path(command[-1].split("input=", 1)[1])
            responses = Path(kwargs["env"]["NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_DIR"])
            self.assertNotEqual(executed, self.root / "query.bin")
            self.assertEqual(executed.read_bytes(), QUERY)
            self.assertEqual((responses / "response.bin").read_bytes(), RESPONSE)
            self.assertEqual([p.name for p in responses.iterdir()], ["response.bin"])
            self.assertNotIn("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL", kwargs["env"])
            self.assertNotIn("NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_SYMBOLIC_SUFFIX", kwargs["env"])
            return subprocess.CompletedProcess(command, 0, "", ORACLE)

        with patch.dict("os.environ", {
            "NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL": "/stale",
            "NAMED_RESOLVER_AFL_SYMCC_RESPONSE_TAIL_SYMBOLIC_SUFFIX": "/stale",
        }):
            with patch.object(evaluation.subprocess, "run", side_effect=run):
                meta = self.run_sample(response_dir=self.response_dir)
        self.assertEqual(meta["sha256"], hashlib.sha256(QUERY).hexdigest())
        self.assertEqual(meta["byte_length"], len(QUERY))
        self.assertEqual(meta["source_path"], str(self.root / "query.bin"))
        response = meta["response_snapshots"][0]
        self.assertEqual(response["sha256"], hashlib.sha256(RESPONSE).hexdigest())
        self.assertEqual(response["byte_length"], len(RESPONSE))
        with self.assertRaises(evaluation.InputModelEvalError):
            self.run_sample(response_dir=self.response_dir)
        saved = json.loads((self.root / "sample/sample.meta.json").read_text())
        self.assertEqual(saved, meta)

    def test_missing_observation_does_not_become_negative_or_capable(self):
        summary = evaluation._model_summary("dst1_transcript", [{
            "returncode": 124, "oracle": parse_oracle_summary("", "bind9"),
        }])
        for field in ("parse_accept_rate", "recursive_or_cache_path_rate",
                      "response_accept_rate", "effective_post_check_rate"):
            self.assertIsNone(summary[field])
        self.assertEqual(summary["post_check_capable_count"], 0)
        self.assertEqual(summary["parse_ok_observed_count"], 0)
        self.assertEqual(summary["parse_ok_missing_count"], 1)
        self.assertEqual(summary["failed_execution_count"], 1)

    def test_false_observation_and_negative_answer_are_preserved(self):
        summary = evaluation._model_summary("not_a_model_hint", [{
            "returncode": 0, "post_check_present": True,
            "oracle": parse_oracle_summary(ORACLE, "bind9"),
        }])
        self.assertEqual(summary["response_accept_rate"], 1)
        self.assertEqual(summary["post_check_capable_count"], 1)
        self.assertEqual(summary["effective_post_check_rate"], 0)
        self.assertEqual(summary["second_query_hit_observed_count"], 1)

    def test_rates_only_use_observed_denominators_and_keep_false_on_failure(self):
        missing = parse_oracle_summary("", "bind9")
        positive = parse_oracle_summary(ORACLE, "bind9")
        negative = parse_oracle_summary(ORACLE.replace("response_accepted=1", "response_accepted=0"), "bind9")
        summary = evaluation._model_summary("dst1_transcript", [
            {"returncode": 0, "oracle": positive, "post_check_present": True},
            {"returncode": 124, "oracle": negative, "post_check_present": True},
            {"returncode": 0, "oracle": missing},
        ])
        self.assertEqual(summary["response_accepted_count"], 1)
        self.assertEqual(summary["response_accepted_observed_count"], 2)
        self.assertEqual(summary["response_accepted_missing_count"], 1)
        self.assertEqual(summary["response_accept_rate"], 0.5)
        self.assertEqual(summary["failed_execution_count"], 1)
        self.assertEqual(summary["missing_observation_count"], 1)

    def test_identity_matches_and_mismatch_are_in_final_artifacts(self):
        with patch.object(evaluation.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "", ORACLE)):
            self.assertEqual(self.run_eval(), 0)
            (self.response_dir / "response.bin").write_bytes(b"mismatch")
            (self.root / "query.bin").write_bytes(b"mismatch")
            self.assertEqual(self.run_eval("mismatch"), 0)
        for out, status in (("out", "verified"), ("mismatch", "unverified")):
            for model in ("query_only", "legacy_response_tail"):
                meta = json.loads((self.root / out / model / "sample-01/sample.meta.json").read_text())
                self.assertEqual(meta["input_relation"]["status"], status)
                self.assertFalse(meta["input_relation"]["semantic_equivalence_claimed"])
        random = json.loads((self.root / "out/random_packet/sample-01/sample.meta.json").read_text())
        self.assertEqual(random["input_relation"]["status"], "negative_control")
        self.assertIsNone(random["input_relation"]["dst1_snapshot"])
        with self.assertRaises(evaluation.InputModelEvalError):
            self.run_eval()

    def test_duplicate_dst1_is_not_claimed_as_a_pair(self):
        source = self.root / "dst1.bin"
        data = source.read_bytes()
        source.unlink()
        source.mkdir()
        (source / "one.bin").write_bytes(data)
        (source / "two.bin").write_bytes(data)
        with patch.object(evaluation.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "", ORACLE)):
            self.run_eval()
        meta = json.loads((self.root / "out/query_only/sample-01/sample.meta.json").read_text())
        self.assertEqual(meta["input_relation"]["status"], "unverified")
        self.assertEqual(meta["input_relation"]["reason"], "ambiguous_dst1_match")
        self.assertIsNone(meta["input_relation"]["dst1_snapshot"])

    def test_missing_and_timeout_exit_nonzero_without_erasing_artifacts(self):
        for index, (returncode, stderr) in enumerate(((0, ""), (124, "timeout evidence\n"),
                                                    (0, ORACLE.replace("timeout=0", "timeout=1")))):
            out = f"failure-{index}"
            with patch.object(evaluation.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], returncode, "", stderr)):
                self.assertEqual(self.run_eval(out), evaluation.EXIT_SUBPROCESS)
            payload = json.loads((self.root / out / "summary.json").read_text())
            rows = list(csv.DictReader((self.root / out / "summary.tsv").read_text().splitlines(), delimiter="\t"))
            if not stderr.startswith("ORACLE_SUMMARY"):
                self.assertIsNone(payload["rows"][0]["parse_accept_rate"])
                self.assertEqual(rows[0]["parse_accept_rate"], "NA")
            self.assertEqual((self.root / out / "dst1_transcript/sample-01/bind9.stderr").read_text(), stderr)

    def test_empty_or_malformed_postcheck_is_not_capable(self):
        for index, data in enumerate((transcript(b""), b"DST1broken")):
            (self.root / "dst1.bin").write_bytes(data)
            with patch.object(evaluation.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, "", ORACLE)):
                self.run_eval(f"post-{index}")
            summary = json.loads((self.root / f"post-{index}/dst1_transcript/summary.json").read_text())
            self.assertEqual(summary["post_check_capable_count"], 0)
            self.assertIsNone(summary["effective_post_check_rate"])


if __name__ == "__main__":
    unittest.main()
