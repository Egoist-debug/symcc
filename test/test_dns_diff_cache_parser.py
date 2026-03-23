import tempfile
import unittest
from pathlib import Path

from tools.dns_diff.cache_parser import CacheParseError, parse_cache_dump


class DnsDiffCacheParserTest(unittest.TestCase):
    def _write_lines(self, path: Path, lines: list[str]) -> None:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_parse_bind9_negative_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_file = Path(tmpdir) / "bind.cache.txt"
            self._write_lines(
                dump_file,
                [
                    ";",
                    "; Cache dump of view '_default' (cache _default)",
                    ";",
                    "example.com. 300 IN \\-A ;-$NXDOMAIN",
                    "300 NSEC example.com. A NS SOA RRSIG NSEC DNSKEY",
                ],
            )
            records = parse_cache_dump("bind9", dump_file)
            rows = [record.to_tsv() for record in records]
            self.assertIn(
                "bind9\t_default\texample.com.\t\\-A\t\\-A\tRRSET\tnegative\t300\t;-$NXDOMAIN\tclass=IN",
                rows,
            )

    def test_parse_unbound_msg_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_file = Path(tmpdir) / "unbound.cache.txt"
            self._write_lines(
                dump_file,
                [
                    "START_RRSET_CACHE",
                    ";rrset 300 2 0 2 1",
                    "example.com. 300 IN A 1.2.3.4",
                    "END_RRSET_CACHE",
                    "START_MSG_CACHE",
                    "msg example.com. IN A 33152 1 300 0 1 0 0 -1",
                    "END_MSG_CACHE",
                    "EOF",
                ],
            )
            records = parse_cache_dump("unbound", dump_file)
            rows = [record.to_tsv() for record in records]
            self.assertIn(
                "unbound\t_\texample.com.\tA\t_\tMSG\tmessage\t300\t_\tclass=IN flags=33152 qd=1 sec=0 an=1 ns=0 ar=0 bogus=-1 reason=_",
                rows,
            )

    def test_parse_cache_dump_invalid_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.cache.txt"
            with self.assertRaises(CacheParseError):
                parse_cache_dump("unbound", missing)
            with self.assertRaises(CacheParseError):
                parse_cache_dump("unknown-resolver", missing)


if __name__ == "__main__":
    unittest.main()
