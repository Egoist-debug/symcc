import tempfile
import unittest
from pathlib import Path
import struct

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

    def test_parse_dnsmasq_cache_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_file = Path(tmpdir) / "dnsmasq.cache.txt"
            self._write_lines(
                dump_file,
                [
                    "May 10 05:49:01 dnsmasq[250875]: Host                           Address                                  Flags      Expires                  Source",
                    "May 10 05:49:01 dnsmasq[250875]: ------------------------------ ---------------------------------------- ---------- ------------------------ ------------",
                    "May 10 05:49:01 dnsmasq[250875]: bind                                                                    !F I    C",
                    "May 10 05:49:01 dnsmasq[250875]: example.com                    1.2.3.4                                  4F         Sun May 10 05:50:01 2026",
                    "May 10 05:49:02 dnsmasq[250875]: exiting on receipt of SIGTERM",
                ],
            )
            records = parse_cache_dump("dnsmasq", dump_file)
            rows = [record.to_tsv() for record in records]
            self.assertIn(
                "dnsmasq\t_\texample.com\tA\tA\tCACHE\trrset\t_\t1.2.3.4\tflags=4F expires=Sun May 10 05:50:01 2026",
                rows,
            )

    def test_parse_smartdns_cache_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_file = Path(tmpdir) / "smartdns.cache"
            query = b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
            packet = (
                b"\x56\x78\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01"
                b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x02\x58\x00\x04\x01\x02\x03\x04"
            )
            info = bytearray(344)
            info[0 : len(b"example.com")] = b"example.com"
            struct.pack_into("<i", info, 256, 1)
            struct.pack_into("<I", info, 292, 0)
            struct.pack_into("<i", info, 296, 600)
            struct.pack_into("<i", info, 300, 0)
            struct.pack_into("<i", info, 304, 6)
            struct.pack_into("<i", info, 308, -1)
            struct.pack_into("<q", info, 328, 111)
            struct.pack_into("<q", info, 336, 222)
            file_header = struct.pack("<Q32sI4x", 0x6548634163536E44, b"cache ver 1.3\0", 1)
            record_header = struct.pack("<I4x", 0x64526352)
            data_head = struct.pack("<i4xqI4x", 1, len(packet), 0x61546144)
            dump_file.write_bytes(file_header + record_header + info + data_head + packet)
            records = parse_cache_dump("smartdns", dump_file)
            rows = [record.to_tsv() for record in records]
            self.assertIn(
                "smartdns\t_\texample.com\tA\tA\tCACHE\tpacket\t600\t1.2.3.4\tclass=1 rcode=0 hitnum=6 speed=-1 query_flag=0 insert_time=111 replace_time=222",
                rows,
            )

    def test_parse_maradns_cache_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            dump_file = Path(tmpdir) / "maradns.cache.txt"
            self._write_lines(
                dump_file,
                [
                    "MARADNS_CACHE_DUMP",
                    r"Fetching \007example\003com\000\000\001 from cache",
                ],
            )
            records = parse_cache_dump("maradns", dump_file)
            rows = [record.to_tsv() for record in records]
            self.assertIn(
                "maradns\t_\texample.com\tA\tA\tCACHE\trrset\t_\t_\tsource=deadwood-log",
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
