#!/usr/bin/env python3
import unittest
from tools.dnsmasq_replay_harness import is_acceptable_dns_response as dnsmasq_acceptable
from tools.smartdns_replay_harness import is_acceptable_dns_response as smartdns_acceptable
from tools.maradns_replay_harness import is_acceptable_dns_response as maradns_acceptable
from tools.knot_resolver_replay_harness import acceptable_response as knot_acceptable

class TestReplayHarnessNegativeControls(unittest.TestCase):
    def test_local_rejection_notimp(self):
        # Query: example.com A (TXID=0x1234)
        query = bytes([
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
            0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01
        ])
        # Response with NOTIMP (rcode=4, QR=1, Flags=0x8004)
        resp_notimp = bytes([
            0x12, 0x34, 0x80, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
            0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01
        ])
        # Response with REFUSED (rcode=5, QR=1, Flags=0x8005)
        resp_refused = bytes([
            0x12, 0x34, 0x80, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
            0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01
        ])
        # Response with SERVFAIL (rcode=2, QR=1, Flags=0x8002)
        resp_servfail = bytes([
            0x12, 0x34, 0x80, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
            0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01
        ])
        # Valid response (NOERROR, ancount=1, QR=1, Flags=0x8180)
        resp_valid = bytes([
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x07, ord('e'), ord('x'), ord('a'), ord('m'), ord('p'), ord('l'), ord('e'),
            0x03, ord('c'), ord('o'), ord('m'), 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
            192, 0, 2, 1
        ])

        for name, fn in [
            ("dnsmasq", dnsmasq_acceptable),
            ("smartdns", smartdns_acceptable),
            ("maradns", maradns_acceptable),
        ]:
            self.assertFalse(fn(resp_notimp, query), f"{name} must reject NOTIMP response")
            self.assertFalse(fn(resp_refused, query), f"{name} must reject REFUSED response")
            self.assertFalse(fn(resp_servfail, query), f"{name} must reject SERVFAIL response")
            self.assertTrue(fn(resp_valid, query), f"{name} must accept valid response")

        # Knot
        self.assertFalse(knot_acceptable(resp_notimp), "knot must reject NOTIMP response")
        self.assertFalse(knot_acceptable(resp_refused), "knot must reject REFUSED response")
        self.assertTrue(knot_acceptable(resp_valid), "knot must accept valid response")

if __name__ == "__main__":
    unittest.main()
