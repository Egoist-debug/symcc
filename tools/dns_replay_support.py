"""重放 oracle 的报文边界与注入事实；接纳不等于投毒或真实缓存证据。"""
import struct
import threading


def _name(packet, offset):
    labels, seen = [], set()
    end = None
    expanded = 1
    while True:
        if offset >= len(packet) or offset in seen:
            raise ValueError("DNS name 越界或指针环")
        seen.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("DNS pointer 截断")
            target = ((length & 0x3F) << 8) | packet[offset + 1]
            if target < 12 or target >= offset:
                raise ValueError("DNS pointer 未指向先前的 name")
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0 or offset + 1 + length > len(packet):
            raise ValueError("DNS label 非法")
        offset += 1
        if length == 0:
            return tuple(labels), offset if end is None else end
        expanded += length + 1
        if expanded > 255:
            raise ValueError("DNS name 过长")
        labels.append(bytes(packet[offset:offset + length]).lower())
        offset += length


def _question(packet):
    if len(packet) < 12 or packet[4:6] != b"\0\1":
        raise ValueError("需要且仅需要一个 Question")
    name, offset = _name(packet, 12)
    if offset + 4 > len(packet):
        raise ValueError("Question 截断")
    return (name, bytes(packet[offset:offset + 4])), offset + 4


def matching_question(packet, query):
    try:
        return _question(packet)[0] == _question(query)[0]
    except ValueError:
        return False


def is_acceptable_dns_response(packet: bytes, query: bytes = b"") -> bool:
    try:
        question, offset = _question(packet)
        flags, _, answers, authority, additional = struct.unpack_from("!5H", packet, 2)
        if not flags & 0x8000 or flags & 0x7A00 or flags & 0xF not in (0, 3):
            return False
        if query and (packet[:2] != query[:2] or question != _question(query)[0]):
            return False
        for _ in range(answers + authority + additional):
            _, offset = _name(packet, offset)
            rrtype, _, ttl, length = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            end = offset + length
            if end > len(packet):
                return False
            if rrtype in (1, 28) and length != (4 if rrtype == 1 else 16):
                return False
            if rrtype in (2, 5, 6, 12, 15, 33, 39):
                start = offset + {15: 2, 33: 6}.get(rrtype, 0)
                _, start = _name(packet, start)
                if rrtype == 6:
                    _, start = _name(packet, start)
                    start += 20
                if start != end:
                    return False
            if rrtype == 16:
                start = offset
                while start < end:
                    start += 1 + packet[start]
                if start != end or not length:
                    return False
            if rrtype == 41:
                if ttl >> 24:
                    return False
                start = offset
                while start < end:
                    if start + 4 > end:
                        return False
                    start += 4 + int.from_bytes(packet[start + 2:start + 4], "big")
                if start != end:
                    return False
            offset = end
        return offset == len(packet)
    except (ValueError, struct.error, IndexError):
        return False


class ReplayUpstream:
    """同一把锁提交 send 成功事实，避免客户端先收包而日志尚未计数。"""

    def __init__(self, query, responses):
        self.query = query
        self.responses = responses
        self.queries = []
        self.matching_queries = []
        self.dispatched = False
        self.lock = threading.Lock()

    def reply(self, packet, send):
        with self.lock:
            self.queries.append(packet)
            matched = (
                len(packet) >= 12 and not packet[2] & 0xF8
                and matching_question(packet, self.query)
            )
            if matched:
                self.matching_queries.append(packet)
            if not self.responses:
                return
            reply = bytearray(self.responses[min(len(self.queries) - 1, len(self.responses) - 1)])
            if len(reply) >= 2:
                reply[:2] = packet[:2]
            try:
                if send(reply) and matched:
                    self.dispatched = True
            except OSError:
                return

    def snapshot(self):
        with self.lock:
            return len(self.queries), bool(self.matching_queries), self.dispatched
