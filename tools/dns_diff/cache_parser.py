import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union

EXIT_USAGE = 2

TSV_COLUMNS: Tuple[str, ...] = (
    "resolver",
    "view",
    "qname",
    "qtype",
    "rrtype",
    "section",
    "cache_type",
    "ttl",
    "rdata_norm",
    "flags",
)

_CLASS_RE = re.compile(r"^(?:IN|CH|HS|CLASS[0-9]+)$")
_TYPE_RE = re.compile(r"^(?:TYPE[0-9]+|[A-Z0-9-]+)$")
_BIND_VIEW_RE = re.compile(r"'([^']+)'")
_BIND_CACHE_ENTRY_RE = re.compile(r"^([^/]+)/([^ ]+) \[ttl ([0-9]+)\]$")
_DNSMASQ_LOG_RE = re.compile(r"^.*dnsmasq\[[0-9]+\]: (.*)$")
_MARADNS_FETCH_RE = re.compile(r"^Fetching (.+) from cache$")
_SMARTDNS_MAGIC = 0x6548634163536E44
_SMARTDNS_RECORD_MAGIC = 0x64526352
_SMARTDNS_DATA_MAGIC = 0x61546144


class CacheParseError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class CacheRecord:
    resolver: str
    view: str
    qname: str
    qtype: str
    rrtype: str
    section: str
    cache_type: str
    ttl: str
    rdata_norm: str
    flags: str

    def to_fields(self) -> Tuple[str, ...]:
        return (
            _clean_field(self.resolver),
            _clean_field(self.view),
            _clean_field(self.qname),
            _clean_field(self.qtype),
            _clean_field(self.rrtype),
            _clean_field(self.section),
            _clean_field(self.cache_type),
            _clean_field(self.ttl),
            _clean_field(self.rdata_norm),
            _clean_field(self.flags),
        )

    def to_tsv(self) -> str:
        return "\t".join(self.to_fields())


def _clean_field(value: object) -> str:
    text = " ".join(str(value).split())
    return text if text else "_"


def _trim(text: str) -> str:
    return text.strip()


def _join_tokens(tokens: Sequence[str], start: int) -> str:
    joined = " ".join(token for token in tokens[start:] if token)
    return joined if joined else "_"


def _is_class_token(token: str) -> bool:
    return bool(_CLASS_RE.fullmatch(token))


def _is_type_token(token: str) -> bool:
    if token == r"\-":
        return True
    if token.startswith(r"\-"):
        token = token[2:]
    return bool(token) and bool(_TYPE_RE.fullmatch(token))


def _find_ttl_index(tokens: Sequence[str]) -> Optional[int]:
    for index, token in enumerate(tokens):
        if token.isdigit():
            return index
    return None


def _looks_like_rr_header(line: str) -> bool:
    stripped = _trim(line)
    if not stripped or stripped.startswith(";") or stripped.startswith("$"):
        return False
    if stripped.startswith("msg "):
        return False
    tokens = stripped.split()
    ttl_index = _find_ttl_index(tokens)
    if ttl_index not in (0, 1):
        return False
    type_index = ttl_index + 1
    if type_index < len(tokens) and _is_class_token(tokens[type_index]):
        type_index += 1
    return type_index < len(tokens) and _is_type_token(tokens[type_index])


def _compose_flags(*parts: Tuple[str, str]) -> str:
    tokens = [f"{key}={value}" for key, value in parts if value and value != "_"]
    return " ".join(tokens) if tokens else "_"


def _compose_message_flags(parts: Sequence[Tuple[str, str]]) -> str:
    tokens = [f"{key}={value}" for key, value in parts if value]
    return " ".join(tokens) if tokens else "_"


def _build_rrset_record(
    *,
    resolver: str,
    view: str,
    section: str,
    pending_rrset: str,
    last_owner: str,
    last_class: str,
) -> Optional[Tuple[CacheRecord, str, str]]:
    tokens = _trim(pending_rrset).split()
    ttl_index = _find_ttl_index(tokens)
    if ttl_index not in (0, 1):
        return None

    owner = tokens[0] if ttl_index == 1 else (last_owner or "_")
    type_index = ttl_index + 1
    class_token = last_class or "_"
    if type_index < len(tokens) and _is_class_token(tokens[type_index]):
        class_token = tokens[type_index]
        type_index += 1

    if type_index >= len(tokens) or not _is_type_token(tokens[type_index]):
        return None

    rrtype = tokens[type_index]
    ttl = tokens[ttl_index]
    rdata_norm = _join_tokens(tokens, type_index + 1)
    cache_type = "negative" if rrtype.startswith(r"\-") else "rrset"
    record = CacheRecord(
        resolver=resolver,
        view=view,
        qname=owner,
        qtype=rrtype,
        rrtype=rrtype,
        section=section,
        cache_type=cache_type,
        ttl=ttl,
        rdata_norm=rdata_norm,
        flags=_compose_flags(("class", class_token)),
    )
    next_owner = owner if owner != "_" else last_owner
    next_class = class_token if class_token != "_" else last_class
    return record, next_owner, next_class


def _build_unbound_msg_record(line: str) -> Optional[CacheRecord]:
    tokens = _trim(line).split()
    if len(tokens) < 12:
        return None

    reason_text = _join_tokens(tokens, 12)
    return CacheRecord(
        resolver="unbound",
        view="_",
        qname=tokens[1],
        qtype=tokens[3],
        rrtype="_",
        section="MSG",
        cache_type="message",
        ttl=tokens[6],
        rdata_norm="_",
        flags=_compose_message_flags(
            (
                ("class", tokens[2]),
                ("flags", tokens[4]),
                ("qd", tokens[5]),
                ("sec", tokens[7]),
                ("an", tokens[8]),
                ("ns", tokens[9]),
                ("ar", tokens[10]),
                ("bogus", tokens[11]),
                ("reason", reason_text),
            )
        ),
    )


def _build_bind_cache_entry_record(
    *, resolver: str, view: str, section: str, raw_line: str
) -> Optional[CacheRecord]:
    match = _BIND_CACHE_ENTRY_RE.fullmatch(raw_line[2:])
    if not match:
        return None
    qname, qtype, ttl = match.groups()
    return CacheRecord(
        resolver=resolver,
        view=view,
        qname=qname,
        qtype=qtype,
        rrtype="_",
        section=section,
        cache_type=section.lower(),
        ttl=ttl,
        rdata_norm="_",
        flags="_",
    )


def _iter_unbound_records(lines: Iterable[str]) -> List[CacheRecord]:
    records: List[CacheRecord] = []
    section = ""
    pending_rrset = ""
    last_owner = ""
    last_class = ""

    def flush_pending() -> None:
        nonlocal pending_rrset, last_owner, last_class
        if not pending_rrset:
            return
        built = _build_rrset_record(
            resolver="unbound",
            view="_",
            section="RRSET",
            pending_rrset=pending_rrset,
            last_owner=last_owner,
            last_class=last_class,
        )
        pending_rrset = ""
        if built is None:
            return
        record, last_owner, last_class = built
        records.append(record)

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        stripped = _trim(line)

        if line == "START_RRSET_CACHE":
            section = "RRSET"
            last_owner = ""
            last_class = ""
            continue
        if line == "START_MSG_CACHE":
            flush_pending()
            section = "MSG"
            continue
        if line.startswith("END_") or line == "EOF" or not stripped:
            flush_pending()
            continue
        if section == "MSG" and line.startswith("msg "):
            record = _build_unbound_msg_record(line)
            if record is not None:
                records.append(record)
            continue
        if section == "MSG":
            continue
        if section == "RRSET" and line.startswith(";rrset"):
            flush_pending()
            last_owner = ""
            last_class = ""
            continue
        if section == "RRSET" and line.startswith(";"):
            flush_pending()
            continue
        if section == "RRSET" and _looks_like_rr_header(line):
            flush_pending()
            pending_rrset = line
            continue
        if section == "RRSET" and pending_rrset:
            pending_rrset = f"{pending_rrset} {stripped}"

    flush_pending()
    return records


def _iter_bind9_records(lines: Iterable[str]) -> List[CacheRecord]:
    records: List[CacheRecord] = []
    current_view = "_"
    current_section = "RRSET"
    pending_rrset = ""
    last_owner = ""
    last_class = ""

    def flush_pending() -> None:
        nonlocal pending_rrset, last_owner, last_class
        if not pending_rrset:
            return
        built = _build_rrset_record(
            resolver="bind9",
            view=current_view,
            section=current_section,
            pending_rrset=pending_rrset,
            last_owner=last_owner,
            last_class=last_class,
        )
        pending_rrset = ""
        if built is None:
            return
        record, last_owner, last_class = built
        if current_section != "ADB":
            records.append(record)

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        stripped = _trim(line)

        if line.startswith("; Cache dump of view "):
            flush_pending()
            view_match = _BIND_VIEW_RE.search(line)
            current_view = view_match.group(1) if view_match else "_"
            current_section = "RRSET"
            last_owner = ""
            last_class = ""
            continue
        if line == "; Address database dump":
            flush_pending()
            current_section = "ADB"
            last_owner = ""
            last_class = ""
            continue
        if line == "; Bad cache":
            flush_pending()
            current_section = "BADCACHE"
            continue
        if line == "; SERVFAIL cache":
            flush_pending()
            current_section = "SERVFAIL"
            continue
        if (
            line.startswith("$DATE")
            or line.startswith("; using ")
            or line.startswith("; [edns success/timeout]")
            or line.startswith("; [plain success/timeout]")
            or line == ";"
            or not stripped
        ):
            flush_pending()
            continue
        if current_section == "SERVFAIL" and line.startswith("; "):
            flush_pending()
            record = _build_bind_cache_entry_record(
                resolver="bind9",
                view=current_view,
                section=current_section,
                raw_line=line,
            )
            if record is not None:
                records.append(record)
            continue
        if current_section == "BADCACHE" and line.startswith("; "):
            flush_pending()
            record = _build_bind_cache_entry_record(
                resolver="bind9",
                view=current_view,
                section=current_section,
                raw_line=line,
            )
            if record is not None:
                records.append(record)
            continue
        if line.startswith(";"):
            flush_pending()
            continue
        if _looks_like_rr_header(line):
            flush_pending()
            pending_rrset = line
            continue
        if pending_rrset:
            pending_rrset = f"{pending_rrset} {stripped}"

    flush_pending()
    return records


def _looks_like_ipv4(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _looks_like_ipv6(token: str) -> bool:
    return ":" in token


def _strip_dnsmasq_log_prefix(line: str) -> str:
    stripped = _trim(line)
    match = _DNSMASQ_LOG_RE.match(stripped)
    return match.group(1) if match else stripped


def _iter_dnsmasq_records(lines: Iterable[str]) -> List[CacheRecord]:
    records: List[CacheRecord] = []
    in_cache_dump = False

    for raw_line in lines:
        line = _strip_dnsmasq_log_prefix(raw_line.rstrip("\n"))
        if line.startswith("Host ") and "Address" in line and "Flags" in line:
            in_cache_dump = True
            continue
        if not in_cache_dump:
            continue
        if line.startswith("------------------------------"):
            continue
        if line.startswith("exiting on receipt of SIGTERM"):
            break
        tokens = line.split()
        if len(tokens) < 3:
            continue
        qname = tokens[0]
        rdata_norm = tokens[1]
        flags_token = tokens[2]
        if qname == "bind":
            continue
        if _looks_like_ipv4(rdata_norm):
            rrtype = qtype = "A"
        elif _looks_like_ipv6(rdata_norm):
            rrtype = qtype = "AAAA"
        else:
            rrtype = qtype = "_"
        records.append(
            CacheRecord(
                resolver="dnsmasq",
                view="_",
                qname=qname,
                qtype=qtype,
                rrtype=rrtype,
                section="CACHE",
                cache_type="rrset",
                ttl="_",
                rdata_norm=rdata_norm,
                flags=_compose_message_flags(
                    (("flags", flags_token), ("expires", _join_tokens(tokens, 3)))
                ),
            )
        )

    return records


def _decode_maradns_name(encoded: str) -> str:
    raw = encoded.encode("latin1", errors="ignore")
    out = bytearray()
    index = 0
    while index < len(raw):
        if raw[index] == 0x5C and index + 3 < len(raw):
            chunk = raw[index + 1 : index + 4]
            if all(48 <= b <= 57 for b in chunk):
                out.append(int(chunk.decode("ascii"), 10))
                index += 4
                continue
        out.append(raw[index])
        index += 1
    labels: List[str] = []
    cursor = 0
    while cursor < len(out):
        length = out[cursor]
        if length == 0:
            break
        cursor += 1
        labels.append(out[cursor : cursor + length].decode("ascii", errors="replace"))
        cursor += length
    return ".".join(labels)


def _iter_maradns_records(lines: Iterable[str]) -> List[CacheRecord]:
    records: List[CacheRecord] = []
    for raw_line in lines:
        line = _trim(raw_line.rstrip("\n"))
        if line.startswith("CACHE_ENTRY\t"):
            fields = line.split("\t")
            if len(fields) >= 4:
                records.append(
                    CacheRecord(
                        resolver="maradns",
                        view="_",
                        qname=fields[1],
                        qtype=fields[2],
                        rrtype=fields[2],
                        section="CACHE",
                        cache_type="rrset",
                        ttl="_",
                        rdata_norm=fields[3],
                        flags="source=deadwood-log",
                    )
                )
            continue
        match = _MARADNS_FETCH_RE.fullmatch(line)
        if not match:
            continue
        qname = _decode_maradns_name(match.group(1))
        records.append(
            CacheRecord(
                resolver="maradns",
                view="_",
                qname=qname,
                qtype="A",
                rrtype="A",
                section="CACHE",
                cache_type="rrset",
                ttl="_",
                rdata_norm="_",
                flags="source=deadwood-log",
            )
        )
    return records


def _iter_knot_resolver_records(lines: Iterable[str]) -> List[CacheRecord]:
    records: List[CacheRecord] = []
    for raw_line in lines:
        line = _trim(raw_line.rstrip("\n"))
        if not line.startswith("CACHE_ENTRY\t"):
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        records.append(
            CacheRecord(
                resolver="knot-resolver",
                view="_",
                qname=fields[1],
                qtype=fields[2],
                rrtype=fields[2],
                section="CACHE",
                cache_type="rrset",
                ttl="_",
                rdata_norm=fields[3],
                flags="source=kresd-harness",
            )
        )
    return records


def _smartdns_qtype_name(qtype: int) -> str:
    mapping = {
        1: "A",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        65: "HTTPS",
        257: "CAA",
    }
    return mapping.get(qtype, f"TYPE{qtype}")


def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    current = offset
    next_offset = offset
    seen = set()
    while current < len(data):
        length = data[current]
        if length == 0:
            if not jumped:
                next_offset = current + 1
            return (".".join(labels) if labels else "."), next_offset
        if length & 0xC0 == 0xC0:
            if current + 1 >= len(data):
                raise CacheParseError("smartdns cache packet 名称指针截断")
            pointer = ((length & 0x3F) << 8) | data[current + 1]
            if pointer in seen:
                raise CacheParseError("smartdns cache packet 名称指针循环")
            seen.add(pointer)
            if not jumped:
                next_offset = current + 2
            current = pointer
            jumped = True
            continue
        current += 1
        label_bytes = data[current : current + length]
        if len(label_bytes) != length:
            raise CacheParseError("smartdns cache packet 标签截断")
        labels.append(label_bytes.decode("utf-8", errors="replace"))
        current += length
        if not jumped:
            next_offset = current
    raise CacheParseError("smartdns cache packet 域名解析失败")


def _smartdns_rdata_to_text(rrtype: int, packet: bytes, offset: int, length: int) -> str:
    rdata = packet[offset : offset + length]
    if rrtype == 1 and length == 4:
        return ".".join(str(part) for part in rdata)
    if rrtype == 28 and length == 16:
        groups = [f"{int.from_bytes(rdata[i:i+2], 'big'):x}" for i in range(0, 16, 2)]
        return ":".join(groups)
    if rrtype in {5, 12}:
        name, _ = _decode_dns_name(packet, offset)
        return name
    return rdata.hex() or "_"


def _iter_smartdns_records(raw_bytes: bytes) -> List[CacheRecord]:
    if len(raw_bytes) < 48:
        raise CacheParseError("smartdns cache 文件过短")
    magic, = struct.unpack_from("<Q", raw_bytes, 0)
    if magic != _SMARTDNS_MAGIC:
        raise CacheParseError("smartdns cache 文件 magic 非法")
    cache_number, = struct.unpack_from("<I", raw_bytes, 40)
    offset = 48
    records: List[CacheRecord] = []
    for _ in range(cache_number):
        if offset + 352 + 24 > len(raw_bytes):
            raise CacheParseError("smartdns cache record 截断")
        record_magic, = struct.unpack_from("<I", raw_bytes, offset)
        if record_magic != _SMARTDNS_RECORD_MAGIC:
            raise CacheParseError("smartdns cache record magic 非法")
        info_base = offset + 8
        domain = raw_bytes[info_base : info_base + 256].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        )
        qtype, = struct.unpack_from("<i", raw_bytes, info_base + 256)
        query_flag, = struct.unpack_from("<I", raw_bytes, info_base + 292)
        ttl, = struct.unpack_from("<i", raw_bytes, info_base + 296)
        rcode, = struct.unpack_from("<i", raw_bytes, info_base + 300)
        hitnum, = struct.unpack_from("<i", raw_bytes, info_base + 304)
        speed, = struct.unpack_from("<i", raw_bytes, info_base + 308)
        insert_time, = struct.unpack_from("<q", raw_bytes, info_base + 328)
        replace_time, = struct.unpack_from("<q", raw_bytes, info_base + 336)

        data_base = offset + 352
        data_magic, = struct.unpack_from("<I", raw_bytes, data_base + 16)
        if data_magic != _SMARTDNS_DATA_MAGIC:
            raise CacheParseError("smartdns cache data magic 非法")
        data_size, = struct.unpack_from("<q", raw_bytes, data_base + 8)
        if data_size < 0:
            raise CacheParseError("smartdns cache data size 非法")
        payload_offset = data_base + 24
        payload_end = payload_offset + data_size
        if payload_end > len(raw_bytes):
            raise CacheParseError("smartdns cache packet 数据截断")
        packet = raw_bytes[payload_offset:payload_end]

        qtype_name = _smartdns_qtype_name(qtype)
        answer_rows: List[CacheRecord] = []
        if len(packet) >= 12:
            qdcount = int.from_bytes(packet[4:6], "big")
            ancount = int.from_bytes(packet[6:8], "big")
            cursor = 12
            for _ in range(qdcount):
                _, cursor = _decode_dns_name(packet, cursor)
                cursor += 4
            for _ in range(ancount):
                name, cursor = _decode_dns_name(packet, cursor)
                rrtype = int.from_bytes(packet[cursor : cursor + 2], "big")
                cursor += 2
                rrclass = int.from_bytes(packet[cursor : cursor + 2], "big")
                cursor += 2
                rrttl = int.from_bytes(packet[cursor : cursor + 4], "big")
                cursor += 4
                rdlength = int.from_bytes(packet[cursor : cursor + 2], "big")
                cursor += 2
                rdata_text = _smartdns_rdata_to_text(rrtype, packet, cursor, rdlength)
                cursor += rdlength
                answer_rows.append(
                    CacheRecord(
                        resolver="smartdns",
                        view="_",
                        qname=name.rstrip("."),
                        qtype=qtype_name,
                        rrtype=_smartdns_qtype_name(rrtype),
                        section="CACHE",
                        cache_type="packet",
                        ttl=str(rrttl if rrttl > 0 else ttl),
                        rdata_norm=rdata_text,
                        flags=_compose_message_flags(
                            (
                                ("class", str(rrclass)),
                                ("rcode", str(rcode)),
                                ("hitnum", str(hitnum)),
                                ("speed", str(speed)),
                                ("query_flag", str(query_flag)),
                                ("insert_time", str(insert_time)),
                                ("replace_time", str(replace_time)),
                            )
                        ),
                    )
                )

        if not answer_rows:
            answer_rows.append(
                CacheRecord(
                    resolver="smartdns",
                    view="_",
                    qname=domain,
                    qtype=qtype_name,
                    rrtype="_",
                    section="CACHE",
                    cache_type="packet",
                    ttl=str(ttl),
                    rdata_norm="_",
                    flags=_compose_message_flags(
                        (
                            ("rcode", str(rcode)),
                            ("hitnum", str(hitnum)),
                            ("speed", str(speed)),
                            ("query_flag", str(query_flag)),
                            ("insert_time", str(insert_time)),
                            ("replace_time", str(replace_time)),
                        )
                    ),
                )
            )
        records.extend(answer_rows)
        offset = payload_end

    return records


def _canonical_resolver_name(resolver: str) -> str:
    normalized = resolver.strip().lower()
    if normalized == "unbound":
        return "unbound"
    if normalized == "dnsmasq":
        return "dnsmasq"
    if normalized == "maradns":
        return "maradns"
    if normalized == "smartdns":
        return "smartdns"
    if normalized in {"knot-resolver", "kresd"}:
        return "knot-resolver"
    if normalized in {"bind9", "named"}:
        return "bind9"
    raise CacheParseError(f"未知 resolver: {resolver}")


def parse_cache_dump(resolver: str, dump_file: Union[str, Path]) -> List[CacheRecord]:
    resolved_resolver = _canonical_resolver_name(resolver)
    dump_path = Path(dump_file).expanduser()
    if not dump_path.is_file():
        raise CacheParseError(f"cache dump 文件不存在或不可读: {dump_file}")

    if resolved_resolver == "unbound":
        with dump_path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(handle)
        return _iter_unbound_records(lines)
    if resolved_resolver == "dnsmasq":
        with dump_path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(handle)
        return _iter_dnsmasq_records(lines)
    if resolved_resolver == "maradns":
        with dump_path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(handle)
        return _iter_maradns_records(lines)
    if resolved_resolver == "knot-resolver":
        with dump_path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(handle)
        return _iter_knot_resolver_records(lines)
    if resolved_resolver == "smartdns":
        return _iter_smartdns_records(dump_path.read_bytes())
    with dump_path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = list(handle)
    return _iter_bind9_records(lines)


def write_cache_tsv(
    resolver: str,
    dump_file: Union[str, Path],
    output_file: Optional[Union[str, Path]] = None,
) -> Path:
    dump_path = Path(dump_file).expanduser()
    if output_file is None:
        output_path = Path(f"{dump_path}.norm.tsv")
    else:
        output_path = Path(output_file).expanduser()

    records = parse_cache_dump(resolver, dump_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(f"{record.to_tsv()}\n" for record in records)
    output_path.write_text(payload, encoding="utf-8")
    return output_path
