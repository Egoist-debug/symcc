import re
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


def _canonical_resolver_name(resolver: str) -> str:
    normalized = resolver.strip().lower()
    if normalized == "unbound":
        return "unbound"
    if normalized in {"bind9", "named"}:
        return "bind9"
    raise CacheParseError(f"未知 resolver: {resolver}")


def parse_cache_dump(resolver: str, dump_file: Union[str, Path]) -> List[CacheRecord]:
    resolved_resolver = _canonical_resolver_name(resolver)
    dump_path = Path(dump_file).expanduser()
    if not dump_path.is_file():
        raise CacheParseError(f"cache dump 文件不存在或不可读: {dump_file}")

    with dump_path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = list(handle)

    if resolved_resolver == "unbound":
        return _iter_unbound_records(lines)
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
