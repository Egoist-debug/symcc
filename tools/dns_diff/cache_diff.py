import ipaddress
import re
from collections import Counter
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .cache_parser import TSV_COLUMNS
from .schema import stamp_with_shared_meta

CacheRow = Tuple[str, str, str, str, str, str, str, str, str, str]
CACHE_ROW_FIELD_COUNT = 10


def cache_comparable(cache_diff: Mapping[str, Any]) -> bool:
    return (
        type(cache_diff.get("cache_comparison_version")) is int
        and cache_diff.get("cache_comparison_version") == 1
        and cache_diff.get("cache_comparison_status") == "comparable"
        and isinstance(cache_diff.get("diff_detected"), bool)
        and isinstance(cache_diff.get("resolver_diffs"), list)
    )


def cache_has_diff(cache_diff: Mapping[str, Any]) -> bool:
    return (
        cache_comparable(cache_diff)
        and cache_diff.get("diff_detected") is True
        and bool(cache_diff.get("resolver_diffs"))
    )


def _coerce_row_fields(row: Any) -> Tuple[Any, ...]:
    if hasattr(row, "to_fields"):
        return tuple(getattr(row, "to_fields")())
    if isinstance(row, (str, bytes, bytearray, Mapping)):
        return (row,)
    try:
        return tuple(row)
    except TypeError:
        return (row,)


def _normalize_row(row: Any) -> CacheRow:
    fields = _coerce_row_fields(row)
    if len(fields) != CACHE_ROW_FIELD_COUNT:
        raise ValueError(
            f"cache 行列数必须是 {CACHE_ROW_FIELD_COUNT} 列，当前为 {len(fields)} 列"
        )
    return tuple(str(field) for field in fields)  # type: ignore[return-value]


def _normalize_rows(rows: Sequence[Any], *, source: str) -> List[CacheRow]:
    normalized: List[CacheRow] = []
    for index, row in enumerate(rows, start=1):
        try:
            normalized.append(_normalize_row(row))
        except ValueError as exc:
            raise ValueError(f"{source}[{index}] 非法: {exc}") from exc
    return normalized


def _structural_key(row: CacheRow) -> Tuple[str, ...]:
    return row[:7] + row[8:10]


def _domain(value: str) -> str:
    if value == ".":
        return value
    value = value.removesuffix(".")
    if not value or value == "_" or not value.isascii() or any(
        not label or len(label) > 63 or re.search(r'[\s\\"]', label)
        for label in value.split(".")
    ):
        raise ValueError("unsupported_domain")
    return value.lower() + "."


def _txt_wire(value: str) -> str:
    wire = bytearray()
    cursor = 0
    while cursor < len(value):
        if value[cursor].isspace():
            cursor += 1
            continue
        if value[cursor] != '"':
            raise ValueError("unsupported_txt")
        cursor += 1
        chunk = bytearray()
        while cursor < len(value) and value[cursor] != '"':
            char = value[cursor]
            cursor += 1
            if char == "\\":
                if cursor == len(value):
                    raise ValueError("unsupported_txt")
                digits = value[cursor:cursor + 3]
                if len(digits) == 3 and digits.isascii() and digits.isdigit():
                    chunk.append(int(digits))
                    cursor += 3
                    continue
                char = value[cursor]
                cursor += 1
            if not char.isascii():
                raise ValueError("unsupported_txt")
            chunk.append(ord(char))
        if cursor == len(value) or len(chunk) > 255:
            raise ValueError("unsupported_txt")
        cursor += 1
        wire.append(len(chunk))
        wire.extend(chunk)
    if not wire:
        raise ValueError("unsupported_txt")
    return wire.hex()


def _rdata(rrtype: str, value: str) -> str:
    if rrtype in {"A", "AAAA"}:
        if "%" in value:
            raise ValueError("invalid_address")
        address = ipaddress.ip_address(value)
        if address.version != (4 if rrtype == "A" else 6):
            raise ValueError("invalid_address")
        return address.packed.hex()
    if rrtype == "TXT":
        return _txt_wire(value)
    if rrtype in {"NS", "CNAME", "DNAME", "PTR"}:
        return _domain(value)
    # shortcut: 只比较当前共享正 RR 类型；扩展时须同步两端解码和 fixture。
    raise ValueError("unsupported_rdata")


def _rrclass(value: str, resolver: str) -> str:
    if not value and resolver in {"dnsmasq", "maradns", "knot-resolver"}:
        value = "IN"
    value = {"IN": "1", "CH": "3", "HS": "4"}.get(value, value.removeprefix("CLASS"))
    if not value.isascii() or not value.isdigit() or not 0 < int(value) <= 65535:
        raise ValueError("unknown_class")
    return str(int(value))


def _semantic_snapshot(rows: Sequence[CacheRow]) -> set:
    output = set()
    for row in rows:
        flags = dict(token.split("=", 1) for token in row[9].split() if "=" in token)
        if row[6] == "message":
            value = flags.get("flags", "")
            positive = value == "NOERROR" or (
                value.isascii() and value.isdigit() and int(value) & 0x20F == 0
            )
            if positive and flags.get("qd") == "1" and flags.get("an", "").isdigit() and int(flags["an"]) > 0 and any(
                other[6] == "rrset" and _domain(other[2]) == _domain(row[2])
                and other[4] == row[3]
                and _rrclass(
                    dict(token.split("=", 1) for token in other[9].split() if "=" in token).get("class", ""),
                    other[0],
                ) == _rrclass(flags.get("class", ""), row[0])
                for other in rows
            ):
                continue
            raise ValueError("unsupported_message_state")
        if row[6] not in {"rrset", "packet", "positive"} or flags.get("rcode", "0") != "0":
            raise ValueError("unsupported_cache_state")
        rrclass = _rrclass(flags.get("class", ""), row[0])
        output.add((_domain(row[2]), row[4], rrclass, _rdata(row[4], row[8])))
    return output


def _semantic_delta(before: Sequence[CacheRow], after: Sequence[CacheRow]) -> list:
    # 先投影为 RR 集合再求差，重复记录、展示变化和实现 metadata 不构成状态变化。
    left, right = _semantic_snapshot(before), _semantic_snapshot(after)
    return [
        {"kind": kind, "fields": dict(zip(("qname", "rrtype", "class", "rdata_norm"), key))}
        for kind, keys in (("removed", left - right), ("added", right - left))
        for key in sorted(keys)
    ]


def _build_delta_items(
    before_rows: Sequence[CacheRow], after_rows: Sequence[CacheRow]
) -> List[Dict[str, Any]]:
    before_counter = Counter(_structural_key(row) for row in before_rows)
    after_counter = Counter(_structural_key(row) for row in after_rows)
    keys = sorted(set(before_counter) | set(after_counter))

    items: List[Dict[str, Any]] = []
    for key in keys:
        before_count = before_counter.get(key, 0)
        after_count = after_counter.get(key, 0)
        if before_count == after_count:
            continue

        kind = "added" if after_count > before_count else "removed"
        fields = {
            "resolver": key[0],
            "view": key[1],
            "qname": key[2],
            "qtype": key[3],
            "rrtype": key[4],
            "section": key[5],
            "cache_type": key[6],
            "rdata_norm": key[7],
            "flags": key[8],
        }
        items.append(
            {
                "kind": kind,
                "count_before": before_count,
                "count_after": after_count,
                "delta": abs(after_count - before_count),
                "fields": fields,
            }
        )
    return items


def _build_resolver_payload(
    before_rows: Sequence[CacheRow],
    after_rows: Sequence[CacheRow],
    *,
    include_details: bool,
) -> Dict[str, Any]:
    has_cache_diff = Counter(_structural_key(row) for row in before_rows) != Counter(
        _structural_key(row) for row in after_rows
    )

    if include_details:
        delta_items = _build_delta_items(before_rows, after_rows)
        interesting_delta_count = len(delta_items)
    else:
        delta_items = []
        interesting_delta_count = 0

    payload = {
        "entries_before": len(before_rows),
        "entries_after": len(after_rows),
        "has_cache_diff": has_cache_diff,
        "interesting_delta_count": interesting_delta_count,
        "delta_items": delta_items,
        "observations_before": [dict(zip(TSV_COLUMNS, row)) for row in before_rows],
        "observations_after": [dict(zip(TSV_COLUMNS, row)) for row in after_rows],
    }
    try:
        payload["semantic_delta"] = _semantic_delta(before_rows, after_rows)
        payload["cache_comparison_status"] = "comparable"
    except ValueError as exc:
        payload["semantic_delta"] = []
        payload["cache_comparison_status"] = "incomparable"
        payload["cache_comparison_reason"] = str(exc)
    return payload


def build_cache_diff(
    sample_id: str,
    bind9_before: Optional[list],
    bind9_after: Optional[list],
    unbound_before: Optional[list],
    unbound_after: Optional[list],
    triggered: bool,
    *,
    secondary_resolver: str = "unbound",
) -> dict:
    bind9_before_rows = _normalize_rows(bind9_before or [], source="bind9_before")
    bind9_after_rows = _normalize_rows(bind9_after or [], source="bind9_after")
    unbound_before_rows = _normalize_rows(unbound_before or [], source="unbound_before")
    unbound_after_rows = _normalize_rows(unbound_after or [], source="unbound_after")

    payload: Dict[str, Any] = {
        "cache_delta_triggered": bool(triggered),
        "bind9": _build_resolver_payload(
            bind9_before_rows,
            bind9_after_rows,
            include_details=bool(triggered),
        ),
        "unbound": _build_resolver_payload(
            unbound_before_rows,
            unbound_after_rows,
            include_details=bool(triggered),
        ),
    }
    for name, before, after in (
        ("bind9", bind9_before, bind9_after), ("unbound", unbound_before, unbound_after),
    ):
        if before is None or after is None:
            payload[name]["cache_comparison_status"] = "unknown"
            payload[name]["cache_comparison_reason"] = "missing_snapshot"
    if (
        secondary_resolver in {"maradns", "knot-resolver"}
        and payload["unbound"]["cache_comparison_status"] != "unknown"
    ):
        payload["unbound"]["cache_comparison_status"] = "incomparable"
        payload["unbound"]["cache_comparison_reason"] = "rdata_not_observable"
    states = [payload[name]["cache_comparison_status"] for name in ("bind9", "unbound")]
    payload["cache_comparison_version"] = 1
    payload["cache_comparison_status"] = (
        "unknown" if "unknown" in states else "incomparable" if "incomparable" in states else "comparable"
    )
    if payload["cache_comparison_status"] == "comparable" and (
        _semantic_snapshot(bind9_before_rows) != _semantic_snapshot(unbound_before_rows)
    ):
        # 相对变化只有在共同初态相同时才可比较，不能借终态相等补足证据。
        payload["cache_comparison_status"] = "incomparable"
        payload["cache_comparison_reason"] = "initial_state_mismatch"
    payload["diff_detected"] = payload["cache_comparison_status"] == "comparable" and (
        payload["bind9"]["semantic_delta"] != payload["unbound"]["semantic_delta"]
    )
    payload["resolver_diffs"] = [
        {"left_resolver": "bind9", "right_resolver": secondary_resolver,
         "difference_fields": ["semantic_delta"]}
    ] if payload["diff_detected"] else []
    payload["compatibility_secondary_resolver"] = secondary_resolver
    return stamp_with_shared_meta(payload, sample_id=sample_id)


__all__ = ["build_cache_diff", "cache_comparable", "cache_has_diff"]
