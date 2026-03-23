from collections import Counter
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .schema import stamp_with_shared_meta

CacheRow = Tuple[str, str, str, str, str, str, str, str, str, str]


def _normalize_row(row: Any) -> CacheRow:
    if hasattr(row, "to_fields"):
        fields = tuple(getattr(row, "to_fields")())
    else:
        fields = tuple(row)
    if len(fields) != 10:
        raise ValueError(f"cache 行列数必须是 10，当前为 {len(fields)}")
    return tuple(str(field) for field in fields)  # type: ignore[return-value]


def _structural_key(row: CacheRow) -> Tuple[str, ...]:
    return row[:7] + row[8:10]


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

    return {
        "entries_before": len(before_rows),
        "entries_after": len(after_rows),
        "has_cache_diff": has_cache_diff,
        "interesting_delta_count": interesting_delta_count,
        "delta_items": delta_items,
    }


def build_cache_diff(
    sample_id: str,
    bind9_before: list,
    bind9_after: list,
    unbound_before: list,
    unbound_after: list,
    triggered: bool,
) -> dict:
    bind9_before_rows = [_normalize_row(row) for row in bind9_before]
    bind9_after_rows = [_normalize_row(row) for row in bind9_after]
    unbound_before_rows = [_normalize_row(row) for row in unbound_before]
    unbound_after_rows = [_normalize_row(row) for row in unbound_after]

    payload: Mapping[str, Any] = {
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
    return stamp_with_shared_meta(payload, sample_id=sample_id)


__all__ = ["build_cache_diff"]
