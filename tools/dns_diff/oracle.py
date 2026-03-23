import re
from typing import Dict, Optional, Union

ORACLE_FIELDS = (
    "parse_ok",
    "resolver_fetch_started",
    "response_accepted",
    "second_query_hit",
    "cache_entry_created",
    "timeout",
)

_SUMMARY_LINE_RE = re.compile(r"^\s*ORACLE_SUMMARY\b(?P<body>.*)$", re.MULTILINE)
OracleValue = Union[bool, None, str]


def _empty_oracle(resolver: str, status: str) -> Dict[str, OracleValue]:
    payload: Dict[str, OracleValue] = {
        f"{resolver}.{key}": None for key in ORACLE_FIELDS
    }
    payload[f"{resolver}.stderr_parse_status"] = status
    return payload


def _summary_scope(stderr_text: str, resolver: str) -> str:
    stage_marker = f"===== {resolver}.after ====="
    if stage_marker in stderr_text:
        return stderr_text.rsplit(stage_marker, 1)[-1]
    return stderr_text


def _parse_bool_token(raw: str) -> Optional[bool]:
    if raw == "0":
        return False
    if raw == "1":
        return True
    return None


def parse_oracle_summary(
    stderr_text: Optional[str], resolver: str
) -> Dict[str, OracleValue]:
    if resolver not in {"bind9", "unbound"}:
        raise ValueError(f"不支持的 resolver: {resolver!r}")

    if stderr_text is None or not stderr_text.strip():
        return _empty_oracle(resolver, "stderr_missing")

    scoped_text = _summary_scope(stderr_text, resolver)
    matches = list(_SUMMARY_LINE_RE.finditer(scoped_text))
    if not matches:
        return _empty_oracle(resolver, "missing_summary")

    body = matches[-1].group("body").strip()
    tokens: Dict[str, str] = {}
    for chunk in body.split():
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        tokens[key] = value

    result = _empty_oracle(resolver, "ok")
    all_ok = True
    for field in ORACLE_FIELDS:
        parsed_value = _parse_bool_token(tokens.get(field, ""))
        if parsed_value is None:
            all_ok = False
        result[f"{resolver}.{field}"] = parsed_value

    if not all_ok:
        result[f"{resolver}.stderr_parse_status"] = "missing_summary"
    return result


__all__ = ["parse_oracle_summary", "ORACLE_FIELDS"]
