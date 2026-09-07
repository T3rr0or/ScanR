"""Spreadsheet-safe serialization helpers for CSV exports."""
from __future__ import annotations

_FORMULA_PREFIXES = ("=", "+", "-", "@")
_IGNORABLE_PREFIX_CHARS = "".join(chr(value) for value in range(33)) + "\x7f\ufeff"


def spreadsheet_safe_cell(value: object) -> object:
    """Neutralize strings that spreadsheet applications may execute as formulas.

    CSV quoting does not stop formula execution. Prefixing an apostrophe makes
    Excel-compatible applications treat the entire field as text. Leading
    whitespace and a Unicode BOM are inspected too because they are common
    parser-dependent bypasses.
    """
    if not isinstance(value, str) or not value:
        return value

    candidate = value.lstrip(_IGNORABLE_PREFIX_CHARS)
    if candidate.startswith(_FORMULA_PREFIXES) or ord(value[0]) < 32 or ord(value[0]) == 127:
        return "'" + value
    return value
