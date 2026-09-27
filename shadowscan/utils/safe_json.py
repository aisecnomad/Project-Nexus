"""Unambiguous JSON decoding for untrusted provider and offline records."""

from __future__ import annotations

import json
import math
from typing import Any


class JSONIntegrityError(ValueError):
    """Well-formed JSON contains ambiguous fields or nonfinite numbers.

    This is intentionally distinct from JSONDecodeError: an integrity failure
    in a document must not cause a retry using a line-oriented format. Error
    messages never include keys or values, which may contain credentials.
    """


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JSONIntegrityError("Duplicate JSON field")
        result[key] = value
    return result


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise JSONIntegrityError("Nonfinite JSON number")
    return result


def strict_json_loads(text: str | bytes | bytearray) -> Any:
    """Decode JSON without allowing overwritten fields or nonfinite values.

    Callers bound the input before decoding and translate parse failures into
    incomplete coverage. Every nested object receives the same validation.
    """
    return json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_float=_finite_float,
        parse_constant=_finite_float,
    )
