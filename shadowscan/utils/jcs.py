"""RFC 8785 JSON Canonicalization Scheme (JCS) for parsed JSON values.

Covers what the strict JSON decoders produce: objects with string keys,
arrays, strings, booleans, null, integers and finite floats. Members are
ordered by their UTF-16 code units and numbers use the ECMAScript number
serialization. A value with no canonical form is refused, never approximated:
integers beyond 2**53 (an IEEE 754 double cannot hold them exactly, so their
canonical digits are not the parsed ones), non-finite numbers, unpaired
surrogates and other types.
"""

from __future__ import annotations

import json
import math
from typing import Any

MAX_EXACT_INTEGER = 2**53
_MAX_DEPTH = 200


class CanonicalizationError(ValueError):
    """The value has no RFC 8785 canonical form; the message names the reason, never the value."""


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 serialization of ``value``."""
    parts: list[str] = []
    _write(value, parts, 0)
    try:
        return "".join(parts).encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalizationError("JSON text contains an unpaired surrogate") from None


def _write(value: Any, parts: list[str], depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise CanonicalizationError("JSON nesting exceeds the canonicalization depth limit")
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, int):
        if abs(value) > MAX_EXACT_INTEGER:
            raise CanonicalizationError("JSON integer is outside the exactly representable range")
        parts.append(str(value))
    elif isinstance(value, float):
        parts.append(es_number(value))
    elif isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise CanonicalizationError("JSON object keys must be strings")
        parts.append("{")
        for position, key in enumerate(sorted(value, key=_utf16_order)):
            if position:
                parts.append(",")
            parts.append(_string(key))
            parts.append(":")
            _write(value[key], parts, depth + 1)
        parts.append("}")
    elif isinstance(value, list):
        parts.append("[")
        for position, item in enumerate(value):
            if position:
                parts.append(",")
            _write(item, parts, depth + 1)
        parts.append("]")
    else:
        raise CanonicalizationError("value is not a JSON type")


def _utf16_order(key: str) -> bytes:
    # Big-endian code units compare like the code units themselves.
    return key.encode("utf-16-be", "surrogatepass")


def _string(value: str) -> str:
    # Python escapes exactly what ECMAScript JSON.stringify escapes when
    # ensure_ascii is off: '"', '\\', \b \f \n \r \t, and the other control
    # characters as lowercase \u00hh. Everything else stays literal.
    return json.dumps(value, ensure_ascii=False)


def es_number(value: float) -> str:
    """Serialize a finite double as ECMAScript ``Number.prototype.toString`` does."""
    if not math.isfinite(value):
        raise CanonicalizationError("JSON number is not finite")
    if value == 0:
        return "0"  # also -0
    sign = "-" if value < 0 else ""
    # repr is the shortest string that round-trips, as ECMAScript requires.
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    combined = whole + fraction
    digits = combined.lstrip("0")
    # The value is 0.<digits> * 10**point.
    point = len(whole) + int(exponent or "0") - (len(combined) - len(digits))
    digits = digits.rstrip("0")
    count = len(digits)
    if count <= point <= 21:
        text = digits + "0" * (point - count)
    elif 0 < point <= 21:
        text = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        text = "0." + "0" * -point + digits
    else:
        power = point - 1
        text = digits[0] + ("." + digits[1:] if count > 1 else "") + "e" + ("+" if power >= 0 else "-")
        text += str(abs(power))
    return sign + text
