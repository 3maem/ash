"""
Canonicalization functions for deterministic serialization.

This module provides RFC 8785 (JCS) compliant JSON canonicalization
and ASH specification compliant query string canonicalization.
"""

from __future__ import annotations

import json
import math
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, quote


class CanonicalizationError(ValueError):
    """Error during canonicalization."""

    pass


def ash_canonicalize_json(input_json: str) -> str:
    """
    Canonicalize JSON to deterministic form per RFC 8785 (JCS).

    Rules:
    - Object keys sorted lexicographically
    - No whitespace
    - Unicode NFC normalized
    - Numbers: -0 becomes 0, whole floats become integers
    - MUST reject: NaN, Infinity

    Args:
        input_json: JSON string to canonicalize

    Returns:
        Canonical JSON string

    Raises:
        json.JSONDecodeError: If input is not valid JSON
        CanonicalizationError: If input contains NaN or Infinity

    Example:
        >>> ash_canonicalize_json('{"z":1,"a":2}')
        '{"a":2,"z":1}'
    """
    data = json.loads(input_json)
    normalized = _normalize_value(data)
    return _build_canonical_json(normalized)


def _build_canonical_json(value: Any) -> str:
    """Build canonical JSON string manually to ensure proper escaping and key ordering."""
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, str):
        return _json_escape_string(value)

    if isinstance(value, (int, float)):
        return str(value)

    if isinstance(value, list):
        items = [_build_canonical_json(item) for item in value]
        return "[" + ",".join(items) + "]"

    if isinstance(value, dict):
        sorted_keys = sorted(value.keys())
        pairs = [
            _json_escape_string(key) + ":" + _build_canonical_json(value[key])
            for key in sorted_keys
        ]
        return "{" + ",".join(pairs) + "}"

    raise CanonicalizationError(f"Cannot serialize type: {type(value).__name__}")


def _json_escape_string(s: str) -> str:
    """
    Escape a string for JSON output per RFC 8785 (JCS).

    Minimal JSON escaping:
    - 0x08 -> \\b (backspace)
    - 0x09 -> \\t (tab)
    - 0x0A -> \\n (newline)
    - 0x0C -> \\f (form feed)
    - 0x0D -> \\r (carriage return)
    - 0x22 -> \\" (double quote)
    - 0x5C -> \\\\ (backslash)
    - 0x00-0x1F (other control chars) -> \\uXXXX (lowercase hex)
    """
    result = ['"']
    for char in s:
        code = ord(char)
        if char == '"':  # 0x22
            result.append('\\"')
        elif char == "\\":  # 0x5C
            result.append("\\\\")
        elif char == "\b":  # 0x08 backspace
            result.append("\\b")
        elif char == "\t":  # 0x09 tab
            result.append("\\t")
        elif char == "\n":  # 0x0A newline
            result.append("\\n")
        elif char == "\f":  # 0x0C form feed
            result.append("\\f")
        elif char == "\r":  # 0x0D carriage return
            result.append("\\r")
        elif code < 0x20:  # Other control characters
            result.append(f"\\u{code:04x}")
        else:
            result.append(char)
    result.append('"')
    return "".join(result)


def ash_canonicalize_query(query: str) -> str:
    """
    Canonicalize a URL query string according to ASH specification.

    9 MUST Rules:
    1. MUST parse query string after ? (or use full string if no ?)
    2. MUST split on & to get key=value pairs
    3. MUST handle keys without values (treat as empty string)
    4. MUST percent-decode all keys and values
    5. MUST apply Unicode NFC normalization
    6. MUST sort pairs by key lexicographically (byte order)
    7. MUST sort duplicate keys by value (byte-wise)
    8. MUST re-encode with uppercase hex (%XX)
    9. MUST join with & separator

    Args:
        query: Query string to canonicalize (with or without leading ?)

    Returns:
        Canonical query string

    Example:
        >>> ash_canonicalize_query('z=3&a=1&b=hello%20world')
        'a=1&b=hello%20world&z=3'
    """
    # Rule 1: Remove leading ? if present
    if query.startswith("?"):
        query = query[1:]

    # Strip fragment (#) if present
    fragment_index = query.find("#")
    if fragment_index != -1:
        query = query[:fragment_index]

    if not query:
        return ""

    # Rule 2 & 3: Parse pairs
    pairs = parse_qsl(query, keep_blank_values=True)

    # Rule 4 & 5: Percent-decode and NFC normalize
    normalized_pairs = []
    for key, value in pairs:
        key = unicodedata.normalize("NFC", key)
        value = unicodedata.normalize("NFC", value)
        normalized_pairs.append((key, value))

    # Rule 6 & 7: Sort by key first, then by value for duplicate keys (byte-wise)
    normalized_pairs.sort(key=lambda x: (x[0], x[1]))

    # Rule 8 & 9: Re-encode with uppercase hex and join
    encoded_pairs = []
    for key, value in normalized_pairs:
        # quote() uses uppercase hex by default
        encoded_key = quote(key, safe="")
        encoded_value = quote(value, safe="")
        encoded_pairs.append(f"{encoded_key}={encoded_value}")

    return "&".join(encoded_pairs)


def ash_canonicalize_urlencoded(input_data: str) -> str:
    """
    Canonicalize URL-encoded data to deterministic form.

    Rules:
    - Parameters sorted by key
    - Values percent-encoded consistently
    - Unicode NFC normalized

    Args:
        input_data: URL-encoded string to canonicalize

    Returns:
        Canonical URL-encoded string

    Example:
        >>> ash_canonicalize_urlencoded('z=1&a=2')
        'a=2&z=1'
    """
    if not input_data:
        return ""

    # Parse into key-value pairs
    pairs = parse_qsl(input_data, keep_blank_values=True)

    # NFC normalize and sort by key, then by value for duplicate keys
    normalized_pairs = []
    for key, value in pairs:
        key = unicodedata.normalize("NFC", key)
        value = unicodedata.normalize("NFC", value)
        normalized_pairs.append((key, value))

    # Sort by key first, then by value for duplicate keys (byte-wise)
    normalized_pairs.sort(key=lambda x: (x[0], x[1]))

    # Encode consistently using RFC 3986
    encoded_pairs = []
    for key, value in normalized_pairs:
        encoded_key = quote(key, safe="")
        encoded_value = quote(value, safe="")
        encoded_pairs.append(f"{encoded_key}={encoded_value}")

    return "&".join(encoded_pairs)


def _normalize_value(value: Any) -> Any:
    """Normalize a value recursively."""
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, dict):
        return _normalize_object(value)
    elif isinstance(value, list):
        return [_normalize_value(item) for item in value]
    elif isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    elif isinstance(value, int):
        return value
    elif isinstance(value, float):
        return _normalize_number(value)
    else:
        raise CanonicalizationError(f"Unsupported type: {type(value).__name__}")


def _normalize_number(num: float) -> int | float:
    """
    Normalize a number according to ASH/JCS spec.

    Rules:
    - Reject NaN and Infinity
    - -0 becomes 0
    - Whole floats become integers
    """
    if math.isnan(num):
        raise CanonicalizationError("NaN values are not allowed")

    if math.isinf(num):
        raise CanonicalizationError("Infinity values are not allowed")

    # Convert -0 to 0
    if num == 0:
        return 0

    # Convert to int if whole number
    if num == int(num):
        return int(num)

    return num


def _normalize_object(obj: dict[str, Any]) -> dict[str, Any]:
    """Normalize an object with sorted keys."""
    normalized: dict[str, Any] = {}

    # Sort keys lexicographically
    for key in sorted(obj.keys()):
        normalized_key = unicodedata.normalize("NFC", key) if isinstance(key, str) else key
        normalized[normalized_key] = _normalize_value(obj[key])

    return normalized


# =========================================================================
# Deprecated Aliases for Backward Compatibility
# =========================================================================

import warnings


def canonicalize_json(input_json: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_canonicalize_json` instead.
    """
    warnings.warn(
        "canonicalize_json is deprecated, use ash_canonicalize_json instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_canonicalize_json(input_json)


def canonicalize_query(query: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_canonicalize_query` instead.
    """
    warnings.warn(
        "canonicalize_query is deprecated, use ash_canonicalize_query instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_canonicalize_query(query)


def canonicalize_urlencoded(input_data: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_canonicalize_urlencoded` instead.
    """
    warnings.warn(
        "canonicalize_urlencoded is deprecated, use ash_canonicalize_urlencoded instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_canonicalize_urlencoded(input_data)
