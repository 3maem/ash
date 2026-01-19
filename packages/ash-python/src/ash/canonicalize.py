"""
Canonicalization functions for deterministic serialization.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, quote


def ash_canonicalize_json(input_json: str) -> str:
    """
    Canonicalize JSON to deterministic form.

    Rules:
    - Object keys sorted lexicographically
    - No whitespace
    - Unicode NFC normalized
    - Numbers normalized

    Args:
        input_json: JSON string to canonicalize

    Returns:
        Canonical JSON string

    Raises:
        json.JSONDecodeError: If input is not valid JSON

    Example:
        >>> ash_canonicalize_json('{"z":1,"a":2}')
        '{"a":2,"z":1}'
    """
    data = json.loads(input_json)
    normalized = _normalize_value(data)
    return json.dumps(normalized, separators=(",", ":"), ensure_ascii=False, sort_keys=False)


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
    7. MUST preserve order of duplicate keys
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

    # Rule 6 & 7: Sort by key (stable sort preserves duplicate key order)
    normalized_pairs.sort(key=lambda x: x[0])

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

    # NFC normalize and sort by key
    normalized_pairs = []
    for key, value in pairs:
        key = unicodedata.normalize("NFC", key)
        value = unicodedata.normalize("NFC", value)
        normalized_pairs.append((key, value))

    # Sort by key
    normalized_pairs.sort(key=lambda x: x[0])

    # Encode consistently using RFC 3986
    encoded_pairs = []
    for key, value in normalized_pairs:
        encoded_key = quote(key, safe="")
        encoded_value = quote(value, safe="")
        encoded_pairs.append(f"{encoded_key}={encoded_value}")

    return "&".join(encoded_pairs)


def _normalize_value(value: Any) -> Any:
    """Normalize a value recursively."""
    if isinstance(value, dict):
        return _normalize_object(value)
    elif isinstance(value, list):
        return [_normalize_value(item) for item in value]
    elif isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    else:
        return value


def _normalize_object(obj: dict[str, Any]) -> dict[str, Any]:
    """Normalize an object with sorted keys."""
    normalized: dict[str, Any] = {}

    # Sort keys lexicographically
    for key in sorted(obj.keys()):
        normalized_key = unicodedata.normalize("NFC", key) if isinstance(key, str) else key
        normalized[normalized_key] = _normalize_value(obj[key])

    return normalized
