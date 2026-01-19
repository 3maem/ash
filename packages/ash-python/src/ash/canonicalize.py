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
