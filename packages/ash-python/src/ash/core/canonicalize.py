"""
ASH Protocol Canonicalization Engine.

Deterministic canonicalization for JSON and URL-encoded payloads.
Same input MUST produce identical output across all implementations.
"""

import re
import unicodedata
from typing import Any, Union
from urllib.parse import quote, unquote_plus

from ash.core.errors import CanonicalizationError


def canonicalize_json(value: Any) -> str:
    """
    Canonicalize a JSON value to a deterministic string.

    Rules (from ASH-Spec-v1.0):
    - JSON minified (no whitespace)
    - Object keys sorted lexicographically (ascending)
    - Arrays preserve order
    - Unicode normalization: NFC
    - Numbers: no scientific notation, remove trailing zeros, -0 becomes 0
    - Unsupported values REJECT: NaN, Infinity, None type objects

    Args:
        value: The value to canonicalize

    Returns:
        Canonical JSON string

    Raises:
        CanonicalizationError: If value contains unsupported types
    """
    return _build_canonical_json(_canonicalize_value(value))


def _build_canonical_json(value: Any) -> str:
    """Build canonical JSON string manually to ensure key ordering."""
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
    """Escape a string for JSON output."""
    result = ['"']
    for char in s:
        if char == '"':
            result.append('\\"')
        elif char == "\\":
            result.append("\\\\")
        elif char == "\n":
            result.append("\\n")
        elif char == "\r":
            result.append("\\r")
        elif char == "\t":
            result.append("\\t")
        elif ord(char) < 0x20:
            result.append(f"\\u{ord(char):04x}")
        else:
            result.append(char)
    result.append('"')
    return "".join(result)


def _canonicalize_value(value: Any) -> Any:
    """Recursively canonicalize a value."""
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        # Apply NFC normalization to strings
        return unicodedata.normalize("NFC", value)

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return _canonicalize_number(value)

    if isinstance(value, list):
        return [_canonicalize_value(item) for item in value]

    if isinstance(value, dict):
        sorted_keys = sorted(value.keys())
        result = {}
        for key in sorted_keys:
            val = value[key]
            if val is not None:
                normalized_key = unicodedata.normalize("NFC", key)
                result[normalized_key] = _canonicalize_value(val)
        return result

    raise CanonicalizationError(f"Unsupported type: {type(value).__name__}")


def _canonicalize_number(num: float) -> Union[int, float]:
    """
    Canonicalize a number according to ASH spec.

    Rules:
    - No scientific notation
    - Remove trailing zeros
    - -0 becomes 0
    - Reject NaN and Infinity
    """
    import math

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


def canonicalize_url_encoded(
    input_data: Union[str, dict[str, Union[str, list[str]]]]
) -> str:
    """
    Canonicalize URL-encoded form data.

    Rules (from ASH-Spec-v1.0):
    - Parse into key-value pairs
    - Percent-decode consistently
    - Sort keys lexicographically
    - For duplicate keys: preserve value order per key
    - Output format: k1=v1&k1=v2&k2=v3
    - Unicode NFC applies after decoding

    Args:
        input_data: URL-encoded string or dict of key-value pairs

    Returns:
        Canonical URL-encoded string

    Raises:
        CanonicalizationError: If input cannot be parsed
    """
    if isinstance(input_data, str):
        pairs = _parse_url_encoded(input_data)
    else:
        pairs = _object_to_pairs(input_data)

    # Normalize all keys and values with NFC
    normalized_pairs = [
        (unicodedata.normalize("NFC", key), unicodedata.normalize("NFC", value))
        for key, value in pairs
    ]

    # Sort by key (stable sort preserves value order for same keys)
    normalized_pairs.sort(key=lambda x: x[0])

    # Encode and join
    return "&".join(
        f"{quote(key, safe='')}"
        f"={quote(value, safe='')}"
        for key, value in normalized_pairs
    )


def _parse_url_encoded(input_str: str) -> list[tuple[str, str]]:
    """
    Parse URL-encoded string into key-value pairs.

    Handles + as space (per application/x-www-form-urlencoded spec).
    Skips empty parts from && or leading/trailing &.
    """
    if input_str == "":
        return []

    pairs: list[tuple[str, str]] = []

    for part in input_str.split("&"):
        if part == "":
            continue

        eq_index = part.find("=")
        if eq_index == -1:
            key = unquote_plus(part)
            if key != "":
                pairs.append((key, ""))
        else:
            key = unquote_plus(part[:eq_index])
            value = unquote_plus(part[eq_index + 1 :])
            if key != "":
                pairs.append((key, value))

    return pairs


def _object_to_pairs(obj: dict[str, Union[str, list[str]]]) -> list[tuple[str, str]]:
    """Convert object to key-value pairs, preserving array order."""
    pairs: list[tuple[str, str]] = []

    for key, value in obj.items():
        if isinstance(value, list):
            for v in value:
                pairs.append((key, v))
        else:
            pairs.append((key, value))

    return pairs


def normalize_binding(method: str, path: str) -> str:
    """
    Normalize a binding string.

    Rules (from ASH-Spec-v1.0):
    - Format: "METHOD /path"
    - Method uppercased
    - Path must start with /
    - Path excludes query string
    - Collapse duplicate slashes

    Args:
        method: HTTP method
        path: Request path

    Returns:
        Normalized binding string
    """
    normalized_method = method.upper()

    # Remove fragment (#...) first
    fragment_index = path.find("#")
    normalized_path = path[:fragment_index] if fragment_index != -1 else path

    # Remove query string
    query_index = normalized_path.find("?")
    normalized_path = (
        normalized_path[:query_index] if query_index != -1 else normalized_path
    )

    # Ensure path starts with /
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path

    # Collapse duplicate slashes
    normalized_path = re.sub(r"/+", "/", normalized_path)

    # Remove trailing slash (except for root)
    if len(normalized_path) > 1 and normalized_path.endswith("/"):
        normalized_path = normalized_path[:-1]

    return f"{normalized_method} {normalized_path}"
