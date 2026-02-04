"""
ASH Protocol Canonicalization Engine.

Deterministic canonicalization for JSON and URL-encoded payloads.
Same input MUST produce identical output across all implementations.
"""

import re
import unicodedata
import warnings
from typing import Any, Union
from urllib.parse import quote, unquote

from ash.core.errors import CanonicalizationError


def ash_canonicalize_json(value: Any) -> str:
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


def ash_canonicalize_url_encoded(
    input_data: Union[str, dict[str, Union[str, list[str]]]]
) -> str:
    """
    Canonicalize URL-encoded form data.

    Rules (from ASH-Spec-v1.0):
    - Parse into key-value pairs
    - Percent-decode consistently
    - Sort keys lexicographically
    - For duplicate keys: sort by value (byte-wise)
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

    # Sort by key first, then by value for duplicate keys (byte-wise)
    normalized_pairs.sort(key=lambda x: (x[0], x[1]))

    # Encode and join
    return "&".join(
        f"{quote(key, safe='')}"
        f"={quote(value, safe='')}"
        for key, value in normalized_pairs
    )


def _parse_url_encoded(input_str: str) -> list[tuple[str, str]]:
    """
    Parse URL-encoded string into key-value pairs.

    Note: Uses unquote (not unquote_plus) to preserve + as literal character.
    ASH protocol treats + as a literal plus sign, not a space.
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
            key = unquote(part)
            if key != "":
                pairs.append((key, ""))
        else:
            key = unquote(part[:eq_index])
            value = unquote(part[eq_index + 1 :])
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
        query: Query string (with or without leading ?)

    Returns:
        Canonical query string
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
    pairs = _parse_url_encoded(query)

    # Rule 4 & 5: NFC normalize
    normalized_pairs = [
        (unicodedata.normalize("NFC", key), unicodedata.normalize("NFC", value))
        for key, value in pairs
    ]

    # Rule 6 & 7: Sort by key first, then by value for duplicate keys (byte-wise)
    normalized_pairs.sort(key=lambda x: (x[0], x[1]))

    # Rule 8 & 9: Re-encode and join
    return "&".join(
        f"{quote(key, safe='')}"
        f"={quote(value, safe='')}"
        for key, value in normalized_pairs
    )


def ash_normalize_binding(method: str, path: str, query: str = "") -> str:
    """
    Normalize a binding string to canonical form (v2.3.1+ format).

    Format: METHOD|PATH|CANONICAL_QUERY

    Rules:
    - Method uppercased
    - Path must start with /
    - Duplicate slashes collapsed
    - Trailing slash removed (except for root)
    - Query string canonicalized
    - Parts joined with | (pipe)

    Args:
        method: HTTP method
        path: Request path
        query: Query string (empty string if none)

    Returns:
        Canonical binding string (METHOD|PATH|QUERY)
    """
    normalized_method = method.upper()

    # Remove fragment (#...) first
    fragment_index = path.find("#")
    normalized_path = path[:fragment_index] if fragment_index != -1 else path

    # Extract path without query string (in case path contains ?)
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

    # Canonicalize query string
    canonical_query = ash_canonicalize_query(query) if query else ""

    # v2.3.1 format: METHOD|PATH|CANONICAL_QUERY
    return f"{normalized_method}|{normalized_path}|{canonical_query}"


def ash_normalize_binding_from_url(method: str, full_path: str) -> str:
    """
    Normalize a binding from a full URL path (including query string).

    Args:
        method: HTTP method
        full_path: Full URL path including query string (e.g., "/api/users?page=1")

    Returns:
        Canonical binding string (METHOD|PATH|QUERY)
    """
    if "?" in full_path:
        path, query = full_path.split("?", 1)
    else:
        path, query = full_path, ""

    return ash_normalize_binding(method, path, query)


# =========================================================================
# Deprecated Aliases for Backward Compatibility
# =========================================================================

def canonicalize_json(value: Any) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_canonicalize_json` instead.
    """
    warnings.warn(
        "canonicalize_json is deprecated, use ash_canonicalize_json instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_canonicalize_json(value)


def canonicalize_url_encoded(
    input_data: Union[str, dict[str, Union[str, list[str]]]]
) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_canonicalize_url_encoded` instead.
    """
    warnings.warn(
        "canonicalize_url_encoded is deprecated, use ash_canonicalize_url_encoded instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_canonicalize_url_encoded(input_data)


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


def normalize_binding(method: str, path: str, query: str = "") -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_normalize_binding` instead.
    """
    warnings.warn(
        "normalize_binding is deprecated, use ash_normalize_binding instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_normalize_binding(method, path, query)


def normalize_binding_from_url(method: str, full_path: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_normalize_binding_from_url` instead.
    """
    warnings.warn(
        "normalize_binding_from_url is deprecated, use ash_normalize_binding_from_url instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_normalize_binding_from_url(method, full_path)
