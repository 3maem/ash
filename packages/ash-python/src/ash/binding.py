"""
Binding normalization utilities.
"""

from __future__ import annotations

import re

from .canonicalize import ash_canonicalize_query


def ash_normalize_binding(method: str, path: str, query: str = "") -> str:
    """
    Normalize a binding string to canonical form (v2.3.1+ format).

    Format: METHOD|PATH|CANONICAL_QUERY

    Rules:
    - Method uppercased
    - Path starts with /
    - Fragment (#) stripped from path
    - Duplicate slashes collapsed
    - Trailing slash removed (except for root)
    - Query string canonicalized
    - Parts joined with | (pipe)

    Args:
        method: HTTP method (GET, POST, etc.)
        path: URL path
        query: Query string (empty string if none)

    Returns:
        Canonical binding string (METHOD|PATH|QUERY)

    Example:
        >>> ash_normalize_binding("post", "/api//test/", "")
        'POST|/api/test|'
        >>> ash_normalize_binding("GET", "/api/users", "page=1&sort=name")
        'GET|/api/users|page=1&sort=name'
    """
    # Uppercase method
    method = method.upper()

    # Strip fragment (#) from path
    fragment_index = path.find("#")
    if fragment_index != -1:
        path = path[:fragment_index]

    # Extract path without query string (in case path contains ?)
    if "?" in path:
        path = path.split("?")[0]

    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path

    # Collapse duplicate slashes
    path = re.sub(r"/+", "/", path)

    # Remove trailing slash (except for root)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Canonicalize query string
    canonical_query = ash_canonicalize_query(query) if query else ""

    # v2.3.1 format: METHOD|PATH|CANONICAL_QUERY
    return f"{method}|{path}|{canonical_query}"


def ash_normalize_binding_from_url(method: str, full_path: str) -> str:
    """
    Normalize a binding from a full URL path (including query string).

    This is a convenience function that extracts the query from the path.

    Args:
        method: HTTP method (GET, POST, etc.)
        full_path: Full URL path including query string (e.g., "/api/users?page=1")

    Returns:
        Canonical binding string (METHOD|PATH|QUERY)

    Example:
        >>> ash_normalize_binding_from_url("GET", "/api/users?page=1&sort=name")
        'GET|/api/users|page=1&sort=name'
    """
    # Strip fragment (#) first - it can appear in path or query
    fragment_index = full_path.find("#")
    if fragment_index != -1:
        full_path = full_path[:fragment_index]

    if "?" in full_path:
        path, query = full_path.split("?", 1)
    else:
        path, query = full_path, ""

    return ash_normalize_binding(method, path, query)


# =========================================================================
# Deprecated Aliases for Backward Compatibility
# =========================================================================

import warnings


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
