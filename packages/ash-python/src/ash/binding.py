"""
Binding normalization utilities.
"""

from __future__ import annotations

import re

from .canonicalize import ash_canonicalize_query


def ash_normalize_binding(method: str, path: str, query: str = "") -> str:
    """
    Normalize a binding string to canonical form (v2.3.2+ format).

    Format: METHOD|PATH|CANONICAL_QUERY

    Rules:
    - Method uppercased
    - Path starts with /
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

    # v2.3.2 format: METHOD|PATH|CANONICAL_QUERY
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
    if "?" in full_path:
        path, query = full_path.split("?", 1)
    else:
        path, query = full_path, ""

    return ash_normalize_binding(method, path, query)
