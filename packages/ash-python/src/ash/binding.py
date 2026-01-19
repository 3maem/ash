"""
Binding normalization utilities.
"""

from __future__ import annotations

import re


def ash_normalize_binding(method: str, path: str) -> str:
    """
    Normalize a binding string to canonical form.

    Rules:
    - Method uppercased
    - Path starts with /
    - Query string excluded
    - Duplicate slashes collapsed
    - Trailing slash removed (except for root)

    Args:
        method: HTTP method (GET, POST, etc.)
        path: URL path

    Returns:
        Canonical binding string

    Example:
        >>> ash_normalize_binding("post", "/api//test/")
        'POST /api/test'
    """
    # Uppercase method
    method = method.upper()

    # Remove query string
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

    return f"{method} {path}"
