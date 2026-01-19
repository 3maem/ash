"""
Constant-time comparison for timing-attack resistance.
"""

from __future__ import annotations

import hmac


def ash_timing_safe_equal(a: str | bytes, b: str | bytes) -> bool:
    """
    Perform a constant-time comparison of two values.

    This function takes the same amount of time regardless of where
    the first difference occurs, preventing timing attacks.

    Args:
        a: First value (string or bytes)
        b: Second value (string or bytes)

    Returns:
        True if values are equal, False otherwise

    Example:
        >>> ash_timing_safe_equal("secret123", "secret123")
        True
        >>> ash_timing_safe_equal("secret123", "secret456")
        False
    """
    # Convert to bytes if needed
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")

    # Use hmac.compare_digest for constant-time comparison
    return hmac.compare_digest(a, b)
