"""
ASH Protocol Constant-Time Comparison.

Prevents timing attacks during proof verification.
"""

import hmac


def timing_safe_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time.

    Uses HMAC comparison to prevent timing attacks.
    Both strings are compared byte-by-byte regardless of where they differ.

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal, False otherwise
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
