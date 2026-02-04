"""
ASH Protocol Constant-Time Comparison.

Prevents timing attacks during proof verification.
"""

import hmac
import warnings


def ash_timing_safe_equal(a: str, b: str) -> bool:
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


# =========================================================================
# Deprecated Aliases for Backward Compatibility
# =========================================================================

def timing_safe_compare(a: str, b: str) -> bool:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_timing_safe_equal` instead.
    """
    warnings.warn(
        "timing_safe_compare is deprecated, use ash_timing_safe_equal instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_timing_safe_equal(a, b)
