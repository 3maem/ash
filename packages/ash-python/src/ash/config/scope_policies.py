"""
Server-side scope policy registry for ASH.

Allows servers to define which fields must be protected for each route,
without requiring client-side scope management.

Example:
    # Register policies at application startup
    ash_register_scope_policy('POST|/api/transfer|', ['amount', 'recipient'])
    ash_register_scope_policy('POST|/api/payment|', ['amount', 'card_last4'])
    ash_register_scope_policy('PUT|/api/users/<id>|', ['role', 'permissions'])

    # Later, get policy for a binding
    scope = ash_get_scope_policy('POST|/api/transfer|')
    # Returns: ['amount', 'recipient']
"""

from __future__ import annotations

import re
import warnings
from typing import Dict, List

# Internal storage for scope policies
_policies: Dict[str, List[str]] = {}


def ash_register_scope_policy(binding: str, fields: List[str]) -> None:
    """
    Register a scope policy for a binding pattern.

    Args:
        binding: The binding pattern (supports <param> and * wildcards)
        fields: The fields that must be protected

    Example:
        ash_register_scope_policy('POST|/api/transfer|', ['amount', 'recipient'])
        ash_register_scope_policy('PUT|/api/users/<id>|', ['role', 'permissions'])
    """
    _policies[binding] = fields


def ash_register_scope_policies(policies: Dict[str, List[str]]) -> None:
    """
    Register multiple scope policies at once.

    Args:
        policies: Map of binding => fields

    Example:
        ash_register_scope_policies({
            'POST|/api/transfer|': ['amount', 'recipient'],
            'POST|/api/payment|': ['amount', 'card_last4'],
        })
    """
    for binding, fields in policies.items():
        _policies[binding] = fields


def ash_get_scope_policy(binding: str) -> List[str]:
    """
    Get the scope policy for a binding.

    Returns empty list if no policy is defined (full payload protection).

    Args:
        binding: The normalized binding string

    Returns:
        The fields that must be protected
    """
    # Exact match first
    if binding in _policies:
        return _policies[binding]

    # Pattern match (supports <param> and * wildcards)
    for pattern, fields in _policies.items():
        if _matches_pattern(binding, pattern):
            return fields

    # Default: no scoping (full payload protection)
    return []


def ash_has_scope_policy(binding: str) -> bool:
    """
    Check if a binding has a scope policy defined.

    Args:
        binding: The normalized binding string

    Returns:
        True if a policy exists
    """
    if binding in _policies:
        return True

    for pattern in _policies:
        if _matches_pattern(binding, pattern):
            return True

    return False


def ash_get_all_scope_policies() -> Dict[str, List[str]]:
    """
    Get all registered policies.

    Returns:
        All registered scope policies
    """
    return dict(_policies)


def ash_clear_scope_policies() -> None:
    """
    Clear all registered policies.

    Useful for testing.
    """
    _policies.clear()


def _matches_pattern(binding: str, pattern: str) -> bool:
    """
    Check if a binding matches a pattern with wildcards.

    Supports:
        - <param> for Flask-style route parameters
        - * for single path segment wildcard
        - ** for multi-segment wildcard

    Args:
        binding: The actual binding
        pattern: The pattern to match against

    Returns:
        True if matches
    """
    # If no wildcards or params, must be exact match
    if '*' not in pattern and '<' not in pattern:
        return binding == pattern

    # Convert pattern to regex
    regex = re.escape(pattern)

    # Replace ** first (multi-segment)
    regex = regex.replace(r'\*\*', '.*')

    # Replace * (single segment - not containing | or /)
    regex = regex.replace(r'\*', '[^|/]*')

    # Replace <param> (Flask-style route params)
    regex = re.sub(r'\\<[a-zA-Z_][a-zA-Z0-9_]*\\>', '[^|/]+', regex)

    return re.match(f'^{regex}$', binding) is not None


# =========================================================================
# Deprecated Aliases for Backward Compatibility
# =========================================================================

def register_scope_policy(binding: str, fields: List[str]) -> None:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_register_scope_policy` instead.
    """
    warnings.warn(
        "register_scope_policy is deprecated, use ash_register_scope_policy instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_register_scope_policy(binding, fields)


def register_scope_policies(policies: Dict[str, List[str]]) -> None:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_register_scope_policies` instead.
    """
    warnings.warn(
        "register_scope_policies is deprecated, use ash_register_scope_policies instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_register_scope_policies(policies)


def get_scope_policy(binding: str) -> List[str]:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_get_scope_policy` instead.
    """
    warnings.warn(
        "get_scope_policy is deprecated, use ash_get_scope_policy instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_get_scope_policy(binding)


def has_scope_policy(binding: str) -> bool:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_has_scope_policy` instead.
    """
    warnings.warn(
        "has_scope_policy is deprecated, use ash_has_scope_policy instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_has_scope_policy(binding)


def get_all_scope_policies() -> Dict[str, List[str]]:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_get_all_scope_policies` instead.
    """
    warnings.warn(
        "get_all_scope_policies is deprecated, use ash_get_all_scope_policies instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_get_all_scope_policies()


def clear_scope_policies() -> None:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_clear_scope_policies` instead.
    """
    warnings.warn(
        "clear_scope_policies is deprecated, use ash_clear_scope_policies instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_clear_scope_policies()
