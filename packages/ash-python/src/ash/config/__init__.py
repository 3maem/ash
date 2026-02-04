"""
ASH Configuration Module.

Server-side configuration for ASH protocol.
"""

from ash.config.scope_policies import (
    # New ASH-prefixed functions
    ash_clear_scope_policies,
    ash_get_all_scope_policies,
    ash_get_scope_policy,
    ash_has_scope_policy,
    ash_register_scope_policies,
    ash_register_scope_policy,
    # Deprecated aliases
    clear_scope_policies,
    get_all_scope_policies,
    get_scope_policy,
    has_scope_policy,
    register_scope_policies,
    register_scope_policy,
)

__all__ = [
    # New ASH-prefixed functions
    "ash_clear_scope_policies",
    "ash_get_all_scope_policies",
    "ash_get_scope_policy",
    "ash_has_scope_policy",
    "ash_register_scope_policies",
    "ash_register_scope_policy",
    # Deprecated aliases
    "clear_scope_policies",
    "get_all_scope_policies",
    "get_scope_policy",
    "has_scope_policy",
    "register_scope_policies",
    "register_scope_policy",
]
