"""
ASH Configuration Module.

Server-side configuration for ASH protocol.
"""

from ash.config.scope_policies import (
    register_scope_policy,
    register_scope_policies,
    get_scope_policy,
    has_scope_policy,
    get_all_scope_policies,
    clear_scope_policies,
)

__all__ = [
    "register_scope_policy",
    "register_scope_policies",
    "get_scope_policy",
    "has_scope_policy",
    "get_all_scope_policies",
    "clear_scope_policies",
]
