"""
ASH (Anti-tamper Security Hash) Python SDK

Request integrity and anti-replay protection for Python applications.

Example:
    >>> from ash import Ash, MemoryStore, AshMode
    >>>
    >>> store = MemoryStore()
    >>> ash = Ash(store)
    >>>
    >>> # Issue a context
    >>> ctx = ash.ash_issue_context("POST /api/update", ttl_ms=30000)
    >>> print(ctx.id)
    >>>
    >>> # Build proof (client-side)
    >>> proof = ash.ash_build_proof(
    ...     AshMode.BALANCED,
    ...     "POST /api/update",
    ...     ctx.id,
    ...     None,
    ...     '{"name":"John"}'
    ... )
"""

from .core import (
    Ash,
    AshMode,
    AshContext,
    AshVerifyResult,
    AshErrorCode,
)
from .canonicalize import (
    ash_canonicalize_json,
    ash_canonicalize_urlencoded,
)
from .proof import ash_build_proof, ash_verify_proof
from .compare import ash_timing_safe_equal
from .binding import ash_normalize_binding
from .stores import ContextStore, MemoryStore, RedisStore

__version__ = "1.0.0"
__ash_version__ = "ASHv1"

__all__ = [
    # Core
    "Ash",
    "AshMode",
    "AshContext",
    "AshVerifyResult",
    "AshErrorCode",
    # Functions
    "ash_canonicalize_json",
    "ash_canonicalize_urlencoded",
    "ash_build_proof",
    "ash_verify_proof",
    "ash_timing_safe_equal",
    "ash_normalize_binding",
    # Stores
    "ContextStore",
    "MemoryStore",
    "RedisStore",
    # Version
    "__version__",
    "__ash_version__",
]
