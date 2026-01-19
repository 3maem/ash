"""
In-Memory Context Store.

WARNING: For development and testing ONLY.
NOT suitable for production - no persistence, no atomic guarantees across processes.
"""

import os
import time
import warnings
from typing import Dict, Optional

from ash.core.types import StoredContext
from ash.server.types import ConsumeResult, ContextStore


class Memory(ContextStore):
    """
    In-memory context store for development and testing.

    WARNING: Do NOT use in production!
    - No persistence across restarts
    - No atomic guarantees in clustered environments
    - Memory will grow unbounded without cleanup
    """

    def __init__(self, suppress_warning: bool = False):
        self._contexts: Dict[str, StoredContext] = {}

        if not suppress_warning and os.environ.get("FLASK_ENV") == "production":
            warnings.warn(
                "[ASH WARNING] Memory store is not suitable for production. "
                "Use Redis store instead.",
                RuntimeWarning,
            )

    async def put(self, ctx: StoredContext) -> None:
        """Store a context."""
        # Create a copy to prevent external modification
        self._contexts[ctx.context_id] = StoredContext(
            context_id=ctx.context_id,
            binding=ctx.binding,
            mode=ctx.mode,
            issued_at=ctx.issued_at,
            expires_at=ctx.expires_at,
            nonce=ctx.nonce,
            consumed_at=ctx.consumed_at,
        )

    async def get(self, context_id: str) -> Optional[StoredContext]:
        """Get a context by ID."""
        ctx = self._contexts.get(context_id)
        if ctx is None:
            return None
        # Return a copy
        return StoredContext(
            context_id=ctx.context_id,
            binding=ctx.binding,
            mode=ctx.mode,
            issued_at=ctx.issued_at,
            expires_at=ctx.expires_at,
            nonce=ctx.nonce,
            consumed_at=ctx.consumed_at,
        )

    async def consume(self, context_id: str, now_ms: int) -> ConsumeResult:
        """Atomically consume a context."""
        ctx = self._contexts.get(context_id)

        if ctx is None:
            return "missing"

        if ctx.consumed_at is not None:
            return "already_consumed"

        # Mark as consumed
        ctx.consumed_at = now_ms
        return "consumed"

    async def cleanup(self) -> int:
        """Remove expired and consumed contexts."""
        now = int(time.time() * 1000)
        removed = 0

        to_remove = []
        for context_id, ctx in self._contexts.items():
            if ctx.expires_at < now or ctx.consumed_at is not None:
                to_remove.append(context_id)

        for context_id in to_remove:
            del self._contexts[context_id]
            removed += 1

        return removed

    def size(self) -> int:
        """Get current store size (for testing)."""
        return len(self._contexts)

    def clear(self) -> None:
        """Clear all contexts (for testing)."""
        self._contexts.clear()
