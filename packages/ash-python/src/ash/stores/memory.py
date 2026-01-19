"""
In-memory context store.
"""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING, Any

from .base import ContextStore

if TYPE_CHECKING:
    from ..core import AshContext, AshMode


class MemoryStore(ContextStore):
    """
    In-memory implementation of ContextStore.

    Suitable for development and single-process deployments.
    For production with multiple workers, use Redis or SQL store.

    Example:
        >>> store = MemoryStore()
        >>> from ash import AshMode
        >>> ctx = store.create("POST /api/update", 30000, AshMode.BALANCED, {})
        >>> print(ctx.id)
    """

    def __init__(self) -> None:
        self._contexts: dict[str, "AshContext"] = {}

    def create(
        self,
        binding: str,
        ttl_ms: int,
        mode: "AshMode",
        metadata: dict[str, Any],
    ) -> "AshContext":
        """Create a new context."""
        from ..core import AshContext, AshMode

        context_id = f"ctx_{secrets.token_hex(16)}"
        nonce = secrets.token_hex(16) if mode == AshMode.STRICT else None

        context = AshContext(
            id=context_id,
            binding=binding,
            expires_at=self._timestamp_ms() + ttl_ms,
            mode=mode,
            used=False,
            nonce=nonce,
            metadata=metadata,
        )

        self._contexts[context_id] = context
        return context

    def get(self, context_id: str) -> "AshContext | None":
        """Get a context by ID."""
        context = self._contexts.get(context_id)

        if context is None:
            return None

        # Check expiration
        if context.is_expired():
            del self._contexts[context_id]
            return None

        return context

    def consume(self, context_id: str) -> bool:
        """Consume a context."""
        context = self.get(context_id)

        if context is None:
            return False

        if context.used:
            return False

        context.used = True
        return True

    def cleanup(self) -> int:
        """Remove expired contexts."""
        now = self._timestamp_ms()
        expired = [
            ctx_id
            for ctx_id, ctx in self._contexts.items()
            if now > ctx.expires_at
        ]

        for ctx_id in expired:
            del self._contexts[ctx_id]

        return len(expired)

    def size(self) -> int:
        """Get the number of active contexts."""
        return len(self._contexts)

    def clear(self) -> None:
        """Clear all contexts."""
        self._contexts.clear()

    def _timestamp_ms(self) -> int:
        """Get current timestamp in milliseconds."""
        return int(time.time() * 1000)
