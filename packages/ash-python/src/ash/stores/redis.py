"""
Redis context store.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import TYPE_CHECKING, Any

from .base import ContextStore

if TYPE_CHECKING:
    from ..core import AshContext, AshMode


class RedisStore(ContextStore):
    """
    Redis implementation of ContextStore.

    Production-ready store for distributed deployments.

    Example:
        >>> import redis
        >>> client = redis.Redis()
        >>> store = RedisStore(client)
    """

    def __init__(
        self,
        client: Any,  # redis.Redis or compatible
        key_prefix: str = "ash:ctx:",
    ) -> None:
        """
        Create a new Redis store.

        Args:
            client: Redis client instance
            key_prefix: Key prefix for context keys
        """
        self._client = client
        self._key_prefix = key_prefix

    def _key(self, context_id: str) -> str:
        """Generate Redis key for context ID."""
        return f"{self._key_prefix}{context_id}"

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

        # Store with TTL (add 1 second buffer)
        ttl_seconds = (ttl_ms // 1000) + 1

        self._client.setex(
            self._key(context_id),
            ttl_seconds,
            json.dumps(context.to_dict()),
        )

        return context

    def get(self, context_id: str) -> "AshContext | None":
        """Get a context by ID."""
        from ..core import AshContext

        data = self._client.get(self._key(context_id))

        if data is None:
            return None

        if isinstance(data, bytes):
            data = data.decode("utf-8")

        context = AshContext.from_dict(json.loads(data))

        # Double-check expiration
        if context.is_expired():
            self._client.delete(self._key(context_id))
            return None

        return context

    def consume(self, context_id: str) -> bool:
        """Consume a context."""
        context = self.get(context_id)

        if context is None:
            return False

        if context.used:
            return False

        # Mark as used
        context.used = True

        # Calculate remaining TTL
        remaining_ms = context.expires_at - self._timestamp_ms()
        remaining_seconds = max(1, remaining_ms // 1000)

        self._client.setex(
            self._key(context_id),
            remaining_seconds,
            json.dumps(context.to_dict()),
        )

        return True

    def cleanup(self) -> int:
        """Cleanup is handled by Redis TTL."""
        return 0

    def _timestamp_ms(self) -> int:
        """Get current timestamp in milliseconds."""
        return int(time.time() * 1000)
