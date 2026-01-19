"""
Redis Context Store.

Production-ready store with atomic operations and automatic expiry.
Requires: pip install ash-protocol[redis]
"""

import json
import time
from typing import Optional, Any

from ash.core.types import StoredContext
from ash.server.types import ContextStore, ConsumeResult


class Redis(ContextStore):
    """
    Redis-backed context store for production use.

    Features:
    - Atomic consume operation via Lua script
    - Automatic expiry via Redis TTL
    - Cluster-safe operations

    Args:
        client: Redis client instance (from redis-py)
        prefix: Key prefix for ASH contexts (default: "ash:")

    Example:
        import redis
        from ash import stores

        redis_client = redis.Redis(host='localhost', port=6379, db=0)
        store = stores.Redis(redis_client)
    """

    # Lua script for atomic consume
    # Returns: 1 = consumed, 0 = already_consumed, -1 = missing
    _CONSUME_SCRIPT = """
    local key = KEYS[1]
    local now_ms = ARGV[1]

    local data = redis.call('GET', key)
    if not data then
        return -1
    end

    local ctx = cjson.decode(data)
    if ctx.consumed_at then
        return 0
    end

    ctx.consumed_at = tonumber(now_ms)
    redis.call('SET', key, cjson.encode(ctx), 'KEEPTTL')
    return 1
    """

    def __init__(self, client: Any, prefix: str = "ash:"):
        self._client = client
        self._prefix = prefix
        self._consume_sha: Optional[str] = None

    def _key(self, context_id: str) -> str:
        """Build Redis key for context."""
        return f"{self._prefix}{context_id}"

    def _serialize(self, ctx: StoredContext) -> str:
        """Serialize context to JSON."""
        return json.dumps(
            {
                "context_id": ctx.context_id,
                "binding": ctx.binding,
                "mode": ctx.mode,
                "issued_at": ctx.issued_at,
                "expires_at": ctx.expires_at,
                "nonce": ctx.nonce,
                "consumed_at": ctx.consumed_at,
            }
        )

    def _deserialize(self, data: str) -> StoredContext:
        """Deserialize context from JSON."""
        obj = json.loads(data)
        return StoredContext(
            context_id=obj["context_id"],
            binding=obj["binding"],
            mode=obj["mode"],
            issued_at=obj["issued_at"],
            expires_at=obj["expires_at"],
            nonce=obj.get("nonce"),
            consumed_at=obj.get("consumed_at"),
        )

    async def put(self, ctx: StoredContext) -> None:
        """Store a context with automatic expiry."""
        key = self._key(ctx.context_id)
        data = self._serialize(ctx)

        # Calculate TTL in milliseconds
        now = int(time.time() * 1000)
        ttl_ms = max(ctx.expires_at - now, 0)

        # Use PSETEX for millisecond precision
        self._client.psetex(key, ttl_ms, data)

    async def get(self, context_id: str) -> Optional[StoredContext]:
        """Get a context by ID."""
        key = self._key(context_id)
        data = self._client.get(key)

        if data is None:
            return None

        if isinstance(data, bytes):
            data = data.decode("utf-8")

        return self._deserialize(data)

    async def consume(self, context_id: str, now_ms: int) -> ConsumeResult:
        """Atomically consume a context using Lua script."""
        key = self._key(context_id)

        # Load script if not cached
        if self._consume_sha is None:
            self._consume_sha = self._client.script_load(self._CONSUME_SCRIPT)

        try:
            result = self._client.evalsha(self._consume_sha, 1, key, str(now_ms))
        except Exception:
            # Script not cached, reload
            self._consume_sha = self._client.script_load(self._CONSUME_SCRIPT)
            result = self._client.evalsha(self._consume_sha, 1, key, str(now_ms))

        if result == 1:
            return "consumed"
        elif result == 0:
            return "already_consumed"
        else:
            return "missing"

    async def cleanup(self) -> int:
        """
        Remove expired contexts.

        Note: Redis handles expiry automatically via TTL,
        so this is mostly a no-op. Returns 0.
        """
        return 0
