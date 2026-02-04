"""
ASH Context Management.

Server-side context issuance for request verification.
"""

import secrets
import time
from typing import Optional

from ash.core.types import AshMode, ContextPublicInfo, StoredContext
from ash.server.types import ContextStore, CreateContextOptions

# Default context configuration
DEFAULT_MODE: AshMode = "balanced"
CONTEXT_ID_BYTES = 16  # 128 bits
NONCE_BYTES = 16  # 128 bits


def _generate_secure_id(num_bytes: int) -> str:
    """Generate a cryptographically secure random ID using CSPRNG."""
    return secrets.token_hex(num_bytes)


async def create(
    store: ContextStore,
    binding: str,
    ttl_ms: int,
    mode: AshMode = DEFAULT_MODE,
    issue_nonce: bool = False,
) -> ContextPublicInfo:
    """
    Create a new verification context.

    Args:
        store: The context store to use
        binding: Endpoint binding (e.g., "POST /api/update")
        ttl_ms: Time-to-live in milliseconds
        mode: Security mode (default: "balanced")
        issue_nonce: Whether to issue a server nonce

    Returns:
        Public context info to return to client

    Example:
        ctx = await ash.context.create(
            store,
            binding="POST /api/update",
            ttl_ms=30000,
        )
        return jsonify(ctx.__dict__)
    """
    options = CreateContextOptions(
        binding=binding,
        ttl_ms=ttl_ms,
        mode=mode,
        issue_nonce=issue_nonce,
    )
    return await create_context(store, options)


async def create_context(
    store: ContextStore,
    options: CreateContextOptions,
) -> ContextPublicInfo:
    """
    Create a new verification context with options object.

    Args:
        store: The context store to use
        options: Context creation options

    Returns:
        Public context info to return to client
    """
    now = int(time.time() * 1000)  # Current time in milliseconds

    # Generate unpredictable context ID (128-bit CSPRNG)
    context_id = _generate_secure_id(CONTEXT_ID_BYTES)

    # Generate nonce if requested (server-assisted mode)
    nonce = _generate_secure_id(NONCE_BYTES) if options.issue_nonce else None

    # Build stored context
    stored_context = StoredContext(
        context_id=context_id,
        binding=options.binding,
        mode=options.mode,
        issued_at=now,
        expires_at=now + options.ttl_ms,
        nonce=nonce,
        consumed_at=None,
    )

    # Store context
    await store.put(stored_context)

    # Return only public info
    return ContextPublicInfo(
        context_id=context_id,
        expires_at=stored_context.expires_at,
        mode=options.mode,
        nonce=nonce,
    )


async def get(store: ContextStore, context_id: str) -> Optional[StoredContext]:
    """
    Get a context by ID.

    Args:
        store: The context store
        context_id: Context ID to look up

    Returns:
        Stored context or None if not found
    """
    return await store.get(context_id)
