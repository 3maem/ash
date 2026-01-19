"""ASH Protocol Core Types."""

from dataclasses import dataclass
from typing import Literal, Optional

# Security modes for ASH protocol
AshMode = Literal["minimal", "balanced", "strict"]

# Error codes returned by ASH verification
AshErrorCode = Literal[
    "ASH_INVALID_CONTEXT",
    "ASH_CONTEXT_EXPIRED",
    "ASH_REPLAY_DETECTED",
    "ASH_INTEGRITY_FAILED",
    "ASH_ENDPOINT_MISMATCH",
    "ASH_MODE_VIOLATION",
    "ASH_UNSUPPORTED_CONTENT_TYPE",
    "ASH_MALFORMED_REQUEST",
    "ASH_CANONICALIZATION_FAILED",
]

# Supported content types
SupportedContentType = Literal["application/json", "application/x-www-form-urlencoded"]


@dataclass
class StoredContext:
    """Context as stored on server."""

    context_id: str
    """Unique context identifier (CSPRNG)."""

    binding: str
    """Canonical binding: 'METHOD /path'."""

    mode: AshMode
    """Security mode."""

    issued_at: int
    """Timestamp when context was issued (ms epoch)."""

    expires_at: int
    """Timestamp when context expires (ms epoch)."""

    nonce: Optional[str] = None
    """Optional nonce for server-assisted mode."""

    consumed_at: Optional[int] = None
    """Timestamp when context was consumed (None if not consumed)."""


@dataclass
class ContextPublicInfo:
    """Public context info returned to client."""

    context_id: str
    """Opaque context ID."""

    expires_at: int
    """Expiration timestamp (ms epoch)."""

    mode: AshMode
    """Security mode."""

    nonce: Optional[str] = None
    """Optional nonce (if server-assisted mode)."""


@dataclass
class BuildProofInput:
    """Input for building a proof."""

    mode: AshMode
    """ASH mode."""

    binding: str
    """Canonical binding: 'METHOD /path'."""

    context_id: str
    """Server-issued context ID."""

    canonical_payload: str
    """Canonicalized payload string."""

    nonce: Optional[str] = None
    """Optional server-issued nonce."""
