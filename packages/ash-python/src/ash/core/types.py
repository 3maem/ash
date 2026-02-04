"""ASH Protocol Core Types."""

from dataclasses import dataclass
from typing import Literal, Optional

# Security modes for ASH protocol
AshMode = Literal["minimal", "balanced", "strict"]

# Error codes returned by ASH verification (v2.3.4 unified specification)
AshErrorCode = Literal[
    "ASH_CTX_NOT_FOUND",
    "ASH_CTX_EXPIRED",
    "ASH_CTX_ALREADY_USED",
    "ASH_PROOF_INVALID",
    "ASH_BINDING_MISMATCH",
    "ASH_SCOPE_MISMATCH",
    "ASH_CHAIN_BROKEN",
    "ASH_TIMESTAMP_INVALID",
    "ASH_PROOF_MISSING",
    "ASH_CANONICALIZATION_ERROR",
    "ASH_MODE_VIOLATION",
    "ASH_UNSUPPORTED_CONTENT_TYPE",
    "ASH_VALIDATION_ERROR",
]


def get_http_status(code: AshErrorCode) -> int:
    """Get the recommended HTTP status code for an ASH error code.

    v2.3.4: Uses unique HTTP status codes in the 450-499 range for ASH-specific errors.
    This enables precise error identification, better monitoring, and targeted retry logic.

    Error Categories:
    - 450-459: Context errors
    - 460-469: Seal/Proof errors
    - 461, 473-479: Binding/Verification errors
    - 480-489: Format/Protocol errors

    Args:
        code: The ASH error code string.

    Returns:
        The recommended HTTP status code.
    """
    status_map = {
        # Context errors (450-459)
        "ASH_CTX_NOT_FOUND": 450,
        "ASH_CTX_EXPIRED": 451,
        "ASH_CTX_ALREADY_USED": 452,
        # Seal/Proof errors (460-469)
        "ASH_PROOF_INVALID": 460,
        # Verification errors (461, 473-479)
        "ASH_BINDING_MISMATCH": 461,
        "ASH_SCOPE_MISMATCH": 473,
        "ASH_CHAIN_BROKEN": 474,
        # Format/Protocol errors (480-489)
        "ASH_TIMESTAMP_INVALID": 482,
        "ASH_PROOF_MISSING": 483,
        # Standard HTTP codes (preserved for semantic clarity)
        "ASH_CANONICALIZATION_ERROR": 422,
        "ASH_MODE_VIOLATION": 400,
        "ASH_UNSUPPORTED_CONTENT_TYPE": 415,
        "ASH_VALIDATION_ERROR": 400,
    }
    return status_map.get(code, 500)

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
