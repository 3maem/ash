"""
Proof generation and verification.
"""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core import AshMode

ASH_VERSION = "ASHv1"


def ash_build_proof(
    mode: "AshMode",
    binding: str,
    context_id: str,
    nonce: str | None,
    canonical_payload: str,
) -> str:
    """
    Build a cryptographic proof for request integrity.

    The proof is computed as:
        proof = BASE64URL(SHA256(
            "ASHv1\\n" +
            mode + "\\n" +
            binding + "\\n" +
            contextId + "\\n" +
            (nonce + "\\n" if present) +
            canonicalPayload
        ))

    Args:
        mode: Security mode
        binding: Canonical binding (e.g., "POST /api/update")
        context_id: Context ID from server
        nonce: Optional nonce for server-assisted mode
        canonical_payload: Canonicalized payload string

    Returns:
        Base64URL-encoded proof string

    Example:
        >>> from ash import AshMode
        >>> proof = ash_build_proof(
        ...     AshMode.BALANCED,
        ...     "POST /api/update",
        ...     "ctx_abc123",
        ...     None,
        ...     '{"name":"John"}'
        ... )
    """
    # Build the proof input string
    parts = [
        ASH_VERSION,
        mode.value,
        binding,
        context_id,
    ]

    if nonce is not None:
        parts.append(nonce)

    input_str = "\n".join(parts) + "\n" + canonical_payload

    # Handle the case where there's no nonce - adjust the format
    if nonce is None:
        input_str = (
            f"{ASH_VERSION}\n{mode.value}\n{binding}\n{context_id}\n{canonical_payload}"
        )
    else:
        input_str = (
            f"{ASH_VERSION}\n{mode.value}\n{binding}\n"
            f"{context_id}\n{nonce}\n{canonical_payload}"
        )

    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(input_str.encode("utf-8")).digest()

    # Encode as Base64URL without padding
    return base64.urlsafe_b64encode(hash_bytes).rstrip(b"=").decode("ascii")


def ash_verify_proof(expected: str, actual: str) -> bool:
    """
    Verify that two proofs match using constant-time comparison.

    Args:
        expected: Expected proof (computed by server)
        actual: Actual proof (received from client)

    Returns:
        True if proofs match, False otherwise
    """
    from .compare import ash_timing_safe_equal

    return ash_timing_safe_equal(expected, actual)
