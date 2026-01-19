"""
ASH Protocol Proof Generation.

Deterministic hash-based integrity proof.
Same inputs MUST produce identical proof across all implementations.
"""

import base64
import hashlib

from ash.core.types import BuildProofInput

# ASH protocol version prefix
ASH_VERSION_PREFIX = "ASHv1"


def build_proof(input_data: BuildProofInput) -> str:
    """
    Build a deterministic proof from the given inputs.

    Proof structure (from ASH-Spec-v1.0):
        proof = SHA256(
          "ASHv1" + "\\n" +
          mode + "\\n" +
          binding + "\\n" +
          contextId + "\\n" +
          (nonce? + "\\n" : "") +
          canonicalPayload
        )

    Output: Base64URL encoded (no padding)

    Args:
        input_data: Proof input parameters

    Returns:
        Base64URL encoded proof string
    """
    # Build the proof input string
    proof_input = (
        f"{ASH_VERSION_PREFIX}\n"
        f"{input_data.mode}\n"
        f"{input_data.binding}\n"
        f"{input_data.context_id}\n"
    )

    # Add nonce if present (server-assisted mode)
    if input_data.nonce is not None and input_data.nonce != "":
        proof_input += f"{input_data.nonce}\n"

    # Add canonical payload
    proof_input += input_data.canonical_payload

    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(proof_input.encode("utf-8")).digest()

    # Encode as Base64URL (no padding)
    return base64url_encode(hash_bytes)


def base64url_encode(data: bytes) -> str:
    """
    Encode bytes as Base64URL (no padding).

    RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(input_str: str) -> bytes:
    """
    Decode a Base64URL string to bytes.

    Handles both padded and unpadded input.
    """
    # Add padding if needed
    pad_length = (4 - len(input_str) % 4) % 4
    input_str += "=" * pad_length
    return base64.urlsafe_b64decode(input_str)


# =========================================================================
# ASH v2.1 - Derived Client Secret & Cryptographic Proof
# =========================================================================

import hmac
import secrets

ASH_VERSION_PREFIX_V21 = "ASHv2.1"


def generate_nonce(bytes_count: int = 32) -> str:
    """
    Generate a cryptographically secure random nonce.

    Args:
        bytes_count: Number of bytes (default 32)

    Returns:
        Hex-encoded nonce (64 chars for 32 bytes)
    """
    return secrets.token_hex(bytes_count)


def generate_context_id() -> str:
    """
    Generate a unique context ID with "ash_" prefix.

    Returns:
        Context ID string
    """
    return "ash_" + secrets.token_hex(16)


def derive_client_secret(nonce: str, context_id: str, binding: str) -> str:
    """
    Derive client secret from server nonce (v2.1).

    SECURITY PROPERTIES:
    - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
    - Context-bound: Unique per contextId + binding combination
    - Safe to expose: Client can use it but cannot forge other contexts

    Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)

    Args:
        nonce: Server-side secret nonce (64 hex chars)
        context_id: Context identifier
        binding: Request binding (e.g., "POST /login")

    Returns:
        Derived client secret (64 hex chars)
    """
    message = f"{context_id}|{binding}"
    return hmac.new(
        nonce.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def build_proof_v21(client_secret: str, timestamp: str, binding: str, body_hash: str) -> str:
    """
    Build v2.1 cryptographic proof (client-side).

    Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)

    Args:
        client_secret: Derived client secret
        timestamp: Request timestamp (milliseconds as string)
        binding: Request binding (e.g., "POST /login")
        body_hash: SHA-256 hash of canonical request body

    Returns:
        Proof (64 hex chars)
    """
    message = f"{timestamp}|{binding}|{body_hash}"
    return hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_proof_v21(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    body_hash: str,
    client_proof: str
) -> bool:
    """
    Verify v2.1 proof (server-side).

    Args:
        nonce: Server-side secret nonce
        context_id: Context identifier
        binding: Request binding
        timestamp: Request timestamp
        body_hash: SHA-256 hash of canonical body
        client_proof: Proof received from client

    Returns:
        True if proof is valid
    """
    # Derive the same client secret server-side
    client_secret = derive_client_secret(nonce, context_id, binding)

    # Compute expected proof
    expected_proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

    # Constant-time comparison
    return hmac.compare_digest(expected_proof, client_proof)


def hash_body(canonical_body: str) -> str:
    """
    Compute SHA-256 hash of canonical body.

    Args:
        canonical_body: Canonicalized request body

    Returns:
        SHA-256 hash (64 hex chars)
    """
    return hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()
