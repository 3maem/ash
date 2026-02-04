"""
ASH Protocol Proof Generation.

Deterministic hash-based integrity proof.
Same inputs MUST produce identical proof across all implementations.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import warnings
from typing import Any

from ash.core.canonicalize import ash_canonicalize_json
from ash.core.errors import ValidationError
from ash.core.types import BuildProofInput

# ASH protocol version prefix
ASH_VERSION_PREFIX = "ASHv1"

# Scope field delimiter for hashing (using U+001F unit separator to avoid collision).
# BUG-002: Prevents collision when field names contain commas.
# Must match Rust ash-core SCOPE_FIELD_DELIMITER.
SCOPE_FIELD_DELIMITER = "\x1F"

# =========================================================================
# Security Constants (Must match Rust ash-core)
# =========================================================================

# Minimum hex characters for nonce in derive_client_secret.
# SEC-014: Ensures adequate entropy (32 hex chars = 16 bytes = 128 bits).
MIN_NONCE_HEX_CHARS = 32

# Maximum nonce length.
# SEC-NONCE-001: Limits nonce beyond minimum entropy requirement.
MAX_NONCE_LENGTH = 128

# Maximum context_id length.
# SEC-CTX-001: Limits context_id to reasonable size for headers and storage.
MAX_CONTEXT_ID_LENGTH = 256

# Maximum binding length.
# SEC-AUDIT-004: Prevents DoS via extremely long bindings.
MAX_BINDING_LENGTH = 8192  # 8KB

# Pattern for valid context_id characters (alphanumeric, underscore, hyphen, dot)
CONTEXT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_.\-]+$')


def ash_normalize_scope_fields(scope: list[str]) -> list[str]:
    """
    Normalize scope fields by sorting and deduplicating.

    BUG-023: Ensures deterministic scope hash across all SDKs.

    Args:
        scope: List of field paths

    Returns:
        Sorted and deduplicated scope list
    """
    # Deduplicate using set, then sort lexicographically
    return sorted(set(scope))


def ash_join_scope_fields(scope: list[str]) -> str:
    """
    Join scope fields with the proper delimiter after normalization.

    BUG-002, BUG-023: Uses unit separator and normalizes for cross-SDK compatibility.

    Args:
        scope: List of field paths

    Returns:
        Joined scope string
    """
    normalized = ash_normalize_scope_fields(scope)
    return SCOPE_FIELD_DELIMITER.join(normalized)


def ash_build_proof(input_data: BuildProofInput) -> str:
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
    return ash_base64url_encode(hash_bytes)


def ash_base64url_encode(data: bytes) -> str:
    """
    Encode bytes as Base64URL (no padding).

    RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ash_base64url_decode(input_str: str) -> bytes:
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

ASH_VERSION_PREFIX_V21 = "ASHv2.1"


def ash_generate_nonce(bytes_count: int = 32) -> str:
    """
    Generate a cryptographically secure random nonce.

    Args:
        bytes_count: Number of bytes (default 32)

    Returns:
        Hex-encoded nonce (64 chars for 32 bytes)
    """
    return secrets.token_hex(bytes_count)


def ash_generate_context_id() -> str:
    """
    Generate a unique context ID with "ash_" prefix.

    Returns:
        Context ID string
    """
    return "ash_" + secrets.token_hex(16)


def ash_derive_client_secret(nonce: str, context_id: str, binding: str) -> str:
    """
    Derive client secret from server nonce (v2.1).

    SECURITY PROPERTIES:
    - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
    - Context-bound: Unique per contextId + binding combination
    - Safe to expose: Client can use it but cannot forge other contexts

    Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)

    Args:
        nonce: Server-side secret nonce (minimum 32 hex chars for adequate entropy)
        context_id: Context identifier (alphanumeric, underscore, hyphen, dot only)
        binding: Request binding (e.g., "POST|/login|")

    Returns:
        Derived client secret (64 hex chars)

    Raises:
        ValidationError: If any input fails validation:
            - nonce has fewer than 32 hex characters (SEC-014: weak key material)
            - nonce exceeds 128 characters (SEC-NONCE-001: DoS prevention)
            - nonce contains non-hexadecimal characters (BUG-004: invalid format)
            - context_id is empty (BUG-041: ambiguous context)
            - context_id exceeds 256 characters (SEC-CTX-001: DoS prevention)
            - context_id contains invalid characters (SEC-CTX-001)
            - binding exceeds 8KB (SEC-AUDIT-004: DoS prevention)
    """
    # SEC-014: Validate nonce has sufficient entropy
    if len(nonce) < MIN_NONCE_HEX_CHARS:
        raise ValidationError(
            f"nonce must be at least {MIN_NONCE_HEX_CHARS} hex characters "
            f"({MIN_NONCE_HEX_CHARS // 2} bytes) for adequate entropy"
        )

    # SEC-NONCE-001: Validate nonce doesn't exceed maximum length
    if len(nonce) > MAX_NONCE_LENGTH:
        raise ValidationError(
            f"nonce exceeds maximum length of {MAX_NONCE_LENGTH} characters"
        )

    # BUG-004: Validate nonce is valid hexadecimal
    try:
        int(nonce, 16)
    except ValueError:
        raise ValidationError(
            "nonce must contain only hexadecimal characters (0-9, a-f, A-F)"
        )

    # BUG-041: Validate context_id is not empty
    if not context_id:
        raise ValidationError("context_id cannot be empty")

    # SEC-CTX-001: Validate context_id doesn't exceed maximum length
    if len(context_id) > MAX_CONTEXT_ID_LENGTH:
        raise ValidationError(
            f"context_id exceeds maximum length of {MAX_CONTEXT_ID_LENGTH} characters"
        )

    # SEC-CTX-001: Validate context_id contains only allowed characters
    if not CONTEXT_ID_PATTERN.match(context_id):
        raise ValidationError(
            "context_id must contain only ASCII alphanumeric characters, "
            "underscore, hyphen, or dot"
        )

    # SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
    if len(binding) > MAX_BINDING_LENGTH:
        raise ValidationError(
            f"binding exceeds maximum length of {MAX_BINDING_LENGTH} bytes"
        )

    message = f"{context_id}|{binding}"
    return hmac.new(
        nonce.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def ash_build_proof_hmac(client_secret: str, timestamp: str, binding: str, body_hash: str) -> str:
    """
    Build cryptographic proof using HMAC (client-side).

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


def ash_verify_proof(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    body_hash: str,
    client_proof: str
) -> bool:
    """
    Verify proof (server-side).

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
    client_secret = ash_derive_client_secret(nonce, context_id, binding)

    # Compute expected proof
    expected_proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

    # Constant-time comparison
    return hmac.compare_digest(expected_proof, client_proof)


def ash_hash_body(canonical_body: str) -> str:
    """
    Compute SHA-256 hash of canonical body.

    Args:
        canonical_body: Canonicalized request body

    Returns:
        SHA-256 hash (64 hex chars)
    """
    return hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()


# =========================================================================
# ASH v2.2 - Context Scoping (Selective Field Protection)
# =========================================================================

def ash_extract_scoped_fields(payload: dict[str, Any], scope: list[str]) -> dict[str, Any]:
    """
    Extract scoped fields from a payload dictionary.

    Args:
        payload: Full payload dictionary
        scope: List of field paths (supports dot notation)

    Returns:
        Dictionary containing only scoped fields
    """
    if not scope:
        return payload

    result: dict[str, Any] = {}
    for field_path in scope:
        value = _get_nested_value(payload, field_path)
        if value is not None:
            _set_nested_value(result, field_path, value)
    return result


def _get_nested_value(obj: dict[str, Any], path: str) -> Any:
    """Get a nested value using dot notation."""
    keys = path.split(".")
    current: Any = obj

    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]

    return current


def _set_nested_value(obj: dict[str, Any], path: str, value: Any) -> None:
    """Set a nested value using dot notation."""
    keys = path.split(".")
    current: Any = obj

    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value


def ash_build_proof_scoped(
    client_secret: str,
    timestamp: str,
    binding: str,
    payload: dict[str, Any],
    scope: list[str],
) -> tuple[str, str]:
    """
    Build proof with scoped fields.

    Args:
        client_secret: Derived client secret
        timestamp: Request timestamp (milliseconds)
        binding: Request binding
        payload: Full payload dictionary
        scope: Fields to protect (empty = all)

    Returns:
        Tuple of (proof, scope_hash)
    """
    # BUG-023: Normalize scope for deterministic ordering
    normalized_scope = ash_normalize_scope_fields(scope)
    scoped_payload = ash_extract_scoped_fields(payload, normalized_scope)
    canonical_scoped = ash_canonicalize_json(scoped_payload)
    body_hash = ash_hash_body(canonical_scoped)

    # BUG-002, BUG-023: Use unit separator and normalized scope
    scope_str = ash_join_scope_fields(scope)
    scope_hash = ash_hash_body(scope_str)

    message = f"{timestamp}|{binding}|{body_hash}|{scope_hash}"
    proof = hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return proof, scope_hash


def ash_verify_proof_scoped(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    payload: dict[str, Any],
    scope: list[str],
    scope_hash: str,
    client_proof: str,
) -> bool:
    """
    Verify proof with scoped fields.

    Returns:
        True if proof is valid
    """
    # BUG-002, BUG-023: Verify scope hash with unit separator and normalization
    scope_str = ash_join_scope_fields(scope)
    expected_scope_hash = ash_hash_body(scope_str)
    if not hmac.compare_digest(expected_scope_hash, scope_hash):
        return False

    client_secret = ash_derive_client_secret(nonce, context_id, binding)
    expected_proof, _ = ash_build_proof_scoped(
        client_secret, timestamp, binding, payload, scope
    )

    return hmac.compare_digest(expected_proof, client_proof)


def ash_hash_scoped_body(payload: dict[str, Any], scope: list[str]) -> str:
    """
    Hash scoped payload fields.

    Args:
        payload: Full payload dictionary
        scope: Fields to hash

    Returns:
        SHA-256 hash of scoped fields
    """
    scoped_payload = ash_extract_scoped_fields(payload, scope)
    canonical = ash_canonicalize_json(scoped_payload)
    return ash_hash_body(canonical)


# =========================================================================
# ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
# =========================================================================


def ash_hash_proof(proof: str) -> str:
    """
    Hash a proof for chaining purposes.

    Args:
        proof: Proof to hash

    Returns:
        SHA-256 hash of the proof (64 hex chars)
    """
    return hashlib.sha256(proof.encode("utf-8")).hexdigest()


def ash_build_proof_unified(
    client_secret: str,
    timestamp: str,
    binding: str,
    payload: dict[str, Any],
    scope: list[str] | None = None,
    previous_proof: str | None = None,
) -> tuple[str, str, str]:
    """
    Build unified cryptographic proof with optional scoping and chaining.

    Formula:
        scopeHash  = len(scope) > 0 ? SHA256(sorted(scope).join("\\x1F")) : ""
        bodyHash   = SHA256(canonicalize(scopedPayload))
        chainHash  = previous_proof ? SHA256(previous_proof) : ""
        proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)

    Args:
        client_secret: Derived client secret
        timestamp: Request timestamp (milliseconds)
        binding: Request binding
        payload: Full payload dictionary
        scope: Fields to protect (None/empty = full payload)
        previous_proof: Previous proof in chain (None = no chaining)

    Returns:
        Tuple of (proof, scope_hash, chain_hash)
    """
    if scope is None:
        scope = []

    # BUG-023: Normalize scope for deterministic ordering
    normalized_scope = ash_normalize_scope_fields(scope) if scope else []

    # Extract and hash scoped payload
    scoped_payload = ash_extract_scoped_fields(payload, normalized_scope)
    canonical_scoped = ash_canonicalize_json(scoped_payload)
    body_hash = ash_hash_body(canonical_scoped)

    # BUG-002, BUG-023: Compute scope hash with unit separator and normalization
    scope_hash = ash_hash_body(ash_join_scope_fields(scope)) if scope else ""

    # Compute chain hash (empty string if no previous proof)
    chain_hash = ash_hash_proof(previous_proof) if previous_proof else ""

    # Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
    message = f"{timestamp}|{binding}|{body_hash}|{scope_hash}|{chain_hash}"
    proof = hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return proof, scope_hash, chain_hash


def ash_verify_proof_unified(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    payload: dict[str, Any],
    client_proof: str,
    scope: list[str] | None = None,
    scope_hash: str = "",
    previous_proof: str | None = None,
    chain_hash: str = "",
) -> bool:
    """
    Verify unified proof with optional scoping and chaining.

    Args:
        nonce: Server-side secret nonce
        context_id: Context identifier
        binding: Request binding
        timestamp: Request timestamp
        payload: Full payload dictionary
        client_proof: Proof received from client
        scope: Fields that were protected (None/empty = full payload)
        scope_hash: Scope hash from client (empty if no scoping)
        previous_proof: Previous proof in chain (None if no chaining)
        chain_hash: Chain hash from client (empty if no chaining)

    Returns:
        True if proof is valid
    """
    if scope is None:
        scope = []

    # SEC-013: Validate consistency - scope_hash must be empty when scope is empty
    if not scope and scope_hash:
        return False

    # BUG-002, BUG-023: Validate scope hash with unit separator and normalization
    if scope:
        expected_scope_hash = ash_hash_body(ash_join_scope_fields(scope))
        if not hmac.compare_digest(expected_scope_hash, scope_hash):
            return False

    # SEC-013: Validate consistency - chain_hash must be empty when previous_proof is absent
    if not previous_proof and chain_hash:
        return False

    # Validate chain hash if chaining is used
    if previous_proof:
        expected_chain_hash = ash_hash_proof(previous_proof)
        if not hmac.compare_digest(expected_chain_hash, chain_hash):
            return False

    # Derive client secret and compute expected proof
    client_secret = ash_derive_client_secret(nonce, context_id, binding)
    expected_proof, _, _ = ash_build_proof_unified(
        client_secret, timestamp, binding, payload, scope, previous_proof
    )

    return hmac.compare_digest(expected_proof, client_proof)


# =========================================================================
# Deprecated Aliases for Backward Compatibility
# =========================================================================

def normalize_scope_fields(scope: list[str]) -> list[str]:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_normalize_scope_fields` instead.
    """
    warnings.warn(
        "normalize_scope_fields is deprecated, use ash_normalize_scope_fields instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_normalize_scope_fields(scope)


def join_scope_fields(scope: list[str]) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_join_scope_fields` instead.
    """
    warnings.warn(
        "join_scope_fields is deprecated, use ash_join_scope_fields instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_join_scope_fields(scope)


def build_proof(input_data: BuildProofInput) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_build_proof` instead.
    """
    warnings.warn(
        "build_proof is deprecated, use ash_build_proof instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_build_proof(input_data)


def base64url_encode(data: bytes) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_base64url_encode` instead.
    """
    warnings.warn(
        "base64url_encode is deprecated, use ash_base64url_encode instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_base64url_encode(data)


def base64url_decode(input_str: str) -> bytes:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_base64url_decode` instead.
    """
    warnings.warn(
        "base64url_decode is deprecated, use ash_base64url_decode instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_base64url_decode(input_str)


def generate_nonce(bytes_count: int = 32) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_generate_nonce` instead.
    """
    warnings.warn(
        "generate_nonce is deprecated, use ash_generate_nonce instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_generate_nonce(bytes_count)


def generate_context_id() -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_generate_context_id` instead.
    """
    warnings.warn(
        "generate_context_id is deprecated, use ash_generate_context_id instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_generate_context_id()


def derive_client_secret(nonce: str, context_id: str, binding: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_derive_client_secret` instead.
    """
    warnings.warn(
        "derive_client_secret is deprecated, use ash_derive_client_secret instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_derive_client_secret(nonce, context_id, binding)


def build_proof_v21(client_secret: str, timestamp: str, binding: str, body_hash: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_build_proof_hmac` instead.
    """
    warnings.warn(
        "build_proof_v21 is deprecated, use ash_build_proof_hmac instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)


def verify_proof_v21(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    body_hash: str,
    client_proof: str
) -> bool:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_verify_proof` instead.
    """
    warnings.warn(
        "verify_proof_v21 is deprecated, use ash_verify_proof instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, client_proof)


def hash_body(canonical_body: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_hash_body` instead.
    """
    warnings.warn(
        "hash_body is deprecated, use ash_hash_body instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_hash_body(canonical_body)


def extract_scoped_fields(payload: dict[str, Any], scope: list[str]) -> dict[str, Any]:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_extract_scoped_fields` instead.
    """
    warnings.warn(
        "extract_scoped_fields is deprecated, use ash_extract_scoped_fields instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_extract_scoped_fields(payload, scope)


def build_proof_v21_scoped(
    client_secret: str,
    timestamp: str,
    binding: str,
    payload: dict[str, Any],
    scope: list[str],
) -> tuple[str, str]:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_build_proof_scoped` instead.
    """
    warnings.warn(
        "build_proof_v21_scoped is deprecated, use ash_build_proof_scoped instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_build_proof_scoped(client_secret, timestamp, binding, payload, scope)


def verify_proof_v21_scoped(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    payload: dict[str, Any],
    scope: list[str],
    scope_hash: str,
    client_proof: str,
) -> bool:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_verify_proof_scoped` instead.
    """
    warnings.warn(
        "verify_proof_v21_scoped is deprecated, use ash_verify_proof_scoped instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_verify_proof_scoped(
        nonce, context_id, binding, timestamp, payload, scope, scope_hash, client_proof
    )


def hash_scoped_body(payload: dict[str, Any], scope: list[str]) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_hash_scoped_body` instead.
    """
    warnings.warn(
        "hash_scoped_body is deprecated, use ash_hash_scoped_body instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_hash_scoped_body(payload, scope)


def hash_proof(proof: str) -> str:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_hash_proof` instead.
    """
    warnings.warn(
        "hash_proof is deprecated, use ash_hash_proof instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_hash_proof(proof)


def build_proof_unified(
    client_secret: str,
    timestamp: str,
    binding: str,
    payload: dict[str, Any],
    scope: list[str] | None = None,
    previous_proof: str | None = None,
) -> tuple[str, str, str]:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_build_proof_unified` instead.
    """
    warnings.warn(
        "build_proof_unified is deprecated, use ash_build_proof_unified instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_build_proof_unified(
        client_secret, timestamp, binding, payload, scope, previous_proof
    )


def verify_proof_unified(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    payload: dict[str, Any],
    client_proof: str,
    scope: list[str] | None = None,
    scope_hash: str = "",
    previous_proof: str | None = None,
    chain_hash: str = "",
) -> bool:
    """
    .. deprecated:: 2.4.0
        Use :func:`ash_verify_proof_unified` instead.
    """
    warnings.warn(
        "verify_proof_unified is deprecated, use ash_verify_proof_unified instead",
        DeprecationWarning,
        stacklevel=2
    )
    return ash_verify_proof_unified(
        nonce, context_id, binding, timestamp, payload, client_proof,
        scope, scope_hash, previous_proof, chain_hash
    )
