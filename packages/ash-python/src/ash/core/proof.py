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


# =========================================================================
# ASH v2.2 - Context Scoping (Selective Field Protection)
# =========================================================================

def extract_scoped_fields(payload: dict, scope: list[str]) -> dict:
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

    result = {}
    for field_path in scope:
        value = _get_nested_value(payload, field_path)
        if value is not None:
            _set_nested_value(result, field_path, value)
    return result


def _get_nested_value(obj: dict, path: str):
    """Get a nested value using dot notation."""
    keys = path.split(".")
    current = obj

    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]

    return current


def _set_nested_value(obj: dict, path: str, value) -> None:
    """Set a nested value using dot notation."""
    keys = path.split(".")
    current = obj

    for i, key in enumerate(keys[:-1]):
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value


def build_proof_v21_scoped(
    client_secret: str,
    timestamp: str,
    binding: str,
    payload: dict,
    scope: list[str],
) -> tuple[str, str]:
    """
    Build v2.2 proof with scoped fields.

    Args:
        client_secret: Derived client secret
        timestamp: Request timestamp (milliseconds)
        binding: Request binding
        payload: Full payload dictionary
        scope: Fields to protect (empty = all)

    Returns:
        Tuple of (proof, scope_hash)
    """
    import json

    scoped_payload = extract_scoped_fields(payload, scope)
    canonical_scoped = json.dumps(scoped_payload, separators=(",", ":"), sort_keys=True)
    body_hash = hash_body(canonical_scoped)

    scope_str = ",".join(scope)
    scope_hash = hash_body(scope_str)

    message = f"{timestamp}|{binding}|{body_hash}|{scope_hash}"
    proof = hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return proof, scope_hash


def verify_proof_v21_scoped(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    payload: dict,
    scope: list[str],
    scope_hash: str,
    client_proof: str,
) -> bool:
    """
    Verify v2.2 proof with scoped fields.

    Returns:
        True if proof is valid
    """
    # Verify scope hash
    scope_str = ",".join(scope)
    expected_scope_hash = hash_body(scope_str)
    if not hmac.compare_digest(expected_scope_hash, scope_hash):
        return False

    client_secret = derive_client_secret(nonce, context_id, binding)
    expected_proof, _ = build_proof_v21_scoped(
        client_secret, timestamp, binding, payload, scope
    )

    return hmac.compare_digest(expected_proof, client_proof)


def hash_scoped_body(payload: dict, scope: list[str]) -> str:
    """
    Hash scoped payload fields.

    Args:
        payload: Full payload dictionary
        scope: Fields to hash

    Returns:
        SHA-256 hash of scoped fields
    """
    import json

    scoped_payload = extract_scoped_fields(payload, scope)
    canonical = json.dumps(scoped_payload, separators=(",", ":"), sort_keys=True)
    return hash_body(canonical)


# =========================================================================
# ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
# =========================================================================


def hash_proof(proof: str) -> str:
    """
    Hash a proof for chaining purposes.

    Args:
        proof: Proof to hash

    Returns:
        SHA-256 hash of the proof (64 hex chars)
    """
    return hashlib.sha256(proof.encode("utf-8")).hexdigest()


def build_proof_unified(
    client_secret: str,
    timestamp: str,
    binding: str,
    payload: dict,
    scope: list[str] | None = None,
    previous_proof: str | None = None,
) -> tuple[str, str, str]:
    """
    Build unified v2.3 cryptographic proof with optional scoping and chaining.

    Formula:
        scopeHash  = len(scope) > 0 ? SHA256(scope.join(",")) : ""
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
    import json

    if scope is None:
        scope = []

    # Extract and hash scoped payload
    scoped_payload = extract_scoped_fields(payload, scope)
    canonical_scoped = json.dumps(scoped_payload, separators=(",", ":"), sort_keys=True)
    body_hash = hash_body(canonical_scoped)

    # Compute scope hash (empty string if no scope)
    scope_hash = hash_body(",".join(scope)) if scope else ""

    # Compute chain hash (empty string if no previous proof)
    chain_hash = hash_proof(previous_proof) if previous_proof else ""

    # Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
    message = f"{timestamp}|{binding}|{body_hash}|{scope_hash}|{chain_hash}"
    proof = hmac.new(
        client_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return proof, scope_hash, chain_hash


def verify_proof_unified(
    nonce: str,
    context_id: str,
    binding: str,
    timestamp: str,
    payload: dict,
    client_proof: str,
    scope: list[str] | None = None,
    scope_hash: str = "",
    previous_proof: str | None = None,
    chain_hash: str = "",
) -> bool:
    """
    Verify unified v2.3 proof with optional scoping and chaining.

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

    # Validate scope hash if scoping is used
    if scope:
        expected_scope_hash = hash_body(",".join(scope))
        if not hmac.compare_digest(expected_scope_hash, scope_hash):
            return False

    # Validate chain hash if chaining is used
    if previous_proof:
        expected_chain_hash = hash_proof(previous_proof)
        if not hmac.compare_digest(expected_chain_hash, chain_hash):
            return False

    # Derive client secret and compute expected proof
    client_secret = derive_client_secret(nonce, context_id, binding)
    expected_proof, _, _ = build_proof_unified(
        client_secret, timestamp, binding, payload, scope, previous_proof
    )

    return hmac.compare_digest(expected_proof, client_proof)
