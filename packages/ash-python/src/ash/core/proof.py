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
