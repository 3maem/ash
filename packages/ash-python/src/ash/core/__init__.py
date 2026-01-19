"""ASH Core - Canonicalization, proof generation, and utilities."""

from ash.core.canonicalize import (
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
)
from ash.core.compare import timing_safe_compare
from ash.core.errors import (
    AshError,
    CanonicalizationError,
    ContextExpiredError,
    EndpointMismatchError,
    IntegrityFailedError,
    InvalidContextError,
    ReplayDetectedError,
    UnsupportedContentTypeError,
)
from ash.core.proof import (
    extract_scoped_fields,
    build_proof_v21_scoped,
    verify_proof_v21_scoped,
    hash_scoped_body,
    base64url_decode,
    base64url_encode,
    build_proof,
    build_proof_v21,
    derive_client_secret,
    generate_context_id,
    generate_nonce,
    hash_body,
    verify_proof_v21,
    # v2.3 unified functions
    build_proof_unified,
    verify_proof_unified,
    hash_proof,
)
from ash.core.types import (
    AshErrorCode,
    AshMode,
    BuildProofInput,
    ContextPublicInfo,
    StoredContext,
    SupportedContentType,
)

__all__ = [
    # Canonicalization
    "canonicalize_json",
    "canonicalize_url_encoded",
    "normalize_binding",
    # Proof
    "build_proof",
    "base64url_encode",
    "base64url_decode",
    # v2.1 functions
    "generate_nonce",
    "generate_context_id",
    "derive_client_secret",
    "build_proof_v21",
    "verify_proof_v21",
    "hash_body",
    # v2.2 scoped functions
    "extract_scoped_fields",
    "build_proof_v21_scoped",
    "verify_proof_v21_scoped",
    "hash_scoped_body",
    # v2.3 unified functions
    "build_proof_unified",
    "verify_proof_unified",
    "hash_proof",
    # Compare
    "timing_safe_compare",
    # Errors
    "AshError",
    "InvalidContextError",
    "ContextExpiredError",
    "ReplayDetectedError",
    "IntegrityFailedError",
    "EndpointMismatchError",
    "CanonicalizationError",
    "UnsupportedContentTypeError",
    # Types
    "AshMode",
    "AshErrorCode",
    "StoredContext",
    "ContextPublicInfo",
    "BuildProofInput",
    "SupportedContentType",
]
