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
    ASH_VERSION_PREFIX,
    ASH_VERSION_PREFIX_V21,
    base64url_decode,
    base64url_encode,
    build_proof,
    build_proof_unified,
    build_proof_v21,
    build_proof_v21_scoped,
    derive_client_secret,
    extract_scoped_fields,
    generate_context_id,
    generate_nonce,
    hash_body,
    hash_proof,
    hash_scoped_body,
    verify_proof_unified,
    verify_proof_v21,
    verify_proof_v21_scoped,
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
    "ASH_VERSION_PREFIX",
    "ASH_VERSION_PREFIX_V21",
    "base64url_decode",
    "base64url_encode",
    "build_proof",
    "build_proof_unified",
    "build_proof_v21",
    "build_proof_v21_scoped",
    "derive_client_secret",
    "extract_scoped_fields",
    "generate_context_id",
    "generate_nonce",
    "hash_body",
    "hash_proof",
    "hash_scoped_body",
    "verify_proof_unified",
    "verify_proof_v21",
    "verify_proof_v21_scoped",
    # Compare
    "timing_safe_compare",
    # Errors
    "AshError",
    "CanonicalizationError",
    "ContextExpiredError",
    "EndpointMismatchError",
    "IntegrityFailedError",
    "InvalidContextError",
    "ReplayDetectedError",
    "UnsupportedContentTypeError",
    # Types
    "AshErrorCode",
    "AshMode",
    "BuildProofInput",
    "ContextPublicInfo",
    "StoredContext",
    "SupportedContentType",
]
