"""ASH Core - Canonicalization, proof generation, and utilities."""

from ash.core.canonicalize import (
    # New ASH-prefixed functions
    ash_canonicalize_json,
    ash_canonicalize_query,
    ash_canonicalize_url_encoded,
    ash_normalize_binding,
    ash_normalize_binding_from_url,
    # Deprecated aliases
    canonicalize_json,
    canonicalize_query,
    canonicalize_url_encoded,
    normalize_binding,
    normalize_binding_from_url,
)
from ash.core.compare import (
    # New ASH-prefixed function
    ash_timing_safe_equal,
    # Deprecated alias
    timing_safe_compare,
)
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
    # New ASH-prefixed functions
    ash_base64url_decode,
    ash_base64url_encode,
    ash_build_proof,
    ash_build_proof_hmac,
    ash_build_proof_scoped,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_extract_scoped_fields,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_hash_proof,
    ash_hash_scoped_body,
    ash_join_scope_fields,
    ash_normalize_scope_fields,
    ash_verify_proof,
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
    # Deprecated aliases
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
    join_scope_fields,
    normalize_scope_fields,
    verify_proof_unified,
    verify_proof_v21,
    verify_proof_v21_scoped,
)
from ash.core.secure_memory import (
    SecureBytes,
    SecureString,
    secure_derive_client_secret,
    secure_zero_memory,
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
    # Canonicalization - New ASH-prefixed functions
    "ash_canonicalize_json",
    "ash_canonicalize_query",
    "ash_canonicalize_url_encoded",
    "ash_normalize_binding",
    "ash_normalize_binding_from_url",
    # Canonicalization - Deprecated aliases
    "canonicalize_json",
    "canonicalize_query",
    "canonicalize_url_encoded",
    "normalize_binding",
    "normalize_binding_from_url",
    # Proof - Constants
    "ASH_VERSION_PREFIX",
    "ASH_VERSION_PREFIX_V21",
    # Proof - New ASH-prefixed functions
    "ash_base64url_decode",
    "ash_base64url_encode",
    "ash_build_proof",
    "ash_build_proof_hmac",
    "ash_build_proof_scoped",
    "ash_build_proof_unified",
    "ash_derive_client_secret",
    "ash_extract_scoped_fields",
    "ash_generate_context_id",
    "ash_generate_nonce",
    "ash_hash_body",
    "ash_hash_proof",
    "ash_hash_scoped_body",
    "ash_join_scope_fields",
    "ash_normalize_scope_fields",
    "ash_verify_proof",
    "ash_verify_proof_scoped",
    "ash_verify_proof_unified",
    # Proof - Deprecated aliases
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
    "join_scope_fields",
    "normalize_scope_fields",
    "verify_proof_unified",
    "verify_proof_v21",
    "verify_proof_v21_scoped",
    # Compare - New ASH-prefixed function
    "ash_timing_safe_equal",
    # Compare - Deprecated alias
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
    # Secure Memory
    "secure_zero_memory",
    "SecureBytes",
    "SecureString",
    "secure_derive_client_secret",
]
