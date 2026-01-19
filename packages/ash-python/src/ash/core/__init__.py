"""ASH Core - Canonicalization, proof generation, and utilities."""

from ash.core.canonicalize import (
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
)
from ash.core.proof import build_proof, base64url_encode, base64url_decode
from ash.core.compare import timing_safe_compare
from ash.core.errors import (
    AshError,
    InvalidContextError,
    ContextExpiredError,
    ReplayDetectedError,
    IntegrityFailedError,
    EndpointMismatchError,
    CanonicalizationError,
    UnsupportedContentTypeError,
)
from ash.core.types import (
    AshMode,
    AshErrorCode,
    StoredContext,
    ContextPublicInfo,
    BuildProofInput,
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
