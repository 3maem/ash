"""
ASH - Authenticity & Stateless Hardening Protocol

A cryptographic protocol for tamper-proof, replay-resistant API requests.

Example:
    from ash import context, stores, middleware

    store = stores.Memory()

    # Issue context
    ctx = context.create(store, binding="POST /api/update", ttl_ms=30000)

    # Flask middleware
    @app.route("/api/update", methods=["POST"])
    @middleware.flask(store, expected_binding="POST /api/update")
    def update():
        return {"status": "ok"}
"""

from ash.core import (
    AshError,
    CanonicalizationError,
    ContextExpiredError,
    EndpointMismatchError,
    IntegrityFailedError,
    InvalidContextError,
    ReplayDetectedError,
    UnsupportedContentTypeError,
    build_proof,
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
    timing_safe_compare,
)
from ash.server import context, middleware, stores, verify

__version__ = "2.3.1"
__author__ = "3maem"

__all__ = [
    # Core functions
    "canonicalize_json",
    "canonicalize_url_encoded",
    "normalize_binding",
    "build_proof",
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
    # Server modules
    "context",
    "stores",
    "middleware",
    "verify",
]
