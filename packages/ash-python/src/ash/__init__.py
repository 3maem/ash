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
    ASH_VERSION_PREFIX,
    ASH_VERSION_PREFIX_V21,
    AshError,
    CanonicalizationError,
    ContextExpiredError,
    EndpointMismatchError,
    IntegrityFailedError,
    InvalidContextError,
    ReplayDetectedError,
    UnsupportedContentTypeError,
    # New ASH-prefixed functions
    ash_build_proof,
    ash_canonicalize_json,
    ash_canonicalize_url_encoded,
    ash_normalize_binding,
    ash_timing_safe_equal,
    # Deprecated aliases
    build_proof,
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
    timing_safe_compare,
)
from ash.server import context, middleware, stores, verify
from ash.config.settings import get_client_ip, get_config

__version__ = "2.3.4"
__author__ = "3maem"

__all__ = [
    # Version constants
    "ASH_VERSION_PREFIX",
    "ASH_VERSION_PREFIX_V21",
    # Core functions - New ASH-prefixed
    "ash_canonicalize_json",
    "ash_canonicalize_url_encoded",
    "ash_normalize_binding",
    "ash_build_proof",
    "ash_timing_safe_equal",
    # Core functions - Deprecated aliases
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
    # Config functions
    "get_client_ip",
    "get_config",
]
