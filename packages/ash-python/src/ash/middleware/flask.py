"""
Flask middleware for ASH verification.

Supports ASH v2.3 unified proof features:
- Context scoping (selective field protection)
- Request chaining (workflow integrity)
- Server-side scope policies (ENH-003)
- IP binding with X-Forwarded-For support (v2.3.4)
- User binding (v2.3.4)

Configuration (via environment variables):
    ASH_TRUST_PROXY=false
    ASH_TRUSTED_PROXIES=
    ASH_TIMESTAMP_TOLERANCE=30
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING, Any, Callable, List, Optional

from ash.config.scope_policies import ash_get_scope_policy
from ash.config.settings import get_client_ip
from ash.core.canonicalize import ash_normalize_binding
from ash.core.proof import ash_normalize_scope_fields

if TYPE_CHECKING:
    from flask import Flask, Response

    from ..core import Ash


# Security constants
MAX_CONTEXT_ID_LENGTH = 256
SHA256_HEX_LENGTH = 64


def _is_production() -> bool:
    """Check if running in production environment."""
    return os.environ.get("FLASK_ENV") != "development"


def _validate_context_id(context_id: str) -> tuple[bool, str]:
    """
    Validate context_id format.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(context_id) > MAX_CONTEXT_ID_LENGTH:
        return False, f"Context ID exceeds maximum length of {MAX_CONTEXT_ID_LENGTH}"
    if not re.match(r'^[A-Za-z0-9_.\-]+$', context_id):
        return False, "Context ID contains invalid characters"
    return True, ""


def _validate_proof_format(proof: str) -> tuple[bool, str]:
    """
    Validate proof format (64 hex characters).
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(proof) != SHA256_HEX_LENGTH:
        return False, f"Proof must be exactly {SHA256_HEX_LENGTH} hex characters"
    if not re.match(r'^[0-9a-fA-F]+$', proof):
        return False, "Proof must contain only hexadecimal characters"
    return True, ""


def _validate_timestamp_freshness(timestamp: str, tolerance_seconds: int = 300) -> tuple[bool, str]:
    """
    Validate timestamp freshness.
    
    Args:
        timestamp: Timestamp string (milliseconds since epoch)
        tolerance_seconds: Maximum age in seconds (default 5 minutes)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    import time
    
    try:
        ts_ms = int(timestamp)
        ts_seconds = ts_ms / 1000.0
        now = time.time()
        
        # Check if timestamp is in the future (with 5 second clock skew tolerance)
        if ts_seconds > now + 5:
            return False, "Timestamp is in the future"
        
        # Check if timestamp is too old
        if now - ts_seconds > tolerance_seconds:
            return False, f"Timestamp is older than {tolerance_seconds} seconds"
        
        return True, ""
    except ValueError:
        return False, "Invalid timestamp format"


class AshFlaskExtension:
    """
    Flask extension for ASH verification.

    Example:
        >>> from flask import Flask
        >>> from ash import Ash, MemoryStore
        >>> from ash.middleware import AshFlaskExtension
        >>>
        >>> app = Flask(__name__)
        >>> store = MemoryStore()
        >>> ash = Ash(store)
        >>>
        >>> ash_ext = AshFlaskExtension(ash)
        >>> ash_ext.init_app(app, protected_paths=["/api/update", "/api/profile"])
        >>>
        >>> # With IP binding
        >>> ash_ext.init_app(app, protected_paths=["/api/admin"], enforce_ip=True)
        >>>
        >>> # With user binding
        >>> ash_ext.init_app(app, protected_paths=["/api/user"], enforce_user=True)
        >>>
        >>> # With unified mode enabled (for scope/chain support)
        >>> ash_ext.init_app(app, protected_paths=["/api/transfer"], enable_unified=True)
    """

    def __init__(self, ash: "Ash") -> None:
        self.ash = ash
        self.protected_paths: list[str] = []
        self.enforce_ip: bool = False
        self.enforce_user: bool = False
        self.enable_unified: bool = False

    def init_app(
        self,
        app: "Flask",
        protected_paths: list[str] | None = None,
        enforce_ip: bool = False,
        enforce_user: bool = False,
        enable_unified: bool = False,
    ) -> None:
        """
        Initialize the extension with a Flask app.
        
        Args:
            app: Flask application instance
            protected_paths: List of paths to protect (supports wildcards)
            enforce_ip: Verify IP address matches context
            enforce_user: Verify authenticated user matches context
            enable_unified: Enable v2.3 unified features (scope/chain support)
        """
        self.protected_paths = protected_paths or []
        self.enforce_ip = enforce_ip
        self.enforce_user = enforce_user
        self.enable_unified = enable_unified
        app.before_request(self._verify_request)

    def _verify_request(self) -> "Response | tuple[Response, int] | None":
        """Verify request before handling."""
        from flask import g, jsonify, request, session

        path = request.path

        # Check if path should be protected
        should_verify = any(
            path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
            for p in self.protected_paths
        )

        if not should_verify:
            return None

        # Get headers
        context_id = request.headers.get("X-ASH-Context-ID")
        proof = request.headers.get("X-ASH-Proof")
        timestamp = request.headers.get("X-ASH-Timestamp", "")
        scope_header = request.headers.get("X-ASH-Scope", "")
        scope_hash = request.headers.get("X-ASH-Scope-Hash", "")
        chain_hash = request.headers.get("X-ASH-Chain-Hash", "")

        # Parse client scope fields
        client_scope: List[str] = []
        if scope_header:
            client_scope = [s.strip() for s in scope_header.split(",") if s.strip()]

        # BUG-23 FIX: Reject scope/chain headers when unified mode is disabled
        if not self.enable_unified and (client_scope or scope_hash or chain_hash):
            return jsonify(
                error="ASH_MODE_VIOLATION",
                message="Scope/chain headers are not supported without enable_unified=True."
            ), 400

        if not context_id:
            return jsonify(
                error="ASH_CTX_NOT_FOUND",
                message="Missing X-ASH-Context-ID header",
            ), 450  # v2.3.4: Context error

        # VULN-004 FIX: Validate context_id format before store lookup
        is_valid_ctx, ctx_error = _validate_context_id(context_id)
        if not is_valid_ctx:
            return jsonify(
                error="ASH_MALFORMED_REQUEST",
                message=ctx_error,
            ), 400

        if not proof:
            return jsonify(
                error="ASH_PROOF_MISSING",
                message="Missing X-ASH-Proof header",
            ), 483  # v2.3.4: Format error

        # VULN-008 FIX: Validate proof format before store lookup
        is_valid_proof, proof_error = _validate_proof_format(proof)
        if not is_valid_proof:
            return jsonify(
                error="ASH_PROOF_INVALID",
                message=proof_error,
            ), 460

        # Normalize binding with query string
        query_string = request.query_string.decode("utf-8") if request.query_string else ""
        binding = ash_normalize_binding(request.method, path, query_string)

        # ENH-003: Check server-side scope policy
        policy_scope = ash_get_scope_policy(binding)
        has_policy_scope = len(policy_scope) > 0

        # BUG-39 FIX: If server has a scope policy but unified mode is disabled,
        # the configuration is invalid
        if has_policy_scope and not self.enable_unified:
            is_prod = _is_production()
            message = (
                "Server configuration error: unified mode required for this endpoint"
                if is_prod
                else f'Server has a scope policy for "{binding}" but enable_unified=False'
            )
            return jsonify(
                error="ASH_MODE_VIOLATION",
                message=message,
            ), 400

        # Determine effective scope
        scope = client_scope

        # ENH-003: Server-side scope policy enforcement
        if has_policy_scope:
            # If server has a policy, client MUST use it
            if not client_scope:
                return jsonify(
                    error="ASH_SCOPE_POLICY_REQUIRED",
                    message="This endpoint requires scope headers per server policy",
                    requiredScope=policy_scope,
                ), 400

            # Verify client scope matches server policy
            # BUG-POTENTIAL-001 FIX: Use ash_normalize_scope_fields for consistent sorting
            normalized_client = ash_normalize_scope_fields(client_scope)
            normalized_policy = ash_normalize_scope_fields(policy_scope)

            if normalized_client != normalized_policy:
                return jsonify(
                    error="ASH_SCOPE_POLICY_VIOLATION",
                    message="Request scope does not match server policy",
                    expected=policy_scope,
                    received=client_scope,
                ), 475  # v2.3.4: Verification error

            scope = policy_scope

        # BUG-22 FIX: Validate timestamp freshness if provided
        if timestamp:
            tolerance = int(os.environ.get("ASH_TIMESTAMP_TOLERANCE", "300"))
            is_valid_ts, ts_error = _validate_timestamp_freshness(timestamp, tolerance)
            if not is_valid_ts:
                return jsonify(
                    error="ASH_TIMESTAMP_INVALID",
                    message=ts_error,
                ), 482

        # Get payload
        payload = request.get_data(as_text=True) or ""
        content_type = request.content_type or ""

        # Verify with v2.3 options
        result = self.ash.ash_verify(
            context_id,
            proof,
            binding,
            payload,
            content_type,
            options={
                "scope": scope,
                "scopeHash": scope_hash,
                "chainHash": chain_hash,
            },
        )

        if not result.valid:
            from ..core.types import get_http_status

            error_code = result.error_code if result.error_code else "ASH_PROOF_INVALID"

            # Map specific v2.3 errors
            if scope and scope_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_SCOPE_MISMATCH"
            if chain_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_CHAIN_BROKEN"

            http_status = get_http_status(error_code)

            # VULN-010 FIX: Use generic error message in production
            is_prod = _is_production()
            if is_prod and error_code in ("ASH_BINDING_MISMATCH", "ASH_PROOF_INVALID"):
                message = "Request binding does not match context"
            else:
                message = result.error_message or "Verification failed"

            return jsonify(
                error=error_code,
                message=message,
            ), http_status

        # v2.3.4: Verify IP binding if requested
        if self.enforce_ip:
            client_ip = get_client_ip(
                request_headers=dict(request.headers),
                remote_addr=request.remote_addr
            )
            context_ip = result.metadata.get('ip') if result.metadata else None
            if context_ip and context_ip != client_ip:
                is_prod = _is_production()
                return jsonify(
                    error="ASH_BINDING_MISMATCH",
                    message="IP address mismatch" if not is_prod else "Request binding does not match context",
                ), 461  # v2.3.4: Binding mismatch

        # v2.3.4: Verify user binding if requested
        if self.enforce_user:
            # Default: look for user ID in Flask-Login style
            current_user_id = None
            if hasattr(request, 'user') and request.user:
                current_user_id = getattr(request.user, 'id', None)
            elif 'user_id' in session:
                current_user_id = session['user_id']
            
            context_user_id = result.metadata.get('user_id') if result.metadata else None
            if context_user_id is not None and str(current_user_id) != str(context_user_id):
                is_prod = _is_production()
                return jsonify(
                    error="ASH_BINDING_MISMATCH",
                    message="User mismatch" if not is_prod else "Request binding does not match context",
                ), 461  # v2.3.4: Binding mismatch

        # Store metadata in g
        g.ash_metadata = result.metadata
        g.ash_scope = scope
        g.ash_scope_policy = policy_scope
        g.ash_chain_hash = chain_hash
        g.ash_client_ip = get_client_ip(
            request_headers=dict(request.headers),
            remote_addr=request.remote_addr
        )

        return None


def ash_flask_before_request(
    ash: "Ash",
    protected_paths: list[str],
    enforce_ip: bool = False,
    enforce_user: bool = False,
    enable_unified: bool = False,
) -> Callable[[], Any]:
    """
    Create a Flask before_request handler for ASH verification.

    Example:
        >>> from flask import Flask
        >>> from ash import Ash, MemoryStore
        >>> from ash.middleware import ash_flask_before_request
        >>>
        >>> app = Flask(__name__)
        >>> store = MemoryStore()
        >>> ash = Ash(store)
        >>>
        >>> app.before_request(ash_flask_before_request(ash, ["/api/*"]))
        >>>
        >>> # With IP binding
        >>> app.before_request(ash_flask_before_request(ash, ["/api/admin"], enforce_ip=True))
        >>>
        >>> # With unified mode enabled
        >>> app.before_request(ash_flask_before_request(ash, ["/api/transfer"], enable_unified=True))
    """
    ext = AshFlaskExtension(ash)
    ext.protected_paths = protected_paths
    ext.enforce_ip = enforce_ip
    ext.enforce_user = enforce_user
    ext.enable_unified = enable_unified
    return ext._verify_request
