"""
FastAPI middleware for ASH verification.

Supports ASH v2.3 unified proof features:
- Context scoping (selective field protection)
- Request chaining (workflow integrity)
- Server-side scope policies (ENH-003)
- IP binding with X-Forwarded-For support (v2.3.4)
- User binding (v2.3.4)
- Timestamp validation (v2.3.4)
- Input validation (v2.3.4)
- Production-safe error messages (v2.3.4)

Configuration (via environment variables):
    ASH_TRUST_PROXY=false
    ASH_TRUSTED_PROXIES=
    ASH_TIMESTAMP_TOLERANCE=30
    ASH_ENABLE_DETAILED_ERRORS=false
"""

from __future__ import annotations

import os
import re
import time
from typing import TYPE_CHECKING, Any, Callable, List, Optional

from ash.config.scope_policies import ash_get_scope_policy
from ash.config.settings import get_client_ip, get_config
from ash.core.canonicalize import ash_normalize_binding
from ash.core.proof import (
    ash_normalize_scope_fields,
    ash_hash_body,
    ash_join_scope_fields,
    CONTEXT_ID_PATTERN,
    MAX_CONTEXT_ID_LENGTH,
)
from ash.core.types import get_http_status

if TYPE_CHECKING:
    from ..core import Ash


# Proof format: 64 hex characters for HMAC-SHA256
PROOF_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
# Scope hash: 64 hex characters
SCOPE_HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
# Chain hash: 64 hex characters
CHAIN_HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
# Timestamp: milliseconds since epoch (13-14 digits)
TIMESTAMP_PATTERN = re.compile(r'^\d{13,14}$')


def _is_production() -> bool:
    """Check if running in production environment."""
    env = os.environ.get('ASH_ENV', os.environ.get('ENV', 'development')).lower()
    return env in ('production', 'prod', 'staging', 'live')


def _get_safe_error_message(
    error_code: str,
    detailed_message: str,
    is_production: bool | None = None
) -> str:
    """Get production-safe error message."""
    if is_production is None:
        is_production = _is_production()
    
    if not is_production:
        return detailed_message
    
    # Production-safe messages (don't leak implementation details)
    safe_messages = {
        "ASH_CTX_NOT_FOUND": "Request context not found",
        "ASH_CTX_EXPIRED": "Request context has expired",
        "ASH_CTX_ALREADY_USED": "Request context already used",
        "ASH_PROOF_INVALID": "Proof verification failed",
        "ASH_BINDING_MISMATCH": "Request binding mismatch",
        "ASH_SCOPE_MISMATCH": "Scope verification failed",
        "ASH_CHAIN_BROKEN": "Chain verification failed",
        "ASH_TIMESTAMP_INVALID": "Invalid request timestamp",
        "ASH_PROOF_MISSING": "Missing proof",
        "ASH_SCOPE_POLICY_REQUIRED": "Scope policy required",
        "ASH_SCOPE_POLICY_VIOLATION": "Scope policy violation",
        "ASH_VALIDATION_ERROR": "Invalid request",
        "ASH_CANONICALIZATION_ERROR": "Request processing error",
        "ASH_UNSUPPORTED_CONTENT_TYPE": "Unsupported content type",
    }
    return safe_messages.get(error_code, "Request verification failed")


def _validate_context_id(context_id: str) -> tuple[bool, str]:
    """
    Validate context ID format.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not context_id:
        return False, "Context ID is required"
    
    if len(context_id) > MAX_CONTEXT_ID_LENGTH:
        return False, f"Context ID exceeds maximum length of {MAX_CONTEXT_ID_LENGTH}"
    
    if not CONTEXT_ID_PATTERN.match(context_id):
        return False, "Context ID contains invalid characters"
    
    return True, ""


def _validate_proof(proof: str) -> tuple[bool, str]:
    """
    Validate proof format (64 hex characters for HMAC-SHA256).
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not proof:
        return False, "Proof is required"
    
    if not PROOF_PATTERN.match(proof):
        return False, "Proof must be 64 hexadecimal characters"
    
    return True, ""


def _validate_timestamp(timestamp: str, tolerance_sec: int | None = None) -> tuple[bool, str]:
    """
    Validate timestamp format and freshness.
    
    Args:
        timestamp: Timestamp string (milliseconds since epoch)
        tolerance_sec: Tolerance in seconds (default from config)
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not timestamp:
        return True, ""  # Timestamp is optional
    
    if not TIMESTAMP_PATTERN.match(timestamp):
        return False, "Timestamp must be milliseconds since epoch"
    
    try:
        ts_ms = int(timestamp)
    except ValueError:
        return False, "Invalid timestamp format"
    
    # Check freshness
    now_ms = int(time.time() * 1000)
    if tolerance_sec is None:
        tolerance_sec = get_config().timestamp_tolerance
    tolerance_ms = tolerance_sec * 1000
    
    if ts_ms > now_ms + tolerance_ms:
        return False, "Timestamp is in the future"
    
    if ts_ms < now_ms - tolerance_ms:
        return False, "Timestamp has expired"
    
    return True, ""


def _validate_scope_hash(scope_hash: str) -> tuple[bool, str]:
    """Validate scope hash format."""
    if not scope_hash:
        return True, ""  # Optional
    
    if not SCOPE_HASH_PATTERN.match(scope_hash):
        return False, "Scope hash must be 64 hexadecimal characters"
    
    return True, ""


def _validate_chain_hash(chain_hash: str) -> tuple[bool, str]:
    """Validate chain hash format."""
    if not chain_hash:
        return True, ""  # Optional
    
    if not CHAIN_HASH_PATTERN.match(chain_hash):
        return False, "Chain hash must be 64 hexadecimal characters"
    
    return True, ""


class AshFastAPIMiddleware:
    """
    FastAPI/Starlette middleware for ASH verification.

    Supports v2.3 unified proof features including scoping, chaining,
    server-side scope policies, IP binding, and user binding.

    Example:
        >>> from fastapi import FastAPI
        >>> from ash import Ash, MemoryStore
        >>> from ash.middleware import AshFastAPIMiddleware
        >>>
        >>> app = FastAPI()
        >>> store = MemoryStore()
        >>> ash = Ash(store)
        >>>
        >>> app.add_middleware(
        ...     AshFastAPIMiddleware,
        ...     ash=ash,
        ...     protected_paths=["/api/update", "/api/profile"],
        ... )
        >>>
        >>> # With IP binding
        >>> app.add_middleware(
        ...     AshFastAPIMiddleware,
        ...     ash=ash,
        ...     protected_paths=["/api/admin"],
        ...     enforce_ip=True,
        ... )
        >>>
        >>> # With user binding
        >>> app.add_middleware(
        ...     AshFastAPIMiddleware,
        ...     ash=ash,
        ...     protected_paths=["/api/user"],
        ...     enforce_user=True,
        ... )
        >>>
        >>> # With unified proof features disabled
        >>> app.add_middleware(
        ...     AshFastAPIMiddleware,
        ...     ash=ash,
        ...     protected_paths=["/api/secure"],
        ...     enable_unified=False,
        ... )
    """

    def __init__(
        self,
        app: Callable[..., Any],
        ash: "Ash",
        protected_paths: list[str] | None = None,
        enforce_ip: bool = False,
        enforce_user: bool = False,
        enable_unified: bool = True,
    ) -> None:
        """
        Initialize the middleware.

        Args:
            app: ASGI application
            ash: Ash instance for verification
            protected_paths: List of paths to protect (supports wildcards with *)
            enforce_ip: Verify IP address matches context metadata
            enforce_user: Verify authenticated user matches context metadata
            enable_unified: Enable v2.3 unified proof features (scope, chain)
        """
        self.app = app
        self.ash = ash
        self.protected_paths = protected_paths or []
        self.enforce_ip = enforce_ip
        self.enforce_user = enforce_user
        self.enable_unified = enable_unified

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Any],
        send: Callable[..., Any],
    ) -> None:
        """ASGI application entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive)
        path = request.url.path

        # Check if path should be protected
        should_verify = any(
            path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
            for p in self.protected_paths
        )

        if not should_verify:
            await self.app(scope, receive, send)
            return

        # Get all 6 ASH headers (v2.3 unified proof)
        context_id = request.headers.get("x-ash-context-id")
        proof = request.headers.get("x-ash-proof")
        timestamp = request.headers.get("x-ash-timestamp", "")
        scope_header = request.headers.get("x-ash-scope", "")
        scope_hash = request.headers.get("x-ash-scope-hash", "")
        chain_hash = request.headers.get("x-ash-chain-hash", "")

        is_production = _is_production()

        # Validate required headers
        if not context_id:
            response = JSONResponse(
                {
                    "error": "ASH_CTX_NOT_FOUND",
                    "message": _get_safe_error_message(
                        "ASH_CTX_NOT_FOUND",
                        "Missing X-ASH-Context-ID header",
                        is_production
                    ),
                },
                status_code=450,  # v2.3.4: Context error
            )
            await response(scope, receive, send)
            return

        # Validate context ID format before store lookup
        is_valid, validation_error = _validate_context_id(context_id)
        if not is_valid:
            response = JSONResponse(
                {
                    "error": "ASH_VALIDATION_ERROR",
                    "message": _get_safe_error_message(
                        "ASH_VALIDATION_ERROR",
                        validation_error,
                        is_production
                    ),
                },
                status_code=400,
            )
            await response(scope, receive, send)
            return

        if not proof:
            response = JSONResponse(
                {
                    "error": "ASH_PROOF_MISSING",
                    "message": _get_safe_error_message(
                        "ASH_PROOF_MISSING",
                        "Missing X-ASH-Proof header",
                        is_production
                    ),
                },
                status_code=483,  # v2.3.4: Format error
            )
            await response(scope, receive, send)
            return

        # Validate proof format
        is_valid, validation_error = _validate_proof(proof)
        if not is_valid:
            response = JSONResponse(
                {
                    "error": "ASH_VALIDATION_ERROR",
                    "message": _get_safe_error_message(
                        "ASH_VALIDATION_ERROR",
                        validation_error,
                        is_production
                    ),
                },
                status_code=400,
            )
            await response(scope, receive, send)
            return

        # Validate timestamp if provided
        if timestamp:
            is_valid, validation_error = _validate_timestamp(timestamp)
            if not is_valid:
                response = JSONResponse(
                    {
                        "error": "ASH_TIMESTAMP_INVALID",
                        "message": _get_safe_error_message(
                            "ASH_TIMESTAMP_INVALID",
                            validation_error,
                            is_production
                        ),
                    },
                    status_code=482,  # v2.3.4: Timestamp error
                )
                await response(scope, receive, send)
                return

        # Validate scope/chain hashes format if provided
        if scope_hash:
            is_valid, validation_error = _validate_scope_hash(scope_hash)
            if not is_valid:
                response = JSONResponse(
                    {
                        "error": "ASH_VALIDATION_ERROR",
                        "message": _get_safe_error_message(
                            "ASH_VALIDATION_ERROR",
                            validation_error,
                            is_production
                        ),
                    },
                    status_code=400,
                )
                await response(scope, receive, send)
                return

        if chain_hash:
            is_valid, validation_error = _validate_chain_hash(chain_hash)
            if not is_valid:
                response = JSONResponse(
                    {
                        "error": "ASH_VALIDATION_ERROR",
                        "message": _get_safe_error_message(
                            "ASH_VALIDATION_ERROR",
                            validation_error,
                            is_production
                        ),
                    },
                    status_code=400,
                )
                await response(scope, receive, send)
                return

        # Reject unified proof headers if disabled
        if not self.enable_unified:
            if scope_header or scope_hash or chain_hash:
                response = JSONResponse(
                    {
                        "error": "ASH_VALIDATION_ERROR",
                        "message": _get_safe_error_message(
                            "ASH_VALIDATION_ERROR",
                            "Unified proof features disabled for this endpoint",
                            is_production
                        ),
                    },
                    status_code=400,
                )
                await response(scope, receive, send)
                return

        # Normalize binding with query string
        query_string = str(request.url.query) if request.url.query else ""
        binding = ash_normalize_binding(request.method, path, query_string)

        # ENH-003: Check server-side scope policy
        policy_scope = ash_get_scope_policy(binding)
        has_policy_scope = len(policy_scope) > 0

        # Parse client scope fields
        client_scope: List[str] = []
        if scope_header:
            client_scope = [s.strip() for s in scope_header.split(",") if s.strip()]

        # Determine effective scope
        scope = client_scope

        # ENH-003: Server-side scope policy enforcement
        if has_policy_scope:
            # If server has a policy, client MUST use it
            if not client_scope:
                response = JSONResponse(
                    {
                        "error": "ASH_SCOPE_POLICY_REQUIRED",
                        "message": _get_safe_error_message(
                            "ASH_SCOPE_POLICY_REQUIRED",
                            "This endpoint requires scope headers per server policy",
                            is_production
                        ),
                        "requiredScope": policy_scope,
                    },
                    status_code=400,
                )
                await response(scope, receive, send)
                return

            # Verify client scope matches server policy using byte-wise sorting
            sorted_client = ash_normalize_scope_fields(client_scope)
            sorted_policy = ash_normalize_scope_fields(policy_scope)

            if sorted_client != sorted_policy:
                response = JSONResponse(
                    {
                        "error": "ASH_SCOPE_POLICY_VIOLATION",
                        "message": _get_safe_error_message(
                            "ASH_SCOPE_POLICY_VIOLATION",
                            "Request scope does not match server policy",
                            is_production
                        ),
                        "expected": policy_scope,
                        "received": client_scope,
                    },
                    status_code=475,  # v2.3.4: Verification error
                )
                await response(scope, receive, send)
                return

            scope = policy_scope

        # Verify scope hash if client provided scope
        if scope and scope_hash:
            expected_scope_hash = ash_hash_body(ash_join_scope_fields(scope))
            if expected_scope_hash != scope_hash:
                response = JSONResponse(
                    {
                        "error": "ASH_SCOPE_MISMATCH",
                        "message": _get_safe_error_message(
                            "ASH_SCOPE_MISMATCH",
                            "Scope hash mismatch",
                            is_production
                        ),
                    },
                    status_code=473,  # v2.3.4: Scope error
                )
                await response(scope, receive, send)
                return

        # Get payload
        body = await request.body()
        payload = body.decode("utf-8") if body else ""
        content_type = request.headers.get("content-type", "")

        # Verify with v2.3 options
        verify_options: dict[str, Any] = {
            "scope": scope,
            "scopeHash": scope_hash,
            "chainHash": chain_hash,
        }
        
        # Add timestamp if provided
        if timestamp:
            verify_options["timestamp"] = timestamp

        result = self.ash.ash_verify(
            context_id,
            proof,
            binding,
            payload,
            content_type,
            options=verify_options,
        )

        if not result.valid:
            error_code = result.error_code if result.error_code else "ASH_PROOF_INVALID"
            http_status = get_http_status(error_code)

            # Map specific v2.3 errors
            if scope and scope_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_SCOPE_MISMATCH"
                    http_status = 473
            if chain_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_CHAIN_BROKEN"
                    http_status = 474

            response = JSONResponse(
                {
                    "error": error_code,
                    "message": _get_safe_error_message(
                        error_code,
                        result.error_message or "Verification failed",
                        is_production
                    ),
                },
                status_code=http_status,
            )
            await response(scope, receive, send)
            return

        # v2.3.4: Verify IP binding if requested
        if self.enforce_ip:
            client_ip = get_client_ip(
                request_headers=dict(request.headers),
                remote_addr=scope.get("client", [None])[0] if isinstance(scope.get("client"), (list, tuple)) else None
            )
            context_ip = result.metadata.get('ip') if result.metadata else None
            if context_ip and context_ip != client_ip:
                response = JSONResponse(
                    {
                        "error": "ASH_BINDING_MISMATCH",
                        "message": _get_safe_error_message(
                            "ASH_BINDING_MISMATCH",
                            "IP address mismatch",
                            is_production
                        ),
                    },
                    status_code=461,  # v2.3.4: Binding mismatch
                )
                await response(scope, receive, send)
                return

        # v2.3.4: Verify user binding if requested
        if self.enforce_user:
            # Default: look for user ID in request state or headers
            current_user_id = None
            
            # Try to get from request state (set by auth middleware)
            if hasattr(request, 'state') and hasattr(request.state, 'user_id'):
                current_user_id = request.state.user_id
            # Try to get from user header (custom header pattern)
            elif request.headers.get('x-user-id'):
                current_user_id = request.headers.get('x-user-id')
            
            context_user_id = result.metadata.get('user_id') if result.metadata else None
            if context_user_id is not None and str(current_user_id) != str(context_user_id):
                response = JSONResponse(
                    {
                        "error": "ASH_BINDING_MISMATCH",
                        "message": _get_safe_error_message(
                            "ASH_BINDING_MISMATCH",
                            "User mismatch",
                            is_production
                        ),
                    },
                    status_code=461,  # v2.3.4: Binding mismatch
                )
                await response(scope, receive, send)
                return

        # Store metadata in request state
        scope["state"] = scope.get("state", {})
        scope["state"]["ash_metadata"] = result.metadata
        scope["state"]["ash_scope"] = scope
        scope["state"]["ash_scope_policy"] = policy_scope
        scope["state"]["ash_chain_hash"] = chain_hash
        scope["state"]["ash_client_ip"] = get_client_ip(
            request_headers=dict(request.headers),
            remote_addr=scope.get("client", [None])[0] if isinstance(scope.get("client"), (list, tuple)) else None
        )

        await self.app(scope, receive, send)


def ash_fastapi_depends(
    ash: "Ash",
    expected_binding: str | None = None,
    enforce_ip: bool = False,
    enforce_user: bool = False,
    enable_unified: bool = True,
) -> Callable[..., Any]:
    """
    FastAPI dependency for ASH verification.

    Supports v2.3 unified proof features including scoping, chaining,
    IP binding, user binding, and timestamp validation.

    Example:
        >>> from fastapi import FastAPI, Depends
        >>> from ash import Ash, MemoryStore
        >>> from ash.middleware import ash_fastapi_depends
        >>>
        >>> app = FastAPI()
        >>> store = MemoryStore()
        >>> ash_instance = Ash(store)
        >>>
        >>> @app.post("/api/update")
        ... async def update(
        ...     request: Request,
        ...     _: None = Depends(ash_fastapi_depends(ash_instance, "POST|/api/update|"))
        ... ):
        ...     return {"success": True}
        >>>
        >>> # With IP binding
        >>> @app.post("/api/admin")
        ... async def admin(
        ...     request: Request,
        ...     _: None = Depends(ash_fastapi_depends(ash_instance, enforce_ip=True))
        ... ):
        ...     return {"success": True}
    """
    from fastapi import HTTPException

    async def verify(request: Any) -> None:
        # Get all 6 ASH headers (v2.3 unified proof)
        context_id = request.headers.get("x-ash-context-id")
        proof = request.headers.get("x-ash-proof")
        timestamp = request.headers.get("x-ash-timestamp", "")
        scope_header = request.headers.get("x-ash-scope", "")
        scope_hash = request.headers.get("x-ash-scope-hash", "")
        chain_hash = request.headers.get("x-ash-chain-hash", "")

        is_production = _is_production()

        if not context_id:
            raise HTTPException(
                status_code=450,
                detail=_get_safe_error_message(
                    "ASH_CTX_NOT_FOUND",
                    "Missing X-ASH-Context-ID header",
                    is_production
                )
            )

        # Validate context ID format
        is_valid, _ = _validate_context_id(context_id)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=_get_safe_error_message(
                    "ASH_VALIDATION_ERROR",
                    "Invalid context ID format",
                    is_production
                )
            )

        if not proof:
            raise HTTPException(
                status_code=483,
                detail=_get_safe_error_message(
                    "ASH_PROOF_MISSING",
                    "Missing X-ASH-Proof header",
                    is_production
                )
            )

        # Validate proof format
        is_valid, _ = _validate_proof(proof)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=_get_safe_error_message(
                    "ASH_VALIDATION_ERROR",
                    "Invalid proof format",
                    is_production
                )
            )

        # Validate timestamp if provided
        if timestamp:
            is_valid, _ = _validate_timestamp(timestamp)
            if not is_valid:
                raise HTTPException(
                    status_code=482,
                    detail=_get_safe_error_message(
                        "ASH_TIMESTAMP_INVALID",
                        "Invalid timestamp",
                        is_production
                    )
                )

        # Reject unified proof headers if disabled
        if not enable_unified:
            if scope_header or scope_hash or chain_hash:
                raise HTTPException(
                    status_code=400,
                    detail=_get_safe_error_message(
                        "ASH_VALIDATION_ERROR",
                        "Unified proof features disabled",
                        is_production
                    )
                )

        # Include query string in binding normalization
        query_string = str(request.url.query) if request.url.query else ""
        binding = expected_binding or ash_normalize_binding(
            request.method, request.url.path, query_string
        )

        # ENH-003: Check server-side scope policy
        policy_scope = ash_get_scope_policy(binding)
        has_policy_scope = len(policy_scope) > 0

        # Parse client scope fields
        client_scope: List[str] = []
        if scope_header:
            client_scope = [s.strip() for s in scope_header.split(",") if s.strip()]

        scope = client_scope

        # ENH-003: Server-side scope policy enforcement
        if has_policy_scope:
            if not client_scope:
                raise HTTPException(
                    status_code=400,
                    detail=_get_safe_error_message(
                        "ASH_SCOPE_POLICY_REQUIRED",
                        "This endpoint requires scope headers per server policy",
                        is_production
                    )
                )

            # Verify client scope matches server policy using byte-wise sorting
            sorted_client = ash_normalize_scope_fields(client_scope)
            sorted_policy = ash_normalize_scope_fields(policy_scope)

            if sorted_client != sorted_policy:
                raise HTTPException(
                    status_code=475,
                    detail=_get_safe_error_message(
                        "ASH_SCOPE_POLICY_VIOLATION",
                        "Request scope does not match server policy",
                        is_production
                    )
                )

            scope = policy_scope

        body = await request.body()
        payload = body.decode("utf-8") if body else ""
        content_type = request.headers.get("content-type", "")

        # Verify with v2.3 options
        verify_options: dict[str, Any] = {
            "scope": scope,
            "scopeHash": scope_hash,
            "chainHash": chain_hash,
        }
        
        if timestamp:
            verify_options["timestamp"] = timestamp

        result = ash.ash_verify(
            context_id,
            proof,
            binding,
            payload,
            content_type,
            options=verify_options,
        )

        if not result.valid:
            error_code = result.error_code if result.error_code else "ASH_PROOF_INVALID"
            http_status = get_http_status(error_code)
            
            # Map specific v2.3 errors
            if scope and scope_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_SCOPE_MISMATCH"
                    http_status = 473
            if chain_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_CHAIN_BROKEN"
                    http_status = 474

            raise HTTPException(
                status_code=http_status,
                detail=_get_safe_error_message(
                    error_code,
                    result.error_message or "Verification failed",
                    is_production
                )
            )

        # v2.3.4: Verify IP binding if requested
        if enforce_ip:
            from starlette.requests import Request as StarletteRequest
            if isinstance(request, StarletteRequest):
                client_ip = get_client_ip(
                    request_headers=dict(request.headers),
                    remote_addr=request.client[0] if request.client else None
                )
            else:
                client_ip = get_client_ip(request_headers=dict(request.headers))
            
            context_ip = result.metadata.get('ip') if result.metadata else None
            if context_ip and context_ip != client_ip:
                raise HTTPException(
                    status_code=461,
                    detail=_get_safe_error_message(
                        "ASH_BINDING_MISMATCH",
                        "IP address mismatch",
                        is_production
                    )
                )

        # v2.3.4: Verify user binding if requested
        if enforce_user:
            current_user_id = None
            if hasattr(request, 'state') and hasattr(request.state, 'user_id'):
                current_user_id = request.state.user_id
            elif request.headers.get('x-user-id'):
                current_user_id = request.headers.get('x-user-id')
            
            context_user_id = result.metadata.get('user_id') if result.metadata else None
            if context_user_id is not None and str(current_user_id) != str(context_user_id):
                raise HTTPException(
                    status_code=461,
                    detail=_get_safe_error_message(
                        "ASH_BINDING_MISMATCH",
                        "User mismatch",
                        is_production
                    )
                )

        request.state.ash_metadata = result.metadata
        request.state.ash_scope = scope
        request.state.ash_scope_policy = policy_scope
        request.state.ash_chain_hash = chain_hash

    return verify
