"""
Django middleware for ASH verification.

Supports ASH v2.3 unified proof features:
- Context scoping (selective field protection)
- Request chaining (workflow integrity)
- Server-side scope policies (ENH-003)
- IP binding with X-Forwarded-For support (v2.3.4)
- User binding (v2.3.4)

Configuration (via Django settings):
    ASH_ENFORCE_IP = False  # Enable IP binding verification
    ASH_ENFORCE_USER = False  # Enable user binding verification
    ASH_ENABLE_UNIFIED = False  # Enable v2.3 unified features
    ASH_TIMESTAMP_TOLERANCE = 300  # Timestamp tolerance in seconds
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Callable, List

from ash.config.scope_policies import ash_get_scope_policy
from ash.config.settings import get_client_ip
from ash.core.canonicalize import ash_normalize_binding
from ash.core.proof import ash_normalize_scope_fields

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

    from ..core import Ash


# Security constants
MAX_CONTEXT_ID_LENGTH = 256
SHA256_HEX_LENGTH = 64


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


class AshDjangoMiddleware:
    """
    Django middleware for ASH verification.

    Usage:
        1. Add to settings.py MIDDLEWARE:
           MIDDLEWARE = [
               ...
               'ash.middleware.django.AshDjangoMiddleware',
           ]

        2. Configure in settings.py:
           ASH_PROTECTED_PATHS = ['/api/update', '/api/profile']
           ASH_ENFORCE_IP = False  # Enable IP binding
           ASH_ENFORCE_USER = False  # Enable user binding
           ASH_ENABLE_UNIFIED = False  # Enable v2.3 unified features
           ASH_TIMESTAMP_TOLERANCE = 300  # Timestamp tolerance in seconds

        3. Create ASH instance in settings.py or apps.py:
           from ash import Ash, MemoryStore
           ASH_INSTANCE = Ash(MemoryStore())

    Example:
        >>> # In settings.py
        >>> from ash import Ash, MemoryStore
        >>> ASH_INSTANCE = Ash(MemoryStore())
        >>> ASH_PROTECTED_PATHS = ['/api/*']
        >>> ASH_ENFORCE_IP = True  # Enable IP binding
        >>> ASH_ENFORCE_USER = True  # Enable user binding
        >>> ASH_ENABLE_UNIFIED = True  # Enable scope/chain support
    """

    def __init__(self, get_response: Callable[["HttpRequest"], "HttpResponse"]) -> None:
        self.get_response = get_response
        self._ash: "Ash | None" = None
        self._protected_paths: list[str] = []
        self._enforce_ip: bool = False
        self._enforce_user: bool = False
        self._enable_unified: bool = False
        self._timestamp_tolerance: int = 300

    def _get_ash(self) -> "Ash":
        """Get ASH instance from Django settings."""
        if self._ash is None:
            from django.conf import settings

            self._ash = getattr(settings, "ASH_INSTANCE", None)
            if self._ash is None:
                raise RuntimeError("ASH_INSTANCE not configured in Django settings")

            self._protected_paths = getattr(settings, "ASH_PROTECTED_PATHS", [])
            self._enforce_ip = getattr(settings, "ASH_ENFORCE_IP", False)
            self._enforce_user = getattr(settings, "ASH_ENFORCE_USER", False)
            self._enable_unified = getattr(settings, "ASH_ENABLE_UNIFIED", False)
            self._timestamp_tolerance = getattr(settings, "ASH_TIMESTAMP_TOLERANCE", 300)

        return self._ash

    def _is_production(self) -> bool:
        """Check if running in production environment."""
        from django.conf import settings
        return not getattr(settings, "DEBUG", False)

    def __call__(self, request: "HttpRequest") -> "HttpResponse":
        from django.http import JsonResponse

        ash = self._get_ash()
        path = request.path

        # Check if path should be protected
        should_verify = any(
            path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
            for p in self._protected_paths
        )

        if not should_verify:
            return self.get_response(request)

        # Get all 6 ASH headers
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
        if not self._enable_unified and (client_scope or scope_hash or chain_hash):
            return JsonResponse(
                {
                    "error": "ASH_MODE_VIOLATION",
                    "message": "Scope/chain headers are not supported without ASH_ENABLE_UNIFIED=True.",
                },
                status=400,
            )

        if not context_id:
            return JsonResponse(
                {"error": "ASH_CTX_NOT_FOUND", "message": "Missing X-ASH-Context-ID header"},
                status=450,  # v2.3.4: Context error
            )

        # VULN-004 FIX: Validate context_id format before store lookup
        is_valid_ctx, ctx_error = _validate_context_id(context_id)
        if not is_valid_ctx:
            return JsonResponse(
                {"error": "ASH_MALFORMED_REQUEST", "message": ctx_error},
                status=400,
            )

        if not proof:
            return JsonResponse(
                {"error": "ASH_PROOF_MISSING", "message": "Missing X-ASH-Proof header"},
                status=483,  # v2.3.4: Format error
            )

        # VULN-008 FIX: Validate proof format before store lookup
        is_valid_proof, proof_error = _validate_proof_format(proof)
        if not is_valid_proof:
            return JsonResponse(
                {"error": "ASH_PROOF_INVALID", "message": proof_error},
                status=460,
            )

        # Normalize binding with query string
        query_string = request.META.get("QUERY_STRING", "")
        binding = ash_normalize_binding(request.method, path, query_string)

        # ENH-003: Check server-side scope policy
        policy_scope = ash_get_scope_policy(binding)
        has_policy_scope = len(policy_scope) > 0

        # BUG-39 FIX: If server has a scope policy but unified mode is disabled,
        # the configuration is invalid
        if has_policy_scope and not self._enable_unified:
            is_prod = self._is_production()
            message = (
                "Server configuration error: unified mode required for this endpoint"
                if is_prod
                else f'Server has a scope policy for "{binding}" but ASH_ENABLE_UNIFIED=False'
            )
            return JsonResponse(
                {"error": "ASH_MODE_VIOLATION", "message": message},
                status=400,
            )

        # Determine effective scope
        scope = client_scope

        # ENH-003: Server-side scope policy enforcement
        if has_policy_scope:
            # If server has a policy, client MUST use it
            if not client_scope:
                return JsonResponse(
                    {
                        "error": "ASH_SCOPE_POLICY_REQUIRED",
                        "message": "This endpoint requires scope headers per server policy",
                        "requiredScope": policy_scope,
                    },
                    status=400,
                )

            # Verify client scope matches server policy
            # BUG-POTENTIAL-001 FIX: Use ash_normalize_scope_fields for consistent sorting
            normalized_client = ash_normalize_scope_fields(client_scope)
            normalized_policy = ash_normalize_scope_fields(policy_scope)

            if normalized_client != normalized_policy:
                return JsonResponse(
                    {
                        "error": "ASH_SCOPE_POLICY_VIOLATION",
                        "message": "Request scope does not match server policy",
                        "expected": policy_scope,
                        "received": client_scope,
                    },
                    status=475,  # v2.3.4: Verification error
                )

            scope = policy_scope

        # BUG-22 FIX: Validate timestamp freshness if provided
        if timestamp:
            is_valid_ts, ts_error = _validate_timestamp_freshness(timestamp, self._timestamp_tolerance)
            if not is_valid_ts:
                return JsonResponse(
                    {"error": "ASH_TIMESTAMP_INVALID", "message": ts_error},
                    status=482,
                )

        # Get payload
        payload = request.body.decode("utf-8") if request.body else ""
        content_type = request.content_type or ""

        # Verify with v2.3 options
        result = ash.ash_verify(
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
            is_prod = self._is_production()
            if is_prod and error_code in ("ASH_BINDING_MISMATCH", "ASH_PROOF_INVALID"):
                message = "Request binding does not match context"
            else:
                message = result.error_message or "Verification failed"

            return JsonResponse(
                {"error": error_code, "message": message},
                status=http_status,
            )

        # v2.3.4: Verify IP binding if requested
        if self._enforce_ip:
            client_ip = get_client_ip(
                request_headers=dict(request.headers),
                remote_addr=request.META.get("REMOTE_ADDR")
            )
            context_ip = result.metadata.get('ip') if result.metadata else None
            if context_ip and context_ip != client_ip:
                is_prod = self._is_production()
                return JsonResponse(
                    {
                        "error": "ASH_BINDING_MISMATCH",
                        "message": "IP address mismatch" if not is_prod else "Request binding does not match context",
                    },
                    status=461,  # v2.3.4: Binding mismatch
                )

        # v2.3.4: Verify user binding if requested
        if self._enforce_user:
            current_user_id = None
            # Check for Django's request.user (set by AuthenticationMiddleware)
            if hasattr(request, 'user') and request.user:
                current_user_id = getattr(request.user, 'id', None)
            # Fallback to session user_id
            elif hasattr(request, 'session') and 'user_id' in request.session:
                current_user_id = request.session['user_id']

            context_user_id = result.metadata.get('user_id') if result.metadata else None
            if context_user_id is not None and str(current_user_id) != str(context_user_id):
                is_prod = self._is_production()
                return JsonResponse(
                    {
                        "error": "ASH_BINDING_MISMATCH",
                        "message": "User mismatch" if not is_prod else "Request binding does not match context",
                    },
                    status=461,  # v2.3.4: Binding mismatch
                )

        # Store metadata in request
        request.ash_metadata = result.metadata
        request.ash_scope = scope
        request.ash_scope_policy = policy_scope
        request.ash_chain_hash = chain_hash
        request.ash_client_ip = get_client_ip(
            request_headers=dict(request.headers),
            remote_addr=request.META.get("REMOTE_ADDR")
        )

        return self.get_response(request)
