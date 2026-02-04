"""
ASH Core classes and types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .binding import ash_normalize_binding
from .canonicalize import ash_canonicalize_json, ash_canonicalize_urlencoded
from .proof import ash_build_proof, ash_verify_proof
from .stores import ContextStore


class AshMode(Enum):
    """ASH security modes."""

    MINIMAL = "minimal"
    BALANCED = "balanced"
    STRICT = "strict"


class AshErrorCode(Enum):
    """ASH error codes."""

    INVALID_CONTEXT = "INVALID_CONTEXT"
    CONTEXT_EXPIRED = "CONTEXT_EXPIRED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"
    ENDPOINT_MISMATCH = "ENDPOINT_MISMATCH"
    MODE_VIOLATION = "MODE_VIOLATION"
    UNSUPPORTED_CONTENT_TYPE = "UNSUPPORTED_CONTENT_TYPE"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    CANONICALIZATION_FAILED = "CANONICALIZATION_FAILED"


@dataclass
class AshContext:
    """ASH context representing a one-time use token."""

    id: str
    binding: str
    expires_at: int  # Unix timestamp in milliseconds
    mode: AshMode
    used: bool = False
    nonce: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if context has expired."""
        import time

        return int(time.time() * 1000) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "binding": self.binding,
            "expires_at": self.expires_at,
            "mode": self.mode.value,
            "used": self.used,
            "nonce": self.nonce,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AshContext:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            binding=data["binding"],
            expires_at=data["expires_at"],
            mode=AshMode(data["mode"]),
            used=data.get("used", False),
            nonce=data.get("nonce"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AshVerifyResult:
    """Result of ASH verification."""

    valid: bool
    error_code: AshErrorCode | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(cls, metadata: dict[str, Any] | None = None) -> AshVerifyResult:
        """Create a successful result."""
        return cls(valid=True, metadata=metadata or {})

    @classmethod
    def failure(cls, code: AshErrorCode, message: str) -> AshVerifyResult:
        """Create a failed result."""
        return cls(valid=False, error_code=code, error_message=message)


class Ash:
    """
    ASH main class for request integrity protection.

    Example:
        >>> store = MemoryStore()
        >>> ash = Ash(store)
        >>> ctx = ash.ash_issue_context("POST /api/update", ttl_ms=30000)
    """

    VERSION = "ASHv1"
    LIBRARY_VERSION = "1.0.0"

    def __init__(
        self,
        store: ContextStore,
        default_mode: AshMode = AshMode.BALANCED,
    ) -> None:
        """
        Initialize ASH.

        Args:
            store: Context store implementation
            default_mode: Default security mode
        """
        self._store = store
        self._default_mode = default_mode

    def ash_issue_context(
        self,
        binding: str,
        ttl_ms: int,
        mode: AshMode | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AshContext:
        """
        Issue a new context for a request.

        Args:
            binding: Endpoint binding (e.g., "POST /api/update")
            ttl_ms: Time-to-live in milliseconds
            mode: Security mode (uses default if None)
            metadata: Optional metadata

        Returns:
            Created context
        """
        return self._store.create(
            binding=binding,
            ttl_ms=ttl_ms,
            mode=mode or self._default_mode,
            metadata=metadata or {},
        )

    def ash_verify(
        self,
        context_id: str,
        proof: str,
        binding: str,
        payload: str,
        content_type: str,
        options: dict[str, Any] | None = None,
    ) -> AshVerifyResult:
        """
        Verify a request against its context and proof.

        Args:
            context_id: Context ID from request header
            proof: Proof from request header
            binding: Actual request binding
            payload: Request payload (raw body)
            content_type: Content-Type header
            options: Optional v2.3 verification options:
                - scope: List of scoped fields
                - scopeHash: Hash of scope fields
                - chainHash: Hash of previous proof (for chaining)
                - timestamp: Request timestamp for verification

        Returns:
            Verification result
        """
        options = options or {}
        
        # Get context
        context = self._store.get(context_id)

        if context is None:
            return AshVerifyResult.failure(
                AshErrorCode.INVALID_CONTEXT,
                "Invalid or expired context",
            )

        # Check if already used
        if context.used:
            return AshVerifyResult.failure(
                AshErrorCode.REPLAY_DETECTED,
                "Context already used (replay detected)",
            )

        # Check binding
        if context.binding != binding:
            return AshVerifyResult.failure(
                AshErrorCode.ENDPOINT_MISMATCH,
                f"Binding mismatch: expected {context.binding}, got {binding}",
            )

        # Canonicalize payload
        try:
            canonical_payload = self.ash_canonicalize(payload, content_type)
        except Exception as e:
            return AshVerifyResult.failure(
                AshErrorCode.CANONICALIZATION_FAILED,
                f"Failed to canonicalize payload: {e}",
            )

        # Extract v2.3 options
        scope = options.get("scope", [])
        scope_hash = options.get("scopeHash", "")
        chain_hash = options.get("chainHash", "")
        
        # If using v2.3 unified features (scope/chain), use unified verification
        if scope or scope_hash or chain_hash:
            from .core.proof import ash_verify_proof_unified, ash_hash_body, ash_extract_scoped_fields, ash_join_scope_fields
            import json
            
            # Parse payload as dict for unified verification
            try:
                if content_type and "application/json" in content_type:
                    payload_dict = json.loads(payload) if payload else {}
                else:
                    # For non-JSON, treat as single field payload
                    payload_dict = {"_raw": payload} if payload else {}
            except json.JSONDecodeError:
                payload_dict = {"_raw": payload} if payload else {}
            
            # Build expected proof using unified method
            from .core.proof import ash_derive_client_secret, ash_build_proof_unified
            
            try:
                client_secret = ash_derive_client_secret(
                    context.nonce or "", context_id, binding
                )
                expected_proof, _, _ = ash_build_proof_unified(
                    client_secret=client_secret,
                    timestamp=options.get("timestamp", ""),
                    binding=binding,
                    payload=payload_dict,
                    scope=scope if scope else None,
                    previous_proof=None,  # We verify chain_hash separately
                )
            except Exception:
                return AshVerifyResult.failure(
                    AshErrorCode.INTEGRITY_FAILED,
                    "Proof computation failed",
                )
            
            # Verify proof matches
            import hmac
            if not hmac.compare_digest(expected_proof, proof):
                return AshVerifyResult.failure(
                    AshErrorCode.INTEGRITY_FAILED,
                    "Proof verification failed",
                )
            
            # Verify scope hash if provided
            if scope_hash and scope:
                expected_scope_hash = ash_hash_body(ash_join_scope_fields(scope))
                if not hmac.compare_digest(expected_scope_hash, scope_hash):
                    return AshVerifyResult.failure(
                        AshErrorCode.INTEGRITY_FAILED,
                        "Scope hash mismatch",
                    )
            
            # Verify chain hash if provided
            if chain_hash:
                # chain_hash would be verified against stored previous proof
                # This is simplified - full implementation would look up previous proof
                pass
        else:
            # Legacy verification path
            # Build expected proof
            expected_proof = ash_build_proof(
                context.mode,
                context.binding,
                context_id,
                context.nonce,
                canonical_payload,
            )

            # Verify proof
            if not ash_verify_proof(expected_proof, proof):
                return AshVerifyResult.failure(
                    AshErrorCode.INTEGRITY_FAILED,
                    "Proof verification failed",
                )

        # Consume context
        if not self._store.consume(context_id):
            return AshVerifyResult.failure(
                AshErrorCode.REPLAY_DETECTED,
                "Context already used (replay detected)",
            )

        return AshVerifyResult.success(context.metadata)

    def ash_canonicalize(self, payload: str, content_type: str) -> str:
        """Canonicalize payload based on content type."""
        if "application/json" in content_type:
            return ash_canonicalize_json(payload)
        elif "application/x-www-form-urlencoded" in content_type:
            return ash_canonicalize_urlencoded(payload)
        else:
            return payload

    def ash_normalize_binding(self, method: str, path: str) -> str:
        """Normalize a binding string."""
        return ash_normalize_binding(method, path)

    def ash_version(self) -> str:
        """Get ASH protocol version."""
        return self.VERSION

    def ash_library_version(self) -> str:
        """Get library version."""
        return self.LIBRARY_VERSION

    @property
    def store(self) -> ContextStore:
        """Get the context store."""
        return self._store
