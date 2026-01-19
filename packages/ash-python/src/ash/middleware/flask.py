"""
Flask middleware for ASH verification.

Supports ASH v2.3 unified proof features:
- Context scoping (selective field protection)
- Request chaining (workflow integrity)
- Server-side scope policies (ENH-003)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, List

from ash.config.scope_policies import get_scope_policy
from ash.core.canonicalize import normalize_binding

if TYPE_CHECKING:
    from flask import Flask, Response

    from ..core import Ash


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
    """

    def __init__(self, ash: "Ash") -> None:
        self.ash = ash
        self.protected_paths: list[str] = []

    def init_app(
        self,
        app: "Flask",
        protected_paths: list[str] | None = None,
    ) -> None:
        """Initialize the extension with a Flask app."""
        self.protected_paths = protected_paths or []
        app.before_request(self._verify_request)

    def _verify_request(self) -> "Response | tuple[Response, int] | None":
        """Verify request before handling."""
        from flask import g, jsonify, request

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
        scope_header = request.headers.get("X-ASH-Scope", "")
        scope_hash = request.headers.get("X-ASH-Scope-Hash", "")
        chain_hash = request.headers.get("X-ASH-Chain-Hash", "")

        if not context_id:
            return jsonify(
                error="MISSING_CONTEXT_ID",
                message="Missing X-ASH-Context-ID header",
            ), 403

        if not proof:
            return jsonify(
                error="MISSING_PROOF",
                message="Missing X-ASH-Proof header",
            ), 403

        # Normalize binding with query string
        query_string = request.query_string.decode("utf-8") if request.query_string else ""
        binding = normalize_binding(request.method, path, query_string)

        # ENH-003: Check server-side scope policy
        policy_scope = get_scope_policy(binding)
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
                return jsonify(
                    error="SCOPE_POLICY_REQUIRED",
                    message="This endpoint requires scope headers per server policy",
                    requiredScope=policy_scope,
                ), 403

            # Verify client scope matches server policy
            sorted_client = sorted(client_scope)
            sorted_policy = sorted(policy_scope)

            if sorted_client != sorted_policy:
                return jsonify(
                    error="SCOPE_POLICY_VIOLATION",
                    message="Request scope does not match server policy",
                    expected=policy_scope,
                    received=client_scope,
                ), 403

            scope = policy_scope

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
            error_code = result.error_code.value if result.error_code else "VERIFICATION_FAILED"

            # Map specific v2.3 errors
            if scope and scope_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_SCOPE_MISMATCH"
            if chain_hash:
                if error_code == "INTEGRITY_FAILED":
                    error_code = "ASH_CHAIN_BROKEN"

            return jsonify(
                error=error_code,
                message=result.error_message or "Verification failed",
            ), 403

        # Store metadata in g
        g.ash_metadata = result.metadata
        g.ash_scope = scope
        g.ash_scope_policy = policy_scope
        g.ash_chain_hash = chain_hash

        return None


def ash_flask_before_request(
    ash: "Ash",
    protected_paths: list[str],
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
    """
    ext = AshFlaskExtension(ash)
    ext.protected_paths = protected_paths
    return ext._verify_request
