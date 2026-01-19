"""
Flask middleware for ASH verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

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

        # Normalize binding
        binding = self.ash.ash_normalize_binding(request.method, path)

        # Get payload
        payload = request.get_data(as_text=True) or ""
        content_type = request.content_type or ""

        # Verify
        result = self.ash.ash_verify(context_id, proof, binding, payload, content_type)

        if not result.valid:
            return jsonify(
                error=result.error_code.value if result.error_code else "VERIFICATION_FAILED",
                message=result.error_message or "Verification failed",
            ), 403

        # Store metadata in g
        g.ash_metadata = result.metadata

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
