"""
ASH Flask Middleware.

Drop-in decorator for Flask applications.

Example:
    from flask import Flask, request, jsonify
    import ash

    app = Flask(__name__)
    store = ash.stores.Memory()

    @app.route("/api/context", methods=["POST"])
    def get_context():
        import asyncio
        ctx = asyncio.run(ash.context.create(
            store,
            binding="POST /api/update",
            ttl_ms=30000,
        ))
        return jsonify({
            "contextId": ctx.context_id,
            "expiresAt": ctx.expires_at,
            "mode": ctx.mode,
        })

    @app.route("/api/update", methods=["POST"])
    @ash.middleware.flask(store, expected_binding="POST /api/update")
    def update():
        return jsonify({"status": "ok"})
"""

import asyncio
from functools import wraps
from typing import Any, Callable, Optional

from ash.core.errors import AshError
from ash.core.types import SupportedContentType
from ash.server.types import ContextStore, VerifyOptions
from ash.server.verify import verify_request

# Default header names
DEFAULT_CONTEXT_ID_HEADER = "X-Ash-Context-Id"
DEFAULT_PROOF_HEADER = "X-Ash-Proof"


def flask(
    store: ContextStore,
    expected_binding: str,
    content_type: SupportedContentType = "application/json",
    context_id_header: str = DEFAULT_CONTEXT_ID_HEADER,
    proof_header: str = DEFAULT_PROOF_HEADER,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Create ASH verification decorator for Flask routes.

    Args:
        store: Context store to use
        expected_binding: Expected binding (e.g., "POST /api/update")
        content_type: Content type of request body (default: application/json)
        context_id_header: Header name for context ID (default: X-Ash-Context-Id)
        proof_header: Header name for proof (default: X-Ash-Proof)

    Returns:
        Flask route decorator

    Example:
        @app.route("/api/update", methods=["POST"])
        @ash.middleware.flask(store, expected_binding="POST /api/update")
        def update():
            return jsonify({"status": "ok"})
    """

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Import Flask request here to avoid import errors when Flask not installed
            try:
                from flask import request, jsonify
            except ImportError:
                raise ImportError(
                    "Flask is required for this middleware. "
                    "Install with: pip install ash-protocol[flask]"
                )

            def extract_context_id(req: Any) -> str:
                return req.headers.get(context_id_header, "")

            def extract_proof(req: Any) -> str:
                return req.headers.get(proof_header, "")

            def extract_payload(req: Any) -> Any:
                if content_type == "application/json":
                    return req.get_json(force=True, silent=True) or {}
                elif content_type == "application/x-www-form-urlencoded":
                    return req.form.to_dict(flat=False)
                return {}

            options = VerifyOptions(
                expected_binding=expected_binding,
                content_type=content_type,
                extract_context_id=extract_context_id,
                extract_proof=extract_proof,
                extract_payload=extract_payload,
            )

            try:
                # Run async verification
                asyncio.run(verify_request(store, request, options))
            except AshError as e:
                return (
                    jsonify({"error": {"code": e.code, "message": e.message}}),
                    e.http_status,
                )

            # Verification passed - call the route handler
            return f(*args, **kwargs)

        return wrapper

    return decorator


def flask_error_handler(app: Any) -> None:
    """
    Register ASH error handler with Flask app.

    This provides consistent error responses for ASH errors
    that bubble up from route handlers.

    Args:
        app: Flask application instance

    Example:
        app = Flask(__name__)
        ash.middleware.flask_error_handler(app)
    """
    try:
        from flask import jsonify
    except ImportError:
        raise ImportError(
            "Flask is required. Install with: pip install ash-protocol[flask]"
        )

    @app.errorhandler(AshError)
    def handle_ash_error(error: AshError) -> tuple[Any, int]:
        return (
            jsonify({"error": {"code": error.code, "message": error.message}}),
            error.http_status,
        )
