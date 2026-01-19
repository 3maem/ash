"""
FastAPI middleware for ASH verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response

    from ..core import Ash


class AshFastAPIMiddleware:
    """
    FastAPI/Starlette middleware for ASH verification.

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
    """

    def __init__(
        self,
        app: "Callable",
        ash: "Ash",
        protected_paths: list[str] | None = None,
    ) -> None:
        self.app = app
        self.ash = ash
        self.protected_paths = protected_paths or []

    async def __call__(self, scope: dict, receive: "Callable", send: "Callable") -> None:
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

        # Get headers
        context_id = request.headers.get("x-ash-context-id")
        proof = request.headers.get("x-ash-proof")

        if not context_id:
            response = JSONResponse(
                {"error": "MISSING_CONTEXT_ID", "message": "Missing X-ASH-Context-ID header"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        if not proof:
            response = JSONResponse(
                {"error": "MISSING_PROOF", "message": "Missing X-ASH-Proof header"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        # Normalize binding
        binding = self.ash.ash_normalize_binding(request.method, path)

        # Get payload
        body = await request.body()
        payload = body.decode("utf-8") if body else ""
        content_type = request.headers.get("content-type", "")

        # Verify
        result = self.ash.ash_verify(context_id, proof, binding, payload, content_type)

        if not result.valid:
            response = JSONResponse(
                {
                    "error": result.error_code.value if result.error_code else "VERIFICATION_FAILED",
                    "message": result.error_message or "Verification failed",
                },
                status_code=403,
            )
            await response(scope, receive, send)
            return

        # Store metadata in request state
        scope["state"] = scope.get("state", {})
        scope["state"]["ash_metadata"] = result.metadata

        await self.app(scope, receive, send)


def ash_fastapi_depends(ash: "Ash", expected_binding: str | None = None):
    """
    FastAPI dependency for ASH verification.

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
        ...     _: None = Depends(ash_fastapi_depends(ash_instance, "POST /api/update"))
        ... ):
        ...     return {"success": True}
    """
    from fastapi import Depends, HTTPException, Request

    async def verify(request: Request):
        context_id = request.headers.get("x-ash-context-id")
        proof = request.headers.get("x-ash-proof")

        if not context_id:
            raise HTTPException(403, detail="Missing X-ASH-Context-ID header")
        if not proof:
            raise HTTPException(403, detail="Missing X-ASH-Proof header")

        binding = expected_binding or ash.ash_normalize_binding(
            request.method, request.url.path
        )

        body = await request.body()
        payload = body.decode("utf-8") if body else ""
        content_type = request.headers.get("content-type", "")

        result = ash.ash_verify(context_id, proof, binding, payload, content_type)

        if not result.valid:
            raise HTTPException(403, detail=result.error_message or "Verification failed")

        request.state.ash_metadata = result.metadata

    return verify
