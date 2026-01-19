"""
Django middleware for ASH verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

    from ..core import Ash


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

        3. Create ASH instance in settings.py or apps.py:
           from ash import Ash, MemoryStore
           ASH_INSTANCE = Ash(MemoryStore())

    Example:
        >>> # In settings.py
        >>> from ash import Ash, MemoryStore
        >>> ASH_INSTANCE = Ash(MemoryStore())
        >>> ASH_PROTECTED_PATHS = ['/api/*']
    """

    def __init__(self, get_response: Callable[["HttpRequest"], "HttpResponse"]) -> None:
        self.get_response = get_response
        self._ash: "Ash | None" = None
        self._protected_paths: list[str] = []

    def _get_ash(self) -> "Ash":
        """Get ASH instance from Django settings."""
        if self._ash is None:
            from django.conf import settings

            self._ash = getattr(settings, "ASH_INSTANCE", None)
            if self._ash is None:
                raise RuntimeError("ASH_INSTANCE not configured in Django settings")

            self._protected_paths = getattr(settings, "ASH_PROTECTED_PATHS", [])

        return self._ash

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

        # Get headers
        context_id = request.headers.get("X-ASH-Context-ID")
        proof = request.headers.get("X-ASH-Proof")

        if not context_id:
            return JsonResponse(
                {"error": "MISSING_CONTEXT_ID", "message": "Missing X-ASH-Context-ID header"},
                status=403,
            )

        if not proof:
            return JsonResponse(
                {"error": "MISSING_PROOF", "message": "Missing X-ASH-Proof header"},
                status=403,
            )

        # Normalize binding
        binding = ash.ash_normalize_binding(request.method, path)

        # Get payload
        payload = request.body.decode("utf-8") if request.body else ""
        content_type = request.content_type or ""

        # Verify
        result = ash.ash_verify(context_id, proof, binding, payload, content_type)

        if not result.valid:
            return JsonResponse(
                {
                    "error": result.error_code.value if result.error_code else "VERIFICATION_FAILED",
                    "message": result.error_message or "Verification failed",
                },
                status=403,
            )

        # Store metadata in request
        request.ash_metadata = result.metadata

        return self.get_response(request)
