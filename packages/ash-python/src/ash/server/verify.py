"""
ASH Request Verification Pipeline.

Fail-closed verification following the ASH-Spec-v1.0 order:
1. Extract contextId
2. Load context
3. Check expiry
4. Verify binding
5. Canonicalize payload
6. Recompute proof
7. Compare proofs (constant-time)
8. Atomic consume
"""

import time
from typing import Any, Callable

from ash.core.canonicalize import ash_canonicalize_json, ash_canonicalize_url_encoded
from ash.core.compare import ash_timing_safe_equal
from ash.core.errors import (
    ContextExpiredError,
    EndpointMismatchError,
    IntegrityFailedError,
    InvalidContextError,
    ReplayDetectedError,
    UnsupportedContentTypeError,
)
from ash.core.proof import ash_build_proof
from ash.core.types import BuildProofInput, SupportedContentType
from ash.server.types import ContextStore, VerifyOptions


async def verify_request(
    store: ContextStore,
    req: Any,
    options: VerifyOptions,
) -> None:
    """
    Verify a request against ASH protocol.

    This function implements the verification pipeline exactly as specified.
    Any failure raises an AshError and stops execution immediately.

    Args:
        store: Context store
        req: The incoming request
        options: Verification options

    Raises:
        InvalidContextError: Context not found or invalid
        ContextExpiredError: Context has expired
        EndpointMismatchError: Binding mismatch
        IntegrityFailedError: Proof verification failed
        ReplayDetectedError: Request replay detected
    """
    if options.extract_context_id is None:
        raise ValueError("extract_context_id is required")
    if options.extract_proof is None:
        raise ValueError("extract_proof is required")
    if options.extract_payload is None:
        raise ValueError("extract_payload is required")

    # Step 1: Extract contextId from request
    context_id = options.extract_context_id(req)
    if not isinstance(context_id, str) or context_id == "":
        raise InvalidContextError("Missing or invalid context ID")

    # Step 2: Load context by contextId
    context = await store.get(context_id)
    if context is None:
        raise InvalidContextError()

    # Step 3: Check expiry
    now = int(time.time() * 1000)
    if context.expires_at <= now:
        raise ContextExpiredError()

    # Step 4: Verify binding matches
    if context.binding != options.expected_binding:
        raise EndpointMismatchError()

    # Step 5: Canonicalize request payload
    payload = options.extract_payload(req)
    canonical_payload = _canonicalize_payload(payload, options.content_type)

    # Step 6: Recompute expected proof
    expected_proof = ash_build_proof(
        BuildProofInput(
            mode=context.mode,
            binding=context.binding,
            context_id=context.context_id,
            nonce=context.nonce,
            canonical_payload=canonical_payload,
        )
    )

    # Step 7: Constant-time compare proofs
    provided_proof = options.extract_proof(req)
    if not isinstance(provided_proof, str) or not ash_timing_safe_equal(
        expected_proof, provided_proof
    ):
        raise IntegrityFailedError()

    # Step 8: Atomically consume context
    consume_result = await store.consume(context_id, now)
    if consume_result == "already_consumed":
        raise ReplayDetectedError()
    if consume_result == "missing":
        # Race condition: context was deleted between get and consume
        raise InvalidContextError()

    # Verification successful - proceed to business logic


def _canonicalize_payload(payload: Any, content_type: SupportedContentType) -> str:
    """Canonicalize payload based on content type."""
    if content_type == "application/json":
        return ash_canonicalize_json(payload)

    if content_type == "application/x-www-form-urlencoded":
        if isinstance(payload, str):
            return ash_canonicalize_url_encoded(payload)
        if isinstance(payload, dict):
            return ash_canonicalize_url_encoded(payload)
        raise UnsupportedContentTypeError(
            "Invalid payload for URL-encoded content type"
        )

    raise UnsupportedContentTypeError(f"Content type not supported: {content_type}")


def create_verifier(store: ContextStore) -> Callable[[Any, VerifyOptions], Any]:
    """Create a verifier bound to a store."""

    async def verify(req: Any, options: VerifyOptions) -> None:
        await verify_request(store, req, options)

    return verify
