"""Tests for ASH verification pipeline."""

import time
import pytest
from ash.server.stores.memory import Memory
from ash.server import context
from ash.server.verify import verify_request
from ash.server.types import VerifyOptions
from ash.core.proof import build_proof
from ash.core.canonicalize import canonicalize_json
from ash.core.types import BuildProofInput
from ash.core.errors import (
    InvalidContextError,
    ContextExpiredError,
    EndpointMismatchError,
    IntegrityFailedError,
    ReplayDetectedError,
)


class MockRequest:
    """Mock HTTP request for testing."""

    def __init__(self, context_id: str, proof: str, payload: dict):
        self.headers = {
            "X-Ash-Context-Id": context_id,
            "X-Ash-Proof": proof,
        }
        self.payload = payload


@pytest.fixture
def store():
    """Create a memory store for testing."""
    return Memory(suppress_warning=True)


@pytest.mark.asyncio
async def test_successful_verification(store):
    """Should verify valid request."""
    # Create context
    ctx = await context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    )

    # Build proof
    payload = {"name": "test"}
    canonical_payload = canonicalize_json(payload)
    proof = build_proof(
        BuildProofInput(
            mode=ctx.mode,
            binding="POST /api/update",
            context_id=ctx.context_id,
            canonical_payload=canonical_payload,
            nonce=ctx.nonce,
        )
    )

    # Create mock request
    req = MockRequest(ctx.context_id, proof, payload)

    # Verify
    options = VerifyOptions(
        expected_binding="POST /api/update",
        content_type="application/json",
        extract_context_id=lambda r: r.headers.get("X-Ash-Context-Id", ""),
        extract_proof=lambda r: r.headers.get("X-Ash-Proof", ""),
        extract_payload=lambda r: r.payload,
    )

    await verify_request(store, req, options)  # Should not raise


@pytest.mark.asyncio
async def test_missing_context(store):
    """Should reject missing context."""
    req = MockRequest("nonexistent-id", "fake-proof", {})

    options = VerifyOptions(
        expected_binding="POST /api/update",
        extract_context_id=lambda r: r.headers.get("X-Ash-Context-Id", ""),
        extract_proof=lambda r: r.headers.get("X-Ash-Proof", ""),
        extract_payload=lambda r: r.payload,
    )

    with pytest.raises(InvalidContextError):
        await verify_request(store, req, options)


@pytest.mark.asyncio
async def test_expired_context(store):
    """Should reject expired context."""
    # Create context with very short TTL
    ctx = await context.create(
        store,
        binding="POST /api/update",
        ttl_ms=1,  # 1ms TTL
    )

    # Wait for expiry
    time.sleep(0.01)

    payload = {"name": "test"}
    canonical_payload = canonicalize_json(payload)
    proof = build_proof(
        BuildProofInput(
            mode=ctx.mode,
            binding="POST /api/update",
            context_id=ctx.context_id,
            canonical_payload=canonical_payload,
        )
    )

    req = MockRequest(ctx.context_id, proof, payload)

    options = VerifyOptions(
        expected_binding="POST /api/update",
        extract_context_id=lambda r: r.headers.get("X-Ash-Context-Id", ""),
        extract_proof=lambda r: r.headers.get("X-Ash-Proof", ""),
        extract_payload=lambda r: r.payload,
    )

    with pytest.raises(ContextExpiredError):
        await verify_request(store, req, options)


@pytest.mark.asyncio
async def test_binding_mismatch(store):
    """Should reject binding mismatch."""
    ctx = await context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    )

    payload = {"name": "test"}
    canonical_payload = canonicalize_json(payload)
    proof = build_proof(
        BuildProofInput(
            mode=ctx.mode,
            binding="POST /api/update",
            context_id=ctx.context_id,
            canonical_payload=canonical_payload,
        )
    )

    req = MockRequest(ctx.context_id, proof, payload)

    options = VerifyOptions(
        expected_binding="POST /api/other",  # Different binding
        extract_context_id=lambda r: r.headers.get("X-Ash-Context-Id", ""),
        extract_proof=lambda r: r.headers.get("X-Ash-Proof", ""),
        extract_payload=lambda r: r.payload,
    )

    with pytest.raises(EndpointMismatchError):
        await verify_request(store, req, options)


@pytest.mark.asyncio
async def test_tampered_payload(store):
    """Should reject tampered payload."""
    ctx = await context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    )

    original_payload = {"name": "test"}
    canonical_payload = canonicalize_json(original_payload)
    proof = build_proof(
        BuildProofInput(
            mode=ctx.mode,
            binding="POST /api/update",
            context_id=ctx.context_id,
            canonical_payload=canonical_payload,
        )
    )

    # Tamper with payload
    tampered_payload = {"name": "hacked"}
    req = MockRequest(ctx.context_id, proof, tampered_payload)

    options = VerifyOptions(
        expected_binding="POST /api/update",
        extract_context_id=lambda r: r.headers.get("X-Ash-Context-Id", ""),
        extract_proof=lambda r: r.headers.get("X-Ash-Proof", ""),
        extract_payload=lambda r: r.payload,
    )

    with pytest.raises(IntegrityFailedError):
        await verify_request(store, req, options)


@pytest.mark.asyncio
async def test_replay_detection(store):
    """Should detect replay attacks."""
    ctx = await context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    )

    payload = {"name": "test"}
    canonical_payload = canonicalize_json(payload)
    proof = build_proof(
        BuildProofInput(
            mode=ctx.mode,
            binding="POST /api/update",
            context_id=ctx.context_id,
            canonical_payload=canonical_payload,
        )
    )

    req = MockRequest(ctx.context_id, proof, payload)

    options = VerifyOptions(
        expected_binding="POST /api/update",
        extract_context_id=lambda r: r.headers.get("X-Ash-Context-Id", ""),
        extract_proof=lambda r: r.headers.get("X-Ash-Proof", ""),
        extract_payload=lambda r: r.payload,
    )

    # First request should succeed
    await verify_request(store, req, options)

    # Second request (replay) should fail
    with pytest.raises(ReplayDetectedError):
        await verify_request(store, req, options)
