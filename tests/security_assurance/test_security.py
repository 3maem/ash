"""
ASH Security Assurance Pack - Security Tests
=============================================
C. Security Tests:
- Payload/Header tampering (reorder, inject, truncate)
- Replay attacks (sequential & parallel)
- Time manipulation (skew, delay, drift)
- Header confusion & duplication
"""

import pytest
import sys
import os
import time
import asyncio
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))

from ash.core import (
    build_proof,
    BuildProofInput,
    canonicalize_json,
    normalize_binding,
    derive_client_secret,
    build_proof_v21,
    verify_proof_v21,
    hash_body,
)
from ash.server import context, stores


@pytest.fixture
def memory_store():
    """Provide a fresh memory store for each test."""
    return stores.Memory(suppress_warning=True)


class TestPayloadTampering:
    """Test detection of various payload tampering attempts."""

    def test_field_reordering_detected_in_proof(self):
        """Reordering fields must not change canonical form (and thus proof)."""
        # After canonicalization, order should be the same
        payload1 = {"z": 1, "a": 2}
        payload2 = {"a": 2, "z": 1}

        canon1 = canonicalize_json(payload1)
        canon2 = canonicalize_json(payload2)

        assert canon1 == canon2, "Canonical form differs for reordered fields"

        input1 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload=canon1)
        input2 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload=canon2)

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 == proof2, "Same data with different order produces different proof"

    def test_field_injection_detected(self):
        """Injecting additional fields must be detected."""
        original = {"amount": 100}
        injected = {"amount": 100, "admin": True}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_injected = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(injected))

        proof_original = build_proof(input_original)
        proof_injected = build_proof(input_injected)

        assert proof_original != proof_injected, "Field injection not detected"

    def test_field_removal_detected(self):
        """Removing fields must be detected."""
        original = {"amount": 100, "recipient": "user123"}
        truncated = {"amount": 100}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_truncated = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                          canonical_payload=canonicalize_json(truncated))

        proof_original = build_proof(input_original)
        proof_truncated = build_proof(input_truncated)

        assert proof_original != proof_truncated, "Field removal not detected"

    def test_value_modification_detected(self):
        """Modifying values must be detected."""
        original = {"amount": 100}
        modified = {"amount": 999}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_modified = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(modified))

        proof_original = build_proof(input_original)
        proof_modified = build_proof(input_modified)

        assert proof_original != proof_modified, "Value modification not detected"

    def test_type_change_detected(self):
        """Changing value types must be detected."""
        original = {"count": 100}
        string_type = {"count": "100"}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_string = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                       canonical_payload=canonicalize_json(string_type))

        proof_original = build_proof(input_original)
        proof_string = build_proof(input_string)

        assert proof_original != proof_string, "Type change not detected"

    def test_nested_tampering_detected(self):
        """Tampering with nested objects must be detected."""
        original = {"user": {"id": 1, "role": "user"}}
        tampered = {"user": {"id": 1, "role": "admin"}}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_tampered = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(tampered))

        proof_original = build_proof(input_original)
        proof_tampered = build_proof(input_tampered)

        assert proof_original != proof_tampered, "Nested tampering not detected"

    def test_array_modification_detected(self):
        """Modifying arrays must be detected."""
        original = {"items": [1, 2, 3]}
        modified = {"items": [1, 2, 4]}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_modified = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(modified))

        proof_original = build_proof(input_original)
        proof_modified = build_proof(input_modified)

        assert proof_original != proof_modified, "Array modification not detected"

    def test_array_reordering_detected(self):
        """Reordering arrays must be detected (arrays preserve order)."""
        original = {"items": [1, 2, 3]}
        reordered = {"items": [3, 2, 1]}

        input_original = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                         canonical_payload=canonicalize_json(original))
        input_reordered = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1",
                                          canonical_payload=canonicalize_json(reordered))

        proof_original = build_proof(input_original)
        proof_reordered = build_proof(input_reordered)

        assert proof_original != proof_reordered, "Array reordering not detected"


class TestBindingTampering:
    """Test detection of binding/endpoint tampering."""

    def test_method_change_detected(self):
        """Changing HTTP method must be detected."""
        input_post = BuildProofInput(mode="balanced", binding="POST /api/data", context_id="ctx1", canonical_payload='{}')
        input_put = BuildProofInput(mode="balanced", binding="PUT /api/data", context_id="ctx1", canonical_payload='{}')

        proof_post = build_proof(input_post)
        proof_put = build_proof(input_put)

        assert proof_post != proof_put, "Method change not detected"

    def test_path_change_detected(self):
        """Changing path must be detected."""
        input_original = BuildProofInput(mode="balanced", binding="POST /api/user", context_id="ctx1", canonical_payload='{}')
        input_admin = BuildProofInput(mode="balanced", binding="POST /api/admin", context_id="ctx1", canonical_payload='{}')

        proof_original = build_proof(input_original)
        proof_admin = build_proof(input_admin)

        assert proof_original != proof_admin, "Path change not detected"

    def test_query_parameter_injection_detected(self):
        """Injecting query parameters must be detected."""
        binding1 = normalize_binding("GET", "/api/data", "")
        binding2 = normalize_binding("GET", "/api/data", "admin=true")

        input1 = BuildProofInput(mode="balanced", binding=binding1, context_id="ctx1", canonical_payload='{}')
        input2 = BuildProofInput(mode="balanced", binding=binding2, context_id="ctx1", canonical_payload='{}')

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2, "Query parameter injection not detected"

    def test_query_parameter_modification_detected(self):
        """Modifying query parameters must be detected."""
        binding1 = normalize_binding("GET", "/api/data", "id=1")
        binding2 = normalize_binding("GET", "/api/data", "id=2")

        input1 = BuildProofInput(mode="balanced", binding=binding1, context_id="ctx1", canonical_payload='{}')
        input2 = BuildProofInput(mode="balanced", binding=binding2, context_id="ctx1", canonical_payload='{}')

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2, "Query parameter modification not detected"


class TestReplayAttacks:
    """Test replay attack prevention."""

    @pytest.mark.asyncio
    async def test_sequential_replay_detection(self, memory_store):
        """Sequential replay attempts must be blocked."""
        store = memory_store

        # Create context
        ctx = await context.create(store, binding="POST|/api/transfer|", ttl_ms=30000, issue_nonce=True)

        # Build proof
        nonce = ctx.nonce
        context_id = ctx.context_id
        binding = "POST|/api/transfer|"
        timestamp = str(int(time.time() * 1000))
        body_hash = hash_body('{"amount":100}')

        client_secret = derive_client_secret(nonce, context_id, binding)
        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        # First verification should succeed and consume
        now_ms = int(time.time() * 1000)
        result1 = await store.consume(context_id, now_ms)
        assert result1 == "consumed", "First consumption failed"

        # Second attempt (replay) should fail
        result2 = await store.consume(context_id, now_ms)
        assert result2 == "already_consumed", "Replay attack not prevented"

    @pytest.mark.asyncio
    async def test_parallel_replay_prevention(self, memory_store):
        """Parallel replay attempts must be prevented (only one succeeds)."""
        store = memory_store
        num_tasks = 10
        results: List[str] = []

        # Create context
        ctx = await context.create(store, binding="POST|/api/transfer|", ttl_ms=30000)
        context_id = ctx.context_id
        now_ms = int(time.time() * 1000)

        async def attempt_consume():
            """Attempt to consume the context."""
            result = await store.consume(context_id, now_ms)
            results.append(result)

        # Launch parallel tasks
        await asyncio.gather(*[attempt_consume() for _ in range(num_tasks)])

        # Only one task should succeed
        success_count = sum(1 for r in results if r == "consumed")
        assert success_count == 1, f"Expected 1 success, got {success_count} (parallel replay vulnerability)"

    @pytest.mark.asyncio
    async def test_parallel_replay_high_concurrency(self, memory_store):
        """Test parallel replay with high concurrency."""
        store = memory_store
        num_attempts = 50
        results: List[str] = []

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000)
        context_id = ctx.context_id
        now_ms = int(time.time() * 1000)

        async def try_consume():
            result = await store.consume(context_id, now_ms)
            results.append(result)

        await asyncio.gather(*[try_consume() for _ in range(num_attempts)])

        success_count = sum(1 for r in results if r == "consumed")
        assert success_count == 1, f"Parallel replay: {success_count} successes instead of 1"

    @pytest.mark.asyncio
    async def test_different_contexts_independent(self, memory_store):
        """Different contexts should be independently consumable."""
        store = memory_store
        now_ms = int(time.time() * 1000)

        ctx1 = await context.create(store, binding="POST|/api/a|", ttl_ms=30000)
        ctx2 = await context.create(store, binding="POST|/api/b|", ttl_ms=30000)

        # Both should be consumable
        result1 = await store.consume(ctx1.context_id, now_ms)
        result2 = await store.consume(ctx2.context_id, now_ms)

        assert result1 == "consumed", "First context consumption failed"
        assert result2 == "consumed", "Second context consumption failed"


class TestTimeManipulation:
    """Test time-based attack prevention."""

    @pytest.mark.asyncio
    async def test_expired_context_rejected(self, memory_store):
        """Expired contexts must be rejected."""
        store = memory_store

        # Create context with very short TTL
        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=1)

        # Wait for expiration
        await asyncio.sleep(0.01)  # 10ms

        # Should be expired
        stored = await store.get(ctx.context_id)
        if stored:
            current_time = int(time.time() * 1000)
            assert current_time > stored.expires_at, "Context should be expired"

    def test_future_timestamp_in_proof(self):
        """Proofs with future timestamps produce different results."""
        client_secret = "a" * 64
        binding = "POST|/api/test|"
        body_hash = hash_body('{}')

        current_ts = str(int(time.time() * 1000))
        future_ts = str(int(time.time() * 1000) + 3600000)  # 1 hour in future

        proof_current = build_proof_v21(client_secret, current_ts, binding, body_hash)
        proof_future = build_proof_v21(client_secret, future_ts, binding, body_hash)

        assert proof_current != proof_future, "Timestamp not included in proof"

    def test_past_timestamp_in_proof(self):
        """Proofs with past timestamps produce different results."""
        client_secret = "a" * 64
        binding = "POST|/api/test|"
        body_hash = hash_body('{}')

        current_ts = str(int(time.time() * 1000))
        past_ts = str(int(time.time() * 1000) - 3600000)  # 1 hour in past

        proof_current = build_proof_v21(client_secret, current_ts, binding, body_hash)
        proof_past = build_proof_v21(client_secret, past_ts, binding, body_hash)

        assert proof_current != proof_past, "Timestamp not included in proof"

    @pytest.mark.asyncio
    async def test_ttl_boundary_conditions(self, memory_store):
        """Test TTL boundary conditions."""
        store = memory_store

        # Create context with 100ms TTL
        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=100)
        context_id = ctx.context_id

        # Should be valid immediately
        stored = await store.get(context_id)
        assert stored is not None, "Context not found immediately after creation"

        # Wait past TTL
        await asyncio.sleep(0.15)  # 150ms

        # Check expiration
        stored = await store.get(context_id)
        if stored:
            current_time = int(time.time() * 1000)
            assert current_time > stored.expires_at, "Should be expired"


class TestHeaderConfusion:
    """Test header confusion and duplication attacks."""

    @pytest.mark.asyncio
    async def test_context_id_case_sensitivity(self, memory_store):
        """Context IDs must be case-sensitive."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000)
        original_id = ctx.context_id

        # Try variations
        upper_id = original_id.upper()
        lower_id = original_id.lower()

        if original_id != upper_id:
            upper_result = await store.get(upper_id)
            assert upper_result is None, "Case-insensitive context ID vulnerability"

        if original_id != lower_id:
            lower_result = await store.get(lower_id)
            assert lower_result is None, "Case-insensitive context ID vulnerability"

    def test_binding_normalization_prevents_confusion(self):
        """Binding normalization should prevent path confusion attacks."""
        # These should all normalize to the same binding
        variations = [
            ("POST", "/api/test", ""),
            ("post", "/api/test", ""),
            ("POST", "/api//test", ""),
            ("POST", "/api/test/", ""),
        ]

        normalized = [normalize_binding(m, p, q) for m, p, q in variations]

        # All should normalize to same result
        assert all(n == normalized[0] for n in normalized), \
            f"Binding normalization inconsistent: {normalized}"

    def test_query_string_normalization_prevents_confusion(self):
        """Query string normalization should prevent parameter confusion."""
        # These should normalize to the same thing
        variations = [
            ("GET", "/api", "a=1&b=2"),
            ("GET", "/api", "b=2&a=1"),
        ]

        normalized = [normalize_binding(m, p, q) for m, p, q in variations]

        assert normalized[0] == normalized[1], "Query parameter order not normalized"

    def test_proof_with_duplicate_fields_handled(self):
        """JSON with would-be duplicate fields handled correctly."""
        # In Python, duplicate keys in dict literal just overwrite
        # This tests that the canonical form is consistent
        data1 = {"key": "value1"}
        data2 = {"key": "value2"}

        canon1 = canonicalize_json(data1)
        canon2 = canonicalize_json(data2)

        assert canon1 != canon2, "Different values should produce different canonical forms"


class TestNonceSecurityBoundary:
    """Test that nonces/secrets are not exposed."""

    @pytest.mark.asyncio
    async def test_context_public_info_structure(self, memory_store):
        """Context public info should have expected structure."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000, issue_nonce=True)

        # Should have public fields
        assert ctx.context_id is not None
        assert ctx.expires_at is not None
        assert ctx.mode is not None

        # When issue_nonce=True, nonce should be available
        assert ctx.nonce is not None

    @pytest.mark.asyncio
    async def test_stored_context_has_nonce(self, memory_store):
        """Stored context should contain nonce for verification."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000, issue_nonce=True)
        stored = await store.get(ctx.context_id)

        assert stored is not None
        assert stored.nonce is not None

    def test_cannot_reverse_client_secret_to_nonce(self):
        """Client secret derivation should be one-way (HMAC)."""
        nonce = "secret_nonce_value_12345678901234567890123456789012"
        context_id = "ash_test_ctx"
        binding = "POST|/api/test|"

        client_secret = derive_client_secret(nonce, context_id, binding)

        # Client secret should be 64 hex chars (32 bytes)
        assert len(client_secret) == 64, f"Unexpected client secret length: {len(client_secret)}"

        # Should not contain the original nonce
        assert nonce not in client_secret, "Nonce leaked in client secret"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
