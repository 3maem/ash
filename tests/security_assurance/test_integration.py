"""
ASH Security Assurance Pack - Integration Tests
================================================
B. Integration Tests:
- Valid request lifecycle (create → verify → consume)
- Expired context/TTL enforcement
- Backend consistency (atomic updates)
"""

import pytest
import sys
import os
import time
import asyncio
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))

from ash.core import (
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


class TestValidRequestLifecycle:
    """Test the complete request lifecycle."""

    @pytest.mark.asyncio
    async def test_create_verify_consume_cycle(self, memory_store):
        """Test complete lifecycle: create context → build proof → verify → consume."""
        store = memory_store
        binding = "POST|/api/transfer|"
        payload = {"amount": 100, "recipient": "user123"}

        # Step 1: Create context
        ctx = await context.create(store, binding=binding, ttl_ms=30000, issue_nonce=True)
        assert ctx.context_id is not None
        assert ctx.nonce is not None

        context_id = ctx.context_id
        nonce = ctx.nonce

        # Step 2: Get stored context to retrieve details
        stored = await store.get(context_id)
        assert stored is not None

        # Step 3: Build proof (client-side simulation)
        client_secret = derive_client_secret(nonce, context_id, binding)
        canonical_payload = canonicalize_json(payload)
        body_hash = hash_body(canonical_payload)
        timestamp = str(int(time.time() * 1000))
        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        assert proof is not None
        assert len(proof) == 64  # HMAC-SHA256 hex

        # Step 4: Verify proof (server-side)
        is_valid = verify_proof_v21(nonce, context_id, binding, timestamp, body_hash, proof)
        assert is_valid, "Valid proof should verify"

        # Step 5: Consume context
        now_ms = int(time.time() * 1000)
        result = await store.consume(context_id, now_ms)
        assert result == "consumed", "Context should be consumable"

        # Step 6: Replay should fail
        result2 = await store.consume(context_id, now_ms)
        assert result2 == "already_consumed", "Consumed context should not be re-consumable"

    @pytest.mark.asyncio
    async def test_multiple_contexts_independent(self, memory_store):
        """Multiple contexts should operate independently."""
        store = memory_store
        num_contexts = 10

        contexts = []
        for i in range(num_contexts):
            binding = f"POST|/api/endpoint_{i}|"
            ctx = await context.create(store, binding=binding, ttl_ms=30000, issue_nonce=True)
            contexts.append((ctx, binding))

        # Each context should be independently verifiable and consumable
        for ctx, binding in contexts:
            context_id = ctx.context_id
            nonce = ctx.nonce

            client_secret = derive_client_secret(nonce, context_id, binding)
            body_hash = hash_body('{}')
            timestamp = str(int(time.time() * 1000))
            proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

            # Verify
            assert verify_proof_v21(nonce, context_id, binding, timestamp, body_hash, proof)

            # Consume
            now_ms = int(time.time() * 1000)
            result = await store.consume(context_id, now_ms)
            assert result == "consumed"

    @pytest.mark.asyncio
    async def test_full_request_simulation(self, memory_store):
        """Simulate a complete HTTP request flow."""
        store = memory_store

        # === Server: Issue context ===
        endpoint_binding = normalize_binding("POST", "/api/payments", "")
        ctx = await context.create(store, binding=endpoint_binding, ttl_ms=30000, issue_nonce=True)

        # === Client: Receive context info ===
        client_context_id = ctx.context_id
        client_nonce = ctx.nonce
        client_expires_at = ctx.expires_at

        # === Client: Prepare request ===
        request_body = {
            "amount": 250.00,
            "currency": "USD",
            "recipient": {
                "id": "user_abc123",
                "name": "John Doe"
            }
        }

        canonical_body = canonicalize_json(request_body)
        client_secret = derive_client_secret(client_nonce, client_context_id, endpoint_binding)
        body_hash = hash_body(canonical_body)
        timestamp = str(int(time.time() * 1000))
        proof = build_proof_v21(client_secret, timestamp, endpoint_binding, body_hash)

        # === Client: Send request headers ===
        headers = {
            "X-ASH-Context-ID": client_context_id,
            "X-ASH-Timestamp": timestamp,
            "X-ASH-Proof": proof,
        }

        # === Server: Verify request ===
        # 1. Get stored context
        stored = await store.get(headers["X-ASH-Context-ID"])
        assert stored is not None, "Context not found"

        # 2. Check not expired
        current_time = int(time.time() * 1000)
        assert current_time < stored.expires_at, "Context expired"

        # 3. Verify proof
        server_body_hash = hash_body(canonical_body)
        is_valid = verify_proof_v21(
            stored.nonce,
            headers["X-ASH-Context-ID"],
            endpoint_binding,
            headers["X-ASH-Timestamp"],
            server_body_hash,
            headers["X-ASH-Proof"]
        )
        assert is_valid, "Proof verification failed"

        # 4. Consume context
        result = await store.consume(headers["X-ASH-Context-ID"], current_time)
        assert result == "consumed", "Context consumption failed"


class TestExpiredContextTTLEnforcement:
    """Test TTL and expiration enforcement."""

    @pytest.mark.asyncio
    async def test_context_valid_before_ttl(self, memory_store):
        """Context should be valid before TTL expires."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=5000)
        context_id = ctx.context_id

        # Immediately should be valid
        stored = await store.get(context_id)
        assert stored is not None
        assert int(time.time() * 1000) < stored.expires_at

    @pytest.mark.asyncio
    async def test_context_expired_after_ttl(self, memory_store):
        """Context should be expired after TTL."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=50)  # 50ms
        context_id = ctx.context_id

        # Wait for expiration
        await asyncio.sleep(0.1)  # 100ms

        stored = await store.get(context_id)
        if stored:
            current_time = int(time.time() * 1000)
            assert current_time >= stored.expires_at, "Context should be expired"

    @pytest.mark.asyncio
    async def test_ttl_boundary_precision(self, memory_store):
        """TTL should be precise to milliseconds."""
        store = memory_store
        ttl_ms = 100  # 100ms

        start = int(time.time() * 1000)
        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=ttl_ms)

        stored = await store.get(ctx.context_id)
        assert stored is not None

        # Expiration should be approximately start + ttl_ms
        expected_expiry = start + ttl_ms
        actual_expiry = stored.expires_at

        # Allow 50ms tolerance for execution time
        assert abs(actual_expiry - expected_expiry) < 50, \
            f"TTL precision issue: expected ~{expected_expiry}, got {actual_expiry}"

    @pytest.mark.asyncio
    async def test_different_ttl_values(self, memory_store):
        """Different TTL values should be respected."""
        store = memory_store

        # Short TTL
        ctx_short = await context.create(store, binding="POST|/api/a|", ttl_ms=100)

        # Long TTL
        ctx_long = await context.create(store, binding="POST|/api/b|", ttl_ms=60000)

        short_stored = await store.get(ctx_short.context_id)
        long_stored = await store.get(ctx_long.context_id)

        assert long_stored.expires_at > short_stored.expires_at


class TestBackendConsistency:
    """Test backend consistency and atomic operations."""

    @pytest.mark.asyncio
    async def test_atomic_consume_single_thread(self, memory_store):
        """Consume should be atomic (single thread baseline)."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000)
        context_id = ctx.context_id
        now_ms = int(time.time() * 1000)

        # First consume succeeds
        result1 = await store.consume(context_id, now_ms)
        assert result1 == "consumed"

        # Second consume fails
        result2 = await store.consume(context_id, now_ms)
        assert result2 == "already_consumed"

    @pytest.mark.asyncio
    async def test_atomic_consume_concurrent(self, memory_store):
        """Only one concurrent consume should succeed (atomicity test)."""
        store = memory_store
        num_tasks = 50
        results: List[str] = []

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000)
        context_id = ctx.context_id
        now_ms = int(time.time() * 1000)

        async def try_consume():
            result = await store.consume(context_id, now_ms)
            results.append(result)

        # Run all consume attempts concurrently
        await asyncio.gather(*[try_consume() for _ in range(num_tasks)])

        success_count = sum(1 for r in results if r == "consumed")
        assert success_count == 1, f"Atomicity violation: {success_count} successful consumes"

    @pytest.mark.asyncio
    async def test_context_state_consistency(self, memory_store):
        """Context state should remain consistent under concurrent reads."""
        store = memory_store

        ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000)
        context_id = ctx.context_id
        expected_binding = "POST|/api/test|"

        read_results = []

        async def read_context():
            for _ in range(100):
                stored = await store.get(context_id)
                if stored:
                    read_results.append(stored.binding)

        # Run concurrent reads
        await asyncio.gather(*[read_context() for _ in range(10)])

        # All reads should return consistent binding
        for binding in read_results:
            assert binding == expected_binding, "Binding inconsistency detected"

    @pytest.mark.asyncio
    async def test_parallel_context_creation(self, memory_store):
        """Parallel context creation should not cause conflicts."""
        store = memory_store
        num_tasks = 10
        contexts_per_task = 100
        all_ids: List[str] = []

        async def create_contexts(task_id: int):
            ids = []
            for i in range(contexts_per_task):
                ctx = await context.create(store, binding=f"POST|/api/{task_id}/{i}|", ttl_ms=30000)
                ids.append(ctx.context_id)
            return ids

        # Run parallel creations
        results = await asyncio.gather(*[create_contexts(i) for i in range(num_tasks)])
        for ids in results:
            all_ids.extend(ids)

        # All IDs should be unique
        assert len(all_ids) == num_tasks * contexts_per_task
        assert len(set(all_ids)) == len(all_ids), "Duplicate context IDs generated"


class TestEndToEndScenarios:
    """End-to-end integration scenarios."""

    @pytest.mark.asyncio
    async def test_payment_flow(self, memory_store):
        """Simulate a payment API flow."""
        store = memory_store

        # 1. Client requests context for payment
        binding = normalize_binding("POST", "/api/payments", "")
        ctx = await context.create(store, binding=binding, ttl_ms=30000, issue_nonce=True)

        # 2. Client prepares payment
        payment = {
            "from_account": "ACC001",
            "to_account": "ACC002",
            "amount": 500.00,
            "currency": "USD"
        }

        client_secret = derive_client_secret(ctx.nonce, ctx.context_id, binding)
        canonical = canonicalize_json(payment)
        body_hash = hash_body(canonical)
        timestamp = str(int(time.time() * 1000))
        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        # 3. Server verifies and processes
        is_valid = verify_proof_v21(
            ctx.nonce,
            ctx.context_id,
            binding,
            timestamp,
            body_hash,
            proof
        )
        assert is_valid

        now_ms = int(time.time() * 1000)
        result = await store.consume(ctx.context_id, now_ms)
        assert result == "consumed"

        # 4. Attempt replay (should fail)
        replay_result = await store.consume(ctx.context_id, now_ms)
        assert replay_result == "already_consumed"

    @pytest.mark.asyncio
    async def test_multi_step_workflow(self, memory_store):
        """Test multi-step workflow with multiple contexts."""
        store = memory_store

        # Step 1: Initiate workflow
        step1_binding = normalize_binding("POST", "/api/workflow/start", "")
        step1_ctx = await context.create(store, binding=step1_binding, ttl_ms=30000, issue_nonce=True)

        step1_payload = {"workflow_type": "approval", "item_id": "ITEM001"}
        step1_secret = derive_client_secret(step1_ctx.nonce, step1_ctx.context_id, step1_binding)
        step1_timestamp = str(int(time.time() * 1000))
        step1_hash = hash_body(canonicalize_json(step1_payload))
        step1_proof = build_proof_v21(step1_secret, step1_timestamp, step1_binding, step1_hash)

        # Verify and consume step 1
        assert verify_proof_v21(
            step1_ctx.nonce,
            step1_ctx.context_id,
            step1_binding,
            step1_timestamp,
            step1_hash,
            step1_proof
        )
        now_ms = int(time.time() * 1000)
        await store.consume(step1_ctx.context_id, now_ms)

        # Step 2: Approval
        step2_binding = normalize_binding("POST", "/api/workflow/approve", "")
        step2_ctx = await context.create(store, binding=step2_binding, ttl_ms=30000, issue_nonce=True)

        step2_payload = {"item_id": "ITEM001", "approved": True}
        step2_secret = derive_client_secret(step2_ctx.nonce, step2_ctx.context_id, step2_binding)
        step2_hash = hash_body(canonicalize_json(step2_payload))
        step2_timestamp = str(int(time.time() * 1000))
        step2_proof = build_proof_v21(step2_secret, step2_timestamp, step2_binding, step2_hash)

        # Verify and consume step 2
        assert verify_proof_v21(
            step2_ctx.nonce,
            step2_ctx.context_id,
            step2_binding,
            step2_timestamp,
            step2_hash,
            step2_proof
        )
        await store.consume(step2_ctx.context_id, now_ms)

    @pytest.mark.asyncio
    async def test_high_value_transaction_protection(self, memory_store):
        """Test protection for high-value transactions."""
        store = memory_store
        binding = normalize_binding("POST", "/api/transfer", "")

        # Create context with shorter TTL for high-value
        ctx = await context.create(store, binding=binding, ttl_ms=10000, issue_nonce=True)

        transaction = {
            "amount": 1000000,  # $1M
            "currency": "USD",
            "from": "CORP_ACC_001",
            "to": "EXTERNAL_ACC_999",
            "reference": "WIRE-2024-001"
        }

        client_secret = derive_client_secret(ctx.nonce, ctx.context_id, binding)
        canonical = canonicalize_json(transaction)
        body_hash = hash_body(canonical)
        timestamp = str(int(time.time() * 1000))

        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        # Verify integrity
        assert verify_proof_v21(
            ctx.nonce,
            ctx.context_id,
            binding,
            timestamp,
            body_hash,
            proof
        )

        # Test tampering detection
        tampered_transaction = transaction.copy()
        tampered_transaction["amount"] = 10000000  # 10x

        tampered_hash = hash_body(canonicalize_json(tampered_transaction))

        # Same proof should NOT verify with tampered hash
        assert not verify_proof_v21(
            ctx.nonce,
            ctx.context_id,
            binding,
            timestamp,
            tampered_hash,
            proof
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
