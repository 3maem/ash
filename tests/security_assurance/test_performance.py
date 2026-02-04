"""
ASH Security Assurance Pack - Performance & Load Tests
=======================================================
E. Performance & Load:
- Signing/verification latency
- Throughput under burst traffic
- Degradation behavior (fail-secure)
"""

import pytest
import sys
import os
import time
import statistics
import asyncio
from typing import List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))

from ash.core import (
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
    build_proof,
    BuildProofInput,
    build_proof_v21,
    verify_proof_v21,
    derive_client_secret,
    hash_body,
    timing_safe_compare,
)
from ash.server import context, stores


@pytest.fixture
def memory_store():
    """Provide a fresh memory store for each test."""
    return stores.Memory(suppress_warning=True)


class TestSigningLatency:
    """Test signing/proof generation latency."""

    def test_canonicalize_json_latency(self):
        """JSON canonicalization should complete within acceptable time."""
        payload = {
            "user": {"id": 123, "name": "Test User"},
            "items": [{"id": i, "price": i * 10} for i in range(10)],
            "metadata": {"timestamp": 1704067200000, "version": "1.0"}
        }

        iterations = 1000
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            canonicalize_json(payload)
            times.append(time.perf_counter() - start)

        avg_ms = statistics.mean(times) * 1000
        p99_ms = sorted(times)[int(iterations * 0.99)] * 1000

        print(f"\nJSON canonicalization: avg={avg_ms:.3f}ms, p99={p99_ms:.3f}ms")

        # Should complete in under 1ms on average
        assert avg_ms < 1.0, f"Canonicalization too slow: {avg_ms:.3f}ms average"
        assert p99_ms < 5.0, f"Canonicalization p99 too slow: {p99_ms:.3f}ms"

    def test_proof_generation_latency(self):
        """Proof generation should complete within acceptable time."""
        canonical_payload = '{"amount":100,"recipient":"user123"}'
        binding = "POST|/api/transfer|"
        context_id = "ash_test_ctx_123456"

        iterations = 1000
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            input_data = BuildProofInput(
                mode="balanced",
                binding=binding,
                context_id=context_id,
                canonical_payload=canonical_payload
            )
            build_proof(input_data)
            times.append(time.perf_counter() - start)

        avg_ms = statistics.mean(times) * 1000
        p99_ms = sorted(times)[int(iterations * 0.99)] * 1000

        print(f"\nProof generation: avg={avg_ms:.3f}ms, p99={p99_ms:.3f}ms")

        # Should complete in under 0.5ms on average
        assert avg_ms < 0.5, f"Proof generation too slow: {avg_ms:.3f}ms average"
        assert p99_ms < 2.0, f"Proof generation p99 too slow: {p99_ms:.3f}ms"

    def test_v21_proof_generation_latency(self):
        """v2.1 proof generation should complete within acceptable time."""
        client_secret = "a" * 64
        timestamp = "1704067200000"
        binding = "POST|/api/transfer|"
        body_hash = hash_body('{"amount":100}')

        iterations = 1000
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            build_proof_v21(client_secret, timestamp, binding, body_hash)
            times.append(time.perf_counter() - start)

        avg_ms = statistics.mean(times) * 1000
        p99_ms = sorted(times)[int(iterations * 0.99)] * 1000

        print(f"\nv2.1 proof generation: avg={avg_ms:.3f}ms, p99={p99_ms:.3f}ms")

        assert avg_ms < 0.5, f"v2.1 proof generation too slow: {avg_ms:.3f}ms average"
        assert p99_ms < 2.0, f"v2.1 proof generation p99 too slow: {p99_ms:.3f}ms"

    def test_client_secret_derivation_latency(self):
        """Client secret derivation should complete within acceptable time."""
        nonce = "0123456789abcdef" * 4
        context_id = "ash_ctx_test"
        binding = "POST|/api/test|"

        iterations = 1000
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            derive_client_secret(nonce, context_id, binding)
            times.append(time.perf_counter() - start)

        avg_ms = statistics.mean(times) * 1000
        p99_ms = sorted(times)[int(iterations * 0.99)] * 1000

        print(f"\nClient secret derivation: avg={avg_ms:.3f}ms, p99={p99_ms:.3f}ms")

        assert avg_ms < 0.5, f"Secret derivation too slow: {avg_ms:.3f}ms average"


class TestVerificationLatency:
    """Test verification latency."""

    def test_v21_verification_latency(self):
        """v2.1 verification should complete within acceptable time."""
        nonce = "0123456789abcdef" * 4
        context_id = "ash_test_ctx"
        binding = "POST|/api/transfer|"
        timestamp = "1704067200000"
        body_hash = hash_body('{"amount":100}')

        client_secret = derive_client_secret(nonce, context_id, binding)
        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        iterations = 1000
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            verify_proof_v21(nonce, context_id, binding, timestamp, body_hash, proof)
            times.append(time.perf_counter() - start)

        avg_ms = statistics.mean(times) * 1000
        p99_ms = sorted(times)[int(iterations * 0.99)] * 1000

        print(f"\nv2.1 verification: avg={avg_ms:.3f}ms, p99={p99_ms:.3f}ms")

        assert avg_ms < 1.0, f"Verification too slow: {avg_ms:.3f}ms average"
        assert p99_ms < 3.0, f"Verification p99 too slow: {p99_ms:.3f}ms"

    def test_timing_safe_compare_latency(self):
        """Timing-safe comparison should complete within acceptable time."""
        str1 = "a" * 64
        str2 = "a" * 64

        iterations = 10000
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            timing_safe_compare(str1, str2)
            times.append(time.perf_counter() - start)

        avg_us = statistics.mean(times) * 1_000_000
        p99_us = sorted(times)[int(iterations * 0.99)] * 1_000_000

        print(f"\nTiming-safe compare: avg={avg_us:.2f}us, p99={p99_us:.2f}us")

        # Should be very fast (under 100 microseconds)
        assert avg_us < 100, f"Compare too slow: {avg_us:.2f}us average"


class TestThroughput:
    """Test throughput under load."""

    def test_proof_generation_throughput(self):
        """Measure proof generation throughput."""
        canonical_payload = '{"amount":100}'
        binding = "POST|/api/test|"

        duration_seconds = 2
        count = 0
        start = time.perf_counter()

        while time.perf_counter() - start < duration_seconds:
            input_data = BuildProofInput(
                mode="balanced",
                binding=binding,
                context_id=f"ctx_{count}",
                canonical_payload=canonical_payload
            )
            build_proof(input_data)
            count += 1

        elapsed = time.perf_counter() - start
        throughput = count / elapsed

        print(f"\nProof generation throughput: {throughput:.0f} ops/sec")

        # Should handle at least 10,000 ops/sec
        assert throughput > 10000, f"Throughput too low: {throughput:.0f} ops/sec"

    def test_concurrent_proof_generation(self):
        """Test concurrent proof generation throughput."""
        canonical_payload = '{"amount":100}'
        binding = "POST|/api/test|"
        num_workers = 4
        operations_per_worker = 1000

        def generate_proofs(worker_id: int) -> Tuple[int, float]:
            start = time.perf_counter()
            for i in range(operations_per_worker):
                input_data = BuildProofInput(
                    mode="balanced",
                    binding=binding,
                    context_id=f"ctx_{worker_id}_{i}",
                    canonical_payload=canonical_payload
                )
                build_proof(input_data)
            return operations_per_worker, time.perf_counter() - start

        start_total = time.perf_counter()

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            results = list(executor.map(generate_proofs, range(num_workers)))

        total_time = time.perf_counter() - start_total
        total_ops = sum(r[0] for r in results)
        throughput = total_ops / total_time

        print(f"\nConcurrent proof throughput ({num_workers} workers): {throughput:.0f} ops/sec")

        # Should scale reasonably with workers
        assert throughput > 20000, f"Concurrent throughput too low: {throughput:.0f} ops/sec"

    @pytest.mark.asyncio
    async def test_context_creation_throughput(self, memory_store):
        """Test context creation throughput."""
        store = memory_store
        binding = "POST|/api/test|"

        iterations = 1000
        start = time.perf_counter()

        for _ in range(iterations):
            await context.create(store, binding=binding, ttl_ms=30000)

        elapsed = time.perf_counter() - start
        throughput = iterations / elapsed

        print(f"\nContext creation throughput: {throughput:.0f} ops/sec")

        assert throughput > 5000, f"Context creation throughput too low: {throughput:.0f} ops/sec"

    def test_hash_throughput(self):
        """Test hashing throughput."""
        payload = '{"amount":100,"recipient":"user123","note":"test"}'

        duration_seconds = 2
        count = 0
        start = time.perf_counter()

        while time.perf_counter() - start < duration_seconds:
            hash_body(payload)
            count += 1

        elapsed = time.perf_counter() - start
        throughput = count / elapsed

        print(f"\nHash throughput: {throughput:.0f} ops/sec")

        assert throughput > 100000, f"Hash throughput too low: {throughput:.0f} ops/sec"


class TestBurstTraffic:
    """Test behavior under burst traffic."""

    def test_burst_proof_generation(self):
        """System should handle sudden bursts of requests."""
        canonical_payload = '{"amount":100}'
        binding = "POST|/api/test|"
        burst_size = 1000

        # Warm up
        for i in range(100):
            input_data = BuildProofInput(
                mode="balanced",
                binding=binding,
                context_id=f"warmup_{i}",
                canonical_payload=canonical_payload
            )
            build_proof(input_data)

        # Burst
        start = time.perf_counter()
        for i in range(burst_size):
            input_data = BuildProofInput(
                mode="balanced",
                binding=binding,
                context_id=f"burst_{i}",
                canonical_payload=canonical_payload
            )
            build_proof(input_data)
        burst_time = time.perf_counter() - start

        burst_rate = burst_size / burst_time

        print(f"\nBurst handling: {burst_size} ops in {burst_time*1000:.1f}ms ({burst_rate:.0f} ops/sec)")

        assert burst_rate > 10000, f"Burst handling too slow: {burst_rate:.0f} ops/sec"

    @pytest.mark.asyncio
    async def test_burst_context_operations(self, memory_store):
        """Context store should handle burst operations."""
        store = memory_store
        binding = "POST|/api/test|"
        burst_size = 500

        # Create contexts in burst
        contexts = []
        start = time.perf_counter()
        for _ in range(burst_size):
            ctx = await context.create(store, binding=binding, ttl_ms=30000)
            contexts.append(ctx.context_id)
        create_time = time.perf_counter() - start

        # Consume contexts in burst
        now_ms = int(time.time() * 1000)
        start = time.perf_counter()
        for ctx_id in contexts:
            await store.consume(ctx_id, now_ms)
        consume_time = time.perf_counter() - start

        create_rate = burst_size / create_time
        consume_rate = burst_size / consume_time

        print(f"\nBurst context create: {create_rate:.0f} ops/sec")
        print(f"Burst context consume: {consume_rate:.0f} ops/sec")

        assert create_rate > 5000, f"Burst create too slow: {create_rate:.0f} ops/sec"
        assert consume_rate > 5000, f"Burst consume too slow: {consume_rate:.0f} ops/sec"


class TestDegradationBehavior:
    """Test graceful degradation under stress."""

    def test_large_payload_handling(self):
        """System should handle large payloads without failure."""
        # Create increasingly large payloads
        sizes = [1, 10, 100, 1000, 10000]  # KB

        for size_kb in sizes:
            payload = {"data": "x" * (size_kb * 1024)}
            canonical = canonicalize_json(payload)

            start = time.perf_counter()
            input_data = BuildProofInput(
                mode="balanced",
                binding="POST /test",
                context_id="ctx1",
                canonical_payload=canonical
            )
            proof = build_proof(input_data)
            elapsed = time.perf_counter() - start

            assert proof is not None, f"Failed on {size_kb}KB payload"
            print(f"\n{size_kb}KB payload: {elapsed*1000:.2f}ms")

    @pytest.mark.asyncio
    async def test_memory_store_under_load(self, memory_store):
        """Memory store should remain stable under load."""
        store = memory_store
        binding = "POST|/api/test|"
        num_contexts = 10000

        # Create many contexts
        context_ids = []
        for i in range(num_contexts):
            ctx = await context.create(store, binding=binding, ttl_ms=60000)
            context_ids.append(ctx.context_id)

        # Verify store is queryable
        for ctx_id in context_ids[:100]:  # Spot check
            stored = await store.get(ctx_id)
            assert stored is not None, f"Context {ctx_id} not found"

        # Consume all
        now_ms = int(time.time() * 1000)
        consumed = 0
        for ctx_id in context_ids:
            result = await store.consume(ctx_id, now_ms)
            if result == "consumed":
                consumed += 1

        assert consumed == num_contexts, f"Only consumed {consumed}/{num_contexts}"

    def test_verification_failure_does_not_crash(self):
        """Verification failures should not cause crashes."""
        nonce = "a" * 64
        context_id = "ash_test"
        binding = "POST|/api/test|"
        timestamp = "1234567890"
        body_hash = hash_body('{}')

        # Generate many invalid proofs
        for i in range(1000):
            invalid_proof = f"invalid_proof_{i}" + "0" * 50
            result = verify_proof_v21(nonce, context_id, binding, timestamp, body_hash, invalid_proof)
            assert result == False, "Invalid proof should not verify"

    @pytest.mark.asyncio
    async def test_concurrent_stress(self, memory_store):
        """System should remain stable under concurrent stress."""
        store = memory_store
        binding = "POST|/api/test|"
        errors: List[str] = []

        async def stress_worker(worker_id: int):
            try:
                for i in range(100):
                    # Create context
                    ctx = await context.create(store, binding=binding, ttl_ms=30000, issue_nonce=True)

                    # Generate proof
                    nonce = ctx.nonce
                    context_id = ctx.context_id
                    client_secret = derive_client_secret(nonce, context_id, binding)
                    body_hash = hash_body(f'{{"worker":{worker_id},"i":{i}}}')
                    proof = build_proof_v21(client_secret, str(int(time.time() * 1000)), binding, body_hash)

                    # Consume
                    now_ms = int(time.time() * 1000)
                    await store.consume(context_id, now_ms)

            except Exception as e:
                errors.append(f"Worker {worker_id}: {e}")

        # Run concurrent workers
        await asyncio.gather(*[stress_worker(i) for i in range(10)])

        assert len(errors) == 0, f"Errors during stress test: {errors}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
