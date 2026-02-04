"""
Stress Tests for ASH Protocol.

Tests for high volume, concurrent operations, and performance characteristics.
"""

import asyncio
import hashlib
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest
from ash.core.proof import (
    ash_build_proof_hmac,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_hash_proof,
    ash_verify_proof,
    ash_verify_proof_unified,
)
from ash.core.canonicalize import (
    ash_canonicalize_json,
    ash_canonicalize_query,
    ash_canonicalize_url_encoded,
    ash_normalize_binding,
)
from ash.core.compare import ash_timing_safe_equal


class TestHighVolumeHashing:
    """Tests for high-volume hash operations."""

    def test_hash_many_bodies(self):
        """Should hash many bodies efficiently."""
        start = time.time()
        hashes = set()

        for i in range(10000):
            h = ash_hash_body(f"body_content_{i}")
            hashes.add(h)

        elapsed = time.time() - start

        # All hashes should be unique
        assert len(hashes) == 10000
        # Should complete in reasonable time (< 5 seconds)
        assert elapsed < 5

    def test_hash_large_bodies(self):
        """Should hash large bodies efficiently."""
        large_body = "x" * 1_000_000  # 1MB

        start = time.time()
        for _ in range(100):
            ash_hash_body(large_body)
        elapsed = time.time() - start

        # 100 hashes of 1MB should complete in < 5 seconds
        assert elapsed < 5

    def test_hash_varied_sizes(self):
        """Should handle varied body sizes."""
        hashes = []
        for size in [0, 1, 10, 100, 1000, 10000, 100000]:
            body = "x" * size
            h = ash_hash_body(body)
            hashes.append(h)

        # All sizes should produce valid 64-char hashes
        assert all(len(h) == 64 for h in hashes)
        # All hashes should be unique
        assert len(set(hashes)) == len(hashes)


class TestHighVolumeProofGeneration:
    """Tests for high-volume proof generation."""

    def test_generate_many_proofs(self):
        """Should generate many proofs efficiently."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        start = time.time()
        proofs = []

        for i in range(5000):
            body_hash = ash_hash_body(f"body_{i}")
            proof = ash_build_proof_hmac(client_secret, str(i), binding, body_hash)
            proofs.append(proof)

        elapsed = time.time() - start

        # All proofs should be unique
        assert len(set(proofs)) == 5000
        # Should complete in reasonable time
        assert elapsed < 10

    def test_generate_unified_proofs_volume(self):
        """Should generate many unified proofs."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        start = time.time()

        for i in range(2000):
            payload = {"index": i, "data": "test"}
            ash_build_proof_unified(client_secret, str(i), binding, payload)

        elapsed = time.time() - start
        assert elapsed < 10


class TestHighVolumeVerification:
    """Tests for high-volume verification."""

    def test_verify_many_proofs(self):
        """Should verify many proofs efficiently."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        # Generate proofs
        test_data = []
        for i in range(2000):
            body_hash = ash_hash_body(f"body_{i}")
            proof = ash_build_proof_hmac(client_secret, str(i), binding, body_hash)
            test_data.append((str(i), body_hash, proof))

        # Verify all proofs
        start = time.time()
        results = []

        for timestamp, body_hash, proof in test_data:
            result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
            results.append(result)

        elapsed = time.time() - start

        # All should verify successfully
        assert all(results)
        # Should complete in reasonable time
        assert elapsed < 10

    def test_verify_invalid_proofs_volume(self):
        """Should reject many invalid proofs quickly."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"

        start = time.time()

        for i in range(2000):
            body_hash = ash_hash_body(f"body_{i}")
            wrong_proof = "0" * 64
            result = ash_verify_proof(nonce, context_id, binding, str(i), body_hash, wrong_proof)
            assert result is False

        elapsed = time.time() - start
        assert elapsed < 10


class TestConcurrentOperations:
    """Tests for concurrent operations."""

    def test_concurrent_hash_generation(self):
        """Should handle concurrent hash generation."""
        def hash_worker(worker_id):
            hashes = []
            for i in range(500):
                h = ash_hash_body(f"worker_{worker_id}_data_{i}")
                hashes.append(h)
            return hashes

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(hash_worker, i) for i in range(10)]
            all_hashes = []
            for future in as_completed(futures):
                all_hashes.extend(future.result())

        # All hashes should be unique (5000 total)
        assert len(set(all_hashes)) == 5000

    def test_concurrent_proof_generation(self):
        """Should handle concurrent proof generation."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        def proof_worker(worker_id):
            proofs = []
            for i in range(200):
                body_hash = ash_hash_body(f"worker_{worker_id}_body_{i}")
                timestamp = f"{worker_id}_{i}"
                proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
                proofs.append(proof)
            return proofs

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(proof_worker, i) for i in range(10)]
            all_proofs = []
            for future in as_completed(futures):
                all_proofs.extend(future.result())

        # All proofs should be unique (2000 total)
        assert len(set(all_proofs)) == 2000

    def test_concurrent_verification(self):
        """Should handle concurrent verification."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        # Pre-generate test data
        test_data = []
        for i in range(1000):
            body_hash = ash_hash_body(f"body_{i}")
            proof = ash_build_proof_hmac(client_secret, str(i), binding, body_hash)
            test_data.append((str(i), body_hash, proof))

        def verify_worker(start_idx, count):
            results = []
            for i in range(start_idx, start_idx + count):
                timestamp, body_hash, proof = test_data[i]
                result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
                results.append(result)
            return results

        with ThreadPoolExecutor(max_workers=10) as executor:
            chunk_size = 100
            futures = []
            for i in range(10):
                future = executor.submit(verify_worker, i * chunk_size, chunk_size)
                futures.append(future)

            all_results = []
            for future in as_completed(futures):
                all_results.extend(future.result())

        # All verifications should pass
        assert all(all_results)


class TestCanonicalizationStress:
    """Stress tests for canonicalization."""

    def test_canonicalize_many_json_objects(self):
        """Should canonicalize many JSON objects."""
        start = time.time()

        for i in range(5000):
            obj = {"index": i, "data": f"value_{i}", "nested": {"a": 1, "b": 2}}
            ash_canonicalize_json(obj)

        elapsed = time.time() - start
        assert elapsed < 10

    def test_canonicalize_deep_nesting(self):
        """Should handle deeply nested objects."""
        def create_deep_object(depth):
            if depth == 0:
                return "leaf"
            return {"nested": create_deep_object(depth - 1)}

        for depth in [10, 20, 50, 100]:
            obj = create_deep_object(depth)
            result = ash_canonicalize_json(obj)
            assert "leaf" in result

    def test_canonicalize_wide_objects(self):
        """Should handle wide objects with many keys."""
        obj = {f"key_{i}": f"value_{i}" for i in range(1000)}
        result = ash_canonicalize_json(obj)

        # Should be sorted
        assert result.index("key_0") < result.index("key_1")

    def test_canonicalize_many_query_strings(self):
        """Should canonicalize many query strings."""
        start = time.time()

        for i in range(5000):
            query = f"z={i}&a={i}&m={i}&b={i}"
            ash_canonicalize_query(query)

        elapsed = time.time() - start
        assert elapsed < 10


class TestNonceGenerationStress:
    """Stress tests for nonce generation."""

    def test_generate_many_nonces(self):
        """Should generate many unique nonces quickly."""
        start = time.time()
        nonces = set()

        for _ in range(10000):
            nonce = ash_generate_nonce()
            nonces.add(nonce)

        elapsed = time.time() - start

        # All nonces should be unique
        assert len(nonces) == 10000
        # Should complete quickly
        assert elapsed < 5

    def test_generate_many_context_ids(self):
        """Should generate many unique context IDs."""
        ids = set()

        for _ in range(10000):
            ctx_id = ash_generate_context_id()
            ids.add(ctx_id)

        # All IDs should be unique
        assert len(ids) == 10000


class TestTimingSafeComparisonStress:
    """Stress tests for timing-safe comparison."""

    def test_many_comparisons(self):
        """Should handle many comparisons efficiently."""
        secret = secrets.token_hex(32)

        start = time.time()
        for i in range(50000):
            # Mix of equal and different comparisons
            if i % 2 == 0:
                ash_timing_safe_equal(secret, secret)
            else:
                ash_timing_safe_equal(secret, secret[:-1] + "x")

        elapsed = time.time() - start
        assert elapsed < 5

    def test_long_string_comparisons(self):
        """Should handle comparisons of long strings."""
        long_str = "a" * 10000

        start = time.time()
        for _ in range(1000):
            ash_timing_safe_equal(long_str, long_str)
            ash_timing_safe_equal(long_str, long_str[:-1] + "b")

        elapsed = time.time() - start
        assert elapsed < 5


class TestMemoryStress:
    """Tests for memory usage under stress."""

    def test_no_memory_leak_hashing(self):
        """Hashing should not leak memory."""
        # Just verify we can do many operations without error
        for _ in range(100000):
            ash_hash_body("test data")

    def test_no_memory_leak_proof_generation(self):
        """Proof generation should not leak memory."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        for i in range(10000):
            body_hash = ash_hash_body(f"body_{i}")
            ash_build_proof_hmac(client_secret, str(i), binding, body_hash)

    def test_no_memory_leak_canonicalization(self):
        """Canonicalization should not leak memory."""
        for i in range(50000):
            obj = {"key": f"value_{i}"}
            ash_canonicalize_json(obj)


class TestRealWorldScenarios:
    """Tests simulating real-world usage patterns."""

    def test_api_request_simulation(self):
        """Simulate many API requests."""
        # Server setup
        server_nonce = ash_generate_nonce()

        def handle_request(request_id):
            context_id = ash_generate_context_id()
            binding = f"POST|/api/action_{request_id % 10}|"

            # Client builds proof
            client_secret = ash_derive_client_secret(server_nonce, context_id, binding)
            payload = {"action": "test", "id": request_id}
            canonical = ash_canonicalize_json(payload)
            body_hash = ash_hash_body(canonical)
            timestamp = str(int(time.time() * 1000))
            proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

            # Server verifies
            return ash_verify_proof(
                server_nonce, context_id, binding, timestamp, body_hash, proof
            )

        # Simulate 1000 requests
        start = time.time()
        results = [handle_request(i) for i in range(1000)]
        elapsed = time.time() - start

        # All should pass
        assert all(results)
        # Should complete in reasonable time
        assert elapsed < 30

    def test_concurrent_api_simulation(self):
        """Simulate concurrent API requests."""
        server_nonce = ash_generate_nonce()

        def handle_request(request_id):
            context_id = ash_generate_context_id()
            binding = "POST|/api/action|"

            client_secret = ash_derive_client_secret(server_nonce, context_id, binding)
            payload = {"id": request_id}
            canonical = ash_canonicalize_json(payload)
            body_hash = ash_hash_body(canonical)
            timestamp = str(int(time.time() * 1000) + request_id)
            proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

            return ash_verify_proof(
                server_nonce, context_id, binding, timestamp, body_hash, proof
            )

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(handle_request, i) for i in range(500)]
            results = [f.result() for f in as_completed(futures)]

        assert all(results)


class TestChainedProofStress:
    """Stress tests for chained proofs."""

    def test_long_proof_chain(self):
        """Should handle long proof chains."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/chain|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        previous_proof = None
        for i in range(100):
            payload = {"step": i}
            proof, _, chain_hash = ash_build_proof_unified(
                client_secret, str(i), binding, payload, None, previous_proof
            )

            # Verify each step
            result = ash_verify_proof_unified(
                nonce, context_id, binding, str(i), payload, proof,
                None, "", previous_proof, chain_hash
            )
            assert result is True

            previous_proof = proof

    def test_many_parallel_chains(self):
        """Should handle many parallel proof chains."""
        nonce = ash_generate_nonce()

        def create_chain(chain_id):
            context_id = f"ash_chain_{chain_id}"
            binding = f"POST|/api/chain_{chain_id}|"
            client_secret = ash_derive_client_secret(nonce, context_id, binding)

            previous_proof = None
            for step in range(10):
                payload = {"chain": chain_id, "step": step}
                proof, _, _ = ash_build_proof_unified(
                    client_secret, str(step), binding, payload, None, previous_proof
                )
                previous_proof = proof

            return previous_proof

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_chain, i) for i in range(50)]
            final_proofs = [f.result() for f in as_completed(futures)]

        # All chains should complete (unique final proofs)
        assert len(set(final_proofs)) == 50
