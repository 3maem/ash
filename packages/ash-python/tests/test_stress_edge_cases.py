"""
Stress and Boundary Tests.

Additional tests for stress testing and boundary conditions
to ensure robustness under various conditions.
"""

import pytest
import secrets
import time
from ash.core.proof import (
    ash_build_proof_hmac,
    ash_build_proof_scoped,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_extract_scoped_fields,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_hash_proof,
    ash_hash_scoped_body,
    ash_join_scope_fields,
    ash_normalize_scope_fields,
    ash_verify_proof,
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
    ash_base64url_encode,
    ash_base64url_decode,
)
from ash.core.canonicalize import (
    ash_canonicalize_json,
    ash_normalize_binding,
    ash_normalize_binding_from_url,
    ash_canonicalize_query,
)
from ash.core.compare import ash_timing_safe_equal


class TestStressLargePayloads:
    """Large payload stress tests."""

    def test_large_string_value(self):
        """Should handle large string value."""
        payload = {"data": "x" * 100000}
        result = ash_canonicalize_json(payload)
        assert len(result) > 100000

    def test_large_array(self):
        """Should handle large array."""
        payload = {"items": list(range(10000))}
        result = ash_canonicalize_json(payload)
        assert "9999" in result

    def test_many_keys(self):
        """Should handle many keys."""
        payload = {f"key_{i}": i for i in range(1000)}
        result = ash_canonicalize_json(payload)
        assert '"key_0":0' in result

    def test_deeply_nested(self):
        """Should handle deeply nested structure."""
        obj = {"level": 0}
        current = obj
        for i in range(1, 50):
            current["nested"] = {"level": i}
            current = current["nested"]
        result = ash_canonicalize_json(obj)
        assert '"level":49' in result


class TestStressRapidOperations:
    """Rapid operation stress tests."""

    def test_rapid_nonce_generation(self):
        """Should generate many nonces rapidly."""
        nonces = [ash_generate_nonce() for _ in range(1000)]
        assert len(set(nonces)) == 1000

    def test_rapid_context_id_generation(self):
        """Should generate many context IDs rapidly."""
        ids = [ash_generate_context_id() for _ in range(1000)]
        assert len(set(ids)) == 1000

    def test_rapid_hashing(self):
        """Should hash many values rapidly."""
        hashes = [ash_hash_body(f"data_{i}") for i in range(1000)]
        assert len(set(hashes)) == 1000

    def test_rapid_proof_building(self):
        """Should build many proofs rapidly."""
        nonce = "a" * 64
        ctx = "ash_test"
        binding = "POST|/api|"
        body_hash = "b" * 64
        client_secret = ash_derive_client_secret(nonce, ctx, binding)

        proofs = [
            ash_build_proof_hmac(client_secret, str(i), binding, body_hash)
            for i in range(1000)
        ]
        assert len(set(proofs)) == 1000

    def test_rapid_verification(self):
        """Should verify many proofs rapidly."""
        nonce = ash_generate_nonce()
        ctx = ash_generate_context_id()
        binding = "POST|/api|"
        timestamp = "1234567890"
        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, ctx, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        results = [
            ash_verify_proof(nonce, ctx, binding, timestamp, body_hash, proof)
            for _ in range(1000)
        ]
        assert all(results)


class TestBoundaryTimestamps:
    """Timestamp boundary tests."""

    def test_timestamp_zero(self):
        """Should handle timestamp 0."""
        nonce = ash_generate_nonce()
        ctx = ash_generate_context_id()
        binding = "POST|/api|"
        timestamp = "0"
        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, ctx, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
        assert ash_verify_proof(nonce, ctx, binding, timestamp, body_hash, proof)

    def test_timestamp_one(self):
        """Should handle timestamp 1."""
        nonce = ash_generate_nonce()
        ctx = ash_generate_context_id()
        binding = "POST|/api|"
        timestamp = "1"
        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, ctx, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
        assert ash_verify_proof(nonce, ctx, binding, timestamp, body_hash, proof)

    def test_timestamp_large(self):
        """Should handle large timestamp."""
        nonce = ash_generate_nonce()
        ctx = ash_generate_context_id()
        binding = "POST|/api|"
        timestamp = str(2**53 - 1)
        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, ctx, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
        assert ash_verify_proof(nonce, ctx, binding, timestamp, body_hash, proof)

    def test_timestamp_current(self):
        """Should handle current timestamp."""
        nonce = ash_generate_nonce()
        ctx = ash_generate_context_id()
        binding = "POST|/api|"
        timestamp = str(int(time.time() * 1000))
        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, ctx, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
        assert ash_verify_proof(nonce, ctx, binding, timestamp, body_hash, proof)


class TestBoundaryStrings:
    """String boundary tests."""

    def test_empty_string_hash(self):
        """Should hash empty string."""
        result = ash_hash_body("")
        assert len(result) == 64

    def test_single_char_hash(self):
        """Should hash single character."""
        result = ash_hash_body("a")
        assert len(result) == 64

    def test_null_char_string(self):
        """Should handle null character in string."""
        result = ash_canonicalize_json("a\x00b")
        assert "\\u0000" in result

    def test_unicode_boundary(self):
        """Should handle Unicode boundary characters."""
        # BOM
        result = ash_canonicalize_json("\uFEFF")
        assert len(result) > 2

    def test_very_long_string(self):
        """Should handle very long string."""
        s = "x" * 1000000
        result = ash_hash_body(s)
        assert len(result) == 64


class TestBoundaryArrays:
    """Array boundary tests."""

    def test_empty_array(self):
        """Should handle empty array."""
        result = ash_canonicalize_json([])
        assert result == "[]"

    def test_single_element_array(self):
        """Should handle single element array."""
        result = ash_canonicalize_json([1])
        assert result == "[1]"

    def test_nested_empty_arrays(self):
        """Should handle nested empty arrays."""
        result = ash_canonicalize_json([[[]]])
        assert result == "[[[]]]"

    def test_mixed_empty_containers(self):
        """Should handle mixed empty containers."""
        result = ash_canonicalize_json([{}, [], {"a": []}])
        assert result == "[{},[],{\"a\":[]}]"


class TestBoundaryObjects:
    """Object boundary tests."""

    def test_empty_object(self):
        """Should handle empty object."""
        result = ash_canonicalize_json({})
        assert result == "{}"

    def test_single_key_object(self):
        """Should handle single key object."""
        result = ash_canonicalize_json({"a": 1})
        assert result == '{"a":1}'

    def test_empty_string_key(self):
        """Should handle empty string key."""
        result = ash_canonicalize_json({"": "value"})
        assert '""' in result

    def test_nested_empty_objects(self):
        """Should handle nested empty objects."""
        result = ash_canonicalize_json({"a": {"b": {}}})
        assert result == '{"a":{"b":{}}}'


class TestBoundaryNumbers:
    """Number boundary tests."""

    def test_zero(self):
        """Should handle zero."""
        assert ash_canonicalize_json(0) == "0"

    def test_negative_zero(self):
        """Should handle negative zero."""
        assert ash_canonicalize_json(-0.0) == "0"

    def test_one(self):
        """Should handle one."""
        assert ash_canonicalize_json(1) == "1"

    def test_negative_one(self):
        """Should handle negative one."""
        assert ash_canonicalize_json(-1) == "-1"

    def test_max_safe_int(self):
        """Should handle max safe integer."""
        assert ash_canonicalize_json(9007199254740991) == "9007199254740991"

    def test_min_safe_int(self):
        """Should handle min safe integer."""
        assert ash_canonicalize_json(-9007199254740991) == "-9007199254740991"

    def test_float_precision(self):
        """Should handle float precision."""
        result = ash_canonicalize_json(0.1)
        assert "0.1" == result


class TestBoundaryQueries:
    """Query string boundary tests."""

    def test_empty_query(self):
        """Should handle empty query."""
        result = ash_canonicalize_query("")
        assert result == ""

    def test_single_param(self):
        """Should handle single parameter."""
        result = ash_canonicalize_query("a=1")
        assert result == "a=1"

    def test_param_no_value(self):
        """Should handle parameter with no value."""
        result = ash_canonicalize_query("flag")
        assert result == "flag="

    def test_param_empty_value(self):
        """Should handle parameter with empty value."""
        result = ash_canonicalize_query("a=")
        assert result == "a="

    def test_many_params(self):
        """Should handle many parameters."""
        params = "&".join([f"p{i}=v{i}" for i in range(100)])
        result = ash_canonicalize_query(params)
        assert "p0=v0" in result
        assert "p99=v99" in result


class TestBoundaryBindings:
    """Binding boundary tests."""

    def test_minimal_binding(self):
        """Should handle minimal binding."""
        result = ash_normalize_binding("GET", "/")
        assert result == "GET|/|"

    def test_long_path(self):
        """Should handle long path."""
        path = "/" + "/".join(["segment"] * 100)
        result = ash_normalize_binding("GET", path)
        assert "segment" in result

    def test_many_query_params(self):
        """Should handle many query parameters."""
        query = "&".join([f"p{i}=v{i}" for i in range(100)])
        result = ash_normalize_binding("GET", "/api", query)
        assert "p0=v0" in result


class TestConsistencyAcrossInvocations:
    """Consistency across multiple invocations."""

    def test_hash_consistency(self):
        """Hash should be consistent."""
        data = "test data"
        results = set()
        for _ in range(100):
            results.add(ash_hash_body(data))
        assert len(results) == 1

    def test_canonicalize_consistency(self):
        """Canonicalize should be consistent."""
        obj = {"z": 1, "a": 2}
        results = set()
        for _ in range(100):
            results.add(ash_canonicalize_json(obj))
        assert len(results) == 1

    def test_binding_consistency(self):
        """Binding should be consistent."""
        results = set()
        for _ in range(100):
            results.add(ash_normalize_binding("GET", "/api", "b=2&a=1"))
        assert len(results) == 1

    def test_client_secret_consistency(self):
        """Client secret should be consistent."""
        nonce = "a" * 64
        ctx = "ash_test"
        binding = "POST|/api|"
        results = set()
        for _ in range(100):
            results.add(ash_derive_client_secret(nonce, ctx, binding))
        assert len(results) == 1

    def test_proof_consistency(self):
        """Proof should be consistent."""
        secret = "a" * 64
        ts = "1234567890"
        binding = "POST|/api|"
        body_hash = "b" * 64
        results = set()
        for _ in range(100):
            results.add(ash_build_proof_hmac(secret, ts, binding, body_hash))
        assert len(results) == 1


class TestParallelSafety:
    """Parallel safety tests (sequential simulation)."""

    def test_independent_contexts_no_interference(self):
        """Independent contexts should not interfere."""
        contexts = []
        for i in range(10):
            nonce = ash_generate_nonce()
            ctx_id = ash_generate_context_id()
            binding = f"POST|/api/v{i}|"
            contexts.append((nonce, ctx_id, binding))

        # Verify all can work independently
        for nonce, ctx_id, binding in contexts:
            client_secret = ash_derive_client_secret(nonce, ctx_id, binding)
            assert len(client_secret) == 64

    def test_interleaved_operations(self):
        """Interleaved operations should work correctly."""
        nonce1 = ash_generate_nonce()
        nonce2 = ash_generate_nonce()

        ctx1 = ash_generate_context_id()
        ctx2 = ash_generate_context_id()

        # Interleave operations
        secret1 = ash_derive_client_secret(nonce1, ctx1, "POST|/api1|")
        secret2 = ash_derive_client_secret(nonce2, ctx2, "POST|/api2|")

        hash1 = ash_hash_body("data1")
        hash2 = ash_hash_body("data2")

        proof1 = ash_build_proof_hmac(secret1, "1", "POST|/api1|", hash1)
        proof2 = ash_build_proof_hmac(secret2, "2", "POST|/api2|", hash2)

        # Verify both work
        assert ash_verify_proof(nonce1, ctx1, "POST|/api1|", "1", hash1, proof1)
        assert ash_verify_proof(nonce2, ctx2, "POST|/api2|", "2", hash2, proof2)


class TestScopeBoundaries:
    """Scope boundary tests."""

    def test_empty_scope(self):
        """Should handle empty scope."""
        payload = {"a": 1, "b": 2}
        result = ash_extract_scoped_fields(payload, [])
        assert result == payload

    def test_single_field_scope(self):
        """Should handle single field scope."""
        payload = {"a": 1, "b": 2}
        result = ash_extract_scoped_fields(payload, ["a"])
        assert result == {"a": 1}

    def test_all_fields_scope(self):
        """Should handle all fields in scope."""
        payload = {"a": 1, "b": 2}
        result = ash_extract_scoped_fields(payload, ["a", "b"])
        assert result == {"a": 1, "b": 2}

    def test_nonexistent_scope(self):
        """Should handle nonexistent scope field."""
        payload = {"a": 1}
        result = ash_extract_scoped_fields(payload, ["nonexistent"])
        assert result == {}

    def test_deeply_nested_scope(self):
        """Should handle deeply nested scope."""
        payload = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        result = ash_extract_scoped_fields(payload, ["a.b.c.d.e"])
        assert result == {"a": {"b": {"c": {"d": {"e": 1}}}}}
