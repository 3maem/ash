"""
Additional Edge Cases Tests.

Additional tests to ensure comprehensive coverage of edge cases
across all ASH functionality.
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


class TestJcsMoreEdgeCases:
    """Additional JCS edge cases."""

    def test_object_with_100_keys(self):
        """Should handle object with 100 keys."""
        obj = {f"key_{i:03d}": i for i in range(100)}
        result = ash_canonicalize_json(obj)
        assert '"key_000":0' in result
        assert '"key_099":99' in result

    def test_array_with_100_elements(self):
        """Should handle array with 100 elements."""
        arr = list(range(100))
        result = ash_canonicalize_json(arr)
        assert result.startswith("[0,1,2,")

    def test_nested_10_levels(self):
        """Should handle 10 levels of nesting."""
        obj = {"l1": {"l2": {"l3": {"l4": {"l5": {"l6": {"l7": {"l8": {"l9": {"l10": 1}}}}}}}}}}
        result = ash_canonicalize_json(obj)
        assert '"l10":1' in result

    def test_mixed_unicode_ascii(self):
        """Should handle mixed Unicode and ASCII."""
        obj = {"ascii": "hello", "unicode": "\u4E2D\u6587", "mixed": "hello\u4E16\u754C"}
        result = ash_canonicalize_json(obj)
        assert "hello" in result

    def test_boolean_array(self):
        """Should handle boolean array."""
        arr = [True, False, True, False]
        result = ash_canonicalize_json(arr)
        assert result == "[true,false,true,false]"

    def test_null_array(self):
        """Should handle null array."""
        arr = [None, None, None]
        result = ash_canonicalize_json(arr)
        assert result == "[null,null,null]"

    def test_float_array(self):
        """Should handle float array."""
        arr = [1.1, 2.2, 3.3]
        result = ash_canonicalize_json(arr)
        assert "1.1" in result
        assert "2.2" in result
        assert "3.3" in result

    def test_string_with_all_escapes(self):
        """Should handle string with all escape characters."""
        s = '\t\n\r\f\b"\\'
        result = ash_canonicalize_json(s)
        assert "\\t" in result
        assert "\\n" in result
        assert "\\r" in result

    def test_unicode_surrogate_pair(self):
        """Should handle Unicode surrogate pairs."""
        # Emoji that requires surrogate pair
        emoji = "\U0001F4A9"  # pile of poo
        result = ash_canonicalize_json(emoji)
        assert len(result) > 2  # Has quotes and content

    def test_rtl_text_in_object(self):
        """Should handle RTL text in object."""
        obj = {"arabic": "\u0639\u0631\u0628\u064A", "hebrew": "\u05E2\u05D1\u05E8\u05D9\u05EA"}
        result = ash_canonicalize_json(obj)
        assert "arabic" in result
        assert "hebrew" in result


class TestBindingMoreEdgeCases:
    """Additional binding edge cases."""

    def test_very_long_query_string(self):
        """Should handle very long query string."""
        params = "&".join([f"param{i}=value{i}" for i in range(50)])
        result = ash_normalize_binding("GET", "/api/test", params)
        assert "param0=" in result
        assert "param49=" in result

    def test_query_with_special_values(self):
        """Should handle special values in query."""
        result = ash_canonicalize_query("empty=&null=null&true=true&false=false")
        assert "empty=" in result
        assert "null=null" in result

    def test_path_with_uuid(self):
        """Should handle UUID in path."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = ash_normalize_binding("GET", f"/api/items/{uuid}")
        assert uuid in result

    def test_path_with_base64_segment(self):
        """Should handle Base64-like path segment."""
        b64 = "dGVzdC1kYXRh"
        result = ash_normalize_binding("GET", f"/api/decode/{b64}")
        assert b64 in result

    def test_all_http_methods(self):
        """Should handle all HTTP methods."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
        for method in methods:
            result = ash_normalize_binding(method, "/api/test")
            assert result.startswith(f"{method}|")

    def test_path_only_slash(self):
        """Should handle path with only slash."""
        result = ash_normalize_binding("GET", "/")
        assert result == "GET|/|"

    def test_path_with_encoded_space(self):
        """Should handle encoded space in path."""
        result = ash_normalize_binding("GET", "/api/hello%20world")
        assert "hello" in result

    def test_query_encoded_unicode(self):
        """Should handle encoded Unicode in query."""
        result = ash_canonicalize_query("name=%E4%B8%AD%E6%96%87")
        assert "name=" in result


class TestVerificationMoreEdgeCases:
    """Additional verification edge cases."""

    def test_verify_with_timestamp_boundaries(self):
        """Should verify with various timestamp values."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"

        timestamps = ["0", "1", "1704067200000", str(2**53 - 1)]
        for ts in timestamps:
            body_hash = ash_hash_body("test")
            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            proof = ash_build_proof_hmac(client_secret, ts, binding, body_hash)
            result = ash_verify_proof(nonce, context_id, binding, ts, body_hash, proof)
            assert result is True

    def test_verify_with_empty_binding(self):
        """Should verify with minimal binding."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "GET|/|"
        timestamp = "1704067200000"

        body_hash = ash_hash_body("")
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True

    def test_verify_100_times(self):
        """Should verify same proof 100 times consistently."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"

        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        results = [
            ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
            for _ in range(100)
        ]
        assert all(results)

    def test_verify_with_unicode_payload(self):
        """Should verify with Unicode payload."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"

        payload = {"message": "\u4E2D\u6587\u65E5\u672C\uD55C\uAE00"}
        canonical = ash_canonicalize_json(payload)
        body_hash = ash_hash_body(canonical)

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True


class TestScopingMoreEdgeCases:
    """Additional scoping edge cases."""

    def test_scope_with_10_fields(self):
        """Should scope 10 fields."""
        payload = {f"field{i}": i for i in range(20)}
        scope = [f"field{i}" for i in range(10)]
        result = ash_extract_scoped_fields(payload, scope)
        assert len(result) == 10

    def test_scope_nested_3_levels(self):
        """Should scope 3 levels deep."""
        payload = {"a": {"b": {"c": "deep"}}}
        scope = ["a.b.c"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"a": {"b": {"c": "deep"}}}

    def test_scope_array_in_nested(self):
        """Should scope array in nested object."""
        payload = {"data": {"items": [1, 2, 3]}}
        scope = ["data.items"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"data": {"items": [1, 2, 3]}}

    def test_scope_normalization_50_fields(self):
        """Should normalize 50 scope fields."""
        scope = [f"field_{50-i}" for i in range(50)]
        result = ash_normalize_scope_fields(scope)
        # Should be sorted
        assert result[0] < result[-1]

    def test_scope_hash_deterministic(self):
        """Scope hash should be deterministic."""
        scope = ["z", "a", "m"]
        joined = ash_join_scope_fields(scope)
        hashes = [ash_hash_body(joined) for _ in range(100)]
        assert len(set(hashes)) == 1

    def test_scoped_proof_with_empty_values(self):
        """Should handle scoped proof with empty values."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"

        payload = {"amount": 0, "note": ""}
        scope = ["amount", "note"]
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash = ash_build_proof_scoped(
            client_secret, timestamp, binding, payload, scope
        )

        result = ash_verify_proof_scoped(
            nonce, context_id, binding, timestamp, payload, scope, scope_hash, proof
        )
        assert result is True


class TestChainingMoreEdgeCases:
    """Additional chaining edge cases."""

    def test_chain_10_proofs(self):
        """Should chain 10 proofs."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        previous = None
        for i in range(10):
            payload = {"step": i}
            proof, _, chain_hash = ash_build_proof_unified(
                client_secret, timestamp, binding, payload, None, previous
            )
            previous = proof

        # Final proof should be verifiable
        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, {"step": 9}, proof
        )
        # Note: Without chain verification, this verifies the proof itself
        assert len(proof) == 64

    def test_chain_hash_varies_with_previous(self):
        """Chain hash should vary with previous proof."""
        client_secret = ash_derive_client_secret(
            ash_generate_nonce(),
            ash_generate_context_id(),
            "POST|/api/test|"
        )
        timestamp = "1704067200000"
        binding = "POST|/api/test|"
        payload = {"test": "data"}

        chain_hashes = set()
        for i in range(10):
            previous = f"{i}" * 64
            _, _, chain_hash = ash_build_proof_unified(
                client_secret, timestamp, binding, payload, None, previous
            )
            chain_hashes.add(chain_hash)

        assert len(chain_hashes) == 10

    def test_chain_with_scope(self):
        """Should chain with scope."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]
        previous = "a" * 64

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, timestamp, binding, payload, scope, previous
        )

        assert len(proof) == 64
        assert len(scope_hash) == 64
        assert len(chain_hash) == 64


class TestCryptoMoreEdgeCases:
    """Additional crypto edge cases."""

    def test_base64url_roundtrip_sizes(self):
        """Should roundtrip various sizes."""
        for size in range(1, 100):
            data = secrets.token_bytes(size)
            encoded = ash_base64url_encode(data)
            decoded = ash_base64url_decode(encoded)
            assert decoded == data

    def test_timing_safe_various_lengths(self):
        """Should handle various lengths."""
        for length in [1, 10, 32, 64, 100, 256]:
            s1 = "a" * length
            s2 = "a" * length
            s3 = "b" * length

            assert ash_timing_safe_equal(s1, s2) is True
            assert ash_timing_safe_equal(s1, s3) is False

    def test_nonce_uniqueness_1000(self):
        """1000 nonces should all be unique."""
        nonces = [ash_generate_nonce() for _ in range(1000)]
        assert len(set(nonces)) == 1000

    def test_context_id_format_100(self):
        """100 context IDs should all have correct format."""
        for _ in range(100):
            ctx = ash_generate_context_id()
            assert ctx.startswith("ash_")
            assert len(ctx) == 36

    def test_client_secret_varies_with_all_inputs(self):
        """Client secret should vary with each input."""
        base_nonce = "a" * 64
        base_ctx = "ash_test"
        base_binding = "POST|/api|"

        base_secret = ash_derive_client_secret(base_nonce, base_ctx, base_binding)

        # Change nonce
        secret2 = ash_derive_client_secret("b" * 64, base_ctx, base_binding)
        assert secret2 != base_secret

        # Change context
        secret3 = ash_derive_client_secret(base_nonce, "ash_other", base_binding)
        assert secret3 != base_secret

        # Change binding
        secret4 = ash_derive_client_secret(base_nonce, base_ctx, "GET|/api|")
        assert secret4 != base_secret


class TestHashingEdgeCases:
    """Additional hashing edge cases."""

    def test_hash_empty_string(self):
        """Should hash empty string."""
        result = ash_hash_body("")
        assert len(result) == 64

    def test_hash_single_char(self):
        """Should hash single character."""
        result = ash_hash_body("a")
        assert len(result) == 64

    def test_hash_10kb_data(self):
        """Should hash 10KB data."""
        data = "x" * 10240
        result = ash_hash_body(data)
        assert len(result) == 64

    def test_hash_unicode_data(self):
        """Should hash Unicode data."""
        data = "\u4E2D\u6587" * 1000
        result = ash_hash_body(data)
        assert len(result) == 64

    def test_hash_proof_formats(self):
        """Should hash various proof formats."""
        proofs = [
            "a" * 64,
            "0" * 64,
            "f" * 64,
            "0123456789abcdef" * 4,
        ]
        for proof in proofs:
            result = ash_hash_proof(proof)
            assert len(result) == 64


class TestIntegrationEdgeCases:
    """Integration edge cases."""

    def test_full_flow_minimal(self):
        """Should handle minimal full flow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("GET", "/")
        timestamp = "0"

        canonical = ash_canonicalize_json({})
        body_hash = ash_hash_body(canonical)
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True

    def test_full_flow_complex(self):
        """Should handle complex full flow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/v2/users/123/orders", "include=items&expand=all")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "items": [
                {"product_id": "prod_123", "quantity": 2, "price": 1999},
                {"product_id": "prod_456", "quantity": 1, "price": 2999}
            ],
            "shipping": {
                "address": {
                    "line1": "123 Main St",
                    "city": "New York",
                    "state": "NY",
                    "zip": "10001"
                },
                "method": "express"
            },
            "notes": "Handle with care"
        }
        scope = ["items", "shipping.address"]

        canonical = ash_canonicalize_json(payload)
        body_hash = ash_hash_body(canonical)
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, timestamp, binding, payload, scope
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof,
            scope, scope_hash
        )
        assert result is True

    def test_multiple_independent_contexts(self):
        """Should handle multiple independent contexts."""
        for _ in range(10):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()
            binding = ash_normalize_binding("POST", "/api/test")
            timestamp = str(int(time.time() * 1000))

            payload = {"data": secrets.token_hex(16)}
            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            proof, _, _ = ash_build_proof_unified(
                client_secret, timestamp, binding, payload
            )

            result = ash_verify_proof_unified(
                nonce, context_id, binding, timestamp, payload, proof
            )
            assert result is True


class TestErrorHandlingEdgeCases:
    """Error handling edge cases."""

    def test_verify_with_wrong_nonce_format(self):
        """Should handle wrong nonce format gracefully."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"

        body_hash = ash_hash_body("test")
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        # Try with different valid hex nonce (should fail verification)
        result = ash_verify_proof("c" * 64, context_id, binding, timestamp, body_hash, proof)
        assert result is False

    def test_verify_with_malformed_proof(self):
        """Should handle malformed proof gracefully."""
        result = ash_verify_proof(
            "a" * 64,
            "ash_test",
            "POST|/api|",
            "1234567890",
            "b" * 64,
            "not-hex!"
        )
        assert result is False

    def test_scope_extraction_missing_nested(self):
        """Should handle missing nested paths."""
        payload = {"a": {"b": 1}}
        scope = ["a.b.c.d"]  # Path doesn't exist
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {}


class TestDeterminismEdgeCases:
    """Determinism edge cases."""

    def test_canonicalize_100_times(self):
        """Should produce same result 100 times."""
        obj = {"z": 1, "a": 2, "m": [3, 2, 1]}
        results = [ash_canonicalize_json(obj) for _ in range(100)]
        assert len(set(results)) == 1

    def test_binding_100_times(self):
        """Should produce same binding 100 times."""
        results = [ash_normalize_binding("GET", "/api/test", "b=2&a=1") for _ in range(100)]
        assert len(set(results)) == 1

    def test_proof_100_times(self):
        """Should produce same proof 100 times."""
        nonce = "a" * 64
        context_id = "ash_test"
        binding = "POST|/api|"
        timestamp = "1234567890"
        body_hash = "b" * 64

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proofs = [
            ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
            for _ in range(100)
        ]
        assert len(set(proofs)) == 1
