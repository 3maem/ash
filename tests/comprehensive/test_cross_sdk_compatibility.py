"""
Test Cross-SDK Compatibility

Tests that ensure all SDKs produce identical outputs for the same inputs:
- Proof generation consistency across all languages
- Canonicalization consistency
- Hash computation consistency

These tests use fixed test vectors that MUST produce the same results
in Rust, Go, Node.js, Python, PHP, and .NET implementations.
"""

import pytest
import hashlib
import hmac
import unicodedata
from ash.core import (
    ash_canonicalize_json,
    ash_canonicalize_url_encoded,
    ash_canonicalize_query,
    ash_normalize_binding,
    ash_build_proof_hmac,
    ash_build_proof_scoped,
    ash_build_proof_unified,
    ash_verify_proof,
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
    ash_derive_client_secret,
    ash_hash_body,
    ash_hash_proof,
    ash_extract_scoped_fields,
    ash_join_scope_fields,
    ash_normalize_scope_fields,
    ash_timing_safe_equal,
)


# ============================================================================
# Fixed Test Vectors
# ============================================================================

TEST_NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TEST_CONTEXT_ID = "ash_test_ctx_12345"
TEST_BINDING = "POST|/api/transfer|"
TEST_TIMESTAMP = "1704067200000"


class TestProofGenerationConsistency:
    """Test that proof generation is consistent across SDKs."""

    def test_client_secret_derivation_deterministic(self):
        """Client secret derivation must be deterministic across SDKs."""
        secret1 = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        secret2 = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        
        assert secret1 == secret2
        assert len(secret1) == 64
        assert secret1 == secret1.lower()
        
        # Verify it's proper HMAC-SHA256
        expected = hmac.new(
            TEST_NONCE.encode(),
            f"{TEST_CONTEXT_ID}|{TEST_BINDING}".encode(),
            hashlib.sha256
        ).hexdigest()
        assert secret1 == expected

    def test_client_secret_different_inputs_produce_different_outputs(self):
        """Different inputs must produce different client secrets."""
        secret1 = ash_derive_client_secret(TEST_NONCE, "ctx_a", TEST_BINDING)
        secret2 = ash_derive_client_secret(TEST_NONCE, "ctx_b", TEST_BINDING)
        secret3 = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, "GET|/api/test|")
        
        assert secret1 != secret2
        assert secret1 != secret3
        assert secret2 != secret3

    def test_hmac_proof_deterministic(self):
        """HMAC proof generation must be deterministic."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body('{"amount":100}')
        
        proof1 = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)
        proof2 = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)
        
        assert proof1 == proof2
        assert len(proof1) == 64
        assert proof1 == proof1.lower()

    def test_hmac_proof_formula(self):
        """Verify the exact HMAC proof formula."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body('{"amount":100}')
        
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)
        
        # Manual computation to verify formula
        message = f"{TEST_TIMESTAMP}|{TEST_BINDING}|{body_hash}"
        expected = hmac.new(
            client_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        assert proof == expected

    def test_scoped_proof_consistency(self):
        """Scoped proof generation must be consistent."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "recipient": "user123", "note": "test"}
        scope = ["amount", "recipient"]
        
        proof1, scope_hash1 = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )
        proof2, scope_hash2 = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )
        
        assert proof1 == proof2
        assert scope_hash1 == scope_hash2
        assert len(proof1) == 64
        assert len(scope_hash1) == 64

    def test_unified_proof_consistency(self):
        """Unified proof generation must be consistent."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "recipient": "user123"}
        
        # Without scope or chaining
        proof1, scope_hash1, chain_hash1 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )
        proof2, scope_hash2, chain_hash2 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )
        
        assert proof1 == proof2
        assert scope_hash1 == scope_hash2 == ""
        assert chain_hash1 == chain_hash2 == ""

    def test_unified_proof_with_scope(self):
        """Unified proof with scope must be consistent."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "recipient": "user123", "note": "test"}
        scope = ["amount", "recipient"]
        
        proof1, scope_hash1, chain_hash1 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )
        proof2, scope_hash2, chain_hash2 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )
        
        assert proof1 == proof2
        assert scope_hash1 == scope_hash2
        assert scope_hash1 != ""
        assert chain_hash1 == chain_hash2 == ""

    def test_unified_proof_with_chaining(self):
        """Unified proof with chaining must be consistent."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"confirmed": True}
        previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        
        proof1, scope_hash1, chain_hash1 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, [], previous_proof
        )
        proof2, scope_hash2, chain_hash2 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, [], previous_proof
        )
        
        assert proof1 == proof2
        assert scope_hash1 == scope_hash2 == ""
        assert chain_hash1 == chain_hash2
        assert chain_hash1 == ash_hash_proof(previous_proof)

    def test_proof_verification_consistency(self):
        """Proof verification must be consistent across SDKs."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body('{"amount":100}')
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)
        
        # Should verify with same parameters
        assert ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, proof
        ) is True
        
        # Should fail with wrong proof
        assert ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, "0" * 64
        ) is False


class TestCanonicalizationConsistency:
    """Test that canonicalization produces identical outputs across SDKs."""

    def test_json_simple_object(self):
        """Simple object canonicalization."""
        result = ash_canonicalize_json({"z": 1, "a": 2, "m": 3})
        assert result == '{"a":2,"m":3,"z":1}'

    def test_json_nested_object(self):
        """Nested object canonicalization."""
        result = ash_canonicalize_json({"outer": {"z": 1, "a": 2}})
        assert result == '{"outer":{"a":2,"z":1}}'

    def test_json_array_order_preserved(self):
        """Array order must be preserved."""
        result = ash_canonicalize_json({"arr": [3, 1, 2]})
        assert result == '{"arr":[3,1,2]}'

    def test_json_empty_values(self):
        """Empty value canonicalization."""
        assert ash_canonicalize_json({}) == "{}"
        assert ash_canonicalize_json([]) == "[]"
        assert ash_canonicalize_json("") == '""'
        assert ash_canonicalize_json(None) == "null"
        assert ash_canonicalize_json(True) == "true"
        assert ash_canonicalize_json(False) == "false"

    def test_json_negative_zero_normalization(self):
        """-0 must become 0 (RFC 8785)."""
        result = ash_canonicalize_json({"value": -0.0})
        assert result == '{"value":0}'

    def test_json_unicode_nfc_normalization(self):
        """Unicode must be NFC normalized."""
        # café in NFD form (e + combining accent)
        nfd = "cafe\u0301"
        # café in NFC form (single character)
        nfc = "café"
        
        result_nfd = ash_canonicalize_json({"text": nfd})
        result_nfc = ash_canonicalize_json({"text": nfc})
        
        # Both should produce the same output
        assert result_nfd == result_nfc
        assert result_nfc == '{"text":"café"}'

    def test_json_escape_sequences(self):
        """Special characters must be properly escaped."""
        result = ash_canonicalize_json({"s": "a\tb\nc"})
        assert result == '{"s":"a\\tb\\nc"}'

    def test_url_encoded_canonicalization(self):
        """URL-encoded data canonicalization."""
        result = ash_canonicalize_url_encoded("z=3&a=1&b=2")
        assert result == "a=1&b=2&z=3"

    def test_url_encoded_plus_as_literal(self):
        """+ must be treated as literal plus, not space."""
        result = ash_canonicalize_url_encoded("a=hello+world")
        assert result == "a=hello%2Bworld"

    def test_url_encoded_uppercase_hex(self):
        """Percent-encoding must use uppercase hex."""
        result = ash_canonicalize_url_encoded("a=hello%2fworld")
        assert result == "a=hello%2Fworld"

    def test_query_string_canonicalization(self):
        """Query string canonicalization."""
        result = ash_canonicalize_query("b=2&a=1")
        assert result == "a=1&b=2"

    def test_query_string_duplicate_keys(self):
        """Duplicate keys sorted by value."""
        result = ash_canonicalize_query("a=z&a=a&a=m")
        assert result == "a=a&a=m&a=z"

    def test_query_string_strip_leading_question(self):
        """Leading ? must be stripped."""
        result = ash_canonicalize_query("?a=1&b=2")
        assert result == "a=1&b=2"

    def test_query_string_strip_fragment(self):
        """Fragment must be stripped."""
        result = ash_canonicalize_query("a=1&b=2#section")
        assert result == "a=1&b=2"

    def test_binding_normalization(self):
        """Binding normalization."""
        assert ash_normalize_binding("POST", "/api/test") == "POST|/api/test|"
        assert ash_normalize_binding("post", "/api/test") == "POST|/api/test|"

    def test_binding_with_query(self):
        """Binding with query string."""
        result = ash_normalize_binding("GET", "/api/users", "z=1&a=2")
        assert result == "GET|/api/users|a=2&z=1"

    def test_binding_collapse_slashes(self):
        """Duplicate slashes must be collapsed."""
        result = ash_normalize_binding("GET", "/api//test///path")
        assert result == "GET|/api/test/path|"

    def test_binding_remove_trailing_slash(self):
        """Trailing slash must be removed (except root)."""
        assert ash_normalize_binding("GET", "/api/test/") == "GET|/api/test|"
        assert ash_normalize_binding("GET", "/") == "GET|/|"


class TestHashComputationConsistency:
    """Test that hash computations are consistent across SDKs."""

    def test_body_hash_known_values(self):
        """Known SHA-256 hash values."""
        # SHA-256 of "test"
        assert ash_hash_body("test") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        # SHA-256 of empty string
        assert ash_hash_body("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_body_hash_format(self):
        """Hash must be 64 lowercase hex characters."""
        result = ash_hash_body('{"amount":100}')
        assert len(result) == 64
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_body_hash_determinism(self):
        """Same input must produce same hash."""
        result1 = ash_hash_body('{"amount":100}')
        result2 = ash_hash_body('{"amount":100}')
        assert result1 == result2

    def test_proof_hash_consistency(self):
        """Proof hashing must be consistent."""
        proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        hash1 = ash_hash_proof(proof)
        hash2 = ash_hash_proof(proof)
        
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_scope_normalization_consistency(self):
        """Scope field normalization must be consistent."""
        # Order shouldn't matter
        scope1 = ["b", "a", "c"]
        scope2 = ["a", "b", "c"]
        
        normalized1 = ash_normalize_scope_fields(scope1)
        normalized2 = ash_normalize_scope_fields(scope2)
        
        assert normalized1 == normalized2 == ["a", "b", "c"]

    def test_scope_deduplication(self):
        """Duplicate scope fields must be deduplicated."""
        scope = ["a", "b", "a", "c", "b"]
        normalized = ash_normalize_scope_fields(scope)
        
        assert normalized == ["a", "b", "c"]

    def test_scope_join_with_unit_separator(self):
        """Scope must be joined with unit separator (U+001F)."""
        scope = ["a", "b", "c"]
        joined = ash_join_scope_fields(scope)
        
        assert joined == "a\x1fb\x1fc"


class TestScopedFieldExtractionConsistency:
    """Test scoped field extraction is consistent across SDKs."""

    def test_extract_simple_fields(self):
        """Extract simple top-level fields."""
        payload = {"amount": 100, "recipient": "user123", "note": "test"}
        scope = ["amount", "recipient"]
        
        result = ash_extract_scoped_fields(payload, scope)
        
        assert result == {"amount": 100, "recipient": "user123"}
        assert "note" not in result

    def test_extract_nested_fields(self):
        """Extract nested fields using dot notation."""
        payload = {
            "user": {
                "name": "John",
                "email": "john@example.com",
                "address": {
                    "city": "NYC",
                    "zip": "10001"
                }
            },
            "amount": 100
        }
        scope = ["user.name", "user.address.city"]
        
        result = ash_extract_scoped_fields(payload, scope)
        
        assert result["user"]["name"] == "John"
        assert result["user"]["address"]["city"] == "NYC"
        assert "email" not in result.get("user", {})
        assert "zip" not in result.get("user", {}).get("address", {})

    def test_empty_scope_returns_full_payload(self):
        """Empty scope should return full payload."""
        payload = {"amount": 100, "note": "test"}
        
        result = ash_extract_scoped_fields(payload, [])
        
        assert result == payload


class TestTimingSafeComparisonConsistency:
    """Test timing-safe comparison is consistent across SDKs."""

    def test_equal_strings(self):
        """Equal strings must return True."""
        assert ash_timing_safe_equal("abc", "abc") is True
        assert ash_timing_safe_equal("", "") is True

    def test_unequal_strings(self):
        """Unequal strings must return False."""
        assert ash_timing_safe_equal("abc", "abd") is False
        assert ash_timing_safe_equal("abc", "abcd") is False
        assert ash_timing_safe_equal("abc", "") is False
        assert ash_timing_safe_equal("", "a") is False

    def test_case_sensitivity(self):
        """Comparison must be case-sensitive."""
        assert ash_timing_safe_equal("abc", "ABC") is False
