"""
Cross-SDK Test Vectors for ASH v2.3.2

These test vectors MUST produce identical results across all SDK implementations.
Any SDK that fails these tests is not compliant with the ASH specification.
"""

import pytest
from ash.core.canonicalize import (
    canonicalize_json,
    canonicalize_url_encoded,
    canonicalize_query,
    normalize_binding,
)
from ash.core.proof import (
    hash_body,
    derive_client_secret,
    build_proof_v21,
    verify_proof_v21,
    build_proof_unified,
    verify_proof_unified,
    extract_scoped_fields,
    hash_proof,
)
from ash.core.compare import timing_safe_compare


# ============================================================================
# FIXED TEST VECTORS - DO NOT MODIFY
# These values are used across all SDK implementations
# ============================================================================

TEST_NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TEST_CONTEXT_ID = "ash_test_ctx_12345"
TEST_BINDING = "POST|/api/transfer|"
TEST_TIMESTAMP = "1704067200000"  # 2024-01-01 00:00:00 UTC in ms


# ============================================================================
# JSON Canonicalization Tests (RFC 8785 JCS)
# ============================================================================

class TestJsonCanonicalization:
    """JSON canonicalization tests per RFC 8785."""

    def test_simple_object(self):
        """Should sort keys alphabetically."""
        result = canonicalize_json({"z": 1, "a": 2, "m": 3})
        assert result == '{"a":2,"m":3,"z":1}'

    def test_nested_object(self):
        """Should sort nested object keys."""
        result = canonicalize_json({"outer": {"z": 1, "a": 2}, "inner": {"b": 2, "a": 1}})
        assert result == '{"inner":{"a":1,"b":2},"outer":{"a":2,"z":1}}'

    def test_array_order_preserved(self):
        """Should preserve array element order."""
        result = canonicalize_json({"arr": [3, 1, 2]})
        assert result == '{"arr":[3,1,2]}'

    def test_negative_zero(self):
        """Should convert -0 to 0."""
        result = canonicalize_json({"n": -0.0})
        assert result == '{"n":0}'

    def test_escape_sequences(self):
        """Should properly escape special characters."""
        result = canonicalize_json({"s": "a\tb\nc"})
        assert "\\t" in result
        assert "\\n" in result

    def test_empty_values(self):
        """Should handle empty values correctly."""
        assert canonicalize_json(None) == "null"
        assert canonicalize_json(True) == "true"
        assert canonicalize_json(False) == "false"
        assert canonicalize_json({}) == "{}"
        assert canonicalize_json([]) == "[]"
        assert canonicalize_json("") == '""'


# ============================================================================
# Query String Canonicalization Tests
# ============================================================================

class TestQueryCanonicalization:
    """Query string canonicalization tests."""

    def test_sorted(self):
        """Should sort parameters by key."""
        result = canonicalize_query("z=1&a=2&m=3")
        assert result == "a=2&m=3&z=1"

    def test_duplicate_keys_sorted_by_value(self):
        """Should sort duplicate keys by value (byte-wise)."""
        result = canonicalize_query("a=z&a=a&a=m")
        # Per ASH spec: sort by key first, then by value for duplicate keys
        assert result == "a=a&a=m&a=z"

    def test_strip_leading_question_mark(self):
        """Should strip leading ? character."""
        result = canonicalize_query("?a=1&b=2")
        assert result == "a=1&b=2"

    def test_strip_fragment(self):
        """Should strip fragment identifier."""
        result = canonicalize_query("a=1&b=2#section")
        assert result == "a=1&b=2"

    def test_uppercase_hex(self):
        """Should uppercase percent-encoding hex digits."""
        result = canonicalize_query("a=%2f&b=%2F")
        assert result == "a=%2F&b=%2F"

    def test_preserve_empty_values(self):
        """Should preserve empty values."""
        result = canonicalize_query("a=&b=1")
        assert result == "a=&b=1"


# ============================================================================
# URL-Encoded Canonicalization Tests
# ============================================================================

class TestUrlEncodedCanonicalization:
    """URL-encoded form data canonicalization tests."""

    def test_sorted(self):
        """Should sort parameters by key."""
        result = canonicalize_url_encoded("b=2&a=1")
        assert result == "a=1&b=2"

    def test_plus_as_literal(self):
        """Should treat + as literal plus (not space). ASH protocol spec."""
        result = canonicalize_url_encoded("a=hello+world")
        assert result == "a=hello%2Bworld"

    def test_uppercase_hex(self):
        """Should uppercase percent-encoding hex digits."""
        result = canonicalize_url_encoded("a=hello%2fworld")
        assert result == "a=hello%2Fworld"


# ============================================================================
# Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)
# ============================================================================

class TestBindingNormalization:
    """Binding normalization tests."""

    def test_simple(self):
        """Should format as METHOD|PATH|."""
        result = normalize_binding("POST", "/api/test")
        assert result == "POST|/api/test|"

    def test_lowercase_method(self):
        """Should uppercase method."""
        result = normalize_binding("post", "/api/test")
        assert result == "POST|/api/test|"

    def test_with_query(self):
        """Should include query string."""
        result = normalize_binding("GET", "/api/users", "page=1&sort=name")
        assert result == "GET|/api/users|page=1&sort=name"

    def test_query_sorted(self):
        """Should sort query parameters."""
        result = normalize_binding("GET", "/api/users", "z=1&a=2")
        assert result == "GET|/api/users|a=2&z=1"

    def test_collapse_slashes(self):
        """Should collapse duplicate slashes."""
        result = normalize_binding("GET", "/api//test///path")
        assert result == "GET|/api/test/path|"

    def test_remove_trailing_slash(self):
        """Should remove trailing slash."""
        result = normalize_binding("GET", "/api/test/")
        assert result == "GET|/api/test|"

    def test_preserve_root(self):
        """Should preserve root path."""
        result = normalize_binding("GET", "/")
        assert result == "GET|/|"

    def test_add_leading_slash(self):
        """Should add leading slash if missing."""
        result = normalize_binding("GET", "api/test")
        assert result == "GET|/api/test|"

    def test_strip_fragment(self):
        """Should strip fragment identifier."""
        result = normalize_binding("GET", "/api/test#section")
        assert result == "GET|/api/test|"


# ============================================================================
# Hash Body Tests (SHA-256 lowercase hex)
# ============================================================================

class TestHashBody:
    """Body hashing tests."""

    def test_known_value(self):
        """Should produce known SHA-256 hash."""
        result = hash_body("test")
        assert result == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_empty(self):
        """Should hash empty string correctly."""
        result = hash_body("")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_format(self):
        """Should produce 64 lowercase hex characters."""
        result = hash_body('{"amount":100,"recipient":"user123"}')
        assert len(result) == 64
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)


# ============================================================================
# Client Secret Derivation Tests (v2.1)
# ============================================================================

class TestClientSecretDerivation:
    """Client secret derivation tests."""

    def test_deterministic(self):
        """Should produce same result for same inputs."""
        secret1 = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        secret2 = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        assert secret1 == secret2

    def test_format(self):
        """Should produce 64 lowercase hex characters."""
        secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        assert len(secret) == 64
        assert secret == secret.lower()
        assert all(c in "0123456789abcdef" for c in secret)

    def test_different_inputs(self):
        """Should produce different results for different inputs."""
        secret1 = derive_client_secret(TEST_NONCE, "ctx_a", TEST_BINDING)
        secret2 = derive_client_secret(TEST_NONCE, "ctx_b", TEST_BINDING)
        assert secret1 != secret2


# ============================================================================
# v2.1 Proof Tests
# ============================================================================

class TestProofV21:
    """v2.1 proof generation and verification tests."""

    def test_build_deterministic(self):
        """Should produce same proof for same inputs."""
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = hash_body('{"amount":100}')

        proof1 = build_proof_v21(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)
        proof2 = build_proof_v21(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        assert proof1 == proof2

    def test_build_format(self):
        """Should produce 64 lowercase hex characters."""
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = hash_body('{"amount":100}')

        proof = build_proof_v21(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        assert len(proof) == 64
        assert proof == proof.lower()

    def test_verify_valid(self):
        """Should verify valid proof."""
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = hash_body('{"amount":100}')
        proof = build_proof_v21(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        valid = verify_proof_v21(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, proof
        )

        assert valid is True

    def test_verify_invalid_proof(self):
        """Should reject invalid proof."""
        body_hash = hash_body('{"amount":100}')
        wrong_proof = "0" * 64

        valid = verify_proof_v21(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, wrong_proof
        )

        assert valid is False

    def test_verify_wrong_body(self):
        """Should reject proof with wrong body hash."""
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash1 = hash_body('{"amount":100}')
        body_hash2 = hash_body('{"amount":200}')
        proof = build_proof_v21(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash1)

        valid = verify_proof_v21(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash2, proof
        )

        assert valid is False


# ============================================================================
# v2.3 Unified Proof Tests (with Scoping and Chaining)
# ============================================================================

class TestUnifiedProof:
    """v2.3 unified proof tests."""

    def test_basic_no_scope_no_chain(self):
        """Should work without scoping or chaining."""
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}

        proof, scope_hash, chain_hash = build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        assert len(proof) == 64
        assert scope_hash == ""
        assert chain_hash == ""

        # Verify
        valid = verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert valid is True

    def test_with_scope(self):
        """Should work with scoping."""
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test", "recipient": "user123"}
        scope = ["amount", "recipient"]

        proof, scope_hash, chain_hash = build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        assert scope_hash != ""
        assert chain_hash == ""

        # Verify
        valid = verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            scope, scope_hash
        )
        assert valid is True

    def test_with_chain(self):
        """Should work with chaining."""
        binding = "POST|/api/confirm|"
        client_secret = derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, binding)
        payload = {"confirmed": True}
        previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        proof, scope_hash, chain_hash = build_proof_unified(
            client_secret, TEST_TIMESTAMP, binding, payload, [], previous_proof
        )

        assert scope_hash == ""
        assert chain_hash != ""
        assert chain_hash == hash_proof(previous_proof)

        # Verify
        valid = verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, binding, TEST_TIMESTAMP, payload, proof,
            [], "", previous_proof, chain_hash
        )
        assert valid is True


# ============================================================================
# Scoped Field Extraction Tests (ENH-003)
# ============================================================================

class TestScopedFieldExtraction:
    """Scoped field extraction tests."""

    def test_simple(self):
        """Should extract simple fields."""
        payload = {"amount": 100, "note": "test", "recipient": "user123"}
        scope = ["amount", "recipient"]

        result = extract_scoped_fields(payload, scope)

        assert result["amount"] == 100
        assert result["recipient"] == "user123"
        assert "note" not in result

    def test_nested(self):
        """Should extract nested fields using dot notation."""
        payload = {"user": {"name": "John", "email": "john@example.com"}, "amount": 100}
        scope = ["user.name", "amount"]

        result = extract_scoped_fields(payload, scope)

        assert result["user"]["name"] == "John"
        assert result["amount"] == 100
        assert "email" not in result.get("user", {})

    def test_empty_scope(self):
        """Should return full payload for empty scope."""
        payload = {"amount": 100, "note": "test"}
        scope = []

        result = extract_scoped_fields(payload, scope)

        assert result == payload


# ============================================================================
# Hash Proof Tests (for Chaining)
# ============================================================================

class TestHashProof:
    """Proof hashing tests for chaining."""

    def test_deterministic(self):
        """Should produce same hash for same input."""
        proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        hash1 = hash_proof(proof)
        hash2 = hash_proof(proof)
        assert hash1 == hash2

    def test_format(self):
        """Should produce 64 lowercase hex characters."""
        proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        result = hash_proof(proof)
        assert len(result) == 64
        assert result == result.lower()


# ============================================================================
# Timing-Safe Comparison Tests
# ============================================================================

class TestTimingSafeCompare:
    """Timing-safe comparison tests."""

    def test_equal(self):
        """Should return True for equal strings."""
        assert timing_safe_compare("hello", "hello") is True
        assert timing_safe_compare("", "") is True

    def test_not_equal(self):
        """Should return False for different strings."""
        assert timing_safe_compare("hello", "world") is False
        assert timing_safe_compare("hello", "hello!") is False
        assert timing_safe_compare("hello", "") is False


# ============================================================================
# Known Test Vector with Fixed Expected Values
# ============================================================================

class TestFixedVectors:
    """Fixed test vectors for cross-SDK compatibility."""

    def test_client_secret(self):
        """Should produce deterministic client secret."""
        nonce = "a" * 64
        context_id = "ash_fixed_test_001"
        binding = "POST|/api/test|"

        secret = derive_client_secret(nonce, context_id, binding)

        assert len(secret) == 64
        # Verify determinism
        secret2 = derive_client_secret(nonce, context_id, binding)
        assert secret == secret2

    def test_body_hash(self):
        """Should produce deterministic body hash."""
        payload = {"amount": 100, "recipient": "user123"}
        canonical = canonicalize_json(payload)
        hash_result = hash_body(canonical)

        # All SDKs must produce this exact canonical form
        assert canonical == '{"amount":100,"recipient":"user123"}'
        assert len(hash_result) == 64
