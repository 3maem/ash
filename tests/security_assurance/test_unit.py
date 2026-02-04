"""
ASH Security Assurance Pack - Unit Tests
=========================================
A. Unit Tests:
- Deterministic signature generation for identical inputs
- Verification failure on single-byte mutation
- Rejection of missing/invalid headers
"""

import pytest
import sys
import os

# Add the ash-python package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))

from ash.core import (
    BuildProofInput,
    build_proof,
    canonicalize_json,
    canonicalize_url_encoded,
    normalize_binding,
    timing_safe_compare,
    derive_client_secret,
    build_proof_v21,
    verify_proof_v21,
    hash_body,
)


class TestDeterministicSignatureGeneration:
    """Test that identical inputs always produce identical outputs."""

    def test_canonicalize_json_deterministic(self):
        """Same JSON input must always produce same canonical output."""
        input_data = {"z": 1, "a": 2, "m": 3}

        results = [canonicalize_json(input_data) for _ in range(100)]

        assert all(r == results[0] for r in results), "Canonicalization is not deterministic"
        assert results[0] == '{"a":2,"m":3,"z":1}'

    def test_canonicalize_json_key_order_deterministic(self):
        """Key ordering must be consistent regardless of input order."""
        input1 = {"z": 1, "a": 2}
        input2 = {"a": 2, "z": 1}

        result1 = canonicalize_json(input1)
        result2 = canonicalize_json(input2)

        assert result1 == result2, "Different input orders produce different outputs"

    def test_build_proof_deterministic(self):
        """Same proof inputs must always produce same proof."""
        input_data = BuildProofInput(
            mode="balanced",
            binding="POST /api/test",
            context_id="ctx_test_123",
            canonical_payload='{"amount":100}',
        )

        proofs = [build_proof(input_data) for _ in range(100)]

        assert all(p == proofs[0] for p in proofs), "Proof generation is not deterministic"

    def test_build_proof_v21_deterministic(self):
        """v2.1 proof must be deterministic."""
        client_secret = "a" * 64
        timestamp = "1704067200000"
        binding = "POST|/api/test|"
        body_hash = hash_body('{"test":1}')

        proofs = [build_proof_v21(client_secret, timestamp, binding, body_hash) for _ in range(100)]

        assert all(p == proofs[0] for p in proofs), "v2.1 proof generation is not deterministic"

    def test_derive_client_secret_deterministic(self):
        """Client secret derivation must be deterministic."""
        nonce = "0123456789abcdef" * 4
        context_id = "ash_test_ctx"
        binding = "POST|/api/test|"

        secrets = [derive_client_secret(nonce, context_id, binding) for _ in range(100)]

        assert all(s == secrets[0] for s in secrets), "Client secret derivation is not deterministic"

    def test_normalize_binding_deterministic(self):
        """Binding normalization must be deterministic."""
        method = "post"
        path = "/api//test/"
        query = "z=1&a=2"

        results = [normalize_binding(method, path, query) for _ in range(100)]

        assert all(r == results[0] for r in results), "Binding normalization is not deterministic"

    def test_hash_body_deterministic(self):
        """Body hashing must be deterministic."""
        body = '{"critical":"data"}'

        hashes = [hash_body(body) for _ in range(100)]

        assert all(h == hashes[0] for h in hashes), "Body hashing is not deterministic"


class TestSingleByteMutationDetection:
    """Test that single-byte mutations are always detected."""

    def test_single_byte_change_in_payload_detected(self):
        """Changing a single byte in payload must produce different proof."""
        original = '{"amount":100}'
        mutated = '{"amount":101}'  # Changed 0 to 1

        input1 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload=original)
        input2 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload=mutated)

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2, "Single byte mutation not detected"

    def test_single_char_change_in_key_detected(self):
        """Changing a single character in key must be detected."""
        original = '{"amount":100}'
        mutated = '{"amounT":100}'  # Changed t to T

        input1 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload=original)
        input2 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload=mutated)

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2, "Key mutation not detected"

    def test_whitespace_addition_detected(self):
        """Adding whitespace must be detected (after canonicalization differs)."""
        # Note: canonicalization removes whitespace, so we test canonical output
        original = {"a": 1}
        mutated = {"a": 1, "b": 2}  # Added field

        canon1 = canonicalize_json(original)
        canon2 = canonicalize_json(mutated)

        assert canon1 != canon2, "Field addition not detected"

    def test_single_byte_in_context_id_detected(self):
        """Single byte change in context ID must produce different proof."""
        input1 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx_abc123", canonical_payload='{}')
        input2 = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx_abc124", canonical_payload='{}')

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2, "Context ID mutation not detected"

    def test_single_byte_in_binding_detected(self):
        """Single byte change in binding must produce different proof."""
        input1 = BuildProofInput(mode="balanced", binding="POST /api", context_id="ctx1", canonical_payload='{}')
        input2 = BuildProofInput(mode="balanced", binding="POST /apj", context_id="ctx1", canonical_payload='{}')

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2, "Binding mutation not detected"

    def test_v21_body_hash_mutation_detected(self):
        """v2.1 verification must detect body hash mutations."""
        nonce = "a" * 64
        context_id = "ash_test"
        binding = "POST|/api|"
        timestamp = "1704067200000"

        body_hash1 = hash_body('{"amount":100}')
        body_hash2 = hash_body('{"amount":101}')

        client_secret = derive_client_secret(nonce, context_id, binding)
        proof = build_proof_v21(client_secret, timestamp, binding, body_hash1)

        # Verify with correct hash should pass
        assert verify_proof_v21(nonce, context_id, binding, timestamp, body_hash1, proof)

        # Verify with mutated hash should fail
        assert not verify_proof_v21(nonce, context_id, binding, timestamp, body_hash2, proof)


class TestMissingInvalidHeaderRejection:
    """Test rejection of missing or invalid headers/parameters."""

    def test_empty_context_id_differentiated(self):
        """Empty context ID should produce different results."""
        input_valid = BuildProofInput(mode="balanced", binding="POST /test", context_id="valid_ctx", canonical_payload='{}')
        input_empty = BuildProofInput(mode="balanced", binding="POST /test", context_id="", canonical_payload='{}')

        proof_valid = build_proof(input_valid)
        proof_empty = build_proof(input_empty)

        assert proof_valid != proof_empty, "Empty context ID not differentiated"

    def test_empty_binding_differentiated(self):
        """Empty binding should produce different results."""
        input_valid = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload='{}')
        input_empty = BuildProofInput(mode="balanced", binding="", context_id="ctx1", canonical_payload='{}')

        proof_valid = build_proof(input_valid)
        proof_empty = build_proof(input_empty)

        assert proof_valid != proof_empty, "Empty binding not differentiated"

    def test_different_modes_produce_different_proofs(self):
        """Different modes should produce different proofs."""
        balanced = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload='{}')
        minimal = BuildProofInput(mode="minimal", binding="POST /test", context_id="ctx1", canonical_payload='{}')
        strict = BuildProofInput(mode="strict", binding="POST /test", context_id="ctx1", canonical_payload='{}')

        proof_balanced = build_proof(balanced)
        proof_minimal = build_proof(minimal)
        proof_strict = build_proof(strict)

        assert proof_balanced != proof_minimal
        assert proof_balanced != proof_strict
        assert proof_minimal != proof_strict

    def test_none_nonce_vs_empty_nonce(self):
        """None nonce and empty nonce should be handled consistently."""
        input_none = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload='{}', nonce=None)
        input_empty = BuildProofInput(mode="balanced", binding="POST /test", context_id="ctx1", canonical_payload='{}', nonce="")

        proof_none = build_proof(input_none)
        proof_empty = build_proof(input_empty)

        # Both should work
        assert proof_none is not None
        assert proof_empty is not None

    def test_v21_empty_timestamp_differentiated(self):
        """Empty timestamp must produce different proof."""
        client_secret = "a" * 64
        binding = "POST|/api|"
        body_hash = hash_body('{}')

        proof_valid = build_proof_v21(client_secret, "1704067200000", binding, body_hash)
        proof_empty = build_proof_v21(client_secret, "", binding, body_hash)

        assert proof_valid != proof_empty, "Empty timestamp not differentiated"

    def test_v21_verification_wrong_nonce_fails(self):
        """Verification with wrong nonce must fail."""
        nonce_correct = "a" * 64
        nonce_wrong = "b" * 64
        context_id = "ash_test"
        binding = "POST|/api|"
        timestamp = "1704067200000"
        body_hash = hash_body('{}')

        client_secret = derive_client_secret(nonce_correct, context_id, binding)
        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        # Correct nonce should verify
        assert verify_proof_v21(nonce_correct, context_id, binding, timestamp, body_hash, proof)

        # Wrong nonce should fail
        assert not verify_proof_v21(nonce_wrong, context_id, binding, timestamp, body_hash, proof)


class TestCanonicalizationConsistency:
    """Test canonicalization edge cases and consistency."""

    def test_unicode_normalization_nfc(self):
        """Unicode must be NFC normalized."""
        import unicodedata
        # é as single char vs e + combining accent
        input1 = {"caf\u00e9": 1}  # é as single codepoint
        input2 = {"cafe\u0301": 1}  # e + combining acute accent

        canon1 = canonicalize_json(input1)
        canon2 = canonicalize_json(input2)

        assert canon1 == canon2, "Unicode NFC normalization not applied"

    def test_number_negative_zero_normalized(self):
        """Negative zero must become positive zero."""
        result = canonicalize_json({"value": -0.0})
        assert result == '{"value":0}', f"Negative zero not normalized: {result}"

    def test_nested_object_key_sorting(self):
        """Nested objects must have keys sorted at all levels."""
        input_data = {
            "z": {"z": 1, "a": 2},
            "a": {"z": 3, "a": 4}
        }

        result = canonicalize_json(input_data)
        expected = '{"a":{"a":4,"z":3},"z":{"a":2,"z":1}}'

        assert result == expected, f"Nested sorting failed: {result}"

    def test_array_order_preserved(self):
        """Array element order must be preserved."""
        input_data = {"arr": [3, 1, 2]}

        result = canonicalize_json(input_data)

        assert '"arr":[3,1,2]' in result, "Array order not preserved"

    def test_special_characters_escaped(self):
        """Special characters must be properly escaped."""
        input_data = {"text": "line1\nline2\ttab\"quote\\backslash"}

        result = canonicalize_json(input_data)

        assert '\\n' in result, "Newline not escaped"
        assert '\\t' in result, "Tab not escaped"
        assert '\\"' in result, "Quote not escaped"
        assert '\\\\' in result, "Backslash not escaped"

    def test_url_encoded_sorting(self):
        """URL-encoded data must be sorted by key."""
        result = canonicalize_url_encoded("z=1&a=2&m=3")

        assert result == "a=2&m=3&z=1", f"URL encoding not sorted: {result}"

    def test_url_encoded_uppercase_hex(self):
        """Percent encoding must use uppercase hex."""
        result = canonicalize_url_encoded("key=hello world")

        assert "%20" in result, f"Space not encoded as %20: {result}"
        # Should not contain lowercase hex letters (a-f) in percent encoding
        # The regex should only match when there's at least one lowercase letter
        import re
        # Look for percent encodings with lowercase letters (e.g., %2f instead of %2F)
        lowercase_hex = re.search(r'%[0-9A-Fa-f][a-f]|%[a-f][0-9A-Fa-f]', result)
        assert lowercase_hex is None, f"Lowercase hex letter found: {result}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
