"""
Comprehensive Verification Tests.

Tests for ash_verify_proof, ash_verify_proof_scoped, ash_verify_proof_unified
and related verification functions.
"""

import pytest
from ash.core.proof import (
    ash_build_proof_hmac,
    ash_build_proof_scoped,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_hash_proof,
    ash_verify_proof,
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
)
from ash.core.canonicalize import ash_canonicalize_json


# Test constants
TEST_NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TEST_CONTEXT_ID = "ash_test_context_12345"
TEST_BINDING = "POST|/api/transfer|"
TEST_TIMESTAMP = "1704067200000"


class TestVerifyProofBasic:
    """Basic verification tests for ash_verify_proof."""

    def test_verify_valid_proof(self):
        """Should verify a valid proof."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"
        body_hash = ash_hash_body('{"test": "data"}')

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True

    def test_reject_invalid_proof(self):
        """Should reject an invalid proof."""
        result = ash_verify_proof(
            TEST_NONCE,
            TEST_CONTEXT_ID,
            TEST_BINDING,
            TEST_TIMESTAMP,
            ash_hash_body("test"),
            "0" * 64  # Wrong proof
        )
        assert result is False

    def test_reject_wrong_nonce(self):
        """Should reject proof with wrong nonce."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_nonce = "f" * 64
        result = ash_verify_proof(
            wrong_nonce, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, proof
        )
        assert result is False

    def test_reject_wrong_context_id(self):
        """Should reject proof with wrong context ID."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        result = ash_verify_proof(
            TEST_NONCE, "wrong_context", TEST_BINDING, TEST_TIMESTAMP, body_hash, proof
        )
        assert result is False

    def test_reject_wrong_binding(self):
        """Should reject proof with wrong binding."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_binding = "GET|/api/other|"
        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, wrong_binding, TEST_TIMESTAMP, body_hash, proof
        )
        assert result is False

    def test_reject_wrong_timestamp(self):
        """Should reject proof with wrong timestamp."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_timestamp = "1704067200001"
        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, wrong_timestamp, body_hash, proof
        )
        assert result is False

    def test_reject_wrong_body_hash(self):
        """Should reject proof with wrong body hash."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("original")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_body_hash = ash_hash_body("tampered")
        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, wrong_body_hash, proof
        )
        assert result is False


class TestVerifyProofTampering:
    """Tests for tamper detection."""

    def test_detect_modified_payload(self):
        """Should detect modified payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original_body = '{"amount": 100}'
        body_hash = ash_hash_body(original_body)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper with payload
        tampered_body = '{"amount": 1000}'
        tampered_hash = ash_hash_body(tampered_body)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_single_bit_change(self):
        """Should detect single bit change in proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Flip one bit
        proof_bytes = bytes.fromhex(proof)
        tampered_bytes = bytearray(proof_bytes)
        tampered_bytes[0] ^= 0x01
        tampered_proof = tampered_bytes.hex()

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, tampered_proof
        )
        assert result is False

    def test_detect_truncated_proof(self):
        """Should reject truncated proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        truncated = proof[:32]  # Half the proof

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, truncated
        )
        assert result is False

    def test_detect_extended_proof(self):
        """Should reject extended proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        extended = proof + "00"  # Extra bytes

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, extended
        )
        assert result is False

    def test_detect_case_change_in_proof(self):
        """Should detect case change in proof (proofs are lowercase)."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        uppercase = proof.upper()

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, uppercase
        )
        # HMAC compare_digest is case-sensitive, so this should fail
        assert result is False


class TestVerifyProofScoped:
    """Tests for scoped proof verification."""

    def test_verify_scoped_proof(self):
        """Should verify scoped proof."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/transfer|"
        timestamp = "1704067200000"
        payload = {"amount": 100, "note": "test", "recipient": "user123"}
        scope = ["amount", "recipient"]

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash = ash_build_proof_scoped(
            client_secret, timestamp, binding, payload, scope
        )

        result = ash_verify_proof_scoped(
            nonce, context_id, binding, timestamp, payload, scope, scope_hash, proof
        )
        assert result is True

    def test_reject_wrong_scope(self):
        """Should reject proof with wrong scope."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        wrong_scope = ["note"]
        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            payload, wrong_scope, scope_hash, proof
        )
        assert result is False

    def test_reject_modified_scoped_field(self):
        """Should reject if scoped field is modified."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        tampered_payload = {"amount": 1000, "note": "test"}
        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            tampered_payload, scope, scope_hash, proof
        )
        assert result is False

    def test_accept_modified_unscoped_field(self):
        """Should accept if only unscoped field is modified."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "original"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Modify unscoped field
        modified_payload = {"amount": 100, "note": "modified"}
        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            modified_payload, scope, scope_hash, proof
        )
        # This should still pass because 'note' is not in scope
        assert result is True

    def test_scoped_nested_fields(self):
        """Should verify nested scoped fields."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"user": {"name": "John", "email": "john@test.com"}, "amount": 100}
        scope = ["user.name", "amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            payload, scope, scope_hash, proof
        )
        assert result is True


class TestVerifyProofUnified:
    """Tests for unified proof verification (with scoping and chaining)."""

    def test_verify_basic_unified(self):
        """Should verify basic unified proof."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"
        timestamp = "1704067200000"
        payload = {"test": "data"}

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_verify_unified_with_scope(self):
        """Should verify unified proof with scoping."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            scope, scope_hash
        )
        assert result is True

    def test_verify_unified_with_chain(self):
        """Should verify unified proof with chaining."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        previous_proof = "a" * 64

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, previous_proof
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", previous_proof, chain_hash
        )
        assert result is True

    def test_verify_unified_with_scope_and_chain(self):
        """Should verify unified proof with both scoping and chaining."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]
        previous_proof = "b" * 64

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope, previous_proof
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            scope, scope_hash, previous_proof, chain_hash
        )
        assert result is True

    def test_reject_wrong_chain_hash(self):
        """Should reject proof with wrong chain hash."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        previous_proof = "a" * 64

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, previous_proof
        )

        wrong_previous_proof = "b" * 64
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", wrong_previous_proof, chain_hash
        )
        assert result is False

    def test_reject_scope_hash_without_scope(self):
        """Should reject scope_hash when scope is empty (SEC-013)."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Try to provide scope_hash without scope
        fake_scope_hash = "0" * 64
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            [], fake_scope_hash  # scope_hash should be empty when no scope
        )
        assert result is False

    def test_reject_chain_hash_without_previous_proof(self):
        """Should reject chain_hash when no previous_proof (SEC-013)."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Try to provide chain_hash without previous_proof
        fake_chain_hash = "0" * 64
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", None, fake_chain_hash  # chain_hash should be empty when no chaining
        )
        assert result is False


class TestVerificationEdgeCases:
    """Edge case tests for verification."""

    def test_empty_payload(self):
        """Should verify proof with empty payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_large_payload(self):
        """Should verify proof with large payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"data": "x" * 10000, "items": list(range(100))}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_special_characters_in_payload(self):
        """Should verify proof with special characters."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"data": "Hello\n\t\"World\"\\Test"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_unicode_payload(self):
        """Should verify proof with Unicode payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"name": "Test", "message": "Hello World"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_nested_payload(self):
        """Should verify proof with deeply nested payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True


class TestConcurrentVerification:
    """Tests for concurrent verification scenarios."""

    def test_independent_verifications(self):
        """Should verify multiple independent proofs."""
        results = []
        for i in range(10):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()
            binding = f"POST|/api/test{i}|"
            payload = {"index": i}

            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            proof, _, _ = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, binding, payload
            )

            result = ash_verify_proof_unified(
                nonce, context_id, binding, TEST_TIMESTAMP, payload, proof
            )
            results.append(result)

        assert all(results)

    def test_same_payload_different_contexts(self):
        """Same payload with different contexts should produce different proofs."""
        payload = {"amount": 100}
        proofs = []

        for i in range(5):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()
            binding = "POST|/api/transfer|"

            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            proof, _, _ = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, binding, payload
            )
            proofs.append(proof)

        # All proofs should be different
        assert len(set(proofs)) == len(proofs)


class TestVerificationConsistency:
    """Tests for verification consistency."""

    def test_verify_multiple_times(self):
        """Should produce consistent results on multiple verifications."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        results = []
        for _ in range(100):
            result = ash_verify_proof_unified(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
            )
            results.append(result)

        assert all(results)

    def test_build_and_verify_roundtrip(self):
        """Build and verify should be inverse operations."""
        for _ in range(10):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()
            binding = "POST|/api/test|"
            payload = {"random": nonce[:16]}

            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            proof, _, _ = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, binding, payload
            )

            # Verify should always pass for correctly built proof
            result = ash_verify_proof_unified(
                nonce, context_id, binding, TEST_TIMESTAMP, payload, proof
            )
            assert result is True

            # Verify with wrong nonce should always fail (different valid hex nonce)
            wrong_nonce = "f" + nonce[1:]  # Change first char to get different valid nonce
            wrong_result = ash_verify_proof_unified(
                wrong_nonce, context_id, binding, TEST_TIMESTAMP, payload, proof
            )
            assert wrong_result is False
