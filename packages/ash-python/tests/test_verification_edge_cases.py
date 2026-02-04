"""
Extended Verification Edge Cases.

Tests for comprehensive tampering detection, error handling,
and verification scenarios.
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


class TestTamperingDetectionPayload:
    """Payload tampering detection tests."""

    def test_detect_added_field(self):
        """Should detect when field is added to payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"amount": 100}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: add field
        tampered = '{"amount": 100, "extra": "field"}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_removed_field(self):
        """Should detect when field is removed from payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"amount": 100, "note": "test"}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: remove field
        tampered = '{"amount": 100}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_changed_string_value(self):
        """Should detect when string value changes."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"recipient": "alice"}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: change string
        tampered = '{"recipient": "bob"}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_changed_number_value(self):
        """Should detect when number value changes."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"amount": 100}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: change number
        tampered = '{"amount": 1000}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_changed_boolean_value(self):
        """Should detect when boolean value changes."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"confirmed": true}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: change boolean
        tampered = '{"confirmed": false}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_type_change_number_to_string(self):
        """Should detect type change from number to string."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"value": 100}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: type change
        tampered = '{"value": "100"}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_array_modification(self):
        """Should detect array modification."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"items": [1, 2, 3]}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: modify array
        tampered = '{"items": [1, 2, 4]}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False

    def test_detect_nested_field_change(self):
        """Should detect deeply nested field change."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        original = '{"user": {"address": {"city": "NYC"}}}'
        body_hash = ash_hash_body(original)
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Tamper: nested change
        tampered = '{"user": {"address": {"city": "LA"}}}'
        tampered_hash = ash_hash_body(tampered)

        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, proof
        )
        assert result is False


class TestTamperingDetectionProof:
    """Proof tampering detection tests."""

    def test_detect_single_bit_flip(self):
        """Should detect single bit flip in proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Flip each bit position
        proof_bytes = bytes.fromhex(proof)
        for byte_idx in range(len(proof_bytes)):
            for bit_idx in range(8):
                tampered = bytearray(proof_bytes)
                tampered[byte_idx] ^= (1 << bit_idx)
                tampered_proof = tampered.hex()

                result = ash_verify_proof(
                    TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, tampered_proof
                )
                assert result is False

    def test_detect_truncated_proof(self):
        """Should detect truncated proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        for length in [0, 16, 32, 48, 62]:
            truncated = proof[:length]
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, truncated
            )
            assert result is False

    def test_detect_extended_proof(self):
        """Should detect extended proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        extensions = ["00", "0000", "00000000", "ff", "ffff"]
        for ext in extensions:
            extended = proof + ext
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, extended
            )
            assert result is False

    def test_detect_case_change(self):
        """Should detect case change in proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Test uppercase
        result = ash_verify_proof(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, proof.upper()
        )
        assert result is False

    def test_detect_completely_wrong_proof(self):
        """Should detect completely wrong proof."""
        body_hash = ash_hash_body("test")

        wrong_proofs = [
            "0" * 64,
            "f" * 64,
            "a" * 64,
            "0123456789abcdef" * 4,
        ]
        for wrong_proof in wrong_proofs:
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, wrong_proof
            )
            assert result is False


class TestTamperingDetectionContext:
    """Context tampering detection tests."""

    def test_detect_wrong_nonce_single_char(self):
        """Should detect single character change in nonce."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        # Change single character in nonce
        wrong_nonce = "f" + TEST_NONCE[1:]
        result = ash_verify_proof(
            wrong_nonce, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, body_hash, proof
        )
        assert result is False

    def test_detect_wrong_context_id(self):
        """Should detect wrong context ID."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_contexts = [
            "ash_wrong_context_12345",
            "ash_test_context_12346",
            "different",
            # Note: Empty context_id is rejected by validation, not just verification
        ]
        for wrong_ctx in wrong_contexts:
            result = ash_verify_proof(
                TEST_NONCE, wrong_ctx, TEST_BINDING, TEST_TIMESTAMP, body_hash, proof
            )
            assert result is False

    def test_detect_wrong_binding_method(self):
        """Should detect wrong HTTP method in binding."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_bindings = [
            "GET|/api/transfer|",
            "PUT|/api/transfer|",
            "DELETE|/api/transfer|",
        ]
        for wrong_binding in wrong_bindings:
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, wrong_binding, TEST_TIMESTAMP, body_hash, proof
            )
            assert result is False

    def test_detect_wrong_binding_path(self):
        """Should detect wrong path in binding."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_bindings = [
            "POST|/api/other|",
            "POST|/api/transfer/extra|",
            "POST|/api|",
        ]
        for wrong_binding in wrong_bindings:
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, wrong_binding, TEST_TIMESTAMP, body_hash, proof
            )
            assert result is False


class TestTamperingDetectionTimestamp:
    """Timestamp tampering detection tests."""

    def test_detect_timestamp_increment(self):
        """Should detect timestamp increment."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_timestamps = [
            str(int(TEST_TIMESTAMP) + 1),
            str(int(TEST_TIMESTAMP) + 1000),
            str(int(TEST_TIMESTAMP) + 60000),
        ]
        for wrong_ts in wrong_timestamps:
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, wrong_ts, body_hash, proof
            )
            assert result is False

    def test_detect_timestamp_decrement(self):
        """Should detect timestamp decrement."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_timestamps = [
            str(int(TEST_TIMESTAMP) - 1),
            str(int(TEST_TIMESTAMP) - 1000),
            str(int(TEST_TIMESTAMP) - 60000),
        ]
        for wrong_ts in wrong_timestamps:
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, wrong_ts, body_hash, proof
            )
            assert result is False

    def test_detect_timestamp_format_change(self):
        """Should detect timestamp format changes."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        body_hash = ash_hash_body("test")
        proof = ash_build_proof_hmac(client_secret, TEST_TIMESTAMP, TEST_BINDING, body_hash)

        wrong_formats = [
            "01704067200000",  # Leading zero
            " 1704067200000",  # Leading space
            "1704067200000 ",  # Trailing space
        ]
        for wrong_ts in wrong_formats:
            result = ash_verify_proof(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, wrong_ts, body_hash, proof
            )
            assert result is False


class TestVerificationScopedTampering:
    """Scoped verification tampering tests."""

    def test_detect_scoped_field_change(self):
        """Should detect change in scoped field."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Tamper with scoped field
        tampered_payload = {"amount": 1000, "note": "test"}

        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            tampered_payload, scope, scope_hash, proof
        )
        assert result is False

    def test_allow_unscoped_field_change(self):
        """Should allow change in unscoped field."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "original"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Change unscoped field
        modified_payload = {"amount": 100, "note": "modified"}

        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            modified_payload, scope, scope_hash, proof
        )
        assert result is True

    def test_detect_scope_hash_tampering(self):
        """Should detect scope hash tampering."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Tamper with scope hash
        wrong_scope_hash = "0" * 64

        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            payload, scope, wrong_scope_hash, proof
        )
        assert result is False

    def test_detect_scope_field_swap(self):
        """Should detect when scope fields are swapped."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Try to verify with different scope
        wrong_scope = ["note"]

        result = ash_verify_proof_scoped(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
            payload, wrong_scope, scope_hash, proof
        )
        assert result is False


class TestVerificationUnifiedTampering:
    """Unified verification tampering tests."""

    def test_detect_scope_hash_without_scope(self):
        """Should reject scope_hash when no scope (SEC-013)."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Inject fake scope_hash
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            [], "0" * 64  # scope_hash should be empty when no scope
        )
        assert result is False

    def test_detect_chain_hash_without_previous(self):
        """Should reject chain_hash when no previous_proof (SEC-013)."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Inject fake chain_hash
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", None, "0" * 64  # chain_hash should be empty when no chaining
        )
        assert result is False

    def test_detect_wrong_chain_hash(self):
        """Should detect wrong chain hash."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        previous_proof = "a" * 64

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, previous_proof
        )

        # Wrong previous proof
        wrong_previous = "b" * 64

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", wrong_previous, chain_hash
        )
        assert result is False

    def test_detect_chain_hash_mismatch(self):
        """Should detect chain hash mismatch."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        previous_proof = "a" * 64

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, previous_proof
        )

        # Wrong chain hash
        wrong_chain_hash = "0" * 64

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", previous_proof, wrong_chain_hash
        )
        assert result is False


class TestVerificationEdgeCasesPayload:
    """Payload edge case verification tests."""

    def test_verify_empty_object(self):
        """Should verify empty object payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_verify_deeply_nested_payload(self):
        """Should verify deeply nested payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"a": {"b": {"c": {"d": {"e": {"f": {"g": "deep"}}}}}}}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_verify_large_array_payload(self):
        """Should verify large array payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"items": list(range(1000))}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_verify_unicode_payload(self):
        """Should verify Unicode payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"text": "\u4E2D\u6587\u65E5\u672C\uD55C\uAE00"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_verify_emoji_payload(self):
        """Should verify emoji payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"reaction": "\U0001F600\U0001F44D\U0001F389"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_verify_special_chars_payload(self):
        """Should verify payload with special characters."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"text": "Line1\nLine2\tTab\"Quote\\Backslash"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True

    def test_verify_boolean_null_payload(self):
        """Should verify payload with booleans and null."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"active": True, "deleted": False, "optional": None}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        assert result is True


class TestVerificationMultipleContexts:
    """Multiple context verification tests."""

    def test_different_nonces_different_proofs(self):
        """Different nonces should produce different proofs."""
        payload = {"test": "data"}
        proofs = []

        for i in range(10):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()

            client_secret = ash_derive_client_secret(nonce, context_id, TEST_BINDING)
            proof, _, _ = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
            )
            proofs.append(proof)

        # All proofs should be unique
        assert len(set(proofs)) == len(proofs)

    def test_same_nonce_different_bindings_different_proofs(self):
        """Same nonce with different bindings should produce different proofs."""
        payload = {"test": "data"}
        proofs = []

        bindings = [
            "GET|/api/a|",
            "GET|/api/b|",
            "POST|/api/a|",
            "POST|/api/b|",
            "PUT|/api/a|",
        ]

        for binding in bindings:
            client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, binding)
            proof, _, _ = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, binding, payload
            )
            proofs.append(proof)

        # All proofs should be unique
        assert len(set(proofs)) == len(proofs)

    def test_proof_not_transferable_between_contexts(self):
        """Proof from one context should not work in another."""
        # Create proof in context 1
        nonce1 = ash_generate_nonce()
        ctx1 = ash_generate_context_id()
        client_secret1 = ash_derive_client_secret(nonce1, ctx1, TEST_BINDING)
        payload = {"test": "data"}
        proof1, _, _ = ash_build_proof_unified(
            client_secret1, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Try to verify in context 2
        nonce2 = ash_generate_nonce()
        ctx2 = ash_generate_context_id()

        result = ash_verify_proof_unified(
            nonce2, ctx2, TEST_BINDING, TEST_TIMESTAMP, payload, proof1
        )
        assert result is False


class TestVerificationConsistency:
    """Verification consistency tests."""

    def test_repeated_verification_consistent(self):
        """Repeated verification should produce consistent results."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        results = []
        for _ in range(100):
            result = ash_verify_proof_unified(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
            )
            results.append(result)

        assert all(results)

    def test_verification_order_independent(self):
        """Verification should not depend on order."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Verify multiple times interspersed with invalid verifications
        for _ in range(10):
            # Valid
            result = ash_verify_proof_unified(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
            )
            assert result is True

            # Invalid
            result = ash_verify_proof_unified(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, "0" * 64
            )
            assert result is False

            # Valid again
            result = ash_verify_proof_unified(
                TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
            )
            assert result is True
