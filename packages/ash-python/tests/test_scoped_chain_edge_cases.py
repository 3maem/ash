"""
Extended Scoped and Chained Proofs Edge Cases.

Tests for comprehensive scoping, chaining, and combined functionality
with complex payloads and edge cases.
"""

import pytest
from ash.core.proof import (
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
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
    SCOPE_FIELD_DELIMITER,
)
from ash.core.canonicalize import ash_canonicalize_json


# Test constants
TEST_NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TEST_CONTEXT_ID = "ash_test_context_12345"
TEST_BINDING = "POST|/api/transfer|"
TEST_TIMESTAMP = "1704067200000"


class TestScopeFieldExtractionEdgeCases:
    """Extended scope field extraction tests."""

    def test_extract_array_element(self):
        """Should extract array as whole (not individual elements)."""
        payload = {"items": [1, 2, 3], "other": "value"}
        scope = ["items"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"items": [1, 2, 3]}

    def test_extract_nested_array(self):
        """Should extract nested array."""
        payload = {"data": {"items": [1, 2, 3]}, "other": "value"}
        scope = ["data.items"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"data": {"items": [1, 2, 3]}}

    def test_extract_multiple_nested(self):
        """Should extract multiple nested fields."""
        payload = {
            "user": {"name": "John", "email": "john@test.com", "age": 30},
            "order": {"id": 123, "amount": 100}
        }
        scope = ["user.name", "order.amount"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"user": {"name": "John"}, "order": {"amount": 100}}

    def test_extract_sibling_nested(self):
        """Should extract sibling nested fields from same parent."""
        payload = {"user": {"name": "John", "email": "john@test.com"}}
        scope = ["user.name", "user.email"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"user": {"name": "John", "email": "john@test.com"}}

    def test_extract_deeply_nested(self):
        """Should extract very deeply nested fields."""
        payload = {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}
        scope = ["a.b.c.d.e.f"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}

    def test_extract_with_special_values(self):
        """Should extract fields with special values."""
        payload = {"bool": True, "number": 0, "string": "", "array": []}
        scope = ["bool", "number", "string", "array"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result["bool"] is True
        assert result["number"] == 0
        assert result["string"] == ""
        assert result["array"] == []

    def test_extract_preserves_types(self):
        """Should preserve value types."""
        payload = {
            "int": 42,
            "float": 3.14,
            "bool": True,
            "string": "test",
            "array": [1, 2, 3],
            "object": {"nested": "value"}
        }
        scope = ["int", "float", "bool", "string", "array", "object"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == payload

    def test_extract_unicode_field_names(self):
        """Should extract fields with Unicode names."""
        payload = {"\u540D\u524D": "value", "other": "data"}
        scope = ["\u540D\u524D"]
        result = ash_extract_scoped_fields(payload, scope)
        assert result == {"\u540D\u524D": "value"}

    def test_extract_field_name_with_dots(self):
        """Should handle field names containing dots - treats as path."""
        payload = {"field.name": "value", "nested": {"path": "other"}}
        scope = ["field.name"]
        # This will be treated as a path, not a literal key
        result = ash_extract_scoped_fields(payload, scope)
        # Looking for payload["field"]["name"] which doesn't exist
        assert result == {}


class TestScopeNormalizationEdgeCases:
    """Extended scope normalization tests."""

    def test_normalize_many_duplicates(self):
        """Should deduplicate many duplicate entries."""
        scope = ["a"] * 100
        result = ash_normalize_scope_fields(scope)
        assert result == ["a"]

    def test_normalize_mixed_duplicates(self):
        """Should deduplicate mixed entries."""
        scope = ["z", "a", "z", "b", "a", "c", "b", "z"]
        result = ash_normalize_scope_fields(scope)
        assert result == ["a", "b", "c", "z"]

    def test_normalize_unicode_fields(self):
        """Should sort Unicode fields correctly."""
        scope = ["\u4E2D", "\u0041", "\u0042"]  # Chinese, A, B
        result = ash_normalize_scope_fields(scope)
        # Sorted by code point: A < B < Chinese
        assert result == ["\u0041", "\u0042", "\u4E2D"]

    def test_normalize_nested_paths(self):
        """Should sort nested paths correctly."""
        scope = ["user.email", "user.name", "user.address.city", "amount"]
        result = ash_normalize_scope_fields(scope)
        assert result == ["amount", "user.address.city", "user.email", "user.name"]

    def test_normalize_preserves_case(self):
        """Should preserve case but sort case-sensitively."""
        scope = ["Name", "name", "NAME"]
        result = ash_normalize_scope_fields(scope)
        assert result == ["NAME", "Name", "name"]

    def test_normalize_empty_string(self):
        """Should handle empty string field name."""
        scope = ["b", "", "a"]
        result = ash_normalize_scope_fields(scope)
        assert result == ["", "a", "b"]

    def test_normalize_special_characters(self):
        """Should handle special characters in field names."""
        scope = ["_field", "field", "-field", "0field"]
        result = ash_normalize_scope_fields(scope)
        # Sorted by ASCII: - < 0 < _ < f
        assert result[0] in ["-field", "0field", "_field", "field"]


class TestScopeJoiningEdgeCases:
    """Extended scope joining tests."""

    def test_join_many_fields(self):
        """Should join many fields."""
        scope = [f"field{i}" for i in range(100)]
        result = ash_join_scope_fields(scope)
        # Should be sorted and joined
        assert SCOPE_FIELD_DELIMITER in result
        parts = result.split(SCOPE_FIELD_DELIMITER)
        assert len(parts) == 100

    def test_join_unicode_fields(self):
        """Should join Unicode fields."""
        scope = ["\u4E2D\u6587", "\u65E5\u672C"]
        result = ash_join_scope_fields(scope)
        assert SCOPE_FIELD_DELIMITER in result

    def test_join_fields_with_delimiter_char(self):
        """Should handle fields that might conflict with delimiter."""
        scope = ["field1", "field2"]
        result = ash_join_scope_fields(scope)
        assert result == f"field1{SCOPE_FIELD_DELIMITER}field2"

    def test_join_deterministic(self):
        """Join should be deterministic."""
        scope = ["z", "a", "m"]
        results = [ash_join_scope_fields(scope) for _ in range(100)]
        assert len(set(results)) == 1


class TestScopedHashingEdgeCases:
    """Extended scoped body hashing tests."""

    def test_hash_single_field(self):
        """Should hash single scoped field."""
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]
        result = ash_hash_scoped_body(payload, scope)
        expected = ash_hash_body(ash_canonicalize_json({"amount": 100}))
        assert result == expected

    def test_hash_multiple_fields(self):
        """Should hash multiple scoped fields."""
        payload = {"a": 1, "b": 2, "c": 3}
        scope = ["a", "c"]
        result = ash_hash_scoped_body(payload, scope)
        expected = ash_hash_body(ash_canonicalize_json({"a": 1, "c": 3}))
        assert result == expected

    def test_hash_order_independent(self):
        """Scope order should not affect hash."""
        payload = {"a": 1, "b": 2, "c": 3}
        result1 = ash_hash_scoped_body(payload, ["a", "b", "c"])
        result2 = ash_hash_scoped_body(payload, ["c", "b", "a"])
        result3 = ash_hash_scoped_body(payload, ["b", "a", "c"])
        assert result1 == result2 == result3

    def test_hash_empty_scope_uses_full(self):
        """Empty scope should use full payload."""
        payload = {"a": 1, "b": 2}
        scope = []
        result = ash_hash_scoped_body(payload, scope)
        expected = ash_hash_body(ash_canonicalize_json(payload))
        assert result == expected


class TestChainHashEdgeCases:
    """Extended chain hash tests."""

    def test_hash_proof_various_lengths(self):
        """Should hash proofs of various lengths."""
        proofs = ["a" * 32, "b" * 64, "c" * 128]
        hashes = [ash_hash_proof(p) for p in proofs]
        # All should be 64 hex chars
        assert all(len(h) == 64 for h in hashes)
        # All should be unique
        assert len(set(hashes)) == len(hashes)

    def test_hash_proof_unicode(self):
        """Should hash proofs with Unicode."""
        proof = "\u4E2D\u6587test"
        result = ash_hash_proof(proof)
        assert len(result) == 64

    def test_hash_proof_special_chars(self):
        """Should hash proofs with special characters."""
        proof = "test\n\t\\\"proof"
        result = ash_hash_proof(proof)
        assert len(result) == 64


class TestScopedProofBuildingEdgeCases:
    """Extended scoped proof building tests."""

    def test_build_with_empty_scope(self):
        """Should build proof with empty scope using full payload."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"a": 1, "b": 2}
        scope = []

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Should build successfully
        assert len(proof) == 64
        assert len(scope_hash) == 64

    def test_build_with_nonexistent_scope(self):
        """Should handle scope fields that don't exist."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"a": 1, "b": 2}
        scope = ["nonexistent"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Should build with empty extracted payload
        assert len(proof) == 64

    def test_build_with_partial_scope(self):
        """Should handle partial scope matches."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"a": 1, "b": 2, "c": 3}
        scope = ["a", "nonexistent", "c"]

        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Should build with partial extraction
        assert len(proof) == 64

    def test_build_scope_deterministic(self):
        """Scoped proof building should be deterministic."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"z": 1, "a": 2, "m": 3}
        scope = ["a", "z"]

        results = []
        for _ in range(100):
            proof, scope_hash = ash_build_proof_scoped(
                client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
            )
            results.append((proof, scope_hash))

        assert len(set(results)) == 1


class TestChainedProofBuildingEdgeCases:
    """Extended chained proof building tests."""

    def test_chain_with_empty_previous(self):
        """Should handle empty previous proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, ""
        )

        # Empty string should result in empty chain_hash
        assert chain_hash == ""

    def test_chain_multiple_proofs(self):
        """Should chain multiple proofs correctly."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)

        # Build chain of proofs
        proofs = []
        current_chain = None

        for i in range(10):
            payload = {"step": i}
            proof, _, chain_hash = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, current_chain
            )
            proofs.append(proof)
            current_chain = proof

        # All proofs should be unique
        assert len(set(proofs)) == len(proofs)

    def test_chain_hash_different_proofs(self):
        """Different proofs should produce different chain hashes."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        chain_hashes = []
        for i in range(10):
            previous = f"proof{i}" * 10
            _, _, chain_hash = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, previous
            )
            chain_hashes.append(chain_hash)

        assert len(set(chain_hashes)) == len(chain_hashes)


class TestUnifiedProofEdgeCases:
    """Extended unified proof tests."""

    def test_unified_all_options(self):
        """Should build proof with all options."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]
        previous_proof = "previous" * 10

        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope, previous_proof
        )

        assert len(proof) == 64
        assert len(scope_hash) == 64
        assert len(chain_hash) == 64

    def test_unified_none_vs_empty_scope(self):
        """None scope should equal empty scope."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        proof1, scope_hash1, chain_hash1 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None
        )
        proof2, scope_hash2, chain_hash2 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, []
        )

        assert proof1 == proof2
        assert scope_hash1 == scope_hash2 == ""
        assert chain_hash1 == chain_hash2 == ""


class TestChainVerificationEdgeCases:
    """Extended chain verification tests."""

    def test_verify_long_chain(self):
        """Should verify long proof chain."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/step|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        # Build chain of 10 proofs
        previous_proof = None
        proofs = []

        for i in range(10):
            payload = {"step": i}
            proof, _, chain_hash = ash_build_proof_unified(
                client_secret, TEST_TIMESTAMP, binding, payload, None, previous_proof
            )
            proofs.append((proof, chain_hash, previous_proof))
            previous_proof = proof

        # Verify last proof with full chain
        last_proof, last_chain_hash, last_previous = proofs[-1]
        result = ash_verify_proof_unified(
            nonce, context_id, binding, TEST_TIMESTAMP, {"step": 9}, last_proof,
            None, "", last_previous, last_chain_hash
        )
        assert result is True

    def test_verify_chain_broken_in_middle(self):
        """Should detect broken chain."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)

        # Build proof chained to proof1
        proof1 = "a" * 64
        payload = {"test": "data"}
        proof2, _, chain_hash2 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, proof1
        )

        # Try to verify with different previous proof
        wrong_previous = "b" * 64
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof2,
            None, "", wrong_previous, chain_hash2
        )
        assert result is False


class TestScopeAndChainCombinedEdgeCases:
    """Extended combined scope and chain tests."""

    def test_scope_and_chain_verification(self):
        """Should verify proof with both scope and chain."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/transfer|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        # First proof without chain
        payload1 = {"amount": 100}
        proof1, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, binding, payload1
        )

        # Second proof with scope and chain
        payload2 = {"amount": 200, "note": "test"}
        scope = ["amount"]
        proof2, scope_hash2, chain_hash2 = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, binding, payload2, scope, proof1
        )

        # Verify
        result = ash_verify_proof_unified(
            nonce, context_id, binding, TEST_TIMESTAMP, payload2, proof2,
            scope, scope_hash2, proof1, chain_hash2
        )
        assert result is True

    def test_scope_protects_through_chain(self):
        """Scoped fields should remain protected through chain."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/transfer|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        # Build proof with scope
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]
        proof, scope_hash, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, binding, payload, scope
        )

        # Tamper with scoped field
        tampered_payload = {"amount": 1000, "note": "test"}

        # Should fail
        result = ash_verify_proof_unified(
            nonce, context_id, binding, TEST_TIMESTAMP, tampered_payload, proof,
            scope, scope_hash
        )
        assert result is False

    def test_unscoped_field_change_with_chain(self):
        """Unscoped field change should be allowed even with chain."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/transfer|"
        client_secret = ash_derive_client_secret(nonce, context_id, binding)

        # Build scoped proof using ash_build_proof_scoped (not unified)
        payload = {"amount": 100, "note": "original"}
        scope = ["amount"]
        proof, scope_hash = ash_build_proof_scoped(
            client_secret, TEST_TIMESTAMP, binding, payload, scope
        )

        # Change unscoped field
        modified_payload = {"amount": 100, "note": "modified"}

        # Should still pass - only "amount" is protected
        result = ash_verify_proof_scoped(
            nonce, context_id, binding, TEST_TIMESTAMP,
            modified_payload, scope, scope_hash, proof
        )
        assert result is True


class TestScopeSecurityEdgeCases:
    """Security-focused scope edge cases."""

    def test_cannot_add_scope_after_fact(self):
        """Cannot claim scope after building without it."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}

        # Build proof without scope
        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Try to verify with fake scope
        fake_scope = ["note"]  # Trying to protect only note
        fake_scope_hash = ash_hash_body(ash_join_scope_fields(fake_scope))

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            fake_scope, fake_scope_hash
        )
        assert result is False

    def test_cannot_remove_scope_after_fact(self):
        """Cannot claim no scope after building with it."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        # Build proof with scope
        proof, scope_hash, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Try to verify without scope
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        # Proof was built with scope, so verifying without scope should fail
        assert result is False

    def test_cannot_modify_scope_after_fact(self):
        """Cannot change scope after building."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"amount": 100, "note": "test"}
        scope = ["amount"]

        # Build proof with scope
        proof, scope_hash, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope
        )

        # Try to verify with different scope
        different_scope = ["amount", "note"]
        different_scope_hash = ash_hash_body(ash_join_scope_fields(different_scope))

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            different_scope, different_scope_hash
        )
        assert result is False


class TestChainSecurityEdgeCases:
    """Security-focused chain edge cases."""

    def test_cannot_add_chain_after_fact(self):
        """Cannot claim chain after building without it."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}

        # Build proof without chain
        proof, _, _ = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload
        )

        # Try to verify with fake chain
        fake_previous = "a" * 64
        fake_chain_hash = ash_hash_proof(fake_previous)

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", fake_previous, fake_chain_hash
        )
        assert result is False

    def test_cannot_remove_chain_after_fact(self):
        """Cannot claim no chain after building with it."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        previous = "a" * 64

        # Build proof with chain
        proof, _, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, previous
        )

        # Try to verify without chain
        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof
        )
        # Proof was built with chain, so verifying without chain should fail
        assert result is False

    def test_cannot_substitute_previous_proof(self):
        """Cannot substitute a different previous proof."""
        client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING)
        payload = {"test": "data"}
        original_previous = "a" * 64

        # Build proof with specific previous
        proof, _, chain_hash = ash_build_proof_unified(
            client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, None, original_previous
        )

        # Try to verify with different previous but same chain_hash
        different_previous = "b" * 64

        result = ash_verify_proof_unified(
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, payload, proof,
            None, "", different_previous, chain_hash
        )
        assert result is False
