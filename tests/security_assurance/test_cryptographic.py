"""
ASH Security Assurance Pack - Cryptographic Tests
==================================================
D. Cryptographic Tests:
- Constant-time comparison validation
- Algorithm strength verification
- No exposure of secrets/nonces
"""

import pytest
import sys
import os
import time
import statistics
import hashlib
import hmac

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))

from ash.core import (
    timing_safe_compare,
    derive_client_secret,
    build_proof_v21,
    hash_body,
    build_proof,
    BuildProofInput,
)


class TestConstantTimeComparison:
    """Test constant-time comparison implementation."""

    def test_equal_strings_return_true(self):
        """Equal strings must return True."""
        assert timing_safe_compare("test123", "test123")
        assert timing_safe_compare("a" * 1000, "a" * 1000)
        assert timing_safe_compare("", "")

    def test_unequal_strings_return_false(self):
        """Unequal strings must return False."""
        assert not timing_safe_compare("test123", "test124")
        assert not timing_safe_compare("abc", "abd")
        assert not timing_safe_compare("short", "longer")

    def test_different_length_strings(self):
        """Different length strings must return False."""
        assert not timing_safe_compare("short", "longer_string")
        assert not timing_safe_compare("a", "aa")
        assert not timing_safe_compare("", "nonempty")

    def test_timing_safety_early_vs_late_difference(self):
        """
        Timing difference between early and late byte differences
        should be minimal (constant-time behavior).

        Note: This is a statistical test and may have some variance.
        """
        iterations = 1000
        base = "a" * 64

        # String differing at first byte
        early_diff = "b" + "a" * 63

        # String differing at last byte
        late_diff = "a" * 63 + "b"

        # Measure early difference timing
        early_times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            timing_safe_compare(base, early_diff)
            early_times.append(time.perf_counter_ns() - start)

        # Measure late difference timing
        late_times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            timing_safe_compare(base, late_diff)
            late_times.append(time.perf_counter_ns() - start)

        # Calculate statistics
        early_median = statistics.median(early_times)
        late_median = statistics.median(late_times)

        # The difference should be small (within 50% typically for constant-time)
        # This is a heuristic - true constant-time is hard to verify in Python
        ratio = max(early_median, late_median) / min(early_median, late_median)

        # Allow up to 3x variance due to Python overhead and system noise
        assert ratio < 3.0, f"Timing ratio {ratio:.2f} suggests non-constant-time comparison"

    def test_timing_safety_equal_vs_unequal(self):
        """Equal and unequal comparisons should have similar timing."""
        iterations = 1000
        str1 = "a" * 64
        str2_equal = "a" * 64
        str2_unequal = "b" * 64

        # Measure equal comparison timing
        equal_times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            timing_safe_compare(str1, str2_equal)
            equal_times.append(time.perf_counter_ns() - start)

        # Measure unequal comparison timing
        unequal_times = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            timing_safe_compare(str1, str2_unequal)
            unequal_times.append(time.perf_counter_ns() - start)

        equal_median = statistics.median(equal_times)
        unequal_median = statistics.median(unequal_times)

        ratio = max(equal_median, unequal_median) / min(equal_median, unequal_median)

        # Should be similar timing
        assert ratio < 3.0, f"Equal/unequal timing ratio {ratio:.2f} suggests timing leak"


class TestAlgorithmStrength:
    """Test cryptographic algorithm strength."""

    def test_proof_uses_sha256(self):
        """Proof should use SHA-256 (32 bytes = 43-44 base64url chars)."""
        input_data = BuildProofInput(
            mode="balanced",
            binding="POST /test",
            context_id="ctx123",
            canonical_payload='{}',
        )
        proof = build_proof(input_data)

        # Base64URL encoded SHA-256 should be 43 characters (no padding)
        assert len(proof) == 43, f"Unexpected proof length: {len(proof)} (expected 43 for SHA-256)"

    def test_v21_proof_uses_hmac_sha256(self):
        """v2.1 proof should use HMAC-SHA256 (64 hex chars)."""
        client_secret = "a" * 64
        timestamp = "1704067200000"
        binding = "POST|/api/test|"
        body_hash = hash_body('{}')

        proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

        # HMAC-SHA256 output is 32 bytes = 64 hex chars
        assert len(proof) == 64, f"Unexpected v2.1 proof length: {len(proof)} (expected 64)"
        assert all(c in '0123456789abcdef' for c in proof), "Proof should be lowercase hex"

    def test_body_hash_uses_sha256(self):
        """Body hash should use SHA-256 (64 hex chars)."""
        body_hash = hash_body('{"test":"data"}')

        assert len(body_hash) == 64, f"Unexpected hash length: {len(body_hash)} (expected 64)"
        assert all(c in '0123456789abcdef' for c in body_hash), "Hash should be lowercase hex"

    def test_client_secret_derivation_uses_hmac(self):
        """Client secret derivation should use HMAC-SHA256."""
        nonce = "0123456789abcdef" * 4  # 64 hex chars
        context_id = "ash_test"
        binding = "POST|/api/test|"

        client_secret = derive_client_secret(nonce, context_id, binding)

        # HMAC-SHA256 output is 32 bytes = 64 hex chars
        assert len(client_secret) == 64, f"Unexpected secret length: {len(client_secret)}"

    def test_different_inputs_produce_different_outputs(self):
        """Different inputs must produce different cryptographic outputs."""
        # Test hash_body
        hash1 = hash_body('{"a":1}')
        hash2 = hash_body('{"a":2}')
        assert hash1 != hash2, "Different payloads produce same hash"

        # Test derive_client_secret
        secret1 = derive_client_secret("a" * 64, "ctx1", "POST|/a|")
        secret2 = derive_client_secret("a" * 64, "ctx2", "POST|/a|")
        assert secret1 != secret2, "Different context IDs produce same secret"

        # Test build_proof_v21
        proof1 = build_proof_v21("a" * 64, "100", "POST|/a|", hash1)
        proof2 = build_proof_v21("a" * 64, "100", "POST|/a|", hash2)
        assert proof1 != proof2, "Different body hashes produce same proof"

    def test_entropy_in_outputs(self):
        """Outputs should have high entropy (no obvious patterns)."""
        # Generate multiple hashes and check they're all different
        hashes = [hash_body(f'{{"n":{i}}}') for i in range(100)]

        unique_hashes = set(hashes)
        assert len(unique_hashes) == 100, "Hash collision detected"

        # Check character distribution (rough entropy check)
        all_chars = ''.join(hashes)
        char_counts = {}
        for c in all_chars:
            char_counts[c] = char_counts.get(c, 0) + 1

        # Each hex character should appear roughly 6.25% of the time
        # Allow 2-12% range for randomness
        total_chars = len(all_chars)
        for char, count in char_counts.items():
            percentage = (count / total_chars) * 100
            assert 2 < percentage < 12, f"Character '{char}' appears {percentage:.1f}% - suspicious distribution"


class TestNoSecretExposure:
    """Test that secrets are not exposed in outputs."""

    def test_nonce_not_in_proof(self):
        """Nonce value must not appear in proof output."""
        nonce = "supersecretnoncevalue1234567890123456789012345678901234"
        context_id = "ash_test"
        binding = "POST|/api/test|"

        client_secret = derive_client_secret(nonce, context_id, binding)
        body_hash = hash_body('{}')
        proof = build_proof_v21(client_secret, "1234567890", binding, body_hash)

        assert nonce not in proof, "Nonce appears in proof"
        assert nonce not in client_secret, "Nonce appears in client secret"

    def test_client_secret_not_in_proof(self):
        """Client secret must not appear directly in proof."""
        client_secret = "a1b2c3d4e5f6" * 5 + "ab"  # 64 chars
        body_hash = hash_body('{}')

        proof = build_proof_v21(client_secret, "1234567890", "POST|/api|", body_hash)

        assert client_secret not in proof, "Client secret appears in proof"

    def test_input_data_not_in_hash(self):
        """Input data must not be recoverable from hash."""
        sensitive_data = '{"password":"supersecret123","ssn":"123-45-6789"}'
        body_hash = hash_body(sensitive_data)

        # Hash should not contain any part of the sensitive data
        assert "supersecret" not in body_hash
        assert "123-45-6789" not in body_hash
        assert "password" not in body_hash

    def test_v21_proof_formula_security(self):
        """Verify v2.1 proof includes all security-relevant components."""
        client_secret = "a" * 64
        body_hash = hash_body('{"amount":100}')

        # Same secret, different timestamps = different proofs
        proof1 = build_proof_v21(client_secret, "1000", "POST|/api|", body_hash)
        proof2 = build_proof_v21(client_secret, "2000", "POST|/api|", body_hash)
        assert proof1 != proof2, "Timestamp not included in proof"

        # Same secret, different bindings = different proofs
        proof3 = build_proof_v21(client_secret, "1000", "POST|/api/a|", body_hash)
        proof4 = build_proof_v21(client_secret, "1000", "POST|/api/b|", body_hash)
        assert proof3 != proof4, "Binding not included in proof"

        # Same everything, different body = different proofs
        hash1 = hash_body('{"a":1}')
        hash2 = hash_body('{"a":2}')
        proof5 = build_proof_v21(client_secret, "1000", "POST|/api|", hash1)
        proof6 = build_proof_v21(client_secret, "1000", "POST|/api|", hash2)
        assert proof5 != proof6, "Body hash not included in proof"


class TestCryptographicEdgeCases:
    """Test cryptographic edge cases."""

    def test_empty_input_hashing(self):
        """Empty input should produce valid hash."""
        hash_empty = hash_body('')
        assert len(hash_empty) == 64, "Empty input hash has wrong length"

    def test_very_long_input_hashing(self):
        """Very long inputs should be handled correctly."""
        long_input = '{"data":"' + "x" * 100000 + '"}'
        hash_long = hash_body(long_input)
        assert len(hash_long) == 64, "Long input hash has wrong length"

    def test_unicode_input_hashing(self):
        """Unicode inputs should be handled correctly."""
        unicode_input = '{"emoji":"🎉","chinese":"中文","arabic":"العربية"}'
        hash_unicode = hash_body(unicode_input)
        assert len(hash_unicode) == 64, "Unicode input hash has wrong length"

    def test_binary_like_strings_in_json(self):
        """Binary-like strings in JSON should be handled."""
        binary_like = '{"data":"\\u0000\\u0001\\u0002"}'
        hash_result = hash_body(binary_like)
        assert len(hash_result) == 64, "Binary-like string hash has wrong length"

    def test_special_json_values(self):
        """Special JSON values should be hashed correctly."""
        # Null
        hash_null = hash_body('{"value":null}')
        assert len(hash_null) == 64

        # Boolean
        hash_bool = hash_body('{"value":true}')
        assert len(hash_bool) == 64

        # Number zero
        hash_zero = hash_body('{"value":0}')
        assert len(hash_zero) == 64

        # All should be different
        assert len({hash_null, hash_bool, hash_zero}) == 3, "Different values produce same hash"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
