"""
Extended Cryptographic Properties Tests.

Tests for additional cryptographic properties including avalanche effect,
hash distribution, timing safety, and key derivation.
"""

import hashlib
import secrets
import time
import statistics
import pytest
from ash.core.proof import (
    ash_base64url_decode,
    ash_base64url_encode,
    ash_build_proof_hmac,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_hash_proof,
)
from ash.core.compare import ash_timing_safe_equal


class TestAvalancheEffectExtended:
    """Extended avalanche effect tests."""

    def test_avalanche_single_bit_multiple_positions(self):
        """Single bit change at various positions should trigger avalanche."""
        base = "a" * 64
        base_hash = ash_hash_body(base)
        base_int = int(base_hash, 16)

        for pos in [0, 16, 32, 48, 63]:
            modified = base[:pos] + "b" + base[pos + 1:]
            modified_hash = ash_hash_body(modified)
            modified_int = int(modified_hash, 16)

            diff_bits = bin(base_int ^ modified_int).count("1")
            # Should change approximately 50% of bits (128 +/- 50)
            assert 78 < diff_bits < 178, f"Position {pos}: only {diff_bits} bits differ"

    def test_avalanche_in_hmac_all_inputs(self):
        """Small change in any HMAC input should cause avalanche."""
        base_secret = "a" * 64
        base_ts = "1704067200000"
        base_binding = "POST|/api/test|"
        base_body_hash = "b" * 64

        base_proof = ash_build_proof_hmac(base_secret, base_ts, base_binding, base_body_hash)
        base_int = int(base_proof, 16)

        # Change secret
        mod_proof = ash_build_proof_hmac("b" + base_secret[1:], base_ts, base_binding, base_body_hash)
        diff = bin(base_int ^ int(mod_proof, 16)).count("1")
        assert diff > 100

        # Change timestamp
        mod_proof = ash_build_proof_hmac(base_secret, "1704067200001", base_binding, base_body_hash)
        diff = bin(base_int ^ int(mod_proof, 16)).count("1")
        assert diff > 100

        # Change binding
        mod_proof = ash_build_proof_hmac(base_secret, base_ts, "POST|/api/test2|", base_body_hash)
        diff = bin(base_int ^ int(mod_proof, 16)).count("1")
        assert diff > 100

        # Change body hash
        mod_proof = ash_build_proof_hmac(base_secret, base_ts, base_binding, "c" + base_body_hash[1:])
        diff = bin(base_int ^ int(mod_proof, 16)).count("1")
        assert diff > 100

    def test_avalanche_client_secret_derivation(self):
        """Client secret derivation should exhibit avalanche."""
        nonce = "a" * 64
        context = "ash_test_ctx"
        binding = "POST|/api/test|"

        base_secret = ash_derive_client_secret(nonce, context, binding)
        base_int = int(base_secret, 16)

        # Change nonce
        mod_secret = ash_derive_client_secret("b" + nonce[1:], context, binding)
        diff = bin(base_int ^ int(mod_secret, 16)).count("1")
        assert diff > 100

        # Change context
        mod_secret = ash_derive_client_secret(nonce, "ash_test_ctx2", binding)
        diff = bin(base_int ^ int(mod_secret, 16)).count("1")
        assert diff > 100

        # Change binding
        mod_secret = ash_derive_client_secret(nonce, context, "POST|/api/test2|")
        diff = bin(base_int ^ int(mod_secret, 16)).count("1")
        assert diff > 100


class TestCollisionResistanceExtended:
    """Extended collision resistance tests."""

    def test_no_collision_incremental_data(self):
        """Incrementally changing data should not collide."""
        hashes = set()
        for i in range(2000):
            data = f"data_{i:08d}"
            h = ash_hash_body(data)
            assert h not in hashes, f"Collision at iteration {i}"
            hashes.add(h)

    def test_no_collision_similar_strings(self):
        """Very similar strings should not collide."""
        base = "The quick brown fox jumps over the lazy dog"
        hashes = set()

        for i in range(len(base)):
            # Change one character at each position
            modified = base[:i] + chr((ord(base[i]) + 1) % 128) + base[i + 1:]
            h = ash_hash_body(modified)
            assert h not in hashes
            hashes.add(h)

    def test_no_collision_prefix_suffix(self):
        """Prefix/suffix variations should not collide."""
        base = "test_data"
        hashes = set()

        for i in range(1000):
            # Prefix
            h = ash_hash_body(f"{i}_{base}")
            assert h not in hashes
            hashes.add(h)

            # Suffix
            h = ash_hash_body(f"{base}_{i}")
            assert h not in hashes
            hashes.add(h)

    def test_no_collision_length_variations(self):
        """Different length strings should not collide."""
        hashes = set()

        for length in range(1, 500):
            h = ash_hash_body("x" * length)
            assert h not in hashes
            hashes.add(h)

    def test_no_collision_unicode_variations(self):
        """Unicode variations should not collide."""
        hashes = set()

        for codepoint in range(0x4E00, 0x4E00 + 500):  # CJK characters
            h = ash_hash_body(chr(codepoint))
            assert h not in hashes
            hashes.add(h)


class TestTimingSafeComparisonExtended:
    """Extended timing-safe comparison tests."""

    def test_timing_equal_lengths_different_content(self):
        """Equal length strings with different content should have consistent timing."""
        secret = secrets.token_hex(32)

        # Generate many wrong values with difference at different positions
        wrong_at_start = [secrets.token_hex(32) for _ in range(100)]
        wrong_at_end = [secret[:-2] + secrets.token_hex(1) for _ in range(100)]

        times_start = []
        for wrong in wrong_at_start:
            start = time.perf_counter_ns()
            ash_timing_safe_equal(secret, wrong)
            times_start.append(time.perf_counter_ns() - start)

        times_end = []
        for wrong in wrong_at_end:
            start = time.perf_counter_ns()
            ash_timing_safe_equal(secret, wrong)
            times_end.append(time.perf_counter_ns() - start)

        # Median times should be similar
        median_start = statistics.median(times_start)
        median_end = statistics.median(times_end)

        ratio = max(median_start, median_end) / max(min(median_start, median_end), 1)
        assert ratio < 3, f"Timing ratio {ratio} suggests timing leak"

    def test_timing_correct_vs_incorrect(self):
        """Correct and incorrect comparisons should have similar timing."""
        secret = secrets.token_hex(32)

        times_correct = []
        for _ in range(100):
            start = time.perf_counter_ns()
            ash_timing_safe_equal(secret, secret)
            times_correct.append(time.perf_counter_ns() - start)

        times_wrong = []
        for _ in range(100):
            wrong = secrets.token_hex(32)
            start = time.perf_counter_ns()
            ash_timing_safe_equal(secret, wrong)
            times_wrong.append(time.perf_counter_ns() - start)

        median_correct = statistics.median(times_correct)
        median_wrong = statistics.median(times_wrong)

        ratio = max(median_correct, median_wrong) / max(min(median_correct, median_wrong), 1)
        assert ratio < 3, f"Timing ratio {ratio} suggests timing leak"


class TestHashDistributionExtended:
    """Extended hash distribution tests."""

    def test_output_length_consistent(self):
        """All hashes should be exactly 64 hex characters."""
        for _ in range(1000):
            data = secrets.token_bytes(secrets.randbelow(1000) + 1)
            h = ash_hash_body(data.hex())
            assert len(h) == 64

    def test_output_lowercase(self):
        """All hashes should be lowercase."""
        for _ in range(1000):
            data = secrets.token_hex(32)
            h = ash_hash_body(data)
            assert h == h.lower()

    def test_byte_distribution(self):
        """Each byte position should have good distribution."""
        byte_values = [[] for _ in range(32)]

        for i in range(1000):
            h = ash_hash_body(f"input_{i}")
            hash_bytes = bytes.fromhex(h)
            for pos, byte in enumerate(hash_bytes):
                byte_values[pos].append(byte)

        # Each position should have reasonable variance
        for pos, values in enumerate(byte_values):
            unique = len(set(values))
            # With 1000 samples, we should see at least 200 unique values
            assert unique > 200, f"Position {pos} has only {unique} unique values"

    def test_first_nibble_distribution(self):
        """First nibble should be uniformly distributed."""
        first_chars = []
        for i in range(10000):
            h = ash_hash_body(f"test_{i}")
            first_chars.append(h[0])

        # Count each hex digit
        counts = {c: first_chars.count(c) for c in "0123456789abcdef"}
        expected = 10000 / 16

        for char, count in counts.items():
            ratio = count / expected
            assert 0.7 < ratio < 1.3, f"First char '{char}' has ratio {ratio}"


class TestBase64URLEncodingExtended:
    """Extended Base64URL tests."""

    def test_roundtrip_various_sizes(self):
        """Roundtrip should work for various sizes."""
        for size in [1, 2, 3, 4, 5, 16, 17, 32, 33, 64, 100, 256]:
            data = secrets.token_bytes(size)
            encoded = ash_base64url_encode(data)
            decoded = ash_base64url_decode(encoded)
            assert decoded == data, f"Roundtrip failed for size {size}"

    def test_no_padding_various_sizes(self):
        """No padding should be present for any size."""
        for size in range(1, 100):
            data = secrets.token_bytes(size)
            encoded = ash_base64url_encode(data)
            assert "=" not in encoded, f"Padding found for size {size}"

    def test_url_safe_characters_only(self):
        """Only URL-safe characters should be used."""
        safe_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

        for _ in range(1000):
            data = secrets.token_bytes(32)
            encoded = ash_base64url_encode(data)
            for char in encoded:
                assert char in safe_chars, f"Unsafe char '{char}' found"

    def test_decode_with_standard_base64(self):
        """Should handle standard Base64 input with + and /."""
        # Standard Base64 encoded "test"
        standard = "dGVzdA=="
        decoded = ash_base64url_decode(standard)
        assert decoded == b"test"


class TestNonceGenerationExtended:
    """Extended nonce generation tests."""

    def test_nonce_entropy(self):
        """Nonces should have good entropy."""
        nonces = [ash_generate_nonce() for _ in range(1000)]

        # Check each character position has good distribution
        for pos in range(64):
            chars_at_pos = [n[pos] for n in nonces]
            unique = len(set(chars_at_pos))
            # Should see at least 12 out of 16 possible hex chars
            assert unique >= 12, f"Position {pos} has only {unique} unique chars"

    def test_nonce_custom_sizes(self):
        """Custom nonce sizes should work correctly."""
        sizes = [8, 16, 24, 32, 48, 64]
        for size in sizes:
            nonce = ash_generate_nonce(size)
            assert len(nonce) == size * 2  # hex encoding doubles length

    def test_nonce_randomness(self):
        """Sequential nonces should not be correlated."""
        nonces = [int(ash_generate_nonce(), 16) for _ in range(100)]

        # Check differences between consecutive nonces
        diffs = [abs(nonces[i+1] - nonces[i]) for i in range(len(nonces) - 1)]

        # Differences should vary widely (not sequential)
        unique_diffs = len(set(diffs))
        assert unique_diffs == len(diffs), "Nonce differences are not random"


class TestContextIdGenerationExtended:
    """Extended context ID generation tests."""

    def test_context_id_prefix_consistent(self):
        """All context IDs should have ash_ prefix."""
        for _ in range(1000):
            ctx = ash_generate_context_id()
            assert ctx.startswith("ash_")

    def test_context_id_suffix_random(self):
        """Context ID suffix should be random."""
        suffixes = [ash_generate_context_id()[4:] for _ in range(1000)]

        # All suffixes should be unique
        assert len(set(suffixes)) == len(suffixes)

    def test_context_id_suffix_hex(self):
        """Context ID suffix should be valid hex."""
        for _ in range(100):
            ctx = ash_generate_context_id()
            suffix = ctx[4:]
            # Should parse as hex without error
            int(suffix, 16)


class TestClientSecretDerivationExtended:
    """Extended client secret derivation tests."""

    def test_secret_uniqueness(self):
        """Different inputs should produce unique secrets."""
        secrets_set = set()

        for i in range(100):
            nonce = ash_generate_nonce()
            ctx = f"ctx_{i}"
            binding = f"POST|/api/v{i}|"
            secret = ash_derive_client_secret(nonce, ctx, binding)
            assert secret not in secrets_set
            secrets_set.add(secret)

    def test_secret_length_consistent(self):
        """All secrets should be 64 hex characters."""
        for _ in range(100):
            nonce = ash_generate_nonce()
            ctx = ash_generate_context_id()
            binding = "POST|/api/test|"
            secret = ash_derive_client_secret(nonce, ctx, binding)
            assert len(secret) == 64

    def test_secret_deterministic(self):
        """Same inputs should always produce same secret."""
        nonce = "a" * 64
        ctx = "ash_test"
        binding = "POST|/api|"

        secrets_list = [
            ash_derive_client_secret(nonce, ctx, binding)
            for _ in range(100)
        ]

        assert len(set(secrets_list)) == 1


class TestHMACPropertiesExtended:
    """Extended HMAC property tests."""

    def test_hmac_different_keys_different_output(self):
        """Different keys should produce different outputs."""
        timestamp = "1234567890"
        binding = "POST|/api/test|"
        body_hash = "a" * 64

        proofs = set()
        for _ in range(100):
            key = secrets.token_hex(32)
            proof = ash_build_proof_hmac(key, timestamp, binding, body_hash)
            assert proof not in proofs
            proofs.add(proof)

    def test_hmac_different_messages_different_output(self):
        """Different messages should produce different outputs."""
        key = "key" * 21 + "k"

        proofs = set()
        for i in range(100):
            body_hash = ash_hash_body(f"message_{i}")
            proof = ash_build_proof_hmac(key, str(i), f"POST|/api/v{i}|", body_hash)
            assert proof not in proofs
            proofs.add(proof)

    def test_hmac_output_format(self):
        """HMAC output should be 64 lowercase hex chars."""
        key = "key" * 21 + "k"
        body_hash = ash_hash_body("test")

        for _ in range(100):
            proof = ash_build_proof_hmac(key, str(secrets.randbelow(10**15)), "POST|/api|", body_hash)
            assert len(proof) == 64
            assert proof == proof.lower()
            assert all(c in "0123456789abcdef" for c in proof)


class TestProofHashingExtended:
    """Extended proof hashing tests."""

    def test_proof_hash_uniqueness(self):
        """Different proofs should produce unique hashes."""
        hashes = set()

        for _ in range(1000):
            proof = secrets.token_hex(32)
            h = ash_hash_proof(proof)
            assert h not in hashes
            hashes.add(h)

    def test_proof_hash_deterministic(self):
        """Same proof should always produce same hash."""
        proof = "test_proof_value"
        hashes = [ash_hash_proof(proof) for _ in range(100)]
        assert len(set(hashes)) == 1

    def test_proof_hash_not_identity(self):
        """Hash should not equal input."""
        for _ in range(100):
            proof = secrets.token_hex(32)
            h = ash_hash_proof(proof)
            assert h != proof
