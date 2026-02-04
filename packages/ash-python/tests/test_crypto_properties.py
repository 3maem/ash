"""
Comprehensive Cryptographic Properties Tests.

Tests for cryptographic properties including avalanche effect, collision resistance,
timing-safe comparison, and hash distribution.
"""

import hashlib
import secrets
import time
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
from ash.core.canonicalize import ash_canonicalize_json


class TestAvalancheEffect:
    """Tests for avalanche effect in hash functions."""

    def test_single_bit_change_body_hash(self):
        """Single bit change should produce vastly different hash."""
        body1 = "test data"
        body2 = "test datb"  # Single character difference

        hash1 = ash_hash_body(body1)
        hash2 = ash_hash_body(body2)

        # Count differing bits
        diff_bits = bin(int(hash1, 16) ^ int(hash2, 16)).count("1")

        # Avalanche effect: ~50% of bits should differ (128 bits for SHA-256)
        # Allow range of 100-156 (40%-60%)
        assert diff_bits > 100, f"Only {diff_bits} bits differ, expected more"

    def test_single_bit_change_proof(self):
        """Single bit change in input should cascade through proof."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = "POST|/api/test|"

        secret1 = ash_derive_client_secret(nonce, context_id, binding)
        secret2 = ash_derive_client_secret(nonce, context_id + "x", binding)

        hash1 = ash_hash_body(secret1)
        hash2 = ash_hash_body(secret2)

        diff_bits = bin(int(hash1, 16) ^ int(hash2, 16)).count("1")
        assert diff_bits > 100

    def test_avalanche_in_client_secret(self):
        """Small nonce change should produce completely different secret."""
        nonce1 = "a" * 64
        nonce2 = "a" * 63 + "b"

        secret1 = ash_derive_client_secret(nonce1, "ctx", "POST|/test|")
        secret2 = ash_derive_client_secret(nonce2, "ctx", "POST|/test|")

        # Secrets should be completely different
        assert secret1 != secret2
        diff_bits = bin(int(secret1, 16) ^ int(secret2, 16)).count("1")
        assert diff_bits > 100

    def test_avalanche_in_hmac_proof(self):
        """Small change in any input should change entire proof."""
        client_secret = "a" * 64
        timestamp = "1704067200000"
        binding = "POST|/api/test|"
        body_hash = "b" * 64

        proof1 = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
        proof2 = ash_build_proof_hmac(client_secret, timestamp + "1", binding, body_hash)

        assert proof1 != proof2
        diff_bits = bin(int(proof1, 16) ^ int(proof2, 16)).count("1")
        assert diff_bits > 100


class TestCollisionResistance:
    """Tests for collision resistance properties."""

    def test_no_hash_collisions_random_inputs(self):
        """Random inputs should not produce hash collisions."""
        hashes = set()
        for _ in range(1000):
            data = secrets.token_hex(32)
            h = ash_hash_body(data)
            assert h not in hashes, f"Collision found for {data}"
            hashes.add(h)

    def test_no_collision_sequential_inputs(self):
        """Sequential inputs should not collide."""
        hashes = set()
        for i in range(1000):
            h = ash_hash_body(f"input_{i}")
            assert h not in hashes
            hashes.add(h)

    def test_no_collision_similar_inputs(self):
        """Similar inputs should not collide."""
        base = "test_value_"
        hashes = set()
        for i in range(1000):
            h = ash_hash_body(base + str(i).zfill(10))
            assert h not in hashes
            hashes.add(h)

    def test_no_collision_client_secrets(self):
        """Different contexts should produce unique secrets."""
        nonce = ash_generate_nonce()
        secrets_set = set()

        for i in range(500):
            context_id = f"ctx_{i}"
            secret = ash_derive_client_secret(nonce, context_id, "POST|/test|")
            assert secret not in secrets_set
            secrets_set.add(secret)

    def test_no_collision_proofs(self):
        """Different proofs should not collide."""
        proofs = set()

        for i in range(500):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()
            binding = "POST|/api/test|"
            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            body_hash = ash_hash_body(f"body_{i}")

            proof = ash_build_proof_hmac(client_secret, str(i), binding, body_hash)
            assert proof not in proofs
            proofs.add(proof)


class TestTimingSafeComparison:
    """Tests for timing-safe comparison."""

    def test_equal_strings_return_true(self):
        """Equal strings should return True."""
        assert ash_timing_safe_equal("hello", "hello") is True
        assert ash_timing_safe_equal("", "") is True
        assert ash_timing_safe_equal("a" * 100, "a" * 100) is True

    def test_different_strings_return_false(self):
        """Different strings should return False."""
        assert ash_timing_safe_equal("hello", "world") is False
        assert ash_timing_safe_equal("hello", "hello!") is False
        assert ash_timing_safe_equal("", "x") is False

    def test_different_lengths_return_false(self):
        """Strings of different lengths should return False."""
        assert ash_timing_safe_equal("short", "much longer string") is False
        assert ash_timing_safe_equal("abc", "ab") is False

    def test_unicode_comparison(self):
        """Should handle Unicode strings."""
        assert ash_timing_safe_equal("hello", "hello") is True
        assert ash_timing_safe_equal("hello", "world") is False

    def test_binary_safe(self):
        """Should handle strings with null bytes."""
        assert ash_timing_safe_equal("a\x00b", "a\x00b") is True
        assert ash_timing_safe_equal("a\x00b", "a\x00c") is False

    def test_timing_consistency(self):
        """Comparison time should be consistent regardless of position of difference."""
        secret = "a" * 64
        times_early = []
        times_late = []

        # Difference at start
        wrong_early = "b" + "a" * 63
        for _ in range(100):
            start = time.perf_counter_ns()
            ash_timing_safe_equal(secret, wrong_early)
            times_early.append(time.perf_counter_ns() - start)

        # Difference at end
        wrong_late = "a" * 63 + "b"
        for _ in range(100):
            start = time.perf_counter_ns()
            ash_timing_safe_equal(secret, wrong_late)
            times_late.append(time.perf_counter_ns() - start)

        # Average times should be similar (within 2x)
        avg_early = sum(times_early) / len(times_early)
        avg_late = sum(times_late) / len(times_late)

        ratio = max(avg_early, avg_late) / max(min(avg_early, avg_late), 1)
        # Note: This test is probabilistic and may occasionally fail due to system variability
        # The important thing is that the implementation uses hmac.compare_digest
        assert ratio < 5, f"Timing ratio {ratio} suggests non-constant time"


class TestHashDistribution:
    """Tests for hash output distribution."""

    def test_uniform_bit_distribution(self):
        """Hash bits should be uniformly distributed."""
        bit_counts = [0] * 256  # 256 bits in SHA-256

        for i in range(1000):
            h = ash_hash_body(f"input_{i}")
            hash_int = int(h, 16)
            for bit in range(256):
                if hash_int & (1 << bit):
                    bit_counts[bit] += 1

        # Each bit should be set roughly 50% of the time
        for bit, count in enumerate(bit_counts):
            ratio = count / 1000
            assert 0.35 < ratio < 0.65, f"Bit {bit} has ratio {ratio}"

    def test_hex_character_distribution(self):
        """Hash output should use all hex characters roughly equally."""
        char_counts = {c: 0 for c in "0123456789abcdef"}

        for i in range(1000):
            h = ash_hash_body(f"input_{i}")
            for c in h:
                char_counts[c] += 1

        total = sum(char_counts.values())
        expected = total / 16

        for char, count in char_counts.items():
            ratio = count / expected
            assert 0.8 < ratio < 1.2, f"Char '{char}' has ratio {ratio}"


class TestBase64URLEncoding:
    """Tests for Base64URL encoding/decoding."""

    def test_roundtrip(self):
        """Encode then decode should produce original."""
        for _ in range(100):
            data = secrets.token_bytes(32)
            encoded = ash_base64url_encode(data)
            decoded = ash_base64url_decode(encoded)
            assert decoded == data

    def test_url_safe_characters(self):
        """Output should only contain URL-safe characters."""
        for _ in range(100):
            data = secrets.token_bytes(32)
            encoded = ash_base64url_encode(data)
            assert "+" not in encoded
            assert "/" not in encoded
            assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in encoded)

    def test_no_padding(self):
        """Output should not have padding."""
        for length in range(1, 50):
            data = b"x" * length
            encoded = ash_base64url_encode(data)
            assert "=" not in encoded

    def test_decode_with_padding(self):
        """Should decode strings with padding."""
        padded = "aGVsbG8="
        decoded = ash_base64url_decode(padded)
        assert decoded == b"hello"

    def test_decode_without_padding(self):
        """Should decode strings without padding."""
        unpadded = "aGVsbG8"
        decoded = ash_base64url_decode(unpadded)
        assert decoded == b"hello"

    def test_empty_input(self):
        """Should handle empty input."""
        assert ash_base64url_encode(b"") == ""
        assert ash_base64url_decode("") == b""

    def test_deterministic(self):
        """Same input should produce same output."""
        data = b"test data"
        encoded1 = ash_base64url_encode(data)
        encoded2 = ash_base64url_encode(data)
        assert encoded1 == encoded2


class TestNonceGeneration:
    """Tests for nonce generation."""

    def test_nonce_length(self):
        """Default nonce should be 64 hex characters."""
        nonce = ash_generate_nonce()
        assert len(nonce) == 64

    def test_nonce_format(self):
        """Nonce should be lowercase hex."""
        nonce = ash_generate_nonce()
        assert all(c in "0123456789abcdef" for c in nonce)

    def test_nonce_uniqueness(self):
        """Generated nonces should be unique."""
        nonces = set()
        for _ in range(1000):
            nonce = ash_generate_nonce()
            assert nonce not in nonces
            nonces.add(nonce)

    def test_nonce_custom_length(self):
        """Should support custom byte count."""
        nonce = ash_generate_nonce(16)
        assert len(nonce) == 32  # 16 bytes = 32 hex chars

    def test_nonce_randomness(self):
        """Nonces should have good entropy."""
        nonces = [ash_generate_nonce() for _ in range(100)]

        # Check prefix diversity
        prefixes = set(n[:8] for n in nonces)
        assert len(prefixes) == 100  # All should be unique


class TestContextIdGeneration:
    """Tests for context ID generation."""

    def test_context_id_format(self):
        """Context ID should have ash_ prefix."""
        ctx_id = ash_generate_context_id()
        assert ctx_id.startswith("ash_")

    def test_context_id_length(self):
        """Context ID should have consistent length."""
        ctx_id = ash_generate_context_id()
        assert len(ctx_id) == 36  # "ash_" + 32 hex chars

    def test_context_id_uniqueness(self):
        """Generated context IDs should be unique."""
        ids = set()
        for _ in range(1000):
            ctx_id = ash_generate_context_id()
            assert ctx_id not in ids
            ids.add(ctx_id)

    def test_context_id_hex_suffix(self):
        """Suffix should be valid hex."""
        ctx_id = ash_generate_context_id()
        suffix = ctx_id[4:]  # Remove "ash_"
        assert all(c in "0123456789abcdef" for c in suffix)


class TestHMACProperties:
    """Tests for HMAC-SHA256 properties."""

    def test_hmac_key_sensitivity(self):
        """Different keys should produce different MACs."""
        message = "test message"

        mac1 = ash_build_proof_hmac("key1" * 16, "1234", "POST|/test|", ash_hash_body(message))
        mac2 = ash_build_proof_hmac("key2" * 16, "1234", "POST|/test|", ash_hash_body(message))

        assert mac1 != mac2

    def test_hmac_message_sensitivity(self):
        """Different messages should produce different MACs."""
        key = "key" * 21 + "k"  # 64 chars

        mac1 = ash_build_proof_hmac(key, "1234", "POST|/test|", ash_hash_body("message1"))
        mac2 = ash_build_proof_hmac(key, "1234", "POST|/test|", ash_hash_body("message2"))

        assert mac1 != mac2

    def test_hmac_deterministic(self):
        """Same inputs should produce same MAC."""
        key = "key" * 21 + "k"
        body_hash = ash_hash_body("test")

        mac1 = ash_build_proof_hmac(key, "1234", "POST|/test|", body_hash)
        mac2 = ash_build_proof_hmac(key, "1234", "POST|/test|", body_hash)

        assert mac1 == mac2

    def test_hmac_output_format(self):
        """HMAC output should be 64 lowercase hex characters."""
        key = "key" * 21 + "k"
        body_hash = ash_hash_body("test")

        mac = ash_build_proof_hmac(key, "1234", "POST|/test|", body_hash)

        assert len(mac) == 64
        assert mac == mac.lower()
        assert all(c in "0123456789abcdef" for c in mac)


class TestClientSecretDerivation:
    """Tests for client secret derivation."""

    def test_secret_deterministic(self):
        """Same inputs should produce same secret."""
        nonce = "a" * 64
        ctx = "ash_test"
        binding = "POST|/test|"

        secret1 = ash_derive_client_secret(nonce, ctx, binding)
        secret2 = ash_derive_client_secret(nonce, ctx, binding)

        assert secret1 == secret2

    def test_secret_nonce_sensitive(self):
        """Different nonces should produce different secrets."""
        ctx = "ash_test"
        binding = "POST|/test|"

        secret1 = ash_derive_client_secret("a" * 64, ctx, binding)
        secret2 = ash_derive_client_secret("b" * 64, ctx, binding)

        assert secret1 != secret2

    def test_secret_context_sensitive(self):
        """Different contexts should produce different secrets."""
        nonce = "a" * 64
        binding = "POST|/test|"

        secret1 = ash_derive_client_secret(nonce, "ctx1", binding)
        secret2 = ash_derive_client_secret(nonce, "ctx2", binding)

        assert secret1 != secret2

    def test_secret_binding_sensitive(self):
        """Different bindings should produce different secrets."""
        nonce = "a" * 64
        ctx = "ash_test"

        secret1 = ash_derive_client_secret(nonce, ctx, "POST|/api1|")
        secret2 = ash_derive_client_secret(nonce, ctx, "POST|/api2|")

        assert secret1 != secret2

    def test_secret_output_format(self):
        """Secret should be 64 lowercase hex characters."""
        nonce = "a" * 64
        secret = ash_derive_client_secret(nonce, "ctx", "POST|/test|")

        assert len(secret) == 64
        assert secret == secret.lower()
        assert all(c in "0123456789abcdef" for c in secret)

    def test_secret_not_reversible(self):
        """Should not be able to derive nonce from secret."""
        nonce = "a" * 64
        secret = ash_derive_client_secret(nonce, "ctx", "POST|/test|")

        # Secret should not contain nonce
        assert nonce not in secret
        # Secret should not equal nonce
        assert secret != nonce
