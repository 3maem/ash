"""Tests for ASH proof generation."""

import pytest
from ash.core.proof import build_proof, base64url_encode, base64url_decode
from ash.core.types import BuildProofInput


class TestBuildProof:
    """Tests for proof generation."""

    def test_deterministic(self):
        """Same inputs should produce same proof."""
        input_data = BuildProofInput(
            mode="balanced",
            binding="POST /api/update",
            context_id="test-context-123",
            canonical_payload='{"name":"test"}',
        )

        proof1 = build_proof(input_data)
        proof2 = build_proof(input_data)

        assert proof1 == proof2

    def test_different_payload_different_proof(self):
        """Different payloads should produce different proofs."""
        input1 = BuildProofInput(
            mode="balanced",
            binding="POST /api/update",
            context_id="test-context-123",
            canonical_payload='{"name":"test1"}',
        )
        input2 = BuildProofInput(
            mode="balanced",
            binding="POST /api/update",
            context_id="test-context-123",
            canonical_payload='{"name":"test2"}',
        )

        proof1 = build_proof(input1)
        proof2 = build_proof(input2)

        assert proof1 != proof2

    def test_with_nonce(self):
        """Should include nonce in proof."""
        without_nonce = BuildProofInput(
            mode="balanced",
            binding="POST /api/update",
            context_id="test-context-123",
            canonical_payload='{"name":"test"}',
        )
        with_nonce = BuildProofInput(
            mode="balanced",
            binding="POST /api/update",
            context_id="test-context-123",
            canonical_payload='{"name":"test"}',
            nonce="server-nonce-456",
        )

        proof_without = build_proof(without_nonce)
        proof_with = build_proof(with_nonce)

        assert proof_without != proof_with

    def test_base64url_format(self):
        """Proof should be valid Base64URL (no padding)."""
        input_data = BuildProofInput(
            mode="balanced",
            binding="POST /api/update",
            context_id="test-context-123",
            canonical_payload='{"name":"test"}',
        )

        proof = build_proof(input_data)

        # Should not contain standard Base64 characters replaced by URL-safe ones
        assert "+" not in proof
        assert "/" not in proof
        assert "=" not in proof

        # Should be decodable
        decoded = base64url_decode(proof)
        assert len(decoded) == 32  # SHA-256 produces 32 bytes


class TestBase64Url:
    """Tests for Base64URL encoding/decoding."""

    def test_roundtrip(self):
        """Should encode and decode correctly."""
        data = b"hello world"
        encoded = base64url_encode(data)
        decoded = base64url_decode(encoded)
        assert decoded == data

    def test_url_safe(self):
        """Should produce URL-safe output."""
        # This data produces + and / in standard Base64
        data = b"\xfb\xff\xfe"
        encoded = base64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_no_padding(self):
        """Should not include padding."""
        data = b"a"  # Would produce padding in standard Base64
        encoded = base64url_encode(data)
        assert "=" not in encoded

    def test_decode_with_padding(self):
        """Should handle padded input."""
        # Standard Base64 with padding
        encoded = "aGVsbG8="
        decoded = base64url_decode(encoded)
        assert decoded == b"hello"
