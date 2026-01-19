"""Tests for Ash core class."""

from ash import Ash, AshErrorCode, AshMode, MemoryStore, ash_build_proof


class TestAsh:
    """Tests for Ash core class."""

    def test_issue_context(self) -> None:
        """Test issuing a context."""
        store = MemoryStore()
        ash = Ash(store)
        
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000)
        
        assert ctx.id.startswith('ctx_')
        assert ctx.binding == 'POST /api/update'
        assert ctx.mode == AshMode.BALANCED

    def test_issue_context_with_mode(self) -> None:
        """Test issuing a context with specific mode."""
        store = MemoryStore()
        ash = Ash(store)
        
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000, mode=AshMode.STRICT)
        
        assert ctx.mode == AshMode.STRICT
        assert ctx.nonce is not None

    def test_issue_context_with_metadata(self) -> None:
        """Test issuing a context with metadata."""
        store = MemoryStore()
        ash = Ash(store)
        
        metadata = {'user_id': 123}
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000, metadata=metadata)
        
        assert ctx.metadata == metadata

    def test_verify_valid_proof(self) -> None:
        """Test verifying a valid proof."""
        store = MemoryStore()
        ash = Ash(store)
        
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000)
        
        payload = '{"name":"John"}'
        proof = ash_build_proof(
            ctx.mode,
            ctx.binding,
            ctx.id,
            ctx.nonce,
            payload
        )
        
        result = ash.ash_verify(ctx.id, proof, 'POST /api/update', payload, 'application/json')
        
        assert result.valid is True

    def test_verify_invalid_context(self) -> None:
        """Test verifying with invalid context."""
        store = MemoryStore()
        ash = Ash(store)
        
        result = ash.ash_verify('invalid_ctx', 'proof', 'POST /api/update', '{}', 'application/json')
        
        assert result.valid is False
        assert result.error_code == AshErrorCode.INVALID_CONTEXT

    def test_verify_replay_detection(self) -> None:
        """Test replay detection."""
        store = MemoryStore()
        ash = Ash(store)
        
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000)
        
        payload = '{"name":"John"}'
        proof = ash_build_proof(
            ctx.mode,
            ctx.binding,
            ctx.id,
            ctx.nonce,
            payload
        )
        
        # First verification should succeed
        result1 = ash.ash_verify(ctx.id, proof, 'POST /api/update', payload, 'application/json')
        assert result1.valid is True
        
        # Second verification should fail (replay)
        result2 = ash.ash_verify(ctx.id, proof, 'POST /api/update', payload, 'application/json')
        assert result2.valid is False
        assert result2.error_code == AshErrorCode.REPLAY_DETECTED

    def test_verify_endpoint_mismatch(self) -> None:
        """Test endpoint mismatch detection."""
        store = MemoryStore()
        ash = Ash(store)
        
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000)
        
        payload = '{"name":"John"}'
        proof = ash_build_proof(
            ctx.mode,
            ctx.binding,
            ctx.id,
            ctx.nonce,
            payload
        )
        
        # Verify with different binding
        result = ash.ash_verify(ctx.id, proof, 'POST /api/delete', payload, 'application/json')
        
        assert result.valid is False
        assert result.error_code == AshErrorCode.ENDPOINT_MISMATCH

    def test_verify_integrity_failed(self) -> None:
        """Test integrity failure detection."""
        store = MemoryStore()
        ash = Ash(store)
        
        ctx = ash.ash_issue_context('POST /api/update', ttl_ms=30000)
        
        # Build proof with one payload
        proof = ash_build_proof(
            ctx.mode,
            ctx.binding,
            ctx.id,
            ctx.nonce,
            '{"name":"John"}'
        )
        
        # Verify with different payload
        result = ash.ash_verify(ctx.id, proof, 'POST /api/update', '{"name":"Jane"}', 'application/json')
        
        assert result.valid is False
        assert result.error_code == AshErrorCode.INTEGRITY_FAILED

    def test_normalize_binding(self) -> None:
        """Test binding normalization through Ash."""
        store = MemoryStore()
        ash = Ash(store)
        
        result = ash.ash_normalize_binding('post', '/api//update/')
        assert result == 'POST /api/update'

    def test_version(self) -> None:
        """Test version methods."""
        store = MemoryStore()
        ash = Ash(store)
        
        assert ash.ash_version() == 'ASHv1'
        assert ash.ash_library_version() == '1.0.0'

    def test_store_property(self) -> None:
        """Test store property."""
        store = MemoryStore()
        ash = Ash(store)
        
        assert ash.store is store
