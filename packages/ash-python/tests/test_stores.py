"""Tests for MemoryStore."""

import time

from ash import AshMode, MemoryStore


class TestMemoryStore:
    """Tests for MemoryStore."""

    def test_create_context(self) -> None:
        """Test creating a context."""
        store = MemoryStore()
        ctx = store.create('POST /api/update', 30000, AshMode.BALANCED, {})
        
        assert ctx.id.startswith('ctx_')
        assert ctx.binding == 'POST /api/update'
        assert ctx.mode == AshMode.BALANCED
        assert ctx.used is False

    def test_get_context(self) -> None:
        """Test getting a context."""
        store = MemoryStore()
        ctx = store.create('POST /api/update', 30000, AshMode.BALANCED, {})
        
        retrieved = store.get(ctx.id)
        assert retrieved is not None
        assert retrieved.id == ctx.id

    def test_get_nonexistent_context(self) -> None:
        """Test getting a nonexistent context."""
        store = MemoryStore()
        retrieved = store.get('nonexistent')
        assert retrieved is None

    def test_consume_context(self) -> None:
        """Test consuming a context."""
        store = MemoryStore()
        ctx = store.create('POST /api/update', 30000, AshMode.BALANCED, {})
        
        assert store.consume(ctx.id) is True
        
        # Second consume should fail
        assert store.consume(ctx.id) is False

    def test_consume_nonexistent_context(self) -> None:
        """Test consuming a nonexistent context."""
        store = MemoryStore()
        assert store.consume('nonexistent') is False

    def test_context_with_nonce_in_strict_mode(self) -> None:
        """Test that strict mode creates a nonce."""
        store = MemoryStore()
        ctx = store.create('POST /api/update', 30000, AshMode.STRICT, {})
        
        assert ctx.nonce is not None

    def test_context_without_nonce_in_balanced_mode(self) -> None:
        """Test that balanced mode does not create a nonce."""
        store = MemoryStore()
        ctx = store.create('POST /api/update', 30000, AshMode.BALANCED, {})
        
        assert ctx.nonce is None

    def test_size(self) -> None:
        """Test store size."""
        store = MemoryStore()
        assert store.size() == 0
        
        store.create('POST /api/update', 30000, AshMode.BALANCED, {})
        assert store.size() == 1
        
        store.create('POST /api/delete', 30000, AshMode.BALANCED, {})
        assert store.size() == 2

    def test_clear(self) -> None:
        """Test clearing the store."""
        store = MemoryStore()
        store.create('POST /api/update', 30000, AshMode.BALANCED, {})
        store.create('POST /api/delete', 30000, AshMode.BALANCED, {})
        
        store.clear()
        assert store.size() == 0

    def test_metadata(self) -> None:
        """Test context with metadata."""
        store = MemoryStore()
        metadata = {'user_id': 123}
        ctx = store.create('POST /api/update', 30000, AshMode.BALANCED, metadata)
        
        assert ctx.metadata == metadata
