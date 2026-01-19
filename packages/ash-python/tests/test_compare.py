"""Tests for timing-safe comparison."""

from ash import ash_timing_safe_equal


class TestTimingSafeEqual:
    """Tests for timing-safe comparison."""

    def test_equal_strings(self) -> None:
        """Test equal strings."""
        assert ash_timing_safe_equal('secret123', 'secret123') is True

    def test_unequal_strings(self) -> None:
        """Test unequal strings."""
        assert ash_timing_safe_equal('secret123', 'secret456') is False

    def test_equal_bytes(self) -> None:
        """Test equal bytes."""
        assert ash_timing_safe_equal(b'secret123', b'secret123') is True

    def test_unequal_bytes(self) -> None:
        """Test unequal bytes."""
        assert ash_timing_safe_equal(b'secret123', b'secret456') is False

    def test_mixed_types(self) -> None:
        """Test string and bytes comparison."""
        assert ash_timing_safe_equal('secret', b'secret') is True

    def test_empty_strings(self) -> None:
        """Test empty strings."""
        assert ash_timing_safe_equal('', '') is True

    def test_different_lengths(self) -> None:
        """Test strings of different lengths."""
        assert ash_timing_safe_equal('short', 'longer') is False
