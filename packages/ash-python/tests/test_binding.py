"""Tests for binding normalization."""

from ash import ash_normalize_binding


class TestNormalizeBinding:
    """Tests for binding normalization."""

    def test_uppercase_method(self) -> None:
        """Test method is uppercased."""
        result = ash_normalize_binding('post', '/api/update')
        assert result == 'POST /api/update'

    def test_remove_query_string(self) -> None:
        """Test query string is removed."""
        result = ash_normalize_binding('GET', '/api/users?id=123')
        assert result == 'GET /api/users'

    def test_ensure_leading_slash(self) -> None:
        """Test path has leading slash."""
        result = ash_normalize_binding('GET', 'api/users')
        assert result == 'GET /api/users'

    def test_collapse_duplicate_slashes(self) -> None:
        """Test duplicate slashes are collapsed."""
        result = ash_normalize_binding('GET', '/api//users///list')
        assert result == 'GET /api/users/list'

    def test_remove_trailing_slash(self) -> None:
        """Test trailing slash is removed."""
        result = ash_normalize_binding('GET', '/api/users/')
        assert result == 'GET /api/users'

    def test_preserve_root_slash(self) -> None:
        """Test root path preserves slash."""
        result = ash_normalize_binding('GET', '/')
        assert result == 'GET /'

    def test_complex_normalization(self) -> None:
        """Test complex normalization case."""
        result = ash_normalize_binding('post', 'api//test/?foo=bar')
        assert result == 'POST /api/test'
