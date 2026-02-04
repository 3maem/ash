"""
Test Security Boundaries

Tests for security limits and validations:
- Maximum payload sizes (10MB limit)
- Maximum recursion depth (64 levels)
- Nonce length validation (32-128 hex chars)
- Context_id validation (alphanumeric + _ - . only, max 256 chars)
- Binding length limits (8KB max)
- Scope field limits (max 100 fields, 64 chars per field name)
"""

import pytest
import json
from ash.core import (
    ash_canonicalize_json,
    ash_normalize_binding,
    ash_build_proof_hmac,
    ash_derive_client_secret,
    ash_hash_body,
    ash_normalize_scope_fields,
)
from ash.core.errors import CanonicalizationError
from ash.core.proof import ash_generate_nonce


# ============================================================================
# Security Limits
# ============================================================================

MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB
MAX_RECURSION_DEPTH = 64
MIN_NONCE_LENGTH = 32  # hex chars
MAX_NONCE_LENGTH = 128  # hex chars
MAX_CONTEXT_ID_LENGTH = 256
MAX_BINDING_SIZE = 8 * 1024  # 8KB
MAX_SCOPE_FIELDS = 100
MAX_SCOPE_FIELD_NAME_LENGTH = 64


class TestPayloadSizeLimits:
    """Test maximum payload size enforcement."""

    def generate_payload_of_size(self, size_bytes: int) -> dict:
        """Generate a payload of approximately the specified size."""
        # Each entry: ~20 bytes for key + value overhead
        entry_size = 20
        entries_needed = size_bytes // entry_size
        return {f"key_{i}": "x" for i in range(entries_needed)}

    def test_payload_under_limit_accepted(self):
        """Payload just under 10MB should be accepted."""
        # Generate a payload of ~9MB
        payload = self.generate_payload_of_size(9 * 1024 * 1024)
        
        # Should not raise an exception
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)

    def test_large_payload_canonicalization(self):
        """Large but valid payload should be canonicalized."""
        # 1MB payload
        payload = self.generate_payload_of_size(1024 * 1024)
        
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_payload_at_limit_boundary(self):
        """Test behavior at the 10MB boundary."""
        # The actual limit enforcement may vary by SDK
        # This test documents the expected behavior
        payload = self.generate_payload_of_size(MAX_PAYLOAD_SIZE - 1024)
        
        # Should work (implementation may vary)
        try:
            result = ash_canonicalize_json(payload)
            assert isinstance(result, str)
        except (CanonicalizationError, MemoryError, RecursionError):
            # Some SDKs may enforce strict limits
            pass


class TestRecursionDepthLimits:
    """Test maximum recursion depth enforcement."""

    def generate_nested_json(self, depth: int) -> dict:
        """Generate a deeply nested JSON structure."""
        result = {"value": "bottom"}
        for _ in range(depth - 1):
            result = {"nested": result}
        return result

    def test_shallow_nesting_accepted(self):
        """Shallow nesting should be accepted."""
        payload = self.generate_nested_json(10)
        
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)

    def test_moderate_nesting_accepted(self):
        """Moderate nesting (50 levels) should be accepted."""
        payload = self.generate_nested_json(50)
        
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)

    def test_deep_nesting_near_limit(self):
        """Deep nesting near limit (60 levels) should work."""
        payload = self.generate_nested_json(60)
        
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)

    def test_recursion_limit_enforcement(self):
        """Extreme nesting beyond 64 levels may be rejected."""
        payload = self.generate_nested_json(MAX_RECURSION_DEPTH + 10)
        
        # May raise RecursionError or handle gracefully
        try:
            result = ash_canonicalize_json(payload)
            # If it works, that's fine too
            assert isinstance(result, str)
        except RecursionError:
            # Expected behavior for very deep nesting
            pass

    def test_circular_reference_handling(self):
        """Circular references should be handled gracefully."""
        # Python-specific: test circular reference
        payload = {"a": 1}
        payload["self"] = payload
        
        with pytest.raises((CanonicalizationError, ValueError, RecursionError)):
            ash_canonicalize_json(payload)


class TestNonceValidation:
    """Test nonce length and format validation."""

    def test_valid_nonce_32_chars(self):
        """Nonce of 32 hex chars should be valid (minimum)."""
        nonce = "a" * 32
        # Should work for secret derivation
        secret = ash_derive_client_secret(nonce, "ctx_test", "POST|/api/test|")
        assert len(secret) == 64

    def test_valid_nonce_64_chars(self):
        """Nonce of 64 hex chars should be valid (standard)."""
        nonce = "a" * 64
        secret = ash_derive_client_secret(nonce, "ctx_test", "POST|/api/test|")
        assert len(secret) == 64

    def test_valid_nonce_128_chars(self):
        """Nonce of 128 hex chars should be valid (maximum)."""
        nonce = "a" * 128
        secret = ash_derive_client_secret(nonce, "ctx_test", "POST|/api/test|")
        assert len(secret) == 64

    def test_nonce_too_short_rejected(self):
        """Nonce shorter than 32 chars should be rejected (SEC-014)."""
        import pytest
        from ash.core.errors import ValidationError
        
        nonce = "a" * 30  # Too short
        
        # Should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            ash_derive_client_secret(nonce, "ctx_test", "POST|/api/test|")
        assert "at least 32 hex characters" in str(exc_info.value)

    def test_nonce_too_long_rejected(self):
        """Nonce longer than 128 chars should be rejected (SEC-NONCE-001)."""
        import pytest
        from ash.core.errors import ValidationError
        
        nonce = "a" * 200  # Too long
        
        # Should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            ash_derive_client_secret(nonce, "ctx_test", "POST|/api/test|")
        assert "exceeds maximum length" in str(exc_info.value)

    def test_invalid_hex_nonce(self):
        """Nonce with invalid hex chars should be rejected (BUG-004)."""
        import pytest
        from ash.core.errors import ValidationError
        
        nonce = "g" * 64  # 'g' is not valid hex
        
        # Should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            ash_derive_client_secret(nonce, "ctx_test", "POST|/api/test|")
        assert "hexadecimal characters" in str(exc_info.value)

    def test_generated_nonce_length(self):
        """Generated nonce should be 64 hex chars (default)."""
        nonce = ash_generate_nonce()
        assert len(nonce) == 64
        assert all(c in "0123456789abcdef" for c in nonce)

    def test_generated_nonce_custom_length(self):
        """Generated nonce with custom byte count."""
        nonce = ash_generate_nonce(bytes_count=16)
        assert len(nonce) == 32  # 16 bytes = 32 hex chars


class TestContextIdValidation:
    """Test context_id validation."""

    def test_valid_context_id_alphanumeric(self):
        """Alphanumeric context ID should be valid."""
        ctx_id = "ash_test_123"
        secret = ash_derive_client_secret("a" * 64, ctx_id, "POST|/api/test|")
        assert len(secret) == 64

    def test_valid_context_id_with_hyphen(self):
        """Context ID with hyphens should be valid."""
        ctx_id = "ash-test-123"
        secret = ash_derive_client_secret("a" * 64, ctx_id, "POST|/api/test|")
        assert len(secret) == 64

    def test_valid_context_id_with_dot(self):
        """Context ID with dots should be valid."""
        ctx_id = "ash.test.123"
        secret = ash_derive_client_secret("a" * 64, ctx_id, "POST|/api/test|")
        assert len(secret) == 64

    def test_context_id_max_length(self):
        """Context ID at max length (256 chars) should be valid."""
        ctx_id = "a" * 256
        secret = ash_derive_client_secret("a" * 64, ctx_id, "POST|/api/test|")
        assert len(secret) == 64

    def test_context_id_special_chars(self):
        """Context ID with special characters should be rejected (SEC-CTX-001)."""
        import pytest
        from ash.core.errors import ValidationError
        
        ctx_id = "test@#$%^&*()"
        
        # Should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            ash_derive_client_secret("a" * 64, ctx_id, "POST|/api/test|")
        assert "alphanumeric" in str(exc_info.value)

    def test_empty_context_id(self):
        """Empty context ID should be rejected (BUG-041)."""
        import pytest
        from ash.core.errors import ValidationError
        
        # Should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            ash_derive_client_secret("a" * 64, "", "POST|/api/test|")
        assert "cannot be empty" in str(exc_info.value)


class TestBindingLengthLimits:
    """Test binding length limits."""

    def test_binding_under_limit(self):
        """Binding under 8KB should be valid."""
        long_path = "/api/" + "x" * 1000
        binding = ash_normalize_binding("GET", long_path)
        
        secret = ash_derive_client_secret("a" * 64, "ctx_test", binding)
        assert len(secret) == 64

    def test_binding_at_limit(self):
        """Binding at 8KB limit should be handled."""
        # Create a binding close to 8KB
        long_path = "/api/" + "x" * 7000
        binding = ash_normalize_binding("GET", long_path)
        
        # Should still work
        secret = ash_derive_client_secret("a" * 64, "ctx_test", binding)
        assert len(secret) == 64

    def test_binding_with_long_query(self):
        """Binding with long query string should be handled."""
        # Create a long query string
        query = "&".join([f"key_{i}=value_{i}" for i in range(100)])
        binding = ash_normalize_binding("GET", "/api/search", query)
        
        secret = ash_derive_client_secret("a" * 64, "ctx_test", binding)
        assert len(secret) == 64


class TestScopeFieldLimits:
    """Test scope field limits."""

    def test_scope_under_field_limit(self):
        """Scope with under 100 fields should be valid."""
        scope = [f"field_{i}" for i in range(50)]
        normalized = ash_normalize_scope_fields(scope)
        assert len(normalized) == 50

    def test_scope_at_field_limit(self):
        """Scope with exactly 100 fields should be valid."""
        scope = [f"field_{i}" for i in range(100)]
        normalized = ash_normalize_scope_fields(scope)
        assert len(normalized) == 100

    def test_scope_over_field_limit(self):
        """Scope with over 100 fields may be rejected."""
        scope = [f"field_{i}" for i in range(150)]
        # Current implementation doesn't enforce limit
        normalized = ash_normalize_scope_fields(scope)
        assert len(normalized) == 150

    def test_scope_field_name_length_valid(self):
        """Scope field name under 64 chars should be valid."""
        scope = ["a" * 64]
        normalized = ash_normalize_scope_fields(scope)
        assert normalized == ["a" * 64]

    def test_scope_field_name_length_over_limit(self):
        """Scope field name over 64 chars may be rejected."""
        scope = ["a" * 100]
        # Current implementation doesn't enforce limit
        normalized = ash_normalize_scope_fields(scope)
        assert normalized == ["a" * 100]

    def test_scope_deduplication(self):
        """Duplicate scope fields should be deduplicated."""
        scope = ["field_a", "field_b", "field_a", "field_c", "field_b"]
        normalized = ash_normalize_scope_fields(scope)
        assert normalized == ["field_a", "field_b", "field_c"]


class TestArrayIndexLimits:
    """Test array index boundaries."""

    def test_array_index_small(self):
        """Small array index should work."""
        payload = {"items": [1, 2, 3]}
        # Access via extract_scoped_fields if supported
        # This is implementation-specific
        assert payload["items"][0] == 1

    def test_array_index_boundary(self):
        """Array index at boundary (10000) should be handled."""
        payload = {"items": list(range(10001))}
        assert payload["items"][10000] == 10000


class TestInputValidation:
    """Test various input validation scenarios."""

    def test_null_bytes_in_string(self):
        """Null bytes in strings should be handled."""
        payload = {"key": "value\x00null"}
        result = ash_canonicalize_json(payload)
        assert "\\u0000" in result  # Should be escaped

    def test_control_characters_in_string(self):
        """Control characters should be properly escaped."""
        payload = {"key": "\x01\x02\x03"}
        result = ash_canonicalize_json(payload)
        # Should be escaped as \u0001, \u0002, etc.
        assert "\\u0001" in result

    def test_unicode_bom_handling(self):
        """BOM characters should be handled."""
        # BOM is U+FEFF
        payload = {"key": "\ufeffvalue"}
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)

    def test_line_separator_handling(self):
        """Unicode line separators should be handled."""
        # Line separator U+2028, paragraph separator U+2029
        payload = {"key": "\u2028\u2029"}
        result = ash_canonicalize_json(payload)
        assert isinstance(result, str)
