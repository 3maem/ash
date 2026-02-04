"""
Pytest configuration and shared fixtures for ASH comprehensive tests.
"""

import pytest
import sys
import os

# Add the ash-python package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'packages', 'ash-python', 'src'))

from ash.core import (
    ash_canonicalize_json,
    ash_canonicalize_url_encoded,
    ash_canonicalize_query,
    ash_normalize_binding,
    ash_build_proof,
    ash_build_proof_hmac,
    ash_build_proof_scoped,
    ash_build_proof_unified,
    ash_verify_proof,
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
    ash_derive_client_secret,
    ash_generate_nonce,
    ash_generate_context_id,
    ash_hash_body,
    ash_hash_proof,
    ash_hash_scoped_body,
    ash_extract_scoped_fields,
    ash_normalize_scope_fields,
    ash_join_scope_fields,
    ash_timing_safe_equal,
    ASH_VERSION_PREFIX,
    ASH_VERSION_PREFIX_V21,
)
from ash.core.types import BuildProofInput, AshMode


# ============================================================================
# Fixed Test Vectors - Used across all tests
# ============================================================================

@pytest.fixture
def test_nonce():
    """Standard test nonce (64 hex chars)."""
    return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def test_context_id():
    """Standard test context ID."""
    return "ash_test_ctx_12345"


@pytest.fixture
def test_binding():
    """Standard test binding."""
    return "POST|/api/transfer|"


@pytest.fixture
def test_timestamp():
    """Standard test timestamp (2024-01-01 00:00:00 UTC in ms)."""
    return "1704067200000"


@pytest.fixture
def test_payload():
    """Standard test payload."""
    return {"amount": 100, "recipient": "user123", "note": "test"}


@pytest.fixture
def test_client_secret(test_nonce, test_context_id, test_binding):
    """Derive a test client secret."""
    return ash_derive_client_secret(test_nonce, test_context_id, test_binding)


@pytest.fixture
def test_scope():
    """Standard test scope."""
    return ["amount", "recipient"]


@pytest.fixture
def valid_proof_params(test_client_secret, test_timestamp, test_binding, test_payload):
    """Valid parameters for building a proof."""
    return {
        "client_secret": test_client_secret,
        "timestamp": test_timestamp,
        "binding": test_binding,
        "payload": test_payload,
    }


# ============================================================================
# Edge Case Fixtures
# ============================================================================

@pytest.fixture
def empty_payload():
    """Empty JSON payload."""
    return {}


@pytest.fixture
def nested_payload():
    """Deeply nested payload for testing recursion."""
    return {
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "value": "deep"
                    }
                }
            }
        }
    }


@pytest.fixture
def unicode_payload():
    """Payload with various Unicode characters."""
    return {
        "emoji": "🎉🚀💯",
        "japanese": "日本語",
        "chinese": "中文",
        "korean": "한국어",
        "arabic": "العربية",
        "hebrew": "עברית",
        "combined": "café",  # NFC form
    }


@pytest.fixture
def large_payload():
    """Large payload for size testing."""
    return {"key_" + str(i): "x" * 1000 for i in range(1000)}


# ============================================================================
# Helper Functions
# ============================================================================

def generate_deeply_nested_json(depth: int) -> dict:
    """Generate a deeply nested JSON structure."""
    result = {"value": "bottom"}
    for _ in range(depth - 1):
        result = {"nested": result}
    return result


def generate_large_payload(size_bytes: int) -> dict:
    """Generate a payload of approximately the specified size."""
    # Each entry is roughly 20 bytes (key) + 100 bytes (value) = 120 bytes
    entries_needed = size_bytes // 120
    return {"key_" + str(i): "x" * 100 for i in range(entries_needed)}


def is_hex_string(s: str, length: int = None) -> bool:
    """Check if a string is valid hexadecimal."""
    if length is not None and len(s) != length:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False
