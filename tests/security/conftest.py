"""
ASH Penetration Testing Suite - Test Configuration
===================================================
Pytest configuration and fixtures for the penetration testing suite.
"""

import pytest
import sys
import os
import asyncio

# Add the ash-python package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "security_critical: marks tests for critical security vulnerabilities"
    )
    config.addinivalue_line(
        "markers", "replay_attack: marks replay attack tests"
    )
    config.addinivalue_line(
        "markers", "timing_attack: marks timing attack tests"
    )
    config.addinivalue_line(
        "markers", "payload_manipulation: marks payload manipulation tests"
    )
    config.addinivalue_line(
        "markers", "dos_protection: marks DoS protection tests"
    )
    config.addinivalue_line(
        "markers", "binding_validation: marks binding validation tests"
    )
    config.addinivalue_line(
        "markers", "scope_manipulation: marks scope manipulation tests"
    )
    config.addinivalue_line(
        "markers", "chain_integrity: marks chain integrity tests"
    )
    config.addinivalue_line(
        "markers", "fuzzing: marks fuzzing tests"
    )


@pytest.fixture
def memory_store():
    """Provide a fresh memory store for each test."""
    from ash.server import stores
    return stores.Memory(suppress_warning=True)


@pytest.fixture
def test_binding():
    """Provide a standard test binding."""
    return "POST|/api/test|"


@pytest.fixture
def test_payload():
    """Provide a standard test payload."""
    return {"amount": 100, "recipient": "user123"}


@pytest.fixture
def async_test_loop():
    """Provide an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def attacker_context():
    """Provide common attacker-controlled values for tests."""
    return {
        "modified_amount": 999999,
        "injected_field": {"admin": True, "role": "superuser"},
        "malicious_payload": "<script>alert('xss')</script>",
        "path_traversal": "../../../etc/passwd",
        "sql_injection": "'; DROP TABLE users; --",
    }


@pytest.fixture
def valid_proof_components():
    """Provide valid proof components for testing."""
    from ash.core.proof import (
        ash_generate_nonce,
        ash_generate_context_id,
        ash_derive_client_secret,
        ash_build_proof_hmac,
        ash_hash_body,
    )
    from ash.core.canonicalize import ash_canonicalize_json
    
    nonce = ash_generate_nonce()
    context_id = ash_generate_context_id()
    binding = "POST|/api/transfer|"
    payload = {"amount": 100, "to": "account123"}
    canonical = ash_canonicalize_json(payload)
    body_hash = ash_hash_body(canonical)
    timestamp = "1704067200000"  # Fixed timestamp for reproducibility
    client_secret = ash_derive_client_secret(nonce, context_id, binding)
    proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)
    
    return {
        "nonce": nonce,
        "context_id": context_id,
        "binding": binding,
        "payload": payload,
        "canonical": canonical,
        "body_hash": body_hash,
        "timestamp": timestamp,
        "client_secret": client_secret,
        "proof": proof,
    }
