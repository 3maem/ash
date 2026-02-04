"""
ASH Security Assurance Pack - Test Configuration
=================================================
Pytest configuration and fixtures for the security assurance test suite.
"""

import pytest
import sys
import os

# Add the ash-python package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../packages/ash-python/src'))


@pytest.fixture
def memory_store():
    """Provide a fresh memory store for each test."""
    from ash.server import stores
    return stores.Memory()


@pytest.fixture
def test_binding():
    """Provide a standard test binding."""
    return "POST|/api/test|"


@pytest.fixture
def test_payload():
    """Provide a standard test payload."""
    return {"amount": 100, "recipient": "user123"}


@pytest.fixture
def test_context(memory_store, test_binding):
    """Provide a pre-created test context."""
    from ash.server import context
    return context.create(memory_store, binding=test_binding, ttl_ms=30000)


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "security: marks security-critical tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks performance tests"
    )
    config.addinivalue_line(
        "markers", "fuzz: marks fuzzing tests"
    )
