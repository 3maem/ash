"""
ASH Comprehensive Test Suite

A comprehensive unit test suite for the ASH library ensuring:
- Cross-SDK compatibility
- Security boundary enforcement
- Error handling robustness
- Edge case coverage
- Timing safety

Version: 2.3.3
"""

ASH_SDK_VERSION = "2.3.3"
ASH_VERSION_PREFIX = "ASHv2.1"

# Security limits
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB
MAX_RECURSION_DEPTH = 64
MIN_NONCE_LENGTH = 32  # hex chars
MAX_NONCE_LENGTH = 128  # hex chars
MAX_CONTEXT_ID_LENGTH = 256
MAX_BINDING_SIZE = 8 * 1024  # 8KB
MAX_SCOPE_FIELDS = 100
MAX_SCOPE_FIELD_NAME_LENGTH = 64
MAX_ARRAY_INDEX = 10000
