# ASH Comprehensive Test Suite

A comprehensive unit test suite for the ASH (Authenticity & Stateless Hardening) library ensuring cross-SDK compatibility, security boundary enforcement, and robust error handling.

## Version

- **ASH SDK Version:** 2.3.3
- **ASH Version Prefix:** ASHv2.1
- **Test Suite Version:** 1.0.0

## Test Files

| File | Description | Test Cases |
|------|-------------|------------|
| `test_cross_sdk_compatibility.py` | Tests ensuring all SDKs produce identical outputs | 40 |
| `test_security_boundaries.py` | Security limits and validations | 36 |
| `test_error_handling.py` | Error codes, messages, and malformed input handling | 27 |
| `test_edge_cases.py` | Edge cases: Unicode, empty payloads, special chars | 39 |
| `test_timing_safety.py` | Constant-time operation verification | 30 |
| **Total** | | **172** |

## Security Limits Tested

| Limit | Value | Test Coverage |
|-------|-------|---------------|
| MAX_PAYLOAD_SIZE | 10 MB | ✅ |
| MAX_RECURSION_DEPTH | 64 levels | ✅ |
| MIN_NONCE_LENGTH | 32 hex chars | ✅ |
| MAX_NONCE_LENGTH | 128 hex chars | ✅ |
| MAX_CONTEXT_ID_LENGTH | 256 chars | ✅ |
| MAX_BINDING_SIZE | 8 KB | ✅ |
| MAX_SCOPE_FIELDS | 100 fields | ✅ |
| MAX_SCOPE_FIELD_NAME_LENGTH | 64 chars | ✅ |
| MAX_ARRAY_INDEX | 10,000 | ✅ |

## Running the Tests

### Prerequisites

```bash
# Install pytest and dependencies
pip install pytest

# Ensure the ASH Python SDK is in your Python path
# Or install it: pip install -e packages/ash-python
```

### Run All Tests

```bash
cd Desktop/ash
pytest tests/comprehensive/ -v
```

### Run Specific Test File

```bash
pytest tests/comprehensive/test_cross_sdk_compatibility.py -v
pytest tests/comprehensive/test_security_boundaries.py -v
pytest tests/comprehensive/test_error_handling.py -v
pytest tests/comprehensive/test_edge_cases.py -v
pytest tests/comprehensive/test_timing_safety.py -v
```

### Run with Coverage

```bash
pytest tests/comprehensive/ --cov=ash --cov-report=html
```

### Run Slow Tests

Some timing tests are marked as slow and skipped by default:

```bash
pytest tests/comprehensive/ --runslow -v
```

## Test Categories

### 1. Cross-SDK Compatibility Tests

These tests verify that all ASH SDK implementations (Rust, Go, Node.js, Python, PHP, .NET) produce identical outputs for the same inputs.

**Key Areas:**
- Proof generation consistency (v2.1, v2.2 scoped, v2.3 unified)
- Client secret derivation
- JSON canonicalization (RFC 8785)
- URL-encoded body canonicalization
- Query string canonicalization
- Binding normalization
- Hash computation (SHA-256)
- Scoped field extraction
- Timing-safe comparison

### 2. Security Boundary Tests

Tests for security limits and input validation.

**Key Areas:**
- Payload size limits (10MB)
- Recursion depth limits (64 levels)
- Nonce validation (32-128 hex chars)
- Context ID validation (max 256 chars)
- Binding size limits (8KB)
- Scope field limits (100 fields, 64 chars each)
- Array index boundaries (10,000)
- Input sanitization

### 3. Error Handling Tests

Comprehensive tests for error handling and graceful degradation.

**Key Areas:**
- All ASH error codes
- HTTP status code mapping
- Error message security (no sensitive data leakage)
- Malformed input handling
- Invalid type handling
- Recovery after errors
- Verification failure modes

### 4. Edge Case Tests

Tests for unusual but valid inputs.

**Key Areas:**
- Empty payloads (objects, arrays, strings)
- Unicode handling (NFC normalization)
- Emoji and CJK characters
- Special characters and escape sequences
- Very large numbers
- Negative zero handling
- Array index boundaries
- Object key sorting
- Mixed edge cases

### 5. Timing Safety Tests

Tests to verify constant-time operations.

**Key Areas:**
- Timing-safe comparison correctness
- Timing independence of difference position
- Timing independence of string length
- HMAC comparison properties
- Sensitive data protection
- Statistical timing analysis

## Test Vectors

The test suite uses fixed test vectors for cross-SDK verification:

```
TEST_NONCE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TEST_CONTEXT_ID = "ash_test_ctx_12345"
TEST_BINDING = "POST|/api/transfer|"
TEST_TIMESTAMP = "1704067200000"
```

## Known Values

| Operation | Input | Expected Output |
|-----------|-------|-----------------|
| hash_body("") | Empty string | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| hash_body("test") | "test" | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` |
| canonicalize_json({"z":1,"a":2}) | Unsorted object | `{"a":2,"z":1}` |
| canonicalize_query("b=2&a=1") | Unsorted query | `a=1&b=2` |

## Fixtures

The `conftest.py` file provides shared fixtures:

- `test_nonce` - Standard test nonce
- `test_context_id` - Standard test context ID
- `test_binding` - Standard test binding
- `test_timestamp` - Standard test timestamp
- `test_payload` - Standard test payload
- `test_client_secret` - Derived test client secret
- `test_scope` - Standard test scope
- `unicode_payload` - Unicode test data
- `nested_payload` - Deeply nested test data

## Contributing

When adding new tests:

1. Follow the existing test structure and naming conventions
2. Add tests to the appropriate file based on category
3. Use fixtures from `conftest.py` where applicable
4. Document any new test vectors or known values
5. Ensure tests are deterministic and don't depend on external state

## References

- [ASH Protocol Tests](../ASH-PROTOCOL-TESTS.md)
- [ASH Security Assurance](../security_assurance/)
- [ASH Python SDK](../../packages/ash-python/)
- RFC 8785: JSON Canonicalization Scheme (JCS)
- RFC 4648: Base64 Encoding
- RFC 2104: HMAC
- RFC 3986: URI Encoding
