# ASH Penetration Testing Suite

A comprehensive security testing suite for the ASH (Application Security Hash) library, designed to test request integrity and anti-replay protection mechanisms.

## Overview

This penetration testing suite contains 164+ security tests covering 8 major attack categories:

| Test File | Description | Tests |
|-----------|-------------|-------|
| `pentest_replay_attacks.py` | Replay attack prevention | 15 |
| `pentest_timing_attacks.py` | Timing side-channel detection | 15 |
| `pentest_payload_manipulation.py` | Payload tampering detection | 35 |
| `pentest_dos_protection.py` | DoS attack resistance | 18 |
| `pentest_binding_validation.py` | HTTP binding validation | 27 |
| `pentest_scope_manipulation.py` | Scope field manipulation | 26 |
| `pentest_chain_integrity.py` | Proof chain integrity (v2.3+) | 16 |
| `pentest_fuzzing.py` | Fuzzing and property-based tests | 12 |

## Attack Vectors Covered

### 1. Replay Attacks (`pentest_replay_attacks.py`)
- **Proof reuse detection**: Verifies that used proofs cannot be replayed
- **Context expiration**: Tests that expired contexts are properly rejected
- **Single-use enforcement**: Ensures exactly one consumption per context
- **Timestamp validation**: Prevents old proof replay
- **Parallel replay prevention**: Tests concurrent consumption attempts
- **Cross-context replay**: Verifies proof binding to specific contexts

### 2. Timing Attacks (`pentest_timing_attacks.py`)
- **Constant-time comparison**: Tests `ash_timing_safe_equal` for timing leaks
- **Proof verification timing**: Checks for timing differences between valid/invalid proofs
- **Length independence**: Verifies proof length doesn't affect timing
- **Early-exit detection**: Tests for early-return vulnerabilities
- **Statistical analysis**: Uses outlier detection for timing anomalies

### 3. Payload Manipulation (`pentest_payload_manipulation.py`)
- **Value modification**: Detects changes to payload values
- **Field injection**: Tests for unauthorized field addition
- **JSON injection**: SQL and XSS injection attempts
- **Path traversal**: Tests scope field path manipulation
- **Canonicalization bypass**: Unicode, whitespace, and encoding attacks
- **Type confusion**: String vs number, boolean vs string tests

### 4. DoS Protection (`pentest_dos_protection.py`)
- **Oversized payloads**: Tests large payload handling (100KB-1MB)
- **Deep nesting**: Tests deeply nested JSON (1000+ levels)
- **Wide objects**: Tests objects with many keys (10000+)
- **Scope exhaustion**: Tests excessive scope fields
- **Hash collision resistance**: Tests for hash collision attacks
- **Memory exhaustion**: Tests circular reference detection

### 5. Binding Validation (`pentest_binding_validation.py`)
- **Method mismatch**: GET vs POST, PUT vs DELETE detection
- **Path manipulation**: Trailing slashes, duplicate slashes, traversal
- **Query tampering**: Parameter addition, modification, reordering
- **Percent-encoding**: Double encoding, incomplete encoding attacks
- **Case sensitivity**: Tests case handling in methods, paths, queries
- **Fragment injection**: Tests fragment identifier handling

### 6. Scope Manipulation (`pentest_scope_manipulation.py`)
- **Field injection**: Adding unauthorized fields to scope
- **Field removal**: Removing fields from scope
- **Delimiter collision**: Tests U+001F unit separator attacks
- **Scope hash forgery**: Tests forged scope hash detection
- **Unauthorized access**: Tests out-of-scope field access
- **Scope enumeration**: Tests for information leakage via errors

### 7. Chain Integrity (`pentest_chain_integrity.py`)
- **Chain break detection**: Missing or wrong previous proof
- **Out-of-order detection**: Wrong proof order in chain
- **Cross-chain attacks**: Using proofs from different chains
- **Chain hash forgery**: Tests forged chain hash detection
- **Middle modification**: Detects modifications in chain middle

### 8. Fuzzing Tests (`pentest_fuzzing.py`)
- **Random inputs**: Tests with random strings, timestamps, bindings
- **JSON fuzzing**: Various JSON structures and edge cases
- **Unicode fuzzing**: Special characters, control characters, emoji
- **Property-based**: Determinism, idempotency, symmetry tests
- **Malformed input**: Tests error handling for invalid inputs

## Running the Tests

### Run all security tests:
```bash
cd Desktop/ash
python -m pytest tests/security/ -v
```

### Run specific test file:
```bash
python -m pytest tests/security/pentest_replay_attacks.py -v
```

### Run with specific markers:
```bash
# Run only critical security tests
python -m pytest tests/security/ -v -m "security_critical"

# Run only replay attack tests
python -m pytest tests/security/ -v -m "replay_attack"

# Run only timing attack tests
python -m pytest tests/security/ -v -m "timing_attack"
```

### Run with timing tolerance (for CI environments):
```bash
python -m pytest tests/security/ -v --tb=short
```

## Test Markers

- `security_critical`: Critical security vulnerability tests
- `replay_attack`: Replay attack prevention tests
- `timing_attack`: Timing side-channel tests
- `payload_manipulation`: Payload tampering tests
- `dos_protection`: DoS resistance tests
- `binding_validation`: HTTP binding tests
- `scope_manipulation`: Scope field tests
- `chain_integrity`: Proof chain tests
- `fuzzing`: Fuzzing and property-based tests

## Configuration

The `conftest.py` file provides:
- `memory_store`: Fresh memory store for each test
- `test_binding`: Standard test binding
- `test_payload`: Standard test payload
- `attacker_context`: Common attacker-controlled values
- `valid_proof_components`: Valid proof components for testing

## Implementation Notes

### Timing Tests
Timing tests use statistical analysis to detect side channels. Due to inherent noise in modern systems (CPU scheduling, power management, virtualization), these tests use tolerance thresholds:
- Ratio tolerance: up to 5x for some comparisons
- Outlier tolerance: up to 50%

The underlying implementation uses `hmac.compare_digest()` which is designed to be constant-time.

### Async Tests
Tests using the context store are async and use `pytest-asyncio`. The `memory_store` fixture provides an isolated store for each test.

### Determinism
All proof generation tests use fixed timestamps (e.g., `"1704067200000"`) to ensure reproducibility.

## Security Assurance

These tests provide assurance that the ASH library correctly implements:
1. **Request integrity**: Any payload modification invalidates the proof
2. **Replay protection**: Single-use contexts prevent replay attacks
3. **Binding enforcement**: Proofs are cryptographically bound to method/path
4. **Scope isolation**: Scoped fields are properly isolated
5. **Chain integrity**: Linked proofs maintain cryptographic integrity
6. **Timing safety**: Comparison operations are timing-safe

## Contributing

When adding new tests:
1. Follow the existing naming convention: `test_<description>`
2. Use appropriate markers for test categorization
3. Include docstrings describing the attack and defense
4. Ensure tests are deterministic (use fixed values where possible)
5. Add async marker for async tests: `@pytest.mark.asyncio`

## License

These tests are part of the ASH SDK and follow the same license terms.
