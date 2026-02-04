# ASH Security Assurance Pack

The Security Assurance Pack is a comprehensive test suite that validates the security properties of ASH SDK implementations across all supported languages.

## Overview

The Security Assurance Pack tests four critical categories:

| Category | Description | Tests |
|----------|-------------|-------|
| **A. Unit Tests** | Deterministic signature generation, mutation detection | ~25 |
| **B. Integration Tests** | Full request flow verification | ~15 |
| **C. Security Tests** | Anti-replay, timing attacks, context expiration | ~30 |
| **D. Cryptographic Tests** | Constant-time comparison, algorithm strength | ~25 |

**Total: ~95 tests per language**

## Test Categories

### A. Unit Tests

- **Deterministic Signature Generation**: Same inputs always produce same outputs
- **Single-Byte Mutation Detection**: Any change to payload/binding/context is detected
- **Missing/Invalid Header Rejection**: Empty or invalid parameters are handled correctly

### B. Integration Tests

- **Full Request Flow**: Context creation → proof generation → verification
- **Async Server Integration**: Tests with async context stores
- **Multi-Step Workflows**: Complex request chains

### C. Security Tests

- **Anti-Replay Protection**: Contexts can only be used once
- **Timing Attack Resistance**: Constant-time comparison prevents timing leaks
- **Context Expiration**: Expired contexts are rejected
- **Proof Binding Validation**: Proofs are bound to specific endpoints/methods/bodies

### D. Cryptographic Tests

- **Constant-Time Comparison**: Equal timing for early vs late differences
- **Algorithm Strength**: SHA-256 for hashing, HMAC-SHA256 for proofs
- **No Secret Exposure**: Secrets don't appear in outputs
- **High Entropy**: Outputs have no obvious patterns

## Running Tests

### Python

```bash
cd tests/security_assurance
pytest -v
```

### Node.js

```bash
cd tests/security_assurance_node
npm install
npx vitest run
```

### Go

```bash
cd tests/security_assurance_go
go test -v ./...
```

### All Languages (CI)

```bash
# Run all security assurance tests
./scripts/run-security-assurance.sh
```

## Test Files

### Python (`tests/security_assurance/`)

| File | Category | Tests |
|------|----------|-------|
| `test_unit.py` | Unit Tests | Deterministic generation, mutation detection |
| `test_cryptographic.py` | Cryptographic | Constant-time, algorithm strength |
| `test_security.py` | Security | Anti-replay, timing, binding |
| `test_integration.py` | Integration | Full request flows |
| `test_performance.py` | Performance | Throughput, latency |
| `test_fuzz.py` | Fuzz Testing | Edge cases, random inputs |

### Node.js (`tests/security_assurance_node/`)

| File | Category | Tests |
|------|----------|-------|
| `test_unit.test.ts` | Unit Tests | Deterministic generation, mutation detection |
| `test_cryptographic.test.ts` | Cryptographic | Constant-time, algorithm strength |
| `test_security.test.ts` | Security | Anti-replay, timing, binding |

### Go (`tests/security_assurance_go/`)

| File | Category | Tests |
|------|----------|-------|
| `security_assurance_test.go` | All Categories | Comprehensive test suite |

## Key Security Properties Tested

### 1. Determinism

All cryptographic operations must be deterministic:

```python
# Same inputs → same output (100 iterations)
proofs = [build_proof(input) for _ in range(100)]
assert all(p == proofs[0] for p in proofs)
```

### 2. Mutation Detection

Single-byte changes must produce different proofs:

```python
proof1 = build_proof('{"amount":100}')
proof2 = build_proof('{"amount":101}')  # Changed 0 to 1
assert proof1 != proof2
```

### 3. Constant-Time Comparison

Timing must not leak information:

```python
# Early difference vs late difference timing should be similar
early_times = [measure(compare(base, "Xaaa..."))]  # First byte differs
late_times = [measure(compare(base, "aaa...X"))]   # Last byte differs
ratio = max(medians) / min(medians)
assert ratio < 3.0  # Allow for system noise
```

### 4. Anti-Replay

Contexts can only be consumed once:

```python
ctx = store.create(binding, ttl_ms=30000)
assert store.consume(ctx.id) == True   # First use: success
assert store.consume(ctx.id) == False  # Second use: blocked
```

### 5. Proof Binding

Proofs are cryptographically bound to request parameters:

```python
# Different endpoint = different proof
proof1 = build_proof(binding="/api/transfer")
proof2 = build_proof(binding="/api/payment")
assert proof1 != proof2

# Verification with wrong binding fails
assert verify(proof1, binding="/api/payment") == False
```

## Cross-SDK Consistency

All SDK implementations must pass identical test vectors:

```json
{
  "test_name": "basic_json_canonicalization",
  "input": {"z": 1, "a": 2, "m": 3},
  "expected": "{\"a\":2,\"m\":3,\"z\":1}"
}
```

Test vectors are stored in `packages/*/src/cross-sdk-test-vectors.json` and validated across all languages.

## Adding New Tests

When adding new security tests:

1. **Add to Python first** - Python is the reference implementation
2. **Port to other languages** - Ensure consistent behavior
3. **Document the security property** - What attack does this prevent?
4. **Add test vectors** - For cross-SDK validation

Example test structure:

```python
class TestNewSecurityProperty:
    """Document the security property being tested."""

    def test_specific_case(self):
        """Clear description of what this tests."""
        # Arrange
        input_data = create_test_input()

        # Act
        result = function_under_test(input_data)

        # Assert
        assert result == expected, "Failure message"
```

## CI Integration

The Security Assurance Pack runs on every PR:

```yaml
# .github/workflows/security-scan.yml
jobs:
  security-assurance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Security Assurance Pack
        run: |
          cd tests/security_assurance
          pytest -v --tb=short
```

## Reporting Issues

If a test fails:

1. **Check if it's a flaky test** - Timing tests have some variance
2. **Verify the SDK version** - Tests may require specific versions
3. **Report with full output** - Include test name, error, and environment

## References

- [ASH Protocol Specification v2.3](../docs/ASH-SPEC.md)
- [RFC 8785 - JSON Canonicalization Scheme](https://tools.ietf.org/html/rfc8785)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
