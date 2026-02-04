# ASH SDK Review and Testing Session Log

**Date:** 2026-01-28
**Environment:** Windows 10 (MSYS_NT-10.0-26200)
**Working Directory:** `C:\Users\java-\desktop\ash`

---

## Table of Contents

1. [Session Overview](#session-overview)
2. [Project Analysis](#project-analysis)
3. [SDK Implementations](#sdk-implementations)
4. [Test Execution](#test-execution)
5. [Dependency Installation](#dependency-installation)
6. [Final Results](#final-results)
7. [Technical Details](#technical-details)

---

## Session Overview

This session involved a comprehensive review and quality testing of the ASH (Application Security Hash) SDK project across all six supported programming languages.

### Objectives Completed

- [x] Read and analyze the entire ASH project structure
- [x] Understand the ASH protocol and its security features
- [x] Run unit tests on all supported languages
- [x] Install missing dependencies (Go, .NET 8.0, PHP)
- [x] Configure PHP extensions for test execution
- [x] Document all activities and results

---

## Project Analysis

### What is ASH?

ASH (Application Security Hash) is a security SDK that provides **request integrity verification** and **anti-replay protection** for HTTP requests. It's designed to complement existing security measures (TLS, authentication, authorization).

**Developed by:** 3maem Co. | شركة عمائم
**Version:** 2.3.3
**License:** ASH Source-Available License (ASAL-1.0)

### Core Security Properties

| Property | Description |
|----------|-------------|
| **Tamper Detection** | Ensures requests haven't been modified in transit |
| **Replay Prevention** | Each context can only be used once |
| **Context Binding** | Proofs are bound to specific endpoints |
| **Time-Bound Validity** | Contexts expire after a configurable TTL |

### Protocol Versions

| Version | Features |
|---------|----------|
| ASHv1 | Basic proof generation with SHA-256 |
| ASHv2.1 | Derived client secret (HMAC-based) |
| ASHv2.2 | Context scoping (selective field protection) |
| ASHv2.3 | Unified proof with scoping + request chaining |

### Proof Formula (v2.3)

```
clientSecret = HMAC-SHA256(nonce, contextId | binding)
bodyHash     = SHA256(canonicalize(payload))
scopeHash    = scope.length > 0 ? SHA256(scope.join(",")) : ""
chainHash    = previousProof ? SHA256(previousProof) : ""
proof        = HMAC-SHA256(clientSecret, timestamp | binding | bodyHash | scopeHash | chainHash)
```

### Security Modes

| Mode | Description |
|------|-------------|
| `minimal` | Basic protection |
| `balanced` | Standard protection (default) |
| `strict` | Maximum protection |

---

## SDK Implementations

### Project Structure

```
ash/
├── Cargo.toml              # Rust workspace configuration
├── package.json            # Node.js workspace configuration
├── composer.json           # PHP composer configuration
├── README.md               # Main documentation
├── LICENSE                 # ASAL-1.0 license
├── packages/
│   ├── ash-core/           # Rust core library
│   ├── ash-wasm/           # WebAssembly bindings
│   ├── ash-node/           # Node.js/TypeScript SDK
│   ├── ash-php/            # PHP SDK
│   ├── ash-python/         # Python SDK
│   ├── ash-go/             # Go SDK
│   └── ash-dotnet/         # .NET SDK
├── docs/                   # Documentation
├── tests/                  # Cross-SDK test vectors
└── examples/               # Example implementations
```

### SDK Details

| SDK | Package Name | Version | Location |
|-----|--------------|---------|----------|
| Rust (Core) | `ash-core` | 2.3.3 | `packages/ash-core/` |
| Rust WASM | `ash-wasm` | 2.3.3 | `packages/ash-wasm/` |
| Node.js | `@3maem/ash-node` | 2.3.3 | `packages/ash-node/` |
| PHP | `3maem/ash-sdk-php` | 2.3.3 | `packages/ash-php/` |
| Python | `ash-sdk` | 2.3.3 | `packages/ash-python/` |
| Go | `github.com/3maem/ash-go/v2` | 2.3.3 | `packages/ash-go/` |
| .NET | `Ash.Core` | 2.3.3 | `packages/ash-dotnet/` |

---

## Test Execution

### Initial Test Run

Tests were executed for all available SDKs. Initial results:

| Language | Initial Status | Issue |
|----------|---------------|-------|
| Rust | ✅ PASSED | None |
| Node.js | ✅ PASSED | None |
| Python | ✅ PASSED | None |
| Go | ⚠️ SKIPPED | `go` command not found |
| PHP | ⚠️ SKIPPED | `php` command not found |
| .NET | ❌ ABORTED | .NET 8.0 runtime missing |

### Commands Used

**Rust:**
```bash
cd "C:\Users\java-\desktop\ash" && cargo test
```

**Node.js:**
```bash
cd "C:\Users\java-\desktop\ash\packages\ash-node" && npm test
```

**Python:**
```bash
cd "C:\Users\java-\desktop\ash\packages\ash-python" && python -m pytest -v
```

**Go:**
```bash
cd "C:\Users\java-\desktop\ash\packages\ash-go" && go test -v ./...
```

**PHP:**
```bash
cd "C:\Users\java-\desktop\ash\packages\ash-php" && php vendor/bin/phpunit
```

**.NET:**
```bash
cd "C:\Users\java-\desktop\ash\packages\ash-dotnet" && dotnet test
```

---

## Dependency Installation

### Go Installation

```bash
winget install GoLang.Go --accept-package-agreements --accept-source-agreements
```

- **Installed Version:** 1.25.6
- **Download Size:** 53.5 MB
- **Source:** https://go.dev/dl/go1.25.6.windows-amd64.msi

### .NET 8.0 Runtime Installation

```bash
winget install Microsoft.DotNet.Runtime.8 --accept-package-agreements --accept-source-agreements
```

- **Installed Version:** 8.0.23
- **Download Size:** 27.0 MB
- **Source:** https://builds.dotnet.microsoft.com/dotnet/Runtime/8.0.23/dotnet-runtime-8.0.23-win-x64.exe

### PHP 8.3 Installation

```bash
winget install PHP.PHP.8.3 --accept-package-agreements --accept-source-agreements
```

- **Installed Version:** 8.3.30
- **Download Size:** 30.9 MB
- **Install Location:** `C:\Users\java-\AppData\Local\Microsoft\WinGet\Packages\PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe\`

### PHP Configuration

The default PHP installation required additional configuration to enable required extensions.

**php.ini Location:**
```
C:\Users\java-\AppData\Local\Microsoft\WinGet\Packages\PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe\php.ini
```

**Configuration Changes:**

1. **Set extension directory:**
```ini
; Before:
;extension_dir = "C:/Users/java-/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/ext"

; After:
extension_dir = "C:/Users/java-/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/ext"
```

2. **Enabled extensions:**
```ini
extension=curl
extension=fileinfo
extension=intl
extension=mbstring
extension=openssl
```

### PHPUnit Upgrade

The test suite uses PHPUnit 10+ attributes (`#[Test]`) but PHPUnit 9 was installed. Upgrade was required:

```bash
php composer.phar update phpunit/phpunit --with-all-dependencies
```

- **Before:** PHPUnit 9.6.32
- **After:** PHPUnit 10.5.63

---

## Final Results

### Summary Table

| Language | Status | Tests | Assertions | Duration |
|----------|--------|-------|------------|----------|
| **Rust** | ✅ PASSED | 175 | - | 30.78s |
| **Node.js** | ✅ PASSED | 100 | - | 2.01s |
| **Python** | ✅ PASSED | 89 | - | 0.21s |
| **Go** | ✅ PASSED | 85 | - | 0.526s |
| **PHP** | ✅ PASSED | 98 | 134 | 0.043s |
| **.NET** | ✅ PASSED | 96 | - | 0.388s |

**Total: 643 tests across 6 languages - ALL PASSED**

### Detailed Test Breakdown

#### Rust (175 tests)

```
ash-core: 95 unit tests
  - canonicalize::tests: 31 tests
  - compare::tests: 5 tests
  - config::scope_policies::tests: 12 tests
  - errors::tests: 4 tests
  - proof::tests: 10 tests
  - proof::tests_v21: 5 tests
  - proof::tests_v22_scoping: 3 tests
  - proof::tests_v23_unified: 6 tests
  - tests: 16 tests
  - types::tests: 5 tests

cross_sdk_test_vectors: 50 tests
unified_proof_integration: 8 tests
ash-wasm: 8 tests
doc-tests: 14 tests
```

#### Node.js (100 tests)

```
src/index.test.ts: 55 tests
src/cross-sdk-test-vectors.test.ts: 45 tests
```

#### Python (89 tests)

```
tests/test_canonicalize.py: 28 tests
  - TestCanonicalizeJson: 13 tests
  - TestCanonicalizeUrlEncoded: 6 tests
  - TestNormalizeBinding: 9 tests

tests/test_cross_sdk_vectors.py: 47 tests
  - TestJsonCanonicalization: 6 tests
  - TestQueryCanonicalization: 6 tests
  - TestUrlEncodedCanonicalization: 3 tests
  - TestBindingNormalization: 9 tests
  - TestHashBody: 3 tests
  - TestClientSecretDerivation: 3 tests
  - TestProofV21: 5 tests
  - TestUnifiedProof: 3 tests
  - TestScopedFieldExtraction: 3 tests
  - TestHashProof: 2 tests
  - TestTimingSafeCompare: 2 tests
  - TestFixedVectors: 2 tests

tests/test_proof.py: 8 tests
tests/test_verify.py: 6 tests
```

#### Go (85 tests)

```
TestVersionConstants
TestBuildProof (3 sub-tests)
TestBuildProofDeterminism
TestBase64URLEncode (3 sub-tests)
TestBase64URLDecode (3 sub-tests)
TestCanonicalizeJSON (12 sub-tests)
TestCanonicalizeJSONKeyOrder
TestCanonicalizeJSONRFC8785Escaping (10 sub-tests)
TestCanonicalizeJSONRejectsNaNAndInfinity (3 sub-tests)
TestCanonicalizeJSONMinusZero
TestParseJSON (3 sub-tests)
TestCanonicalizeURLEncoded (8 sub-tests)
TestCanonicalizeQueryUppercaseHex (3 sub-tests)
TestCanonicalizeQueryFragmentStripping (3 sub-tests)
TestCanonicalizeQueryEmptyValues (2 sub-tests)
TestNormalizeBinding (10 sub-tests)
TestTimingSafeCompare (5 sub-tests)
TestTimingSafeCompareBytes (3 sub-tests)
TestIsValidMode (5 sub-tests)
TestIsValidHTTPMethod (7 sub-tests)
TestAshError
TestValidateProofInput (4 sub-tests)
TestIsASCII (6 sub-tests)
TestContextPublicInfoJSON
TestCanonicalizeURLEncodedFromMap
TestHashBodyLowercaseHex
TestConstantTimeComparison
+ 35 cross-SDK vector tests
+ 8 scope policy tests
```

#### PHP (98 tests, 134 assertions)

```
Ash\Tests\AshTest: ~10 tests
Ash\Tests\CanonicalizeTest: ~25 tests
Ash\Tests\CompareTest: ~5 tests
Ash\Tests\CrossSdkTestVectorsTest: ~50 tests
Ash\Tests\ProofTest: ~8 tests
```

#### .NET (96 tests)

```
Ash.Core.Tests: 96 tests
  - Canonicalization tests
  - Proof generation tests
  - Cross-SDK vector tests
  - Unified proof tests
```

---

## Technical Details

### Test Categories Verified

All SDKs were tested for consistency across:

1. **JSON Canonicalization (RFC 8785)**
   - Object key sorting (lexicographic)
   - No whitespace
   - Unicode NFC normalization
   - Number normalization (no -0, no trailing zeros)
   - Proper escape sequences

2. **URL-Encoded Canonicalization**
   - Key sorting
   - Duplicate key handling
   - Plus-to-space conversion
   - Uppercase hex encoding

3. **Query String Canonicalization**
   - Leading `?` removal
   - Fragment (`#`) stripping
   - Key-value sorting
   - Empty value preservation

4. **Binding Normalization (v2.3.2 format)**
   - Method uppercasing
   - Leading slash enforcement
   - Duplicate slash collapsing
   - Trailing slash removal (except root)
   - Query string canonicalization
   - Pipe-delimited format: `METHOD|PATH|QUERY`

5. **Proof Generation**
   - v1 proof (SHA-256 based)
   - v2.1 proof (HMAC-based with derived client secret)
   - v2.2 scoped proof (selective field protection)
   - v2.3 unified proof (scoping + chaining)

6. **Security Functions**
   - Timing-safe string comparison
   - Client secret derivation
   - Body hashing
   - Proof hashing (for chaining)

### Cross-SDK Test Vectors

The project includes standardized test vectors in `tests/unified_proof_test_vectors.json` to ensure all SDKs produce identical outputs for the same inputs.

### Known Issues

1. **PHP Deprecation Warning:** 1 PHPUnit deprecation warning (non-blocking)
2. **Node.js WASM:** WASM not available in test environment, uses native fallback

---

## Appendix

### File Locations

| File | Path |
|------|------|
| Rust Cargo.toml | `packages/ash-core/Cargo.toml` |
| Node.js package.json | `packages/ash-node/package.json` |
| Python setup | `packages/ash-python/pyproject.toml` |
| Go module | `packages/ash-go/go.mod` |
| PHP composer.json | `packages/ash-php/composer.json` |
| .NET project | `packages/ash-dotnet/src/Ash.Core/Ash.Core.csproj` |

### PHP Executable Path

```
C:\Users\java-\AppData\Local\Microsoft\WinGet\Packages\PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe\php.exe
```

### Go Executable Path

```
C:\Program Files\Go\bin\go.exe
```

---

**Initial session completed successfully. All 643 tests passed across 6 programming languages.**

---

## Security Assurance Pack Implementation

### Overview

Following the initial SDK testing, a comprehensive Security Assurance Pack test suite was implemented based on the formal test plan document (`Ash Security Assurance Pack.pdf`).

### Test Categories Implemented

| Category | Test File | Tests | Description |
|----------|-----------|-------|-------------|
| A. Unit Tests | `test_unit.py` | 26 | Deterministic signatures, mutation detection, header validation |
| B. Integration Tests | `test_integration.py` | 14 | Request lifecycle, TTL enforcement, backend consistency |
| C. Security Tests | `test_security.py` | 27 | Tampering detection, replay prevention, time attacks |
| D. Cryptographic Tests | `test_cryptographic.py` | 20 | Constant-time comparison, algorithm verification |
| E. Performance Tests | `test_performance.py` | 16 | Latency, throughput, burst handling |
| F. Fuzz Tests | `test_fuzz.py` | 31 | Malformed JSON, Unicode edge cases, oversized payloads |

### Test Files Created

```
tests/security_assurance/
├── __init__.py           # Package documentation
├── conftest.py           # Pytest fixtures and configuration
├── test_unit.py          # Unit tests (Section A)
├── test_integration.py   # Integration tests (Section B)
├── test_security.py      # Security tests (Section C)
├── test_cryptographic.py # Cryptographic tests (Section D)
├── test_performance.py   # Performance tests (Section E)
└── test_fuzz.py          # Fuzz & abuse tests (Section F)
```

### Technical Implementation Details

#### API Corrections

The test suite required corrections to use the proper ASH Python API:

**Correct `build_proof` usage:**
```python
from ash.core import BuildProofInput, build_proof

input_data = BuildProofInput(
    mode="balanced",
    binding="POST /api/test",
    context_id="ctx_test_123",
    canonical_payload='{"amount":100}',
)
proof = build_proof(input_data)
```

**Async Server Module:**
```python
from ash.server import context, stores

store = stores.Memory(suppress_warning=True)
ctx = await context.create(store, binding="POST|/api/test|", ttl_ms=30000, issue_nonce=True)
result = await store.consume(ctx.context_id, now_ms)
```

### Security Assurance Pack Results

**Final Test Run: 134 tests - ALL PASSED**

```
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-8.4.2

tests/security_assurance/test_cryptographic.py: 20 passed
tests/security_assurance/test_fuzz.py: 31 passed
tests/security_assurance/test_integration.py: 14 passed
tests/security_assurance/test_performance.py: 16 passed
tests/security_assurance/test_security.py: 27 passed
tests/security_assurance/test_unit.py: 26 passed

============================= 134 passed in 10.70s =============================
```

### Performance Metrics

| Operation | Average Latency | p99 Latency | Throughput |
|-----------|-----------------|-------------|------------|
| JSON Canonicalization | 0.065ms | 0.090ms | - |
| Proof Generation | 0.003ms | 0.003ms | 345,823 ops/sec |
| v2.1 Proof Generation | 0.004ms | 0.008ms | - |
| Client Secret Derivation | 0.004ms | 0.005ms | - |
| v2.1 Verification | 0.008ms | 0.015ms | - |
| Timing-safe Compare | 0.32µs | 0.40µs | - |
| Hash Body | - | - | 878,147 ops/sec |
| Context Creation | - | - | 256,542 ops/sec |
| Concurrent Proofs (4 workers) | - | - | 201,856 ops/sec |

### Large Payload Performance

| Payload Size | Processing Time |
|--------------|-----------------|
| 1 KB | 0.05ms |
| 10 KB | 0.05ms |
| 100 KB | 0.28ms |
| 1 MB | 2.55ms |
| 10 MB | 32.06ms |

### Test Categories Breakdown

#### A. Unit Tests (26 tests)

**Deterministic Signature Generation:**
- `test_canonicalize_json_deterministic`
- `test_canonicalize_json_key_order_deterministic`
- `test_build_proof_deterministic`
- `test_build_proof_v21_deterministic`
- `test_derive_client_secret_deterministic`
- `test_normalize_binding_deterministic`
- `test_hash_body_deterministic`

**Single-Byte Mutation Detection:**
- `test_single_byte_change_in_payload_detected`
- `test_single_char_change_in_key_detected`
- `test_whitespace_addition_detected`
- `test_single_byte_in_context_id_detected`
- `test_single_byte_in_binding_detected`
- `test_v21_body_hash_mutation_detected`

**Missing/Invalid Header Rejection:**
- `test_empty_context_id_differentiated`
- `test_empty_binding_differentiated`
- `test_different_modes_produce_different_proofs`
- `test_none_nonce_vs_empty_nonce`
- `test_v21_empty_timestamp_differentiated`
- `test_v21_verification_wrong_nonce_fails`

**Canonicalization Consistency:**
- `test_unicode_normalization_nfc`
- `test_number_negative_zero_normalized`
- `test_nested_object_key_sorting`
- `test_array_order_preserved`
- `test_special_characters_escaped`
- `test_url_encoded_sorting`
- `test_url_encoded_uppercase_hex`

#### B. Integration Tests (14 tests)

**Valid Request Lifecycle:**
- `test_create_verify_consume_cycle`
- `test_multiple_contexts_independent`
- `test_full_request_simulation`

**TTL Enforcement:**
- `test_context_valid_before_ttl`
- `test_context_expired_after_ttl`
- `test_ttl_boundary_precision`
- `test_different_ttl_values`

**Backend Consistency:**
- `test_atomic_consume_single_thread`
- `test_atomic_consume_concurrent`
- `test_context_state_consistency`
- `test_parallel_context_creation`

**End-to-End Scenarios:**
- `test_payment_flow`
- `test_multi_step_workflow`
- `test_high_value_transaction_protection`

#### C. Security Tests (27 tests)

**Payload Tampering Detection:**
- Field reordering, injection, removal
- Value modification, type changes
- Nested object tampering
- Array modification and reordering

**Binding Tampering Detection:**
- HTTP method changes
- Path modifications
- Query parameter injection/modification

**Replay Attack Prevention:**
- Sequential replay detection
- Parallel replay prevention (50 concurrent attempts)
- Independent context isolation

**Time Manipulation Prevention:**
- Expired context rejection
- Future/past timestamp detection
- TTL boundary conditions

**Header Confusion Prevention:**
- Case-sensitive context IDs
- Binding normalization
- Query string normalization

#### D. Cryptographic Tests (20 tests)

**Constant-Time Comparison:**
- Equal/unequal string comparison
- Different length handling
- Timing safety verification (early vs late byte differences)

**Algorithm Strength:**
- SHA-256 proof verification
- HMAC-SHA256 for v2.1 proofs
- Body hash verification
- Client secret derivation verification
- Entropy distribution checks

**Secret Exposure Prevention:**
- Nonce not in proof
- Client secret not in proof
- Input data not in hash
- One-way derivation verification

#### E. Performance Tests (16 tests)

**Signing Latency:**
- JSON canonicalization < 1ms avg
- Proof generation < 0.5ms avg
- Client secret derivation < 0.5ms avg

**Verification Latency:**
- v2.1 verification < 1ms avg
- Timing-safe compare < 100µs avg

**Throughput:**
- Single-thread > 10,000 ops/sec
- Concurrent (4 workers) > 20,000 ops/sec
- Hash operations > 100,000 ops/sec
- Context creation > 5,000 ops/sec

**Burst Traffic:**
- 1000 ops burst handling
- Context operation bursts

**Degradation Behavior:**
- Large payload handling (up to 10MB)
- Memory store stability (10,000 contexts)
- Invalid proof rejection
- Concurrent stress testing

#### F. Fuzz Tests (31 tests)

**Malformed JSON Handling:**
- Invalid JSON strings
- Deeply nested objects (100 levels)
- Wide objects (1000 keys)
- Large arrays (10,000 elements)
- Mixed types in arrays

**Unicode Edge Cases:**
- NFC/NFD normalization
- Emoji handling
- Zero-width characters
- Bidirectional text
- Surrogate pairs
- Control characters
- Private Use Area characters

**Oversized Payloads:**
- 1MB, 10MB payloads
- Long string values
- Many array elements
- Oversized URL-encoded data

**Randomized Fuzzing:**
- Random JSON objects (100 iterations)
- Random URL-encoded data
- Random binding inputs
- Byte mutation fuzzing

---

## Updated Session Summary

### Total Tests Executed

| Test Suite | Tests Passed |
|------------|--------------|
| SDK Unit Tests (6 languages) | 643 |
| Security Assurance Pack | 134 |
| **Total** | **777** |

**All 777 tests passed successfully.**

---

**Session completed. ASH SDK v2.3.3 has been thoroughly tested across all supported languages with comprehensive security assurance verification.**
