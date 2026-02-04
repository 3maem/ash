# ASH Node.js SDK Test Documentation

Complete test coverage documentation for the ASH (Application Security Hash) **Node.js SDK**.

**Total Tests: 713**
**Test Files: 18**
**Status: All Passing**

> **Note:** This document is specific to the Node.js SDK implementation.
> For universal protocol tests that apply to all SDKs, see:
> - [ASH-PROTOCOL-TESTS.md](../../../tests/ASH-PROTOCOL-TESTS.md) - Universal tests for all SDKs
> - [SDK-SPECIFIC-TESTS.md](../../../tests/SDK-SPECIFIC-TESTS.md) - Language-specific tests
> - [MIDDLEWARE-TESTS.md](../../../tests/MIDDLEWARE-TESTS.md) - HTTP middleware tests

---

## Table of Contents

1. [Core SDK Tests](#1-core-sdk-tests)
2. [Security Audit Tests](#2-security-audit-tests)
3. [Advanced Penetration Tests](#3-advanced-penetration-tests)
4. [Fuzzing Tests](#4-fuzzing-tests)
5. [RFC Compliance Tests](#5-rfc-compliance-tests)
6. [Cross-SDK Test Vectors](#6-cross-sdk-test-vectors)
7. [Cross-Platform Compatibility Tests](#7-cross-platform-compatibility-tests)
8. [Production Edge Cases Tests](#8-production-edge-cases-tests)
9. [External Security Audit Tests](#9-external-security-audit-tests)
10. [Error Handling Tests](#10-error-handling-tests)
11. [Store Tests](#11-store-tests)
12. [TypeScript Types Tests](#12-typescript-types-tests)
13. [Property-Based Tests](#13-property-based-tests)
14. [HTTP Integration Tests](#14-http-integration-tests)
15. [Deep Fuzzer Tests](#15-deep-fuzzer-tests)
16. [Performance Benchmark Tests](#16-performance-benchmark-tests)
17. [Version Compatibility Tests](#17-version-compatibility-tests)
18. [Documentation Examples Tests](#18-documentation-examples-tests)

---

## 1. Core SDK Tests

**File:** `src/index.test.ts`
**Tests:** 117

### Initialization
- [ ] `ashInit` should initialize without error
- [ ] `ashInit` should be idempotent (safe to call multiple times)
- [ ] `ashVersion` should return protocol version string

### Nonce Generation
- [ ] `ashGenerateNonce` should return 64-character hex string
- [ ] `ashGenerateNonce` should produce unique values
- [ ] `ashGenerateNonce` should be cryptographically random

### Context ID Generation
- [ ] `ashGenerateContextId` should return string with correct prefix
- [ ] `ashGenerateContextId` should produce unique values
- [ ] `ashGenerateContextId256` should return 256-bit context ID

### JSON Canonicalization (RFC 8785)
- [ ] Should sort object keys lexicographically
- [ ] Should handle nested objects
- [ ] Should preserve array order
- [ ] Should normalize Unicode to NFC
- [ ] Should reject NaN values
- [ ] Should reject Infinity values
- [ ] Should reject undefined values
- [ ] Should handle -0 as 0
- [ ] Should escape control characters correctly
- [ ] Should handle empty objects
- [ ] Should handle empty arrays

### Query String Canonicalization
- [ ] Should sort parameters by key
- [ ] Should sort by value when keys are equal
- [ ] Should uppercase percent-encoding
- [ ] Should strip leading `?`
- [ ] Should strip fragment `#`
- [ ] Should preserve empty values
- [ ] Should treat `+` as literal plus

### URL-Encoded Body Canonicalization
- [ ] Should sort parameters
- [ ] Should convert `+` to `%2B`
- [ ] Should preserve `%20` as space
- [ ] Should handle duplicate keys

### Binding Normalization
- [ ] Should format as `METHOD|PATH|QUERY`
- [ ] Should uppercase HTTP method
- [ ] Should normalize path (remove trailing slash)
- [ ] Should canonicalize query string
- [ ] Should handle empty query

### Body Hashing
- [ ] `ashHashBody` should return 64-character lowercase hex
- [ ] Should produce consistent hashes for same input
- [ ] Should produce different hashes for different inputs

### Client Secret Derivation
- [ ] `ashDeriveClientSecret` should return 64-character hex
- [ ] Should be deterministic (same inputs = same output)
- [ ] Should validate nonce format
- [ ] Should validate context ID
- [ ] Should validate binding

### Proof Building (v2.1)
- [ ] `ashBuildProofV21` should return 64-character hex
- [ ] Should be deterministic
- [ ] Should validate all inputs

### Proof Verification (v2.1)
- [ ] `ashVerifyProofV21` should return true for valid proof
- [ ] Should return false for invalid proof
- [ ] Should return false for tampered body
- [ ] Should return false for tampered timestamp
- [ ] Should return false for tampered binding

### Scoped Proofs (v2.2)
- [ ] `ashBuildProofScoped` should return proof and scopeHash
- [ ] Should only protect specified fields
- [ ] Non-scoped field changes should not invalidate proof
- [ ] Scoped field changes should invalidate proof
- [ ] Should normalize scope (sort, deduplicate)
- [ ] Should reject dangerous scope paths (`__proto__`, etc.)

### Unified/Chained Proofs (v2.3)
- [ ] `ashBuildProofUnified` should return proof, scopeHash, chainHash
- [ ] Should support chaining to previous proof
- [ ] Should verify chain integrity
- [ ] Wrong previous proof should fail verification

### Timestamp Validation
- [ ] `ashValidateTimestamp` should accept valid current timestamp
- [ ] Should reject expired timestamp
- [ ] Should reject future timestamp (beyond clock skew)
- [ ] Should respect custom maxAge parameter
- [ ] Should respect custom clockSkew parameter

### Timing-Safe Comparison
- [ ] `ashTimingSafeEqual` should return true for equal strings
- [ ] Should return false for different strings
- [ ] Should handle different length strings

### Security Limits
- [ ] Should enforce maximum nonce length
- [ ] Should enforce maximum context ID length
- [ ] Should enforce maximum binding length
- [ ] Should enforce maximum payload size (10MB)
- [ ] Should enforce maximum recursion depth (64)
- [ ] Should enforce maximum scope fields (100)
- [ ] Should enforce maximum array index (10000)

---

## 2. Security Audit Tests

**File:** `src/security-audit.test.ts`
**Tests:** 58

### Input Validation Security
- [ ] Should reject null inputs
- [ ] Should reject undefined inputs
- [ ] Should reject non-string inputs
- [ ] Should handle empty strings appropriately
- [ ] Should reject inputs exceeding size limits

### Injection Prevention
- [ ] Should prevent JSON injection
- [ ] Should prevent prototype pollution
- [ ] Should prevent path traversal in scope
- [ ] Should sanitize special characters

### Cryptographic Security
- [ ] Should use cryptographically secure random
- [ ] Should produce high-entropy nonces
- [ ] Should use constant-time comparison
- [ ] Should not leak timing information

### Replay Prevention
- [ ] Context should be single-use
- [ ] Should reject replayed proofs
- [ ] Should enforce timestamp freshness

### Information Disclosure Prevention
- [ ] Error messages should not leak secrets
- [ ] Error messages should not leak expected proof
- [ ] Error messages should not leak nonce

---

## 3. Advanced Penetration Tests

**File:** `src/pentest-advanced.test.ts`
**Tests:** 53

### Protocol-Level Attacks
- [ ] Binding confusion attack
- [ ] Method override attack
- [ ] Path normalization bypass
- [ ] Query parameter pollution

### Cryptographic Attacks
- [ ] Length extension attack prevention
- [ ] Collision resistance verification
- [ ] Key derivation security

### Timing Attacks
- [ ] Constant-time proof comparison
- [ ] No early-exit on mismatch

### Encoding Attacks
- [ ] Double encoding prevention
- [ ] Mixed encoding handling
- [ ] Unicode normalization attacks

### Resource Exhaustion
- [ ] Large payload handling
- [ ] Deep nesting limits
- [ ] Many scope fields handling

---

## 4. Fuzzing Tests

**File:** `src/fuzz.test.ts`
**Tests:** 51

### Random Input Fuzzing
- [ ] Random JSON structures
- [ ] Random query strings
- [ ] Random bindings
- [ ] Random nonces
- [ ] Random timestamps

### Boundary Testing
- [ ] Empty inputs
- [ ] Maximum length inputs
- [ ] Unicode edge cases
- [ ] Control characters

### Malformed Input Handling
- [ ] Invalid JSON
- [ ] Invalid hex strings
- [ ] Invalid timestamps
- [ ] Truncated inputs

---

## 5. RFC Compliance Tests

**File:** `src/compliance.test.ts`
**Tests:** 49

### RFC 8785 - JSON Canonicalization Scheme (JCS)
- [ ] 3.2.2.1 Primitive literals (null, true, false)
- [ ] 3.2.2.2 Numbers (integers, floats, -0, scientific notation)
- [ ] 3.2.2.3 Strings (escaping, Unicode)
- [ ] 3.2.3 Arrays (order preservation)
- [ ] 3.2.4 Objects (key sorting, whitespace removal)
- [ ] 3.2.5 Unicode normalization (NFC)

### RFC 4648 - Base16 Encoding
- [ ] Lowercase hex for hashes
- [ ] Lowercase hex for proofs
- [ ] 64-character output (32 bytes)

### RFC 2104 - HMAC
- [ ] Consistent HMAC output
- [ ] 256-bit output length
- [ ] Correct key usage

### RFC 3986 - URI Encoding
- [ ] Percent encoding (uppercase hex)
- [ ] Query string parsing
- [ ] Fragment stripping

### ASH Protocol Specification
- [ ] Section 3.1: Nonce requirements (256-bit, hex)
- [ ] Section 3.2: Context ID format (ash_ prefix)
- [ ] Section 4.1: Binding format (METHOD|PATH|QUERY)
- [ ] Section 4.2: Proof construction (HMAC-SHA256)
- [ ] Section 5.1: Scoped fields (normalization)
- [ ] Section 5.2: Proof chaining

### Timing Safety
- [ ] Constant-time comparison
- [ ] Symmetric comparison

### URL-Encoded Body
- [ ] `+` as literal plus (%2B)
- [ ] `%20` as space
- [ ] Parameter sorting

---

## 6. Cross-SDK Test Vectors

**File:** `src/cross-sdk-test-vectors.test.ts`
**Tests:** 45

### Deterministic Test Vectors
- [ ] Fixed nonce + fixed context + fixed binding = expected proof
- [ ] JSON canonicalization test vectors
- [ ] Query canonicalization test vectors
- [ ] Hash test vectors

### Cross-Platform Compatibility
- [ ] Same inputs produce same outputs across SDKs
- [ ] Test vectors match Rust SDK
- [ ] Test vectors match browser SDK

---

## 7. Cross-Platform Compatibility Tests

**File:** `src/cross-platform.test.ts`
**Tests:** 42

### Unicode Handling
- [ ] UTF-8 encoding consistency
- [ ] NFC normalization across platforms
- [ ] Emoji handling
- [ ] RTL text handling

### Number Representation
- [ ] Integer serialization
- [ ] Float serialization
- [ ] Large number handling
- [ ] Negative zero handling

### String Encoding
- [ ] Control character escaping
- [ ] Backslash escaping
- [ ] Quote escaping

### Byte Order
- [ ] Consistent byte ordering
- [ ] Hex encoding consistency

---

## 8. Production Edge Cases Tests

**File:** `src/production-edge-cases.test.ts`
**Tests:** 38

### Unicode Edge Cases
- [ ] Combining characters
- [ ] Zero-width characters
- [ ] Surrogate pairs
- [ ] Private use area characters

### Concurrency
- [ ] Concurrent proof generation
- [ ] Concurrent verification
- [ ] Concurrent context operations
- [ ] Race condition prevention

### Memory
- [ ] Large payload handling
- [ ] Memory cleanup
- [ ] No memory leaks over time

### Time
- [ ] Timestamp at epoch
- [ ] Timestamp near max safe integer
- [ ] Clock skew handling
- [ ] Timezone independence

---

## 9. External Security Audit Tests

**File:** `src/external-audit.test.ts`
**Tests:** 36

### OWASP Top 10 Coverage

#### A01:2021 - Broken Access Control
- [ ] Context isolation
- [ ] Binding enforcement
- [ ] Single-use tokens

#### A02:2021 - Cryptographic Failures
- [ ] Strong key derivation
- [ ] Secure random generation
- [ ] No weak algorithms

#### A03:2021 - Injection
- [ ] JSON injection prevention
- [ ] Header injection prevention
- [ ] Path injection prevention

#### A04:2021 - Insecure Design
- [ ] Secure defaults
- [ ] Fail-safe behavior
- [ ] Defense in depth

#### A05:2021 - Security Misconfiguration
- [ ] Sensible default limits
- [ ] Clear error messages
- [ ] No debug info leakage

#### A06:2021 - Vulnerable Components
- [ ] Minimal dependencies
- [ ] Secure crypto library usage

#### A07:2021 - Authentication Failures
- [ ] Proof verification
- [ ] Replay prevention
- [ ] Timestamp validation

#### A08:2021 - Data Integrity Failures
- [ ] Body hash verification
- [ ] Binding verification
- [ ] Chain integrity

#### A09:2021 - Logging Failures
- [ ] No sensitive data in errors
- [ ] Meaningful error codes

#### A10:2021 - SSRF
- [ ] URL validation in binding
- [ ] Path normalization

---

## 10. Error Handling Tests

**File:** `src/error-handling.test.ts`
**Tests:** 33

### Error Message Quality
- [ ] Meaningful error for empty nonce
- [ ] Meaningful error for invalid nonce format
- [ ] Meaningful error for empty context ID
- [ ] Meaningful error for empty binding
- [ ] Meaningful error for invalid JSON
- [ ] Meaningful error for invalid timestamp
- [ ] Meaningful error for expired timestamp
- [ ] Meaningful error for future timestamp

### Resource Limit Errors
- [ ] Meaningful error for oversized JSON
- [ ] Meaningful error for deeply nested JSON
- [ ] Meaningful error for oversized nonce

### Scope Extraction Errors
- [ ] Error for dangerous keys
- [ ] Error for missing scope field (strict mode)
- [ ] Error for invalid array index

### Error Codes
- [ ] INVALID_PROOF_FORMAT for null proof
- [ ] INVALID_PROOF_FORMAT for wrong length
- [ ] PROOF_MISMATCH for incorrect proof

### No Sensitive Data Leakage
- [ ] No nonce in error messages
- [ ] No client secret in error messages
- [ ] No body content in error messages
- [ ] No expected proof in verification failure

### Graceful Fallback
- [ ] WASM failure falls back to native
- [ ] Verification failure returns false (not throw)
- [ ] Empty string inputs handled gracefully

### Store Error Handling
- [ ] Non-existent context returns null
- [ ] Oversized metadata rejected
- [ ] Expired context consume returns false

### Runtime Type Safety
- [ ] Throws on undefined input
- [ ] Throws on number input to string function
- [ ] Throws on object input to string function
- [ ] Accepts valid array JSON

### Recovery
- [ ] Recovers after multiple failed operations
- [ ] Recovers after store operation failures

---

## 11. Store Tests

**File:** `src/store.test.ts`
**Tests:** 32

### AshMemoryStore Basic Operations
- [ ] Create context with all required fields
- [ ] Create context with metadata
- [ ] Get context by ID
- [ ] Return null for non-existent context
- [ ] Consume context exactly once

### TTL and Expiration
- [ ] Expire context after TTL
- [ ] Set correct expiration time
- [ ] Reject zero TTL
- [ ] Reject negative TTL

### Concurrent Access
- [ ] Handle 100 concurrent creates
- [ ] Ensure exactly-once consumption under race
- [ ] Handle mixed operations concurrently

### Edge Cases
- [ ] Handle very long binding
- [ ] Handle special characters in binding
- [ ] Handle empty metadata
- [ ] Reject oversized metadata
- [ ] Return false when consuming expired context

### Cleanup
- [ ] Cleanup expired contexts
- [ ] Report correct size
- [ ] Clear all on destroy

### Redis Store Simulation
- [ ] Create context with Redis-style TTL
- [ ] Atomically consume context
- [ ] Handle concurrent consume with locking
- [ ] Handle connection recovery

### SQL Store Simulation
- [ ] Create context with SQL transaction
- [ ] Get context by ID
- [ ] Consume context with transaction isolation
- [ ] Cleanup expired contexts
- [ ] Store and retrieve metadata
- [ ] Handle concurrent transactions

### Interface Compliance
- [ ] AshMemoryStore implements required methods
- [ ] Create returns context with all required fields

---

## 12. TypeScript Types Tests

**File:** `src/types.test.ts`
**Tests:** 36

### Exports Verification
- [ ] Export all core functions
- [ ] Export v2.2 scoped proof functions
- [ ] Export v2.3 unified proof functions
- [ ] Export utility functions
- [ ] Export native implementations
- [ ] Export store class

### Type Inference
- [ ] ashGenerateNonce returns string
- [ ] ashGenerateContextId returns string
- [ ] ashHashBody returns string
- [ ] ashBuildProofV21 returns string
- [ ] ashVerifyProofV21 returns boolean
- [ ] ashBuildProofScoped returns AshScopedProofResult
- [ ] ashBuildProofUnified returns AshUnifiedProofResult

### AshContext Type
- [ ] Correct shape from store.create
- [ ] Accepts metadata

### AshContextOptions Type
- [ ] Accepts valid options
- [ ] Accepts mode
- [ ] Accepts metadata

### AshMode Type
- [ ] Accepts 'minimal'
- [ ] Accepts 'balanced'
- [ ] Accepts 'strict'

### AshContextStore Interface
- [ ] AshMemoryStore implements interface

### Function Signatures
- [ ] ashDeriveClientSecret correct signature
- [ ] ashNormalizeBinding correct signature
- [ ] ashCanonicalizeJson correct signature
- [ ] ashTimingSafeEqual correct signature
- [ ] ashValidateTimestamp correct signature

### Optional Parameters
- [ ] ashValidateTimestamp accepts optional parameters
- [ ] ashBuildProofUnified accepts optional previousProof

### Array and Object Types
- [ ] ashBuildProofScoped accepts string array for scope
- [ ] ashExtractScopedFields accepts object and string array
- [ ] ashBuildProofScoped accepts Record<string, unknown>

### Async Operations
- [ ] store.create returns Promise<AshContext>
- [ ] store.get returns Promise<AshContext | null>
- [ ] store.consume returns Promise<boolean>
- [ ] store.cleanup returns Promise<number>

### Return Values
- [ ] Hash functions return 64-char hex strings
- [ ] Proof functions return 64-char hex strings
- [ ] Scoped proof result has correct structure
- [ ] Unified proof result has correct structure

---

## 13. Property-Based Tests

**File:** `src/property-based.test.ts`
**Tests:** 27

### Hash Properties
- [ ] Determinism: same input → same hash
- [ ] Avalanche effect: small change → different hash
- [ ] Length consistency: always 64 chars

### Proof Properties
- [ ] Soundness: valid proof verifies
- [ ] Completeness: only correct proof verifies
- [ ] Determinism: same inputs → same proof

### Canonicalization Properties
- [ ] Idempotence: canon(canon(x)) = canon(x)
- [ ] Determinism: same input → same output
- [ ] Stability: round-trip preserves semantics

### Scope Properties
- [ ] Normalization: order-independent
- [ ] Deduplication: no duplicate fields

### Mathematical Invariants
- [ ] Associativity where applicable
- [ ] Commutativity where applicable

---

## 14. HTTP Integration Tests

**File:** `src/http-integration.test.ts`
**Tests:** 26

### HTTP Method Tests
- [ ] Sign and verify GET request
- [ ] Sign and verify POST request with JSON
- [ ] Sign and verify POST request with form data
- [ ] Sign and verify PUT request
- [ ] Sign and verify PATCH request
- [ ] Sign and verify DELETE request
- [ ] Sign and verify HEAD request
- [ ] Sign and verify OPTIONS request

### Express Middleware Simulation
- [ ] Process valid request through middleware
- [ ] Reject request with missing proof header
- [ ] Reject request with wrong binding
- [ ] Reject replay attack

### Fetch Interceptor Simulation
- [ ] Sign outgoing fetch request
- [ ] Include correct headers

### Content Types
- [ ] Handle application/json
- [ ] Handle application/x-www-form-urlencoded
- [ ] Handle multipart/form-data (body hash only)
- [ ] Handle text/plain

### Query String Handling
- [ ] Include query in binding
- [ ] Handle complex query parameters
- [ ] Handle encoded query values

### Error Scenarios
- [ ] Handle missing body
- [ ] Handle malformed JSON
- [ ] Handle network-like failures

---

## 15. Deep Fuzzer Tests

**File:** `src/deep-fuzzer.test.ts`
**Tests:** 24

### High-Iteration Fuzzing (10,000+ iterations each)
- [ ] Random JSON canonicalization
- [ ] Random query canonicalization
- [ ] Random proof generation
- [ ] Random proof verification
- [ ] Random scope extraction

### Targeted Fuzzing
- [ ] Unicode stress testing
- [ ] Number edge cases
- [ ] String length variations
- [ ] Nesting depth variations

### Crash Resistance
- [ ] No crashes on random input
- [ ] Graceful handling of edge cases
- [ ] Memory stability under load

---

## 16. Performance Benchmark Tests

**File:** `src/benchmarks.test.ts`
**Tests:** 21

### Proof Generation
- [ ] Generate ≥5,000 proofs/sec
- [ ] Generate 10,000 proofs in <2 seconds

### Proof Verification
- [ ] Verify ≥5,000 proofs/sec
- [ ] Verify 10,000 proofs in <2 seconds

### JSON Canonicalization
- [ ] Canonicalize ≥10,000 small JSON/sec
- [ ] Canonicalize ≥5,000 medium JSON/sec
- [ ] Canonicalize ≥500 large JSON/sec

### Query Canonicalization
- [ ] Canonicalize ≥20,000 simple queries/sec
- [ ] Canonicalize ≥5,000 complex queries/sec

### Hashing
- [ ] Hash ≥50,000 small bodies/sec
- [ ] Hash ≥5,000 large bodies (10KB)/sec

### Client Secret Derivation
- [ ] Derive ≥10,000 secrets/sec

### Context Store
- [ ] Create ≥5,000 contexts/sec
- [ ] Consume ≥10,000 contexts/sec
- [ ] Handle 1,000 concurrent operations in <2 seconds

### Scoped Proofs
- [ ] Build ≥3,000 scoped proofs/sec
- [ ] Verify ≥3,000 scoped proofs/sec

### End-to-End Workflow
- [ ] Complete ≥2,000 full workflows/sec

### Memory Stability
- [ ] <50MB growth over 100,000 operations

### Nonce Generation
- [ ] Generate ≥50,000 nonces/sec
- [ ] Generate ≥50,000 context IDs/sec

---

## 17. Version Compatibility Tests

**File:** `src/versioning.test.ts`
**Tests:** 13

### Protocol Version
- [ ] Report current protocol version
- [ ] Support ASH v2.1 proof format
- [ ] Support ASH v2.2 scoped proof format
- [ ] Support ASH v2.3 unified proof format

### Backward Compatibility
- [ ] v2.1 proof works with same inputs as v2.3 without scope/chain
- [ ] Same inputs produce same v2.1 proof across versions

### Version Negotiation
- [ ] Gracefully handle unknown version headers

### Migration Scenarios
- [ ] v2.1 to v2.2 migration (add scoping)
- [ ] v2.2 to v2.3 migration (add chaining)

### Deprecation Handling
- [ ] Deprecated v2.1 aliases still work

### Feature Detection
- [ ] Export all v2.1 functions
- [ ] Export all v2.2 functions
- [ ] Export all v2.3 functions

---

## 18. Documentation Examples Tests

**File:** `src/documentation-examples.test.ts`
**Tests:** 12

### README Quick Start
- [ ] Quick Start example works

### Basic Usage
- [ ] JSON canonicalization example works
- [ ] Query string canonicalization example works
- [ ] Binding normalization example works
- [ ] Body hashing example works

### Proof Lifecycle
- [ ] Full proof lifecycle example works

### Scoped Proofs
- [ ] Scoped proof example works

### Chained Proofs
- [ ] Chained proof example works

### Context Store
- [ ] Memory store example works

### Error Handling
- [ ] Error handling example works

### URL-Encoded Forms
- [ ] Form data example works

### Complete API Flow
- [ ] Complete flow example works

---

## Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- src/security-audit.test.ts

# Run tests with coverage
npm test -- --coverage

# Run tests in watch mode
npm test -- --watch

# Run benchmarks only
npm test -- src/benchmarks.test.ts
```

## Test Configuration

Tests use [Vitest](https://vitest.dev/) as the test runner.

**Configuration:** `vitest.config.ts`

```typescript
export default {
  test: {
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
    },
  },
};
```

---

## Contributing

When adding new features, please ensure:

1. All existing tests pass
2. New functionality has corresponding tests
3. Security-sensitive code has penetration tests
4. Performance-critical code has benchmarks
5. Public API has TypeScript type tests
6. Documentation examples are tested

---

*Last Updated: January 2026*
*Test Suite Version: 2.3.4*
