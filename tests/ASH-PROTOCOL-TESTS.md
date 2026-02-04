# ASH Protocol Tests - Universal SDK Requirements

**Version:** 2.3.3
**Last Updated:** January 2026

This document defines the **mandatory tests** that ALL ASH SDK implementations must pass to ensure cross-SDK compatibility and protocol compliance.

---

## Table of Contents

1. [Cross-SDK Test Vectors](#1-cross-sdk-test-vectors)
2. [RFC Compliance Tests](#2-rfc-compliance-tests)
3. [Core SDK Tests](#3-core-sdk-tests)
4. [Security Tests](#4-security-tests)
5. [Production Edge Cases](#5-production-edge-cases)
6. [Error Handling Tests](#6-error-handling-tests)
7. [Property-Based Tests](#7-property-based-tests)

---

## 1. Cross-SDK Test Vectors

**Priority:** CRITICAL
**Purpose:** Ensure identical outputs across all SDK implementations

These test vectors use fixed inputs to produce deterministic outputs. All SDKs MUST produce identical results.

### 1.1 Fixed Test Vectors

```
NONCE:      "a]60 (64 chars)
CONTEXT_ID: "ctx_test"
BINDING:    "POST|/api/test|"
TIMESTAMP:  "1700000000"
BODY:       "{}"
```

| Test | Function | Expected Output |
|------|----------|-----------------|
| Body Hash (empty) | `hashBody("{}")` | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` |
| Body Hash (known) | `hashBody("test")` | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` |

### 1.2 Binding Normalization Vectors

| Input Method | Input Path | Input Query | Expected Output |
|--------------|------------|-------------|-----------------|
| `"POST"` | `"/api/users"` | `""` | `"POST\|/api/users\|"` |
| `"get"` | `"/api"` | `""` | `"GET\|/api\|"` |
| `"POST"` | `"/api/"` | `""` | `"POST\|/api\|"` (trailing slash removed) |
| `"GET"` | `"/api//users"` | `""` | `"GET\|/api/users\|"` (double slash collapsed) |
| `"GET"` | `"/api"` | `"b=2&a=1"` | `"GET\|/api\|a=1&b=2"` (sorted) |

### 1.3 JSON Canonicalization Vectors

| Input JSON | Expected Canonical Output |
|------------|---------------------------|
| `{"z":1,"a":2}` | `{"a":2,"z":1}` |
| `{"outer":{"z":1,"a":2}}` | `{"outer":{"a":2,"z":1}}` |
| `{"arr":[3,1,4]}` | `{"arr":[3,1,4]}` (order preserved) |
| `{"value":-0}` | `{"value":0}` (-0 becomes 0) |
| `{"text":"café"}` | `{"text":"café"}` (NFC normalized) |
| `{"text":"cafe\u0301"}` | `{"text":"café"}` (NFD→NFC) |

### 1.4 Query String Canonicalization Vectors

| Input Query | Expected Output |
|-------------|-----------------|
| `"b=2&a=1"` | `"a=1&b=2"` |
| `"a=2&a=1"` | `"a=1&a=2"` (stable sort by value) |
| `"?a=1&b=2"` | `"a=1&b=2"` (leading ? stripped) |
| `"a=1#section"` | `"a=1"` (fragment stripped) |
| `"key=%2f"` | `"key=%2F"` (uppercase hex) |
| `"key=%252F"` | `"key=%252F"` (double-encoding preserved) |

### 1.5 URL-Encoded Body Vectors

| Input | Expected Output |
|-------|-----------------|
| `"z=3&a=1"` | `"a=1&z=3"` |
| `"key=a+b"` | `"key=a%2Bb"` (+ becomes %2B) |
| `"key=a%20b"` | `"key=a%20b"` (%20 preserved) |

### 1.6 Timing-Safe Comparison Vectors

| Input A | Input B | Expected Result |
|---------|---------|-----------------|
| `"abc"` | `"abc"` | `true` |
| `"abc"` | `"abd"` | `false` |
| `"abc"` | `"abcd"` | `false` |
| `""` | `""` | `true` |
| `""` | `"a"` | `false` |

### 1.7 Scoped Field Extraction Vectors

| Payload | Scope | Expected Extracted |
|---------|-------|-------------------|
| `{"a":1,"b":2}` | `["a"]` | `{"a":1}` |
| `{"user":{"name":"John"}}` | `["user.name"]` | `{"user.name":"John"}` |
| `{"items":[1,2,3]}` | `["items[0]"]` | `{"items[0]":1}` |
| `{"a":1}` | `[]` | `{}` |

---

## 2. RFC Compliance Tests

### 2.1 RFC 8785 - JSON Canonicalization Scheme (JCS)

#### 3.2.2.1 Primitive Literals
- [ ] Serialize `null` as `null`
- [ ] Serialize `true` as `true`
- [ ] Serialize `false` as `false`

#### 3.2.2.2 Numbers
- [ ] Serialize integers without decimal point: `42` → `42`
- [ ] Normalize `-0` to `0`
- [ ] Serialize floats with minimal representation: `3.14` → `3.14`
- [ ] Whole floats become integers: `3.0` → `3`
- [ ] Reject `NaN`
- [ ] Reject `Infinity`

#### 3.2.2.3 Strings
- [ ] Escape newline: `\n` → `\\n`
- [ ] Escape backslash: `\` → `\\`
- [ ] Escape quote: `"` → `\"`
- [ ] Preserve Unicode characters
- [ ] Escape control characters (U+0000-U+001F)

#### 3.2.3 Arrays
- [ ] Preserve array element order
- [ ] Handle empty arrays: `[]`
- [ ] Handle nested arrays

#### 3.2.4 Objects
- [ ] Sort object keys lexicographically (byte-wise)
- [ ] Sort nested object keys
- [ ] Handle empty objects: `{}`
- [ ] Remove all whitespace

#### 3.2.5 Unicode
- [ ] Normalize to NFC form
- [ ] Handle combining characters
- [ ] Handle surrogate pairs

### 2.2 RFC 4648 - Base16 Encoding

- [ ] Hash output: 64 lowercase hex characters
- [ ] Proof output: 64 lowercase hex characters
- [ ] No uppercase in output
- [ ] Accept both upper and lowercase input

### 2.3 RFC 2104 - HMAC

- [ ] Consistent output for same inputs (deterministic)
- [ ] 256-bit output length (HMAC-SHA256)
- [ ] Different keys produce different outputs

### 2.4 RFC 3986 - URI Encoding

- [ ] Uppercase percent-encoding hex digits
- [ ] Preserve double-encoded values
- [ ] Strip fragment identifier
- [ ] Strip leading `?` from query

---

## 3. Core SDK Tests

### 3.1 Nonce Generation

- [ ] `generateNonce()` returns 64-character hex string
- [ ] Each call produces unique value
- [ ] Uses cryptographically secure random

### 3.2 Context ID Generation

- [ ] `generateContextId()` returns string with `ctx_` prefix
- [ ] Each call produces unique value
- [ ] `generateContextId256()` returns 256-bit context ID

### 3.3 Client Secret Derivation

- [ ] `deriveClientSecret(nonce, contextId, binding)` returns 64-char hex
- [ ] Deterministic: same inputs → same output
- [ ] Different inputs → different outputs
- [ ] Rejects invalid nonce (non-hex, too short, too long)
- [ ] Rejects empty context ID
- [ ] Validates nonce length (32-128 hex chars)

### 3.4 Proof Building (v2.1)

- [ ] `buildProof(secret, timestamp, binding, bodyHash)` returns 64-char hex
- [ ] Deterministic
- [ ] Rejects empty inputs
- [ ] Rejects invalid body hash format

### 3.5 Proof Verification (v2.1)

- [ ] Returns `true` for valid proof
- [ ] Returns `false` for invalid proof
- [ ] Returns `false` for tampered body
- [ ] Returns `false` for tampered timestamp
- [ ] Returns `false` for tampered binding
- [ ] Never throws on invalid proof (returns false)

### 3.6 Scoped Proofs (v2.2)

- [ ] `buildProofScoped(secret, timestamp, binding, payload, scope)` returns `(proof, scopeHash)`
- [ ] Only protects specified fields
- [ ] Non-scoped field changes don't invalidate proof
- [ ] Scoped field changes invalidate proof
- [ ] Normalizes scope (sort, deduplicate)
- [ ] Supports nested field paths: `user.address.city`
- [ ] Supports array indices: `items[0]`

### 3.7 Unified/Chained Proofs (v2.3)

- [ ] `buildProofUnified(secret, timestamp, binding, payload, scope, previousProof)` returns `(proof, scopeHash, chainHash)`
- [ ] Works without chaining (previousProof = null)
- [ ] Works without scoping (scope = [])
- [ ] Verifies chain integrity
- [ ] Wrong previous proof fails verification

### 3.8 Timestamp Validation

- [ ] Accepts valid current timestamp
- [ ] Rejects expired timestamp (beyond maxAge)
- [ ] Rejects future timestamp (beyond clockSkew)
- [ ] Respects custom maxAge parameter
- [ ] Respects custom clockSkew parameter
- [ ] Rejects non-numeric timestamps
- [ ] Rejects negative timestamps
- [ ] Rejects timestamps with leading zeros

### 3.9 Hash Functions

- [ ] `hashBody(body)` returns 64-char lowercase hex
- [ ] `hashBody("")` returns SHA-256 of empty string
- [ ] Consistent output for same input
- [ ] `hashProof(proof)` returns hash of proof
- [ ] `hashScope(scope)` returns hash of normalized scope

---

## 4. Security Tests

### 4.1 Input Validation

- [ ] Reject empty nonce
- [ ] Reject short nonce (< 32 hex chars)
- [ ] Reject non-hex nonce
- [ ] Reject oversized nonce (> 128 hex chars)
- [ ] Reject empty context ID
- [ ] Reject empty binding (in proof functions)
- [ ] Reject invalid JSON
- [ ] Reject JSON with NaN
- [ ] Reject JSON with Infinity

### 4.2 Size Limits

- [ ] Reject JSON payload > 10MB
- [ ] Reject JSON nesting depth > 64
- [ ] Reject binding > 8KB
- [ ] Reject scope with > 100 fields
- [ ] Reject scope field name > 64 chars
- [ ] Reject array index > 10000

### 4.3 Injection Prevention

- [ ] JSON injection prevented
- [ ] Path traversal in scope prevented
- [ ] Special characters properly escaped

### 4.4 Cryptographic Security

- [ ] Use cryptographically secure random for nonces
- [ ] Timing-safe comparison for proof verification
- [ ] No timing information leakage

### 4.5 Information Disclosure Prevention

- [ ] Error messages don't leak nonce
- [ ] Error messages don't leak client secret
- [ ] Error messages don't leak expected proof
- [ ] Verification failure returns false, not error with details

### 4.6 Replay Prevention

- [ ] Timestamp validation enforced
- [ ] Context single-use (where applicable)

---

## 5. Production Edge Cases

### 5.1 Unicode Edge Cases

- [ ] Emoji handling: `{"emoji":"🎉🚀💯"}`
- [ ] CJK characters: `{"jp":"日本語","cn":"中文","kr":"한국어"}`
- [ ] RTL text: `{"ar":"العربية","he":"עברית"}`
- [ ] Zero-width characters: ZWSP, ZWJ, ZWNJ
- [ ] Combining characters: `café` (NFC) = `cafe` + combining accent (NFD)
- [ ] Surrogate pairs: `\uD83D\uDE00` → 😀

### 5.2 Time Edge Cases

- [ ] Unix epoch (timestamp = 0)
- [ ] Year 2038 boundary (2147483647)
- [ ] Year 3000 (64-bit timestamp)
- [ ] Negative timestamps rejected

### 5.3 Boundary Conditions

- [ ] Minimum valid nonce (32 hex chars)
- [ ] Maximum valid nonce (128 hex chars)
- [ ] Empty JSON object: `{}`
- [ ] Empty JSON array: `[]`
- [ ] Numeric string keys sorted lexicographically: `"1"`, `"10"`, `"2"`

### 5.4 Concurrency (where applicable)

- [ ] Concurrent proof generation produces unique results
- [ ] Concurrent verification is thread-safe
- [ ] No race conditions in context operations

### 5.5 Memory

- [ ] Handle 1MB payload within limits
- [ ] Reject 11MB payload
- [ ] Handle objects with 1000 keys

---

## 6. Error Handling Tests

### 6.1 Error Message Quality

- [ ] Meaningful error for empty nonce
- [ ] Meaningful error for invalid nonce format
- [ ] Meaningful error for short nonce
- [ ] Meaningful error for empty context ID
- [ ] Meaningful error for empty binding
- [ ] Meaningful error for invalid JSON
- [ ] Meaningful error for invalid timestamp format
- [ ] Meaningful error for expired timestamp
- [ ] Meaningful error for future timestamp

### 6.2 Resource Limit Errors

- [ ] Meaningful error for oversized JSON
- [ ] Meaningful error for deeply nested JSON
- [ ] Meaningful error for oversized nonce

### 6.3 Graceful Handling

- [ ] Verification failure returns false (not throw)
- [ ] Empty body hash produces valid hash
- [ ] Empty query canonicalization returns empty string
- [ ] Empty JSON canonicalization of `{}` returns `{}`

### 6.4 Recovery

- [ ] Recovers after multiple failed operations
- [ ] State not corrupted by errors

---

## 7. Property-Based Tests

### 7.1 Hash Properties

- [ ] **Determinism:** `hash(x) == hash(x)` always
- [ ] **Avalanche:** small input change → significantly different hash
- [ ] **Length consistency:** output always 64 chars

### 7.2 Proof Properties

- [ ] **Soundness:** valid proof always verifies
- [ ] **Completeness:** only correct proof verifies
- [ ] **Determinism:** same inputs → same proof

### 7.3 Canonicalization Properties

- [ ] **Idempotence:** `canon(canon(x)) == canon(x)`
- [ ] **Determinism:** same input → same output
- [ ] **Semantic preservation:** parsed value unchanged

### 7.4 Scope Properties

- [ ] **Order independence:** `["a","b"]` and `["b","a"]` produce same hash
- [ ] **Deduplication:** `["a","a"]` treated as `["a"]`

---

## Implementation Checklist

Use this checklist when implementing a new ASH SDK:

### Phase 1: Core Functions
- [ ] JSON canonicalization (RFC 8785)
- [ ] Query string canonicalization
- [ ] URL-encoded body canonicalization
- [ ] Body hashing (SHA-256)
- [ ] Nonce generation
- [ ] Context ID generation
- [ ] Client secret derivation
- [ ] Binding normalization

### Phase 2: Proof Operations
- [ ] Proof building (v2.1)
- [ ] Proof verification (v2.1)
- [ ] Scoped proof building (v2.2)
- [ ] Scoped proof verification (v2.2)
- [ ] Unified proof building (v2.3)
- [ ] Unified proof verification (v2.3)

### Phase 3: Validation
- [ ] Input validation
- [ ] Size limits
- [ ] Timestamp validation
- [ ] Timing-safe comparison

### Phase 4: Cross-SDK Verification
- [ ] All test vectors pass
- [ ] RFC compliance verified
- [ ] Security tests pass

---

## Supported SDKs

| SDK | Language | Status |
|-----|----------|--------|
| ash-core | Rust | Reference Implementation |
| ash-node | Node.js/TypeScript | Production |
| ash-go | Go | Production |
| ash-python | Python | Production |
| ash-php | PHP | Production |
| ash-dotnet | C#/.NET | Needs Fix |
| ash-wasm | WebAssembly | Production |

---

## Test Coverage Matrix

Current test coverage across SDKs (as of January 2026):

| Test Category | Rust | Node.js | Go | Python | PHP | .NET |
|---------------|------|---------|-----|--------|-----|------|
| **Cross-SDK Test Vectors** | ✅ 50 | ✅ 45 | ✅ 24+ | ✅ 89 | ✅ 99 | ⚠️ Build Error |
| **RFC Compliance** | ✅ 45 | ✅ 49 | ⭕ | ⭕ | ⭕ | ⭕ |
| **Security Audit** | ✅ 35 | ✅ 58 | ⭕ | ⭕ | ⭕ | ⭕ |
| **Production Edge Cases** | ✅ 28 | ✅ 38 | ⭕ | ⭕ | ⭕ | ⭕ |
| **Error Handling** | ✅ 26 | ✅ 33 | ⭕ | ⭕ | ⭕ | ⭕ |
| **Core Unit Tests** | ✅ 183 | ✅ 117 | ✅ | ✅ | ✅ | ⭕ |
| **Fuzzing** | ⭕ | ✅ 51 | ⭕ | ⭕ | ⭕ | ⭕ |
| **Benchmarks** | ⭕ | ✅ 21 | ⭕ | ⭕ | ⭕ | ⭕ |

**Legend:**
- ✅ = Implemented and passing
- ⭕ = Not yet implemented (recommended)
- ⚠️ = Has issues

### Priority for Missing Tests

1. **High Priority** - All SDKs should implement:
   - Cross-SDK Test Vectors (ensures compatibility)
   - RFC Compliance Tests (protocol correctness)
   - Security Audit Tests (vulnerability prevention)

2. **Medium Priority** - Recommended for production SDKs:
   - Production Edge Cases
   - Error Handling Tests

3. **Low Priority** - Nice to have:
   - Fuzzing Tests
   - Benchmark Tests

---

*This document is the authoritative source for ASH protocol test requirements.*
