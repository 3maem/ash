# SDK-Specific Tests

**Version:** 2.3.3
**Last Updated:** January 2026

This document defines tests that are specific to individual SDK implementations, including language-specific type safety, platform-specific features, and performance benchmarks.

---

## Table of Contents

1. [TypeScript/JavaScript Tests](#1-typescriptjavascript-tests)
2. [Rust Tests](#2-rust-tests)
3. [Go Tests](#3-go-tests)
4. [Python Tests](#4-python-tests)
5. [PHP Tests](#5-php-tests)
6. [.NET/C# Tests](#6-netc-tests)
7. [Context Store Tests](#7-context-store-tests)
8. [Performance Benchmarks](#8-performance-benchmarks)
9. [Fuzzing Tests](#9-fuzzing-tests)

---

## 1. TypeScript/JavaScript Tests

**Applies to:** `ash-node`, `ash-wasm`

### 1.1 Type Exports Verification

- [ ] Export all core functions
- [ ] Export v2.2 scoped proof functions
- [ ] Export v2.3 unified proof functions
- [ ] Export utility functions
- [ ] Export store classes

### 1.2 Type Inference

| Function | Expected Return Type |
|----------|---------------------|
| `ashGenerateNonce()` | `string` |
| `ashGenerateContextId()` | `string` |
| `ashHashBody(body)` | `string` |
| `ashBuildProofV21(...)` | `string` |
| `ashVerifyProofV21(...)` | `boolean` |
| `ashBuildProofScoped(...)` | `AshScopedProofResult` |
| `ashBuildProofUnified(...)` | `AshUnifiedProofResult` |

### 1.3 Interface Types

```typescript
// AshContext
interface AshContext {
  id: string;      // ctx_ prefix
  nonce: string;   // 64-char hex
  binding: string;
  expiresAt: number;
  metadata?: Record<string, unknown>;
}

// AshScopedProofResult
interface AshScopedProofResult {
  proof: string;
  scopeHash: string;
}

// AshUnifiedProofResult
interface AshUnifiedProofResult {
  proof: string;
  scopeHash: string;
  chainHash: string;
}
```

### 1.4 Function Signatures

- [ ] `ashDeriveClientSecret(nonce: string, contextId: string, binding: string): string`
- [ ] `ashNormalizeBinding(method: string, path: string, query: string): string`
- [ ] `ashCanonicalizeJson(json: string): string`
- [ ] `ashTimingSafeEqual(a: string, b: string): boolean`
- [ ] `ashValidateTimestamp(ts: string, maxAge?: number, clockSkew?: number): boolean`

### 1.5 Optional Parameters

- [ ] `ashValidateTimestamp` accepts optional maxAge and clockSkew
- [ ] `ashBuildProofUnified` accepts optional previousProof

### 1.6 Async Operations (Store)

- [ ] `store.create()` returns `Promise<AshContext>`
- [ ] `store.get(id)` returns `Promise<AshContext | null>`
- [ ] `store.consume(id)` returns `Promise<boolean>`
- [ ] `store.cleanup()` returns `Promise<number>`

### 1.7 Runtime Type Safety

- [ ] Throws on `undefined` input
- [ ] Throws on `number` input to string function
- [ ] Throws on `object` input to string function
- [ ] Accepts valid array JSON

---

## 2. Rust Tests

**Applies to:** `ash-core`

### 2.1 Error Types

```rust
// AshError should have code and message
assert!(error.code() == AshErrorCode::MalformedRequest);
assert!(!error.message().is_empty());
```

### 2.2 Result Types

- [ ] All fallible functions return `Result<T, AshError>`
- [ ] `UnifiedProofResult` struct has `proof`, `scope_hash`, `chain_hash` fields

### 2.3 Ownership and Borrowing

- [ ] Functions accept `&str` for string inputs
- [ ] Functions return owned `String` for outputs
- [ ] No unnecessary cloning

### 2.4 Thread Safety

- [ ] All functions are `Send + Sync`
- [ ] No global mutable state
- [ ] Safe concurrent usage

### 2.5 No-Std Compatibility (if applicable)

- [ ] Core functions work without std (with alloc)

---

## 3. Go Tests

**Applies to:** `ash-go`

### 3.1 Error Handling

```go
// Go uses error returns
proof, err := ash.BuildProof(secret, timestamp, binding, bodyHash)
if err != nil {
    // Handle error
}
```

### 3.2 Function Signatures

- [ ] `GenerateNonce() string`
- [ ] `GenerateContextId() string`
- [ ] `HashBody(body string) string`
- [ ] `DeriveClientSecret(nonce, contextId, binding string) (string, error)`
- [ ] `BuildProof(...) (string, error)`
- [ ] `VerifyProof(...) (bool, error)`

### 3.3 Struct Types

```go
type ScopedProofResult struct {
    Proof     string
    ScopeHash string
}

type UnifiedProofResult struct {
    Proof     string
    ScopeHash string
    ChainHash string
}
```

### 3.4 Goroutine Safety

- [ ] Concurrent usage is safe
- [ ] No race conditions

---

## 4. Python Tests

**Applies to:** `ash-python`

### 4.1 Type Hints

```python
def generate_nonce() -> str: ...
def hash_body(body: str) -> str: ...
def derive_client_secret(nonce: str, context_id: str, binding: str) -> str: ...
def build_proof(secret: str, timestamp: str, binding: str, body_hash: str) -> str: ...
def verify_proof(...) -> bool: ...
```

### 4.2 Exception Handling

- [ ] `AshError` exception with `code` and `message`
- [ ] Specific error types inherit from `AshError`

### 4.3 Dataclass Types

```python
@dataclass
class ScopedProofResult:
    proof: str
    scope_hash: str

@dataclass
class UnifiedProofResult:
    proof: str
    scope_hash: str
    chain_hash: str
```

### 4.4 Optional Parameters

- [ ] `validate_timestamp(ts, max_age=300, clock_skew=60)`
- [ ] `build_proof_unified(..., previous_proof=None)`

---

## 5. PHP Tests

**Applies to:** `ash-php`

### 5.1 Class Structure

```php
class Ash {
    public static function generateNonce(): string;
    public static function hashBody(string $body): string;
    public static function deriveClientSecret(string $nonce, string $contextId, string $binding): string;
    public static function buildProof(...): string;
    public static function verifyProof(...): bool;
}
```

### 5.2 Exception Handling

- [ ] `AshException` with code and message
- [ ] `AshValidationException` for input errors
- [ ] `AshCryptoException` for cryptographic errors

### 5.3 Return Types

```php
class ScopedProofResult {
    public string $proof;
    public string $scopeHash;
}
```

---

## 6. .NET/C# Tests

**Applies to:** `ash-dotnet`

### 6.1 Namespace and Class Structure

```csharp
namespace Ash.Core {
    public static class AshSdk {
        public static string GenerateNonce();
        public static string HashBody(string body);
        public static string DeriveClientSecret(string nonce, string contextId, string binding);
    }
}
```

### 6.2 Exception Types

- [ ] `AshException` base exception
- [ ] `AshValidationException` for input errors
- [ ] Exception has `Code` and `Message` properties

### 6.3 Record Types

```csharp
public record ScopedProofResult(string Proof, string ScopeHash);
public record UnifiedProofResult(string Proof, string ScopeHash, string ChainHash);
```

### 6.4 Nullable Reference Types

- [ ] Proper nullable annotations
- [ ] Non-null returns for generation functions

---

## 7. Context Store Tests

### 7.1 Memory Store (All SDKs)

| Test | Description |
|------|-------------|
| Create context | Store returns context with all required fields |
| Create with metadata | Metadata is stored and retrievable |
| Get by ID | Returns context for valid ID |
| Get non-existent | Returns null/None/nil for unknown ID |
| Consume once | First consume returns true |
| Consume twice | Second consume returns false |
| Expire after TTL | Context not retrievable after expiration |
| Reject zero TTL | Zero TTL is rejected |
| Reject negative TTL | Negative TTL is rejected |
| Cleanup expired | Removes expired contexts |
| Size reporting | Reports correct number of contexts |

### 7.2 Concurrent Access

- [ ] Handle 100 concurrent creates
- [ ] Ensure exactly-once consumption under race
- [ ] No corruption with mixed operations

### 7.3 Edge Cases

- [ ] Very long binding (within limits)
- [ ] Special characters in binding
- [ ] Empty metadata
- [ ] Reject oversized metadata

### 7.4 Redis Store (Where Implemented)

- [ ] Atomic create and consume
- [ ] TTL enforcement by Redis
- [ ] Reconnection handling

### 7.5 SQL Store (Where Implemented)

- [ ] Transaction isolation
- [ ] Concurrent transaction handling
- [ ] Cleanup query efficiency

---

## 8. Performance Benchmarks

**Note:** Thresholds are guidelines. Actual performance varies by language and platform.

### 8.1 Proof Operations

| Operation | Node.js | Rust | Go | Python |
|-----------|---------|------|-----|--------|
| Proof generation/sec | ≥5,000 | ≥50,000 | ≥20,000 | ≥2,000 |
| Proof verification/sec | ≥5,000 | ≥50,000 | ≥20,000 | ≥2,000 |

### 8.2 Canonicalization

| Operation | Node.js | Rust | Go | Python |
|-----------|---------|------|-----|--------|
| Small JSON canon/sec | ≥10,000 | ≥100,000 | ≥50,000 | ≥5,000 |
| Query string canon/sec | ≥20,000 | ≥200,000 | ≥100,000 | ≥10,000 |

### 8.3 Hashing

| Operation | Node.js | Rust | Go | Python |
|-----------|---------|------|-----|--------|
| Small body hash/sec | ≥50,000 | ≥500,000 | ≥200,000 | ≥20,000 |
| 10KB body hash/sec | ≥5,000 | ≥50,000 | ≥20,000 | ≥2,000 |

### 8.4 Nonce Generation

| Operation | All SDKs |
|-----------|----------|
| Nonce generation/sec | ≥50,000 |
| Context ID generation/sec | ≥50,000 |

### 8.5 Context Store

| Operation | Node.js | Rust | Go | Python |
|-----------|---------|------|-----|--------|
| Create context/sec | ≥5,000 | ≥50,000 | ≥20,000 | ≥2,000 |
| Consume context/sec | ≥10,000 | ≥100,000 | ≥50,000 | ≥5,000 |

### 8.6 Memory Stability

- [ ] <50MB growth over 100,000 operations
- [ ] No memory leaks in long-running tests

---

## 9. Fuzzing Tests

### 9.1 Random Input Generation

| Test | Iterations | Target |
|------|------------|--------|
| Random JSON | 10,000 | No crashes, consistent error handling |
| Random query strings | 10,000 | No crashes |
| Random bindings | 10,000 | No crashes |
| Random nonces | 10,000 | Proper validation |
| Random timestamps | 10,000 | Proper validation |

### 9.2 Boundary Fuzzing

- [ ] Empty inputs
- [ ] Maximum length inputs
- [ ] Unicode stress testing
- [ ] Control characters

### 9.3 Malformed Input

- [ ] Invalid JSON variations
- [ ] Invalid hex strings
- [ ] Truncated inputs
- [ ] Null bytes

### 9.4 Crash Resistance

- [ ] No panics/crashes on any input
- [ ] Graceful error handling
- [ ] Memory stability under fuzzing

---

## Implementation Notes

### Adding Tests for a New SDK

1. **Start with ASH-PROTOCOL-TESTS.md** - Implement all universal tests first
2. **Add language-specific tests** from this document
3. **Run cross-SDK test vectors** to verify compatibility
4. **Add performance benchmarks** appropriate for the language

### Test Framework Recommendations

| Language | Recommended Framework |
|----------|----------------------|
| TypeScript/JavaScript | Vitest or Jest |
| Rust | Built-in `#[test]`, cargo test |
| Go | Built-in testing package |
| Python | pytest |
| PHP | PHPUnit |
| C#/.NET | xUnit or NUnit |

---

*This document supplements ASH-PROTOCOL-TESTS.md with language-specific requirements.*
