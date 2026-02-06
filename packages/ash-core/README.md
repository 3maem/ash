# ash-core

[![Crates.io](https://img.shields.io/crates/v/ash-core.svg)](https://crates.io/crates/ash-core)
[![Documentation](https://docs.rs/ash-core/badge.svg)](https://docs.rs/ash-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../../LICENSE)

**Developed by 3maem Co. | شركة عمائم**

Core Rust implementation of the ASH (Application Security Hash) protocol for request integrity verification and anti-replay protection.

## Overview

ASH Core provides the foundational cryptographic primitives and canonicalization functions used across all ASH SDK implementations. It ensures byte-identical output across all platforms through deterministic processing.

## Features

- **RFC 8785 Compliant**: JSON Canonicalization Scheme (JCS) for deterministic serialization
- **Cryptographic Proofs**: HMAC-SHA256 based proof generation and verification
- **Timing Attack Resistance**: Constant-time comparison for all security-sensitive operations
- **Anti-Replay Protection**: Single-use context enforcement with TTL
- **Field Scoping**: Protect specific fields while allowing others to change
- **Request Chaining**: Link sequential requests cryptographically
- **WASM Compatible**: Works in browsers via ash-wasm bindings

## Installation

```bash
cargo add ash-core
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
ash-core = "2.3.4"
```

## Quick Start

### JSON Canonicalization

```rust
use ash_core::ash_canonicalize_json;

// Keys are sorted, whitespace removed
let canonical = ash_canonicalize_json(r#"{"z": 1, "a": 2}"#).unwrap();
assert_eq!(canonical, r#"{"a":2,"z":1}"#);
```

### Proof Generation

```rust
use ash_core::{
    ash_derive_client_secret, ash_build_proof, ash_hash_body,
    ash_generate_nonce, ash_generate_context_id, ash_canonicalize_json,
};

// Server generates nonce and context
let nonce = ash_generate_nonce(32).unwrap();
let context_id = ash_generate_context_id().unwrap();
let binding = "POST|/api/transfer|";

// Client canonicalizes payload
let payload = r#"{"amount":100}"#;
let canonical = ash_canonicalize_json(payload).unwrap();

// Client derives secret and builds proof
let client_secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
let body_hash = ash_hash_body(&canonical);
let timestamp = "1706400000";
let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();
```

### Proof Verification

```rust
use ash_core::ash_verify_proof;

let is_valid = ash_verify_proof(
    &nonce,
    &context_id,
    binding,
    timestamp,
    &body_hash,
    &client_proof,
).unwrap();
```

### Binding Normalization

```rust
use ash_core::ash_normalize_binding;

// Binding format: METHOD|PATH|CANONICAL_QUERY
let binding = ash_normalize_binding("post", "/api//users/", "").unwrap();
assert_eq!(binding, "POST|/api/users|");

let binding_with_query = ash_normalize_binding("GET", "/api/users", "z=3&a=1").unwrap();
assert_eq!(binding_with_query, "GET|/api/users|a=1&z=3");
```

### Scoped Proofs (Protect Specific Fields)

```rust
use ash_core::{ash_build_proof_scoped, ash_verify_proof_scoped};

// Only protect "amount" and "recipient" fields
let scope = vec!["amount", "recipient"];
let result = ash_build_proof_scoped(
    &client_secret, timestamp, binding, payload, &scope
).unwrap();

// Other fields can change without invalidating the proof
```

### Request Chaining

```rust
use ash_core::{ash_build_proof_unified, ash_hash_proof};

// Chain this request to the previous one
let chain_hash = ash_hash_proof(&previous_proof).unwrap();
let result = ash_build_proof_unified(
    &nonce, &context_id, binding, timestamp,
    payload, &[], Some(&previous_proof)
).unwrap();
```

## Documentation

- **[SPECIFICATION.md](SPECIFICATION.md)** - Complete protocol specification for SDK implementers
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and migration guides
- **[API Documentation](https://docs.rs/ash-core)** - Full Rust API docs

## API Reference

### Core Proof Functions

| Function | Description |
|----------|-------------|
| `ash_derive_client_secret(nonce, ctx_id, binding)` | Derive HMAC key from nonce |
| `ash_build_proof(secret, timestamp, binding, body_hash)` | Build HMAC-SHA256 proof |
| `ash_verify_proof(nonce, ctx_id, binding, timestamp, body_hash, proof)` | Verify proof |

### Scoped Proof Functions

| Function | Description |
|----------|-------------|
| `ash_build_proof_scoped(...)` | Build proof protecting specific fields |
| `ash_verify_proof_scoped(...)` | Verify scoped proof |
| `ash_extract_scoped_fields(payload, scope)` | Extract fields for scoping |
| `ash_hash_scoped_body(payload, scope)` | Hash only scoped fields |

### Unified Proof Functions (Scoping + Chaining)

| Function | Description |
|----------|-------------|
| `ash_build_proof_unified(...)` | Build proof with scoping + chaining |
| `ash_verify_proof_unified(...)` | Verify unified proof |
| `ash_hash_proof(proof)` | Compute chain hash |

### Canonicalization Functions

| Function | Description |
|----------|-------------|
| `ash_canonicalize_json(input)` | Canonicalize JSON (RFC 8785) |
| `ash_canonicalize_query(query)` | Canonicalize URL query string |
| `ash_canonicalize_urlencoded(input)` | Canonicalize form data |
| `ash_normalize_binding(method, path, query)` | Normalize endpoint binding |

### Utility Functions

| Function | Description |
|----------|-------------|
| `ash_generate_nonce(bytes)` | Generate cryptographic nonce |
| `ash_generate_context_id()` | Generate unique context ID |
| `ash_hash_body(body)` | SHA-256 hash of body |
| `ash_hash_scope(scope)` | Hash scope field list |
| `ash_timing_safe_equal(a, b)` | Constant-time comparison |
| `ash_validate_timestamp(ts, now, max_age, skew)` | Validate timestamp |

### Types

| Type | Description |
|------|-------------|
| `AshMode` | Security mode: `Minimal`, `Balanced`, `Strict` |
| `AshError` | Error type with code and message |
| `AshErrorCode` | Error codes (e.g., `CtxNotFound`, `ProofInvalid`) |
| `UnifiedProofResult` | Result from unified proof functions |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ASH_VERSION_PREFIX` | `"ASHv2.1"` | Protocol version prefix |
| `ASH_SDK_VERSION` | `"2.3.4"` | SDK version |
| `DEFAULT_MAX_TIMESTAMP_AGE_SECONDS` | `300` | Default max age (5 min) |
| `DEFAULT_CLOCK_SKEW_SECONDS` | `30` | Default clock skew allowance |

## Security Modes

| Mode | Use Case | Performance |
|------|----------|-------------|
| `Minimal` | Development/testing | Fastest |
| `Balanced` | General production use | Recommended |
| `Strict` | High-security transactions | Most thorough |

## Cryptographic Details

| Component | Algorithm |
|-----------|-----------|
| Proof Generation | HMAC-SHA256 |
| Body Hashing | SHA-256 |
| Nonce Generation | CSPRNG (`getrandom`) |
| Comparison | Constant-time (`subtle` crate) |
| Key Derivation | HMAC-based |

## Error Handling

```rust
use ash_core::{ash_canonicalize_json, AshError, AshErrorCode};

match ash_canonicalize_json("invalid json") {
    Ok(canonical) => println!("Canonical: {}", canonical),
    Err(e) => {
        println!("Error code: {:?}", e.code());
        println!("HTTP status: {}", e.code().http_status());
        println!("Message: {}", e.message());
    }
}
```

### Error Codes (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

| Code | HTTP | Category | Description |
|------|------|----------|-------------|
| `CtxNotFound` | 450 | Context | Context ID not found |
| `CtxExpired` | 451 | Context | Context TTL exceeded |
| `CtxAlreadyUsed` | 452 | Context | Context already consumed (replay) |
| `ProofInvalid` | 460 | Seal | Proof verification failed |
| `BindingMismatch` | 461 | Binding | Endpoint binding mismatch |
| `ScopeMismatch` | 473 | Verification | Scope hash mismatch |
| `ChainBroken` | 474 | Verification | Chain verification failed |
| `TimestampInvalid` | 482 | Format | Invalid timestamp format |
| `ProofMissing` | 483 | Format | Required proof not provided |
| `CanonicalizationError` | 422 | Standard | Canonicalization failed |
| `MalformedRequest` | 400 | Standard | Invalid request format |
| `ModeViolation` | 400 | Standard | Mode requirements not met |
| `UnsupportedContentType` | 415 | Standard | Content type not supported |
| `ScopedFieldMissing` | 422 | Standard | Required scoped field missing |
| `InternalError` | 500 | Standard | Internal server error |

## Input Validation

The Rust SDK performs comprehensive input validation in `ash_derive_client_secret`:

### Validation Rules

| Parameter | Rule | Constant |
|-----------|------|----------|
| `nonce` | Minimum 32 hex characters | `MIN_NONCE_HEX_CHARS` |
| `nonce` | Maximum 128 characters | `MAX_NONCE_LENGTH` |
| `nonce` | Hexadecimal only | - |
| `context_id` | Cannot be empty | - |
| `context_id` | Maximum 256 characters | `MAX_CONTEXT_ID_LENGTH` |
| `context_id` | Alphanumeric + `_` `-` `.` | `CONTEXT_ID_PATTERN` |
| `binding` | Maximum 8192 bytes | `MAX_BINDING_LENGTH` |

### Example

```rust
use ash_core::ash_derive_client_secret;

match ash_derive_client_secret(&nonce, &context_id, binding) {
    Ok(secret) => {
        // Use the derived secret
    }
    Err(e) => {
        // Handle validation error
        eprintln!("Validation failed: {}", e.message());
    }
}
```

All other SDKs (Go, Python, PHP, .NET, Node.js) implement identical validation to ensure cross-SDK compatibility.

## Thread Safety

All functions are thread-safe and can be called concurrently.

## Performance

Typical operation latencies (measured on Apple M1):

| Operation | Latency |
|-----------|---------|
| JSON canonicalization | ~50-100μs |
| Proof generation | ~3μs |
| Proof verification | ~6μs |

## Security Notes

ASH verifies **what** is being submitted, not **who** is submitting it.
It should be used alongside authentication systems (JWT, OAuth, etc.).

## Implementing Other SDKs

See **[SPECIFICATION.md](SPECIFICATION.md)** for the complete protocol specification including:
- Detailed algorithms with pseudocode
- Test vectors for verification
- Security requirements checklist
- HTTP header formats

## Related Crates

- [`ash-wasm`](https://crates.io/crates/ash-wasm) - WebAssembly bindings

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
- [API Documentation](https://docs.rs/ash-core)
- [Protocol Specification](SPECIFICATION.md)
- [Security Policy](../../SECURITY.md)

© 3maem Co. | شركة عمائم
