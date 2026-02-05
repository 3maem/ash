# Changelog

All notable changes to the ASH SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.4] - 2026-02-04

### Security
- Fixed timing attack vulnerability in query string sorting (now uses byte-wise comparison)
- Added input validation before store lookup to prevent enumeration attacks
- Production-safe error messages to prevent information disclosure
- Fixed prototype pollution vulnerability in metadata handling

### Added
- Environment-based configuration across all SDKs (`ASH_TRUST_PROXY`, `ASH_TRUSTED_PROXIES`, `ASH_RATE_LIMIT_WINDOW`, `ASH_RATE_LIMIT_MAX`, `ASH_TIMESTAMP_TOLERANCE`)
- IP and user binding enforcement in all middleware
- Unique HTTP status codes (450-483 range) for ASH-specific errors

### Changed
- **Breaking**: HTTP status codes changed for ASH errors (see Migration Guide below)
  - Context errors: 450-452 (was 404, 401, 409)
  - Proof errors: 460 (was 401)
  - Binding/scope errors: 461, 473-474 (was 403)
  - Format errors: 482-483 (was 400, 401)

### Fixed
- WASM bindings now call correct function names
- WASM binary loading issue in Node.js SDK
- Content-Type handling consistency in Express/Fastify middleware
- Memory store returns defensive copies to prevent mutation attacks
- Redis Lua script handles type confusion and JSON corruption
- TTL overflow validation in all stores
- Scope sorting consistency across all SDKs (byte-wise)

## [2.3.3] - 2026-01-29

### Security
- Fixed SQL injection vulnerability in Node.js SQL store table name handling
- Fixed ReDoS vulnerability in scope policy pattern matching
- Added timestamp validation to prevent replay attacks with stale proofs
- Fixed timing side channel in length comparison

### Added
- Unified error codes across all 6 SDKs
- Cross-SDK test vectors (38 vectors for interoperability testing)
- Secure memory utilities for Python and Node.js (auto-clearing sensitive data)
- `ValidationError` / `ValidationException` classes in all SDKs
- Security constants matching Rust implementation

### Fixed
- Scope delimiter mismatch across SDKs (now uses unit separator `\x1F`)
- Missing scope normalization in non-Rust SDKs
- Duplicate key sorting in URL-encoded canonicalization
- JSON canonicalization in proof functions (now uses RFC 8785 JCS)
- Missing query string in PHP middleware binding normalization
- Array index handling in scoped field extraction

## [2.3.2] - 2026-01-15

### Added
- Context scoping (v2.2) - Selective field protection
- Request chaining (v2.3) - Multi-step workflow support
- Unified proof functions (`buildProofUnified`, `verifyProofUnified`)

### Changed
- Binding format changed to `METHOD|PATH|QUERY` (pipe-separated)
- Improved query string canonicalization

## [2.3.1] - 2026-01-01

### Added
- Scope policy configuration
- Server-side scope validation
- Cross-SDK test vectors

### Fixed
- Unicode NFC normalization edge cases
- Negative zero handling in JSON canonicalization

## [2.3.0] - 2025-12-15

### Added
- ASH v2.3 protocol support
- Request chaining with `previousProof` parameter
- `hashProof()` function for chain linking

## [2.2.0] - 2025-12-01

### Added
- ASH v2.2 protocol support
- Context scoping with `scope` parameter
- `extractScopedFields()` function
- Scoped proof functions

## [2.1.0] - 2025-11-15

### Added
- ASH v2.1 protocol support
- Derived client secret (`deriveClientSecret()`)
- HMAC-SHA256 proof generation
- Body hashing (`hashBody()`)

### Security
- Nonce no longer exposed to client
- Client secret derived from nonce (one-way function)

## [2.0.0] - 2025-11-01

### Changed
- Complete protocol redesign
- Context-based verification model
- Breaking changes to all APIs

### Removed
- Legacy v1.x proof format

## [1.0.0] - 2025-10-01

### Added
- Initial release
- Basic proof generation and verification
- JSON canonicalization (RFC 8785)
- URL-encoded canonicalization

---

## Migration Guide

### v2.3.3 to v2.3.4

**HTTP Status Code Changes:**

Update client error handling for new status codes:

| Error | Old Status | New Status |
|-------|------------|------------|
| Context not found | 404 | 450 |
| Context expired | 401 | 451 |
| Replay detected | 409 | 452 |
| Proof invalid | 401 | 460 |
| Binding mismatch | 403 | 461 |
| Scope mismatch | 403 | 473 |
| Chain broken | 403 | 474 |
| Timestamp invalid | 400 | 482 |
| Proof missing | 401 | 483 |

### v2.2.x to v2.3.x

No breaking changes. New features are additive.

### v2.1.x to v2.2.x

No breaking changes. Scoping is opt-in.

### v2.0.x to v2.1.x

**Breaking**: Proof format changed from SHA-256 hash to HMAC-SHA256.

```python
# Old (v2.0)
proof = build_proof(mode, binding, context_id, nonce, payload)

# New (v2.1)
client_secret = derive_client_secret(nonce, context_id, binding)
body_hash = hash_body(payload)
proof = build_proof(client_secret, timestamp, binding, body_hash)
```

### v1.x to v2.x

Complete rewrite required. See documentation.
