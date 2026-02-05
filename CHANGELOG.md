# Changelog

All notable changes to the ASH SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.3.4] - 2026-02-04

### Security
- Fixed timing attack vulnerability in query string sorting
- Added input validation before store lookup
- Production-safe error messages
- Fixed prototype pollution vulnerability

### Added
- Environment-based configuration (`ASH_TRUST_PROXY`, `ASH_TIMESTAMP_TOLERANCE`, etc.)
- IP and user binding enforcement
- Unique HTTP status codes (450-483 range)

### Changed
- **Breaking**: HTTP status codes changed for ASH errors

### Fixed
- WASM bindings function names and binary loading
- Content-Type handling in middleware
- Memory store defensive copies
- Redis Lua script type handling
- TTL overflow validation

**Details:** [docs/releases/2.3.4.md](docs/releases/2.3.4.md) | **Migration:** [docs/migrations/2.3.3-to-2.3.4.md](docs/migrations/2.3.3-to-2.3.4.md)

---

## [2.3.3] - 2026-01-29

### Security
- Fixed SQL injection in Node.js SQL store
- Fixed ReDoS in scope policy matching
- Added timestamp validation for replay prevention
- Fixed timing side channel in length comparison

### Added
- Unified error codes across all SDKs
- Cross-SDK test vectors (38 vectors)
- Secure memory utilities
- Validation classes in all SDKs

### Fixed
- Scope delimiter mismatch (now `\x1F`)
- JSON canonicalization (RFC 8785 JCS)
- URL-encoded canonicalization

---

## [2.3.2] - 2026-01-15

### Added
- Context scoping (v2.2)
- Request chaining (v2.3)
- Unified proof functions

### Changed
- Binding format: `METHOD|PATH|QUERY`

---

## [2.3.1] - 2026-01-01

### Added
- Scope policy configuration
- Server-side scope validation

### Fixed
- Unicode NFC normalization
- Negative zero handling

---

## [2.3.0] - 2025-12-15

### Added
- ASH v2.3 protocol support
- Request chaining with `previousProof`
- `hashProof()` function

---

## [2.2.0] - 2025-12-01

### Added
- ASH v2.2 protocol support
- Context scoping with `scope` parameter
- Scoped proof functions

---

## [2.1.0] - 2025-11-15

### Added
- ASH v2.1 protocol support
- Derived client secret
- HMAC-SHA256 proof generation

### Security
- Nonce no longer exposed to client

---

## [2.0.0] - 2025-11-01

### Changed
- Complete protocol redesign
- Context-based verification model

### Removed
- Legacy v1.x proof format

---

## [1.0.0] - 2025-10-01

### Added
- Initial release
- Basic proof generation and verification
- JSON canonicalization (RFC 8785)
