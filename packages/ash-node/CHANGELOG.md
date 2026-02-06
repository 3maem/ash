# Changelog

All notable changes to the ASH Node.js SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the complete project changelog, see [../../CHANGELOG.md](../../CHANGELOG.md).

---

## [2.3.4] - 2026-02-04

### Security
- Fixed timing attack vulnerability in query string sorting
- Added input validation before store lookup
- Production-safe error messages in middleware
- Fixed prototype pollution vulnerability in stores

### Added
- Environment-based configuration (`ASH_TRUST_PROXY`, `ASH_TIMESTAMP_TOLERANCE`, etc.)
- IP and user binding enforcement in Express/Fastify middleware
- Unique HTTP status codes (450-483 range)

### Changed
- **Breaking**: HTTP status codes changed for ASH errors
- License changed to Apache 2.0

### Fixed
- Content-Type handling consistency in Express/Fastify middleware
- Memory store returns defensive copies to prevent mutation attacks
- Redis Lua script handles type confusion and JSON corruption
- SQL Store prevents SQL injection via identifier validation

---

## [2.3.3] - 2026-01-29

### Security
- Fixed SQL injection in SQL store table name handling
- Fixed ReDoS in scope policy matching
- Added timestamp validation for replay prevention

### Added
- Unified error codes
- Cross-SDK test vectors (38 vectors)
- Secure memory utilities
- ValidationError class

### Fixed
- Scope delimiter mismatch (now `\x1F`)
- JSON canonicalization (RFC 8785 JCS)

---

## [2.3.2] - 2026-01-15

### Added
- Context scoping (v2.2)
- Request chaining (v2.3)
- Unified proof functions

---

## [2.3.1] - 2026-01-01

### Added
- Scope policy configuration
- Server-side scope validation

---

## [2.3.0] - 2025-12-15

### Added
- ASH v2.3 protocol support
- Request chaining

---

## [2.2.0] - 2025-12-01

### Added
- Context scoping support
- Scoped proof functions

---

## [2.1.0] - 2025-11-15

### Added
- HMAC-SHA256 proof generation
- Derived client secret

---

## [2.0.0] - 2025-11-01

### Added
- Initial v2 release
- Express and Fastify middleware
