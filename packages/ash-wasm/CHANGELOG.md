# Changelog

All notable changes to ASH WASM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the complete project changelog, see [../../CHANGELOG.md](../../CHANGELOG.md).

---

## [2.3.4] - 2026-02-04

### Security
- Fixed timing attack vulnerability in query string sorting
- Added input validation in `ashDeriveClientSecret`

### Added
- Unique HTTP status codes (450-483 range)

### Changed
- **Breaking**: HTTP status codes changed for ASH errors
- License changed to Apache 2.0

### Fixed
- WASM bindings now call correct ash_core function names (missing `ash_` prefix)
- WASM initialization now loads the binary module correctly

---

## [2.3.3] - 2026-01-29

### Security
- Added timestamp validation for replay prevention

### Added
- Unified error codes
- Cross-SDK test vectors

### Fixed
- Query string sorting (UTF-16 to byte-wise)
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
- `ashBuildProofHmac` function

---

## [2.0.0] - 2025-11-01

### Added
- Initial v2 release
- WebAssembly bindings for ash-core
