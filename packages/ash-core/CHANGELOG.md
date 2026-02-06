# Changelog

All notable changes to ASH Core are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.4] - 2026-02-04

### Security
- Fixed timing attack vulnerability in query string sorting (byte-wise comparison)
- Added input validation before store lookup to prevent enumeration attacks
- Production-safe error messages to prevent information disclosure

### Added
- Unique HTTP status codes (450-483 range) for ASH-specific errors
- Environment-based configuration support
- Cross-SDK validation alignment in `ash_derive_client_secret`

### Changed
- **Breaking**: HTTP status codes changed for ASH errors (see migration guide)
- License changed to Apache 2.0

### Fixed
- WASM bindings now call correct function names (missing `ash_` prefix)
- TTL overflow validation in all stores
- Scope sorting consistency (byte-wise)

---

## [2.3.3] - 2026-01-29

### Added

- Comprehensive SPECIFICATION.md for SDK implementers
- Module-level documentation with examples and tables
- New test for delimiter in scope field names (BUG-028)
- New test for empty proof rejection (BUG-029)
- New test for encoded query delimiter bypass (BUG-027)
- New function `ash_canonicalize_json_value_with_size_check()` for Values from untrusted sources (BUG-044)
- BUG_REPORT.md documenting all identified and fixed bugs

### Changed

- **BREAKING**: Removed deprecated v1 functions:
  - `ash_build_proof_v1` (removed)
  - `ash_build_proof_v1_from_input` (removed)
  - `ash_verify_proof_v1` (removed)

- **BREAKING**: Renamed v21 functions to cleaner names:
  - `ash_build_proof_v21` → `ash_build_proof`
  - `ash_verify_proof_v21` → `ash_verify_proof`
  - `ash_build_proof_v21_scoped` → `ash_build_proof_scoped`
  - `ash_verify_proof_v21_scoped` → `ash_verify_proof_scoped`
  - `ash_build_proof_v21_unified` → `ash_build_proof_unified`
  - `ash_verify_proof_v21_unified` → `ash_verify_proof_unified`

- **BREAKING**: `ash_hash_scope()` now returns `Result<String, AshError>`
  - Validates field names don't contain delimiter (BUG-028)
  - Validates field names are not empty (BUG-039)

- **BREAKING**: `ash_hash_proof()` now returns `Result<String, AshError>`
  - Rejects empty proof strings (BUG-029)

- **BREAKING**: `ash_derive_client_secret()` now rejects empty context_id (BUG-041)

- **BREAKING**: `ash_build_proof()` now validates body_hash format (BUG-040)
  - Must be exactly 64 hex characters (SHA-256)
  - Must contain only hexadecimal characters

- **BREAKING**: `ash_validate_timestamp_format()` now rejects leading zeros (BUG-038)
  - "0123456789" rejected, "123456789" accepted, "0" accepted

- **BREAKING**: `ash_normalize_binding()` now rejects non-ASCII method names (BUG-042)

- `ASH_VERSION_PREFIX` now equals `"ASHv2.1"` (was `"ASHv1"`)
- Removed `ASH_VERSION_PREFIX_V21` constant (redundant)
- Comparison size extended from 1024 to 2048 bytes (BUG-037)

### Fixed

- **BUG-027**: Encoded query delimiter `%3F` now detected after decoding
  - Path containing `%3F` is rejected (decodes to `?`)
  - Prevents silent data loss and bypass attacks

- **BUG-028**: Scope hash collision with unit separator
  - Field names containing `\x1F` (unit separator) are now rejected
  - Prevents hash collisions like `["a\x1Fb","c"]` == `["a","b\x1Fc"]`

- **BUG-029**: Empty proof in chain hashing
  - `ash_hash_proof("")` now returns an error
  - Prevents ambiguous chain starts

- **BUG-030**: Timing leak in comparison loop
  - Fixed iteration count now used (8 iterations, extended from 4)
  - Prevents leaking length information via timing

- **BUG-034**: Documented BTreeMap ordering in `register_many`
  - Added warning that patterns are registered in alphabetical order

- **BUG-035**: Path `.` and `..` segments now normalized
  - `/api/./users` → `/api/users`
  - `/api/users/../admin` → `/api/admin`
  - `/../api` → `/api` (can't go above root)
  - Prevents cross-implementation mismatches

- **BUG-036**: Large array allocation DoS prevented
  - Total array allocation limited to 10,000 elements across all scope paths
  - Prevents memory exhaustion via crafted scope arrays

- **BUG-037**: Comparison truncation extended to 2048 bytes
  - Provides safety margin for longer cryptographic values

- **BUG-038**: Timestamps with leading zeros now rejected
  - Ensures cross-implementation consistency

- **BUG-039**: Empty scope field names now rejected
  - Prevents confusion and potential hash collisions

- **BUG-040**: Body hash format now validated
  - Must be valid 64-character SHA-256 hex string

- **BUG-041**: Empty context_id now rejected
  - Prevents ambiguous contexts

- **BUG-042**: Non-ASCII method names now rejected
  - Uses ASCII-only uppercase for cross-platform consistency

- **BUG-043**: Whitespace-only query strings now treated as empty
  - Query string is trimmed before canonicalization

- **BUG-044**: Added size-checked Value canonicalization
  - `ash_canonicalize_json_value_with_size_check()` for untrusted Values

- **BUG-045**: Timestamp future check uses saturating_add
  - Prevents theoretical integer overflow

### Security

- Timing-safe comparison now uses fixed iteration count (8 iterations, 2048 bytes)
- Scope field delimiter validation prevents hash collisions
- Empty proof rejection prevents chain manipulation
- Path normalization prevents traversal-based signature bypass
- Array allocation limits prevent memory exhaustion DoS
- Body hash validation prevents malformed input acceptance
- Context ID validation prevents ambiguous contexts

## [2.3.2] - 2024-01-15

### Added

- Binding normalization with `METHOD|PATH|QUERY` format
- `ash_normalize_binding()` function
- `ash_normalize_binding_from_url()` convenience function
- Path percent-encoding normalization (BUG-025)

### Fixed

- **BUG-025**: Paths with encoded slashes (`%2F`) now normalized correctly
- Duplicate slashes collapsed after decoding
- Trailing slashes removed (except root)

## [2.3.1] - 2024-01-10

### Added

- Query string canonicalization rules
- Fragment stripping from query strings
- Plus sign (`+`) treated as literal (not space)

### Fixed

- Query parameters now sorted by key then value
- Uppercase hex encoding in query strings

## [2.3.0] - 2024-01-05

### Added

- Request chaining support
- `ash_hash_proof()` for chain hash computation
- `ash_build_proof_unified()` with scoping + chaining
- `ash_verify_proof_unified()` for unified verification
- `UnifiedProofResult` struct

## [2.2.0] - 2024-01-01

### Added

- Field-level scoping support
- `ash_extract_scoped_fields()` function
- `ash_extract_scoped_fields_strict()` for required fields
- `ash_hash_scope()` function
- `ash_hash_scoped_body()` function
- `ash_build_proof_scoped()` function
- `ash_verify_proof_scoped()` function
- Scope policy registry for server-side configuration

### Fixed

- **BUG-020**: Escape sequence handling in patterns
- **BUG-021**: Depth tracking for nested paths
- **BUG-022**: Multi-dimensional array support
- **BUG-023**: Auto-sorting scope fields
- **BUG-024**: Empty payload handling

## [2.1.0] - 2023-12-15

### Added

- HMAC-SHA256 based proof generation
- `ash_derive_client_secret()` function
- `ash_build_proof()` (was `ash_build_proof_v21`)
- `ash_verify_proof()` (was `ash_verify_proof_v21`)
- Timestamp validation with SEC-005

### Deprecated

- v1 proof functions (now removed in 2.3.3)

### Security

- **SEC-008**: Constant-time comparison
- **SEC-012**: Input validation
- **SEC-014**: Minimum nonce entropy
- **SEC-015**: Context ID delimiter validation

## [2.0.0] - 2023-12-01

### Added

- JSON canonicalization (RFC 8785)
- URL-encoded canonicalization
- Query string canonicalization
- Unicode NFC normalization

### Security

- **VULN-001**: Max recursion depth (64)
- **VULN-002**: Max payload size (10 MB)

## [1.0.0] - 2023-11-01

### Added

- Initial release
- SHA-256 based proof (v1, now deprecated and removed)
- Basic canonicalization

---

## Migration Guide

### From 2.3.2 to 2.3.3

1. **Update function names**:
   ```rust
   // Before
   ash_build_proof_v21(...)
   ash_verify_proof_v21(...)

   // After
   ash_build_proof(...)
   ash_verify_proof(...)
   ```

2. **Handle new Result types**:
   ```rust
   // Before
   let scope_hash = ash_hash_scope(&scope);

   // After
   let scope_hash = ash_hash_scope(&scope)?;
   // or
   let scope_hash = ash_hash_scope(&scope).unwrap();
   ```

3. **Remove v1 function usage**:
   - If using `ash_build_proof_v1`, migrate to `ash_build_proof`
   - Requires deriving client secret first

### From 2.2.x to 2.3.x

1. **Update imports**:
   ```rust
   // Add unified proof functions
   use ash_core::{
       ash_build_proof_unified,
       ash_verify_proof_unified,
       UnifiedProofResult,
   };
   ```

2. **Use normalized bindings**:
   ```rust
   // Before
   let binding = format!("{} {}", method, path);

   // After
   let binding = ash_normalize_binding(method, path, query)?;
   ```
