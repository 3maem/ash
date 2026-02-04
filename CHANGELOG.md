# Changelog

All notable changes to the ASH SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.4] - 2026-02-04

### Middleware Security Hardening

All middlewares have been hardened with production-safe error messages and input validation:

#### Production-Safe Error Messages
- **All SDKs**: Middleware now checks environment (NODE_ENV, APP_ENV, GIN_MODE, etc.)
- **Production**: Returns generic error messages to prevent information disclosure
- **Development**: Returns detailed error messages for debugging
- **Example**: Binding mismatch shows "Request binding does not match context" in production

#### Input Validation Before Store Lookup
- **All SDKs**: Added validation before database/store queries to prevent enumeration attacks
- **Context ID**: Validates length (max 256) and format (alphanumeric + `_-.`)
- **Proof**: Validates format (exactly 64 hex characters)
- **Returns**: HTTP 400 for malformed requests

#### Fixed Middleware Implementations
| SDK | Middleware | Status |
|-----|------------|--------|
| **Node.js** | Express | ✅ Complete (was already complete) |
| **Node.js** | Fastify | ✅ Added IP/User binding, production-safe errors |
| **Python** | Flask | ✅ Added validation, production-safe errors, timestamp validation |
| **Python** | FastAPI | ✅ Completed with all v2.3 features |
| **Python** | Django | ✅ Completed with all v2.3 features |
| **Go** | Gin | ✅ Added production-safe errors, TTL for MemoryStore |
| **PHP** | Laravel | ✅ Added validation, production-safe errors, timestamp validation |
| **PHP** | WordPress | ✅ Added scope policies, validation, production-safe errors |
| **PHP** | CodeIgniter | ✅ Completed with all v2.3 features |
| **PHP** | Drupal | ✅ Completed with all v2.3 features |
| **.NET** | ASP.NET | ✅ Added validation, production-safe errors, scope hash validation |

#### Bug Fixes
- **Go**: Fixed weak IP validation in `config.go` (now uses `net.ParseIP()`)
- **Go**: Added TTL/expiration to `AshMemoryStore` with background cleanup
- **Python**: Fixed scope sorting to use byte-wise sorting
- **PHP**: Fixed scope sorting to use byte-wise sorting
- **.NET**: Fixed scope sorting with `ByteWiseComparer`
- **All**: Fixed test files to use valid 32+ character hex nonces

### Production-Ready Configuration & Security (v2.3.3)

All SDKs now support environment-based configuration and production-ready security features:

#### Environment-Based Configuration

- **NEW**: Configuration via environment variables across all SDKs
  - `ASH_TRUST_PROXY` - Enable X-Forwarded-For header processing (default: false)
  - `ASH_TRUSTED_PROXIES` - Comma-separated list of trusted proxy IPs
  - `ASH_RATE_LIMIT_WINDOW` - Rate limiting window in seconds (default: 60)
  - `ASH_RATE_LIMIT_MAX` - Maximum requests per window (default: 10)
  - `ASH_TIMESTAMP_TOLERANCE` - Clock skew tolerance in seconds (default: 30)

- **SDK Implementations**:
  - **PHP**: `Ash::loadConfig()` and `Ash::getClientIp()` in `Ash.php`
  - **Node.js**: `DEFAULT_*` constants in `index.ts`
  - **Python**: `AshConfig` class and `ash_get_client_ip()` function
  - **Go**: `AshConfig` struct, `AshLoadConfig()`, `AshGetClientIP()` in `config.go`
  - **.NET**: `AshConfig` class with `GetClientIP()` extension method

#### IP and User Binding Enforcement

- **NEW**: Middleware options for binding verification (all SDKs)
  - `enforceIp` / `EnforceIp` / `enforce_ip` - Verify client IP matches context metadata
  - `enforceUser` / `EnforceUser` / `enforce_user` - Verify user ID matches context metadata
  - Returns HTTP 461 (`ASH_BINDING_MISMATCH`) on mismatch

- **SDK Implementations**:
  - **PHP Laravel**: `middleware('ash:enforce_ip,enforce_user')`
  - **PHP CodeIgniter**: `['before' => ['api/*' => ['enforce_ip', 'enforce_user']]]`
  - **PHP WordPress**: `['enforce_ip' => true, 'enforce_user' => true]`
  - **Node.js Express**: `ashExpressMiddleware({ enforceIp: true, enforceUser: true })`
  - **Python Flask**: `@middleware.flask(store, enforce_ip=True, enforce_user=True)`
  - **Go Gin**: `AshGinMiddleware(&AshMiddlewareOptions{EnforceIP: true, EnforceUser: true})`
  - **.NET Core**: `UseAsh(ash, new AshMiddlewareOptions { EnforceIp = true, EnforceUser = true })`

#### Server-Side Scope Policy Validation

- **NEW**: `validateScopePolicy()` / `ValidateScopePolicy()` across all SDKs
  - Validates extracted scoped payload matches policy requirements
  - Enforces server-side field restrictions beyond client-provided scope
  - Used after `extractScopedFields()` to ensure compliance

### Breaking Changes (HTTP Status Codes)

- **CHANGED**: Unique HTTP status codes for ASH-specific errors (450-499 range)
  - This enables precise error identification, better monitoring, and targeted retry logic
  - **Context errors (450-459)**:
    - `ASH_CTX_NOT_FOUND`: 404 → 450
    - `ASH_CTX_EXPIRED`: 401 → 451
    - `ASH_CTX_ALREADY_USED`: 409 → 452
  - **Seal/Proof errors (460-469)**:
    - `ASH_PROOF_INVALID`: 401 → 460
  - **Binding/Verification errors (461, 473-479)**:
    - `ASH_BINDING_MISMATCH`: 403 → **461**
    - `ASH_SCOPE_MISMATCH`: 403 → 473
    - `ASH_CHAIN_BROKEN`: 403 → 474
  - **Format/Protocol errors (480-489)**:
    - `ASH_TIMESTAMP_INVALID`: 400 → 482
    - `ASH_PROOF_MISSING`: 401 → 483
  - **Preserved standard HTTP codes**:
    - `ASH_CANONICALIZATION_ERROR`: 422 (unchanged)
    - `ASH_MODE_VIOLATION`: 400 (unchanged)
    - `ASH_UNSUPPORTED_CONTENT_TYPE`: 415 (unchanged)
    - `ASH_VALIDATION_ERROR`: 400 (unchanged)
    - `ASH_INTERNAL_ERROR`: 500 (unchanged)
  - **Migration**: Update client error handling to check for new status codes
  - **Affected SDKs**: All (Rust, Go, Node.js, Python, PHP, .NET)

### Security (Cross-SDK Validation Alignment)

- **FIXED** (Issue H1): Input validation now consistent across all SDKs
  - All SDKs now validate inputs in `ash_derive_client_secret` / `AshDeriveClientSecret`:
    - SEC-014: Nonce minimum length (32 hex chars = 128 bits entropy)
    - SEC-NONCE-001: Nonce maximum length (128 chars)
    - BUG-004: Nonce must be valid hexadecimal
    - BUG-041: Context ID cannot be empty
    - SEC-CTX-001: Context ID max length (256 chars)
    - SEC-CTX-001: Context ID charset (alphanumeric, `_`, `-`, `.` only)
    - SEC-AUDIT-004: Binding max length (8KB)
  - **Go SDK** (`ash-go/ash.go`):
    - `AshDeriveClientSecret` now returns `(string, error)`
    - `AshVerifyProof`, `AshVerifyProofScoped`, `AshVerifyProofUnified` now return `(bool, error)`
    - Added `*Unsafe` variants for backward compatibility
    - Updated middleware to handle error returns
  - **Python SDK** (`ash-python/src/ash/core/proof.py`):
    - `ash_derive_client_secret` now raises `ValidationError` on invalid input
  - **PHP SDK** (`ash-php/src/Core/Proof.php`):
    - `ashDeriveClientSecret` now throws `ValidationException` on invalid input
  - **.NET SDK** (`ash-dotnet/src/Ash.Core/Proof.cs`):
    - `AshDeriveClientSecret` now throws `ValidationException` on invalid input

### Added

- **PHP SDK Configuration** (`ash-php/src/Ash.php`):
  - Environment-based configuration via `loadConfig()` method
  - Support for `ASH_TRUST_PROXY` to enable X-Forwarded-For handling
  - Support for `ASH_TRUSTED_PROXIES` for specifying trusted proxy IPs
  - Support for `ASH_RATE_LIMIT_WINDOW` and `ASH_RATE_LIMIT_MAX` for rate limiting
  - Support for `ASH_TIMESTAMP_TOLERANCE` for clock skew tolerance
  - New `getClientIp()` static method with proxy support

- **PHP Middleware Enhancements**:
  - `AshLaravelMiddleware`: Added IP binding (`enforce_ip`) and user binding (`enforce_user`) guards
  - `AshFilter` (CodeIgniter): Added IP binding, user binding, and v2.3 headers support
  - `WordPressHandler`: Added IP binding, user binding, and per-route configuration options

- **PHP Examples Updated**:
  - Laravel config (`examples/laravel/config/ash.php`): Added new configuration options
  - CodeIgniter filter: Full v2.3 feature support with binding enforcement
  - WordPress plugin: Enhanced with binding enforcement capabilities

- **NEW**: `ValidationError` / `ValidationException` classes added to all SDKs
  - Go: Uses existing `AshError` type with `ErrProofInvalid` code
  - Python: New `ValidationError` class in `ash.core.errors`
  - PHP: New `ValidationException` class, new `ValidationError` enum case
  - .NET: New `ValidationException` class, new `ValidationError` constant

- **NEW**: Security constants added to all SDKs (matching Rust ash-core)
  - `MIN_NONCE_HEX_CHARS` = 32
  - `MAX_NONCE_LENGTH` = 128
  - `MAX_CONTEXT_ID_LENGTH` = 256
  - `MAX_BINDING_LENGTH` = 8192

- **NEW**: Go Gin middleware for ASH verification
  - `AshGinMiddleware` - Ready-to-use middleware for Gin web framework
  - Supports v2.1 standard verification and v2.3 unified verification (scoping + chaining)
  - `AshContextStore` interface for custom storage backends (Redis, database, etc.)
  - `AshMemoryStore` - In-memory context store implementation
  - `AshValidateTimestamp` - Timestamp freshness validation
  - Configurable options: `ExpectedBinding`, `EnableUnified`, `MaxTimestampAgeSeconds`, `Skip`, `OnError`
  - 71 comprehensive middleware tests
  - **Affected files**: `ash-go/middleware.go`, `ash-go/middleware_test.go`

- **NEW**: Cross-SDK test vectors for Go middleware
  - Header constants compatibility tests (`X-ASH-Context-ID`, `X-ASH-Proof`, etc.)
  - Error codes compatibility tests (`ASH_CTX_NOT_FOUND`, `ASH_PROOF_INVALID`, etc.)
  - Scope normalization tests (BUG-002 unit separator compliance)
  - Proof hash chaining tests
  - **Affected file**: `ash-go/cross_sdk_test.go`

### Documentation

- **UPDATED**: Go SDK README with comprehensive middleware documentation
  - Basic usage examples
  - Unified verification (v2.3) examples
  - All middleware options explained
  - Custom error handler examples
  - Custom context store interface
  - Complete error codes table
  - **Affected file**: `ash-go/README.md`

- **UPDATED**: Project reports with Go middleware and current test counts
  - `CROSS_SDK_VERIFICATION_REPORT.md` - Added Go Gin middleware verification section, updated test counts (Go: 1238, Node.js: 1136, Python: 1020, PHP: 1349, .NET: 1422), added middleware row to compatibility matrix
  - `ASH_SDK_BUG_FIXES_REPORT.md` - Updated test counts, added Go middleware to middleware analysis
  - `BENCHMARK_REPORT.md` - Added Go Gin middleware performance section
  - `SECURITY_AUDIT_REPORT.md` - Added Go middleware security notes
  - `TODO_FIXME_REPORT.md` - Updated to include middleware.go

### Naming Convention Compliance

- **UPDATED**: All SDKs now follow NAMING_CONVENTION.md
  - Go: `Ash` prefix for exported functions (e.g., `AshGinMiddleware`, `AshContextStore`)
  - Backward-compatible aliases with deprecation notices
  - Middleware types: `AshMiddlewareContext`, `AshMemoryStore`, `AshVerifyError`

## [2.3.4] - 2026-01-31

### Critical Fixes (WASM)

- **FIXED** (BUG-LOGIC-130): WASM bindings called wrong ash_core function names
  - WASM functions like `ashCanonicalizeUrlencoded` called `ash_core::canonicalize_urlencoded`
  - But ash_core exports `ash_core::ash_canonicalize_urlencoded` (with `ash_` prefix)
  - This prevented WASM from compiling/working correctly
  - Fixed all WASM bindings to use correct function names
  - URL-encoded canonicalization now correctly treats `+` as literal plus (%2B), NOT space
  - **Affected files**: `ash-wasm/src/lib.rs`

- **FIXED** (BUG-LOGIC-129): WASM initialization never loaded binary
  - `wasm.ashInit()` was called but WASM module was never loaded
  - wasm-bindgen requires `initSync({ module: wasmBinary })` before use
  - Added proper binary loading via `fs.readFileSync()` and `initSync()`
  - **Affected file**: `ash-node/src/index.ts`

- **REMOVED**: Legacy `ashBuildProof` WASM function
  - Used old API that no longer exists in ash_core
  - Replaced by `ashBuildProofV21` and `ashBuildProofUnified`
  - **Affected file**: `ash-wasm/src/lib.rs`

### Security (Penetration Testing Findings)

- **FIXED** (PENTEST-001): Query string sorting used UTF-16 instead of bytes
  - `canonicalQueryNative()` was using JavaScript's `<` and `>` operators
  - These compare UTF-16 code units, not bytes, causing cross-SDK inconsistency
  - Now uses `Buffer.compare()` for true byte-wise sorting
  - Ensures query parameters with non-ASCII characters sort correctly
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (PENTEST-002): Content-Type handling inconsistency in middleware
  - Body canonicalization used exact MIME type matching (`mimeType === 'application/json'`)
  - But payload parsing for scoping used substring matching (`contentType.includes('application/json')`)
  - This caused inconsistent behavior with non-standard JSON content types
  - Now both use exact MIME type matching for consistency
  - **Affected files**: `ash-node/src/middleware/express.ts`, `ash-node/src/middleware/fastify.ts`

### Bug Fixes

- **FIXED** (BUG-LOGIC-052): SecureBuffer hex constructor didn't validate hex string
  - `Buffer.from(str, 'hex')` silently skips invalid characters, creating partial buffers
  - Now validates that string contains only hex characters (0-9, a-f, A-F)
  - Now validates that string has even length (each byte = 2 hex chars)
  - Throws `TypeError` with clear message on invalid input
  - **Affected file**: `ash-node/src/utils/secureMemory.ts`

- **FIXED** (BUG-LOGIC-053): ashValidateTimestamp allowed negative clockSkewSeconds/maxAgeSeconds
  - Negative values would cause incorrect timestamp validation behavior
  - Now throws error if either parameter is negative
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-054): Redis Store get() had side effect on read
  - Was deleting corrupted data on read, violating principle of idempotent reads
  - Now logs warning instead and lets TTL handle cleanup
  - **Affected file**: `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-055): Memory Store accepted negative autoCleanupMs
  - Negative values behaved like 0 but semantics were unclear
  - Now throws error for negative values with clear message
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-056): Regex cache used FIFO instead of LRU eviction
  - Frequently accessed patterns could be evicted prematurely
  - Now uses true LRU by re-inserting on access (Map maintains insertion order)
  - **Affected file**: `ash-node/src/config/scopePolicies.ts`

- **FIXED** (BUG-LOGIC-057): Unexpected errors mapped to ASH_CANONICALIZATION_ERROR
  - Database errors, Redis timeouts etc. got misleading error code
  - Now uses ASH_INTERNAL_ERROR for non-ASH exceptions
  - **Affected file**: `ash-node/src/middleware/express.ts`

- **FIXED** (BUG-LOGIC-058): Express vs Fastify Content-Type array handling differed
  - Fastify handled array Content-Type headers, Express didn't
  - Now both middlewares handle arrays consistently
  - **Affected file**: `ash-node/src/middleware/express.ts`

- **FIXED** (BUG-LOGIC-059): Memory Store get() returned mutable reference (SECURITY)
  - Callers could mutate the returned context object to bypass anti-replay protection
  - Example: `ctx.used = false; await store.consume(ctx.id);` would succeed again
  - Now returns a shallow copy of the context with copied metadata
  - Redis and SQL stores were not affected (they create new objects from JSON/rows)
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-060): Context creation didn't validate ttlMs
  - Zero, negative, or NaN ttlMs values created useless/expired contexts
  - Now validates ttlMs is a positive finite number in all stores
  - **Affected files**: `ash-node/src/stores/memory.ts`, `ash-node/src/stores/redis.ts`, `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-066): Fastify middleware didn't catch unexpected errors (SECURITY)
  - Unhandled exceptions could leak stack traces in non-production environments
  - Now wrapped in try-catch returning ASH_INTERNAL_ERROR
  - **Affected file**: `ash-node/src/middleware/fastify.ts`

- **FIXED** (BUG-LOGIC-068): ashValidateTimestamp allowed Infinity/NaN values
  - Passing `Infinity` as maxAgeSeconds would bypass timestamp freshness validation
  - Now validates both maxAgeSeconds and clockSkewSeconds are finite numbers
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-072): SQL Store didn't handle BigInt values from drivers
  - Some SQL drivers return BigInt for affected row counts
  - Now explicitly checks for BigInt type before Number conversion
  - **Affected file**: `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-079): Context creation didn't validate metadata
  - No size or structure validation on metadata during context creation
  - Now validates metadata is a plain object (not array)
  - Rejects dangerous keys (__proto__, constructor, prototype)
  - Enforces 64KB size limit on serialized metadata
  - **Affected files**: `ash-node/src/stores/memory.ts`, `ash-node/src/stores/redis.ts`, `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-081): Memory Store shallow copy allowed nested metadata mutation
  - Spread operator only did shallow copy, nested objects were still mutable
  - Now uses JSON.parse(JSON.stringify()) for deep copy of metadata
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-083): ashExtractScopedFieldsStrict error revealed missing field names
  - Error message disclosed which specific field was missing (information disclosure)
  - Now uses generic error: "One or more required scoped fields are missing"
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-099): Memory Store didn't validate mode like Redis/SQL stores
  - Redis and SQL stores validate and correct invalid mode values on retrieval
  - Memory store now has the same validation for consistency
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-102): Redis Lua script type confusion in expiresAt comparison
  - If expiresAt was corrupted to a string, Lua comparison could behave unexpectedly
  - Now validates expiresAt is a number before comparison, deletes corrupted contexts
  - **Affected file**: `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-103): Array allocation check happened after adding to total
  - Could theoretically exceed MAX_TOTAL_ARRAY_ALLOCATION by one allocation
  - Now checks if allocation would exceed limit BEFORE adding
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-104): Unbounded clockSkewSeconds/maxAgeSeconds values
  - Very large values could bypass timestamp freshness validation
  - Now enforces maximum 24 hours for clockSkewSeconds, 1 year for maxAgeSeconds
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-105): Missing payload validation in scope extraction
  - ashExtractScopedFields and ashExtractScopedFieldsStrict didn't validate payload type
  - Now validates payload is a plain object (not null, array, or primitive)
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-106): Configuration information disclosure in Express middleware
  - Error message revealed scope policy existence to clients
  - Now uses generic message in production environment
  - **Affected file**: `ash-node/src/middleware/express.ts`

- **FIXED** (BUG-LOGIC-107): Silent NaN return from SQL cleanup()
  - When driver returned unexpected type, Number() could return NaN
  - Now validates result and returns 0 for invalid values
  - **Affected file**: `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-109): Integer overflow in Redis TTL calculation
  - Very large ttlMs could exceed Redis TTL limits
  - Now caps TTL at ~10 years maximum
  - **Affected file**: `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-110): SQL Boolean type coercion vulnerability
  - Boolean("false") incorrectly returns true
  - Now handles string, number, and boolean types correctly
  - **Affected file**: `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-111): Missing binding format validation
  - Binding format (METHOD|PATH|QUERY) was not validated
  - Now warns about malformed bindings in development
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-112): Missing nonce validation in ashContextToClient
  - Function didn't verify context had required nonce for v2.1
  - Now throws error if nonce is missing
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-113): Redis Lua script JSON decode could crash on corruption
  - cjson.decode() errors weren't caught, causing Lua runtime errors
  - Now uses pcall() to safely handle corrupted JSON data
  - **Affected file**: `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-114): Redis TTL calculation could have precision loss
  - Very large ttlMs values could cause floating-point precision issues
  - Now validates TTL is a safe integer before use
  - **Affected file**: `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-116): SecureBuffer constructor missing number validation
  - Negative, non-integer, or very large numbers caused unclear errors
  - Now validates number is non-negative integer within safe limits
  - **Affected file**: `ash-node/src/utils/secureMemory.ts`

- **FIXED** (BUG-LOGIC-118): Memory Store cleanup() race condition with consume()
  - Cleanup could delete a context while it was being consumed, causing incorrect replay detection
  - Now skips contexts that have active consume locks during cleanup
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-119): Memory Store TTL precision loss for large values
  - Very large ttlMs values could cause Date.now() + ttlMs to exceed safe integer range
  - Now validates TTL won't cause overflow and caps at ~10 years
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-120): Fastify middleware scope policy error inconsistent with Express
  - Express used environment-aware error messages, Fastify always included debug info
  - Now both middlewares use generic message in production for scope policy errors
  - **Affected file**: `ash-node/src/middleware/fastify.ts`

- **FIXED** (BUG-LOGIC-121): Memory Store metadata copy didn't use null prototype
  - JSON.parse creates objects with Object.prototype, allowing prototype pollution
  - Now uses Object.create(null) and filters dangerous keys for defense in depth
  - **Affected file**: `ash-node/src/stores/memory.ts`

- **FIXED** (BUG-LOGIC-122): SecureBuffer hex string missing length validation
  - Very long hex strings could allocate huge buffers without validation
  - Now validates hex string length is within safe buffer size limits
  - **Affected file**: `ash-node/src/utils/secureMemory.ts`

- **FIXED** (BUG-LOGIC-123): SQL and Redis stores missing TTL overflow validation
  - Memory store had MAX_TTL_MS validation, but SQL and Redis stores did not
  - Very large ttlMs could cause Date.now() + ttlMs to lose precision
  - Now all three stores have consistent TTL validation (~10 year max)
  - **Affected files**: `ash-node/src/stores/sql.ts`, `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-124): SQL Store expiresAt conversion could return NaN
  - Number(row.expires_at) could return NaN if database value was corrupted
  - NaN would propagate causing unexpected behavior in expiration checks
  - Now validates result is finite, defaults to 0 (expired) if corrupted
  - **Affected file**: `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-125): Redis consume() strict equality failed with some clients
  - Lua script `result === 1` check failed when Redis clients returned BigInt or string
  - ioredis returns numbers, but other clients may return `1n` (BigInt) or `"1"` (string)
  - Now handles all return types with explicit type checks
  - **Affected file**: `ash-node/src/stores/redis.ts`

- **FIXED** (BUG-LOGIC-126): Express middleware missing try-catch for canonicalization
  - Fastify had try-catch around canonicalization, but Express did not
  - Malformed JSON/form data could throw uncaught exceptions
  - Now wraps canonicalization in try-catch returning ASH_CANONICALIZATION_ERROR
  - **Affected file**: `ash-node/src/middleware/express.ts`

- **FIXED** (BUG-LOGIC-127): `__proto__` prototype pollution not detected (SECURITY)
  - `Object.keys()` doesn't enumerate `__proto__` so dangerous key check was bypassed
  - Attacker could pass `{"__proto__": {...}}` via JSON to pollute Object.prototype
  - Now uses `Object.prototype.hasOwnProperty.call()` to detect all dangerous keys
  - **Affected files**: `ash-node/src/stores/memory.ts`, `ash-node/src/stores/redis.ts`, `ash-node/src/stores/sql.ts`

- **FIXED** (BUG-LOGIC-128): WASM functions crash without fallback
  - WASM functions like `ashCanonicalizeJson`, `ashCanonicalizeUrlencoded`, etc. had no error handling
  - When WASM failed or was unavailable, cryptic errors were thrown
  - Now all WASM functions have try-catch with automatic fallback to native implementations
  - Added `canonicalizeUrlencodedNative()` for URL-encoded form body fallback
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-LOGIC-129): WASM binary never loaded before use
  - `ashInit()` called `wasm.ashInit()` but the WASM binary wasn't loaded first
  - The wasm-bindgen generated code requires `initSync()` with the binary before functions work
  - Now properly loads WASM binary via `fs.readFileSync()` and `initSync()`
  - **Affected file**: `ash-node/src/index.ts`

- **WORKAROUND** (BUG-LOGIC-130): WASM converts + to space in URL-encoded canonicalization
  - WASM implementation converts `+` to `%20` (space) instead of `%2B` (literal plus)
  - Per ASH spec, URL-encoded form bodies should treat `+` as literal plus
  - SDK now uses native implementation for `ashCanonicalizeUrlencoded()` until WASM is fixed
  - **Bug location**: `ash-wasm` (Rust) - requires fix in ash-core
  - **Affected file**: `ash-node/src/index.ts`

- **FIXED** (BUG-051): Inconsistent scope sorting in middleware (previously fixed 2026-01-31)
- **DOCUMENTED** (INFO-004): Numeric string keys limitation in `ashExtractScopedFields()`
- **DOCUMENTED** (INFO-005): `SecureString.length` returns byte length, not character count
- **DOCUMENTED** (INFO-006): Timestamp "0" passes format validation (intentional per spec)
- **DOCUMENTED** (INFO-007): Scope path format requirements (must have base key)
- **DOCUMENTED** (INFO-008): SQL Store consume() doesn't distinguish failure reasons
- **DOCUMENTED** (INFO-009): canonicalQueryNative trims leading/trailing whitespace

## [2.3.3] - 2026-01-29

### Critical Cross-SDK Fixes

- **FIXED** (CRIT-001): Scope delimiter mismatch across SDKs
  - Rust ash-core was using `\x1F` (unit separator) but all other SDKs used `,` (comma)
  - This caused complete cross-SDK interoperability failure for scoped proofs
  - All SDKs now use `\x1F` as the scope field delimiter
  - Added `SCOPE_FIELD_DELIMITER` constant to all SDKs
  - **Affected SDKs**: Node.js, Python, Go, .NET, PHP

- **FIXED** (CRIT-002): Missing scope normalization in non-Rust SDKs
  - Rust sorted and deduplicated scope arrays, but other SDKs did not
  - This caused scope order-dependent hash differences across SDKs
  - Added `normalizeScopeFields()` / `NormalizeScopeFields()` to all SDKs
  - Added `joinScopeFields()` / `JoinScopeFields()` for proper joining
  - **Affected SDKs**: Node.js, Python, Go, .NET, PHP

- **FIXED** (SEC-013 propagation): Added consistency validation to all non-Rust SDKs
  - `scope_hash` must be empty when `scope` is empty
  - `chain_hash` must be empty when `previous_proof` is absent
  - Previously only Rust validated this, now all SDKs do
  - **Affected SDKs**: Node.js, Python, Go, .NET, PHP

- **FIXED** (MED-001): Scope policy registry cache inconsistency on update (Rust)
  - When updating an existing policy, the `exact_matches` HashMap could become stale
  - Now properly removes old entry and re-adds if pattern type changes

### Security

- **FIXED**: SQL injection vulnerability in Node.js SQL store table name handling
  - Added `validateSqlIdentifier()` function to validate table names
  - Only allows alphanumeric characters and underscores
  - Limits identifier length to 64 characters

- **FIXED** (SEC-001): ReDoS vulnerability in scope policy pattern matching
  - Added pattern length limit (512 characters)
  - Added wildcard count limit (8 per pattern)
  - Changed `**` wildcard to use bounded character class instead of `.*`
  - Added regex size limit (10KB) via `RegexBuilder`
  - Cached compiled regex patterns to prevent repeated compilation

- **FIXED** (SEC-002): Panic on RNG failure could crash server
  - `generate_nonce()` now returns `Result<String, AshError>` instead of panicking
  - `generate_context_id()` now returns `Result<String, AshError>`
  - Added `generate_nonce_or_panic()` for backwards compatibility

- **FIXED** (SEC-003): RwLock poisoning could cause cascading failures
  - All global registry access now recovers from poison using `into_inner()`

- **FIXED** (SEC-005): Added timestamp validation
  - New `validate_timestamp()` function prevents replay attacks with stale proofs
  - Configurable max age and clock skew tolerance

- **FIXED** (SEC-006): Silent field omission in scoped extraction
  - New `extract_scoped_fields_strict()` with strict mode option
  - Returns error if required scoped fields are missing

- **FIXED** (SEC-007): Non-deterministic pattern matching order
  - Changed `ScopePolicyRegistry` to use `BTreeMap` for deterministic ordering

- **FIXED** (SEC-008): Timing side channel on length comparison
  - `timing_safe_equal()` now uses constant-time length comparison
  - Added `timing_safe_equal_fixed_length()` for known-length comparisons

- **FIXED** (SEC-009): Regex compilation in hot path
  - Patterns are now compiled once on registration and cached

- **ADDED** (SEC-010): Higher entropy context IDs
  - New `generate_context_id_256()` for 256-bit context IDs

- **FIXED** (SEC-011): Memory exhaustion via large array index in scope paths
  - Added `MAX_ARRAY_INDEX` limit (10,000) to prevent DoS
  - Scope paths like `"items[999999999]"` are now silently ignored
  - Prevents allocating billions of null entries in arrays

- **FIXED** (SEC-012): Empty input validation in `build_proof_v21`
  - Now validates that `client_secret`, `timestamp`, `binding`, and `body_hash` are non-empty
  - Returns `Result<String, AshError>` instead of `String`
  - Prevents generation of weak proofs from empty inputs

- **FIXED** (SEC-013): Inconsistent scope/chain hash validation in `verify_proof_v21_unified`
  - Now validates that `scope_hash` is empty when `scope` is empty
  - Now validates that `chain_hash` is empty when `previous_proof` is absent
  - Returns error instead of proceeding with mismatched parameters

- **FIXED** (SEC-014): Weak key material from short nonces in `derive_client_secret`
  - `derive_client_secret()` now returns `Result<String, AshError>`
  - Requires minimum 32 hex characters (128 bits / 16 bytes) for nonce
  - Prevents weak HMAC key derivation from insufficient entropy
  - Added `MIN_NONCE_HEX_CHARS` constant

- **FIXED** (SEC-015): Delimiter collision in context_id validation
  - `derive_client_secret()` now validates that `context_id` does not contain `|`
  - Prevents different context_id + binding combinations from producing same hash
  - Returns error with clear message about delimiter collision risk

- **DEPRECATED** (SEC-016): v1 proof API uses SHA-256 without secret key
  - `build_proof()` and `verify_proof()` are now marked `#[deprecated]`
  - Added security warning in documentation about lack of authentication
  - Recommends migration to `derive_client_secret()` + `build_proof_v21()` + `verify_proof_v21()`
  - v1 API provides integrity but NOT authentication

- **FIXED** (SEC-018): Unreasonably large timestamp validation
  - `validate_timestamp()` now rejects timestamps beyond year 3000
  - Added `MAX_TIMESTAMP` constant (32503680000)
  - Prevents integer overflow and unreasonable future timestamps

- **FIXED** (SEC-019): Stack overflow via deep scope paths
  - Added `MAX_SCOPE_PATH_DEPTH` limit (32 levels)
  - Scope paths with more than 32 dot-separated segments are silently ignored
  - Prevents stack overflow from malicious deeply-nested paths

### Bug Fixes (Deep Code Review)

- **FIXED** (BUG-001): Delimiter collision in HMAC message format
  - The HMAC message `context_id|binding` could have delimiter collision
  - Fixed: `context_id` validated to not contain `|` (SEC-015)
  - Binding may contain `|` (required for v2.3.2+ format `METHOD|PATH|QUERY`)
  - First `|` unambiguously separates context_id from binding

- **FIXED** (BUG-002): Scope hash collision with comma-containing field names
  - Scope fields joined with comma caused `["field,name"]` and `["field", "name"]` to collide
  - Fixed: Using unit separator (`\x1F`) instead of comma as delimiter
  - Added `SCOPE_FIELD_DELIMITER` constant and `hash_scope()` function

- **FIXED** (BUG-004): Nonce validation didn't verify hexadecimal characters
  - `derive_client_secret()` only checked nonce length, not format
  - Fixed: Added `nonce.chars().all(|c| c.is_ascii_hexdigit())` validation
  - Ensures adequate entropy by rejecting non-hex strings

- **FIXED** (BUG-006): Scope policy pattern matching order was alphabetical
  - `ScopePolicyRegistry` used `BTreeMap` which iterates alphabetically
  - Fixed: Using `Vec` for `policies_ordered` to preserve registration order
  - First registered pattern now wins (documentation was correct, code was wrong)

- **FIXED** (BUG-007): `verify_proof_v21` didn't validate timestamp format
  - Timestamp was passed directly without validation
  - Fixed: Added `validate_timestamp_format()` call in all verify functions

- **FIXED** (BUG-008): Timing variation in chunk comparison loop
  - Comparison loop iterated variable times based on shorter length
  - Fixed: Always perform work on `MAX_COMPARISON_LENGTH` (256) bytes
  - Normalizes timing regardless of actual input lengths

- **FIXED** (BUG-009): `normalize_binding` silently discarded embedded query
  - If path contained `?`, embedded query was silently ignored
  - Fixed: Returns error if path contains `?`
  - Use `normalize_binding_from_url` for combined path+query

- **FIXED** (BUG-010): No escape mechanism for literal wildcards in scope patterns
  - Patterns containing `*`, `<`, `:`, `{` were always treated as wildcards
  - Fixed: Supporting escape sequences: `\\*`, `\\<`, `\\:`, `\\{`

- **FIXED** (BUG-011): `hash_scoped_body` didn't have strict mode
  - Only `extract_scoped_fields_strict()` had strict mode
  - Fixed: Added `hash_scoped_body_strict()` function

- **FIXED** (BUG-012): `validate_timestamp` accepted whitespace
  - Rust's `parse::<u64>()` accepts leading/trailing whitespace
  - Fixed: Added explicit digit-only validation before parsing

- **FIXED** (BUG-018): No maximum scope field count limit
  - Large scope arrays could cause DoS via excessive processing
  - Fixed: Added `MAX_SCOPE_FIELDS` constant (100)

- **FIXED** (BUG-046): Missing input validation in `ash_build_proof_scoped`
  - `ash_build_proof_scoped` didn't validate `client_secret`, `timestamp`, or `binding` for empty values
  - Unlike `ash_build_proof` which has this validation
  - Fixed: Added same validation checks as `ash_build_proof`

- **FIXED** (BUG-047): Missing input validation in `ash_build_proof_unified`
  - Same issue as BUG-046 but in `ash_build_proof_unified`
  - Fixed: Added validation for empty `client_secret`, `timestamp`, and `binding`

- **FIXED** (BUG-048): Documentation error in `ash_parse_all_array_indices`
  - Comment incorrectly stated mixed valid/invalid indices like `"items[0][abc]"` would return `indices=[0]`
  - Actual behavior returns `indices=[]` (all indices invalidated due to unparsed trailing content)
  - Fixed: Corrected documentation to match actual safer behavior

- **FIXED** (BUG-049): Missing SEC-013 validation in `ash_verify_proof_scoped`
  - `ash_verify_proof_unified` had SEC-013 consistency validation but `ash_verify_proof_scoped` did not
  - When scope is empty but scope_hash is non-empty, unified returned `Err(ScopeMismatch)` while scoped returned `Ok(false)`
  - Fixed: Added SEC-013 validation to `ash_verify_proof_scoped` for API consistency

- **FIXED** (BUG-050): Integer overflow in `ash_calculate_total_array_allocation`
  - Expression `*idx + 1` could overflow when `idx = usize::MAX`
  - In debug mode this caused a panic; in release mode the overflow would wrap to 0
  - Could theoretically bypass allocation limit check (though secondary MAX_ARRAY_INDEX check would still catch it)
  - Fixed: Using `idx.saturating_add(1)` to prevent overflow

- **FIXED** (BUG-051): Inconsistent scope sorting in middleware scope policy comparison (Node.js)
  - Express and Fastify middleware used JavaScript's default `.sort()` (UTF-16 code units)
  - But `normalizeScopeFields()` used byte-wise `Buffer.compare()` for proof verification
  - For non-ASCII scope field names, this could cause false "scope policy violation" errors
  - Fixed: Middleware now uses `normalizeScopeFields()` for consistent byte-wise sorting
  - **Affected files**: `src/middleware/express.ts`, `src/middleware/fastify.ts`

### Documentation Improvements

- **DOCUMENTED** (INFO-004): Numeric string keys limitation in scoped field extraction
  - Scope paths with all-digit segments (e.g., `"items.0"`) are treated as array indices
  - If payload has object with numeric string keys like `{"items": {"0": "value"}}`,
    extracted result will have array structure `{"items": ["value"]}` instead
  - This is consistent across SDKs - use non-numeric keys if structure preservation is critical
  - **Affected file**: `src/index.ts` (`ashExtractScopedFields`)

- **DOCUMENTED** (INFO-005): `SecureString.length` returns byte length, not character count
  - For multi-byte UTF-8 characters, `.length` differs from JavaScript's `string.length`
  - Example: `"café"` has 4 characters but 5 bytes (é is 2 bytes in UTF-8)
  - **Affected file**: `src/utils/secureMemory.ts`

### Security Guardrails (DoS Prevention)

- **ADDED** (SEC-CTX-001): Context ID length and charset validation
  - Maximum length: 256 characters
  - Allowed characters: ASCII alphanumeric, underscore, hyphen, dot (`A-Za-z0-9_-.`)
  - Prevents DoS via oversized headers and storage exhaustion
  - Prevents issues with proxies, WAFs, and log systems

- **ADDED** (SEC-NONCE-001): Nonce maximum length validation
  - Maximum length: 128 characters (in addition to existing minimum of 32)
  - Prevents DoS via oversized HMAC keys
  - Note: Nonce encoding (hex) is documented; case is preserved (different cases = different secrets)

- **ADDED** (SEC-SCOPE-001): Scope field length validation
  - Maximum field name length: 64 characters per field
  - Maximum total scope length: 4096 bytes (after canonicalization)
  - Prevents DoS via excessive scope processing and memory allocation

### Node.js SDK Updates (v2.3.3)

#### Function Naming Convention (Breaking Change)

Following the Rust SDK naming convention:

**Removed legacy v1 WASM functions** (as done in Rust SDK):
- Removed `ashBuildProof` (old v1 WASM function)
- Removed `ashVerifyProof` (old v1 WASM function)

**Renamed v2.1+ functions** (removed "V21" suffix):
- `ashBuildProofV21` → `ashBuildProof`
- `ashVerifyProofV21` → `ashVerifyProof`
- `ashBuildProofV21Scoped` → `ashBuildProofScoped`
- `ashVerifyProofV21Scoped` → `ashVerifyProofScoped`

**Deprecated aliases** (for backwards compatibility):
- `ashBuildProofV21`, `ashVerifyProofV21`, `ashBuildProofV21Scoped`, `ashVerifyProofV21Scoped` still work but are deprecated.

**Updated `ash.proof` namespace**:
- `ash.proof.build` → HMAC-SHA256 proof builder
- `ash.proof.verify` → HMAC-SHA256 proof verifier
- `ash.proof.buildScoped` → scoped proof builder
- `ash.proof.verifyScoped` → scoped proof verifier
- `ash.proof.buildUnified` → unified proof with scoping + chaining
- `ash.proof.verifyUnified` → unified proof verifier
- `ash.proof.deriveClientSecret` → derive client secret from nonce

**Updated middleware** (Express & Fastify):
- Now uses v2.1+ proof flow (`ashDeriveClientSecret`, `ashHashBody`, `ashVerifyProof`)
- Removed dependency on legacy v1 WASM functions

#### Security Guardrails

- **ADDED**: Security constants matching Rust implementation
  - `MIN_NONCE_BYTES` (16)
  - `MIN_NONCE_HEX_CHARS` (32)
  - `MAX_NONCE_LENGTH` (128)
  - `MAX_CONTEXT_ID_LENGTH` (256)
  - `MAX_BINDING_LENGTH` (8192)
  - `MAX_SCOPE_FIELD_NAME_LENGTH` (64)
  - `MAX_TOTAL_SCOPE_LENGTH` (4096)
  - `MAX_SCOPE_FIELDS` (100)
  - `SHA256_HEX_LENGTH` (64)

- **ADDED** (SEC-NONCE-001): Nonce validation in `ashDeriveClientSecret()`
  - Validates minimum length (32 hex characters)
  - Validates maximum length (128 characters)
  - Validates hex-only characters

- **ADDED** (SEC-CTX-001): Context ID validation in `ashDeriveClientSecret()`
  - Validates not empty
  - Validates maximum length (256 characters)
  - Validates charset (only `A-Za-z0-9_.-` allowed)

- **ADDED** (SEC-AUDIT-004): Binding validation
  - Validates not empty (in proof functions)
  - Validates maximum length (8192 bytes)

- **ADDED** (SEC-SCOPE-001): Scope field validation in `validateScopeFields()` and `joinScopeFields()`
  - Validates field names not empty
  - Validates individual field length (64 max)
  - Validates no delimiter characters in field names
  - Validates total scope length (4096 max)
  - Validates scope array length (100 max)

- **ADDED**: Body hash validation in `ashBuildProofV21()`
  - Validates length (64 hex characters)
  - Validates hex-only characters

- **ADDED**: Timestamp validation in `ashBuildProofV21()` and `ashVerifyProofV21()`
  - Validates not empty
  - Validates digits only
  - Validates no leading zeros

- **ADDED**: 56 new tests for security guardrails

### Security Audit Fixes

- **FIXED** (SEC-AUDIT-001): Potential timing leak in conditional assignment
  - The `ash_timing_safe_equal` function used a branch for conditional assignment
  - Changed to use `Choice::conditional_select` from `subtle` crate for fully constant-time operation
  - Eliminates micro-timing differences from branch prediction

- **ADDED** (SEC-AUDIT-002): `ash_verify_proof_with_freshness()` convenience function
  - Combines proof verification with timestamp freshness validation
  - Prevents replay attacks by ensuring developers don't forget to validate timestamp freshness
  - Takes `max_age_seconds` and `clock_skew_seconds` parameters

- **FIXED** (SEC-AUDIT-003): Error messages could leak user input
  - Scope field delimiter validation no longer echoes the field name in error messages
  - Prevents potential information disclosure in multi-tenant systems

- **FIXED** (SEC-AUDIT-004): No maximum length validation for binding parameter
  - Added `MAX_BINDING_LENGTH` constant (8KB)
  - `ash_derive_client_secret` and `ash_build_proof` now validate binding length
  - Prevents memory exhaustion from extremely long bindings

### Added

- `ash_hash_scope()` - Safely hash scope fields using unit separator
- `ash_hash_scoped_body_strict()` - Hash scoped body with missing field validation
- `MAX_SCOPE_FIELDS` constant (100) - Prevent DoS via large scope arrays
- `MAX_COMPARISON_LENGTH` constant (256) - Normalize timing-safe comparison
- `SCOPE_FIELD_DELIMITER` constant (`\x1F`) - Unit separator for scope hashing

### Documentation

- **IMPROVED**: Added security note to `canonicalize_json_value` about missing size validation
  - Documents that this function doesn't check payload size (already parsed)
  - Recommends using `canonicalize_json` for untrusted input

- **IMPROVED**: Documented field name limitation in `extract_scoped_fields`
  - Field names containing dots (`.`) cannot be addressed in scope paths
  - Dot is used as path separator, not literal character

- **IMPROVED**: Better panic message in `generate_nonce_or_panic`
  - Now indicates both possible failure reasons (byte count and RNG)

### Fixed

#### Critical: Cross-SDK Canonicalization Bugs

Six bugs were discovered during comprehensive line-by-line SDK quality analysis:

**Bug #1: Duplicate Key Sorting in URL-Encoded Canonicalization**

All SDKs were incorrectly sorting URL-encoded/query string parameters only by key, not by key then value for duplicate keys. This caused different SDKs to produce different canonical outputs for identical inputs.

- **Rust** (`ash-core/src/canonicalize.rs`): Fixed sorting to use key-then-value comparison
- **Go** (`ash-go/ash.go`): Fixed `sort.SliceStable` to compare values when keys are equal
- **PHP** (`ash-php/src/Core/Canonicalize.php`): Fixed `usort` to use `strcmp($a[0], $b[0]) ?: strcmp($a[1], $b[1])`
- **.NET** (`ash-dotnet/src/Ash.Core/Canonicalize.cs`): Fixed `.ThenBy()` to sort by value instead of original index
- **Python** (`ash-python/src/ash/core/canonicalize.py`, `src/ash/canonicalize.py`): Fixed sort key to `(x[0], x[1])`

**Bug #2: JSON Canonicalization in Proof Functions**

Scoped and unified proof functions were using native JSON serializers instead of RFC 8785 JCS canonicalization, causing inconsistent proof generation across SDKs.

- **Rust** (`ash-core/src/proof.rs`): Changed to use `canonicalize_json_value()` instead of `serde_json::to_string()`
- **Go** (`ash-go/ash.go`): Changed to use `CanonicalizeJSON()` instead of `json.Marshal()`
- **PHP** (`ash-php/src/Core/Proof.php`): Changed to use `Canonicalize::json()` instead of `json_encode()`
- **.NET** (`ash-dotnet/src/Ash.Core/Proof.cs`): Changed to use `Canonicalize.Json()` instead of `JsonSerializer.Serialize()`
- **Node.js** (`ash-node/src/index.ts`): Changed to use `canonicalizeJsonNative()` instead of `JSON.stringify()`

**Bug #3: Missing Query String in PHP Middleware**

Three PHP middleware files were not including query strings when normalizing bindings:

- **WordPressHandler.php**: Added `$_SERVER['QUERY_STRING']` to binding normalization
- **CodeIgniterFilter.php**: Added `$_SERVER['QUERY_STRING']` to binding normalization
- **DrupalMiddleware.php**: Added `$request->getQueryString()` to binding normalization

**Bug #4: Array Index Ignored in Scoped Fields (ASH Core)**

The `set_nested_value` function was ignoring array indices when reconstructing scoped payloads. Scope paths like `"items[0]"` would extract the correct value but lose the array structure in the result.

- **Rust** (`ash-core/src/proof.rs`): Fixed `set_nested_value` to properly handle array indices and preserve array structure

**Bug #5: Floating-Point Bounds Check (ASH Core)**

The RFC 8785 whole-float-to-integer conversion used incorrect bounds. `i64::MAX as f64` rounds up due to floating-point precision limits, potentially allowing values larger than `i64::MAX`.

- **Rust** (`ash-core/src/canonicalize.rs`): Changed to use `MAX_SAFE_INTEGER` (2^53 - 1) for safe bounds checking

**Bug #6: Code Duplication (ASH Core)**

Duplicate `percent_encode` and `percent_encode_uppercase` functions were identical.

- **Rust** (`ash-core/src/canonicalize.rs`): Removed duplicate function, unified usage

#### Test Fixes

- Updated test expectations in Rust, .NET, and Python that incorrectly expected preserved value order instead of sorted values for duplicate keys

#### Documentation Fixes

- Fixed comments in multiple SDKs that incorrectly stated "preserve order of duplicate keys" (now correctly states "sort duplicate keys by value")
- Updated `ash-wasm/src/lib.rs` documentation

### Added

#### Unified Error Codes

- Standardized error codes across all 6 SDKs (ASH_CTX_*, ASH_PROOF_*, etc.)
- New `docs/ERROR_CODE_SPECIFICATION.md` with complete reference
- Updated error codes with HTTP status mapping (v2.3.3 updated to unique 450-499 range, see [Unreleased] Breaking Changes):
  - `ASH_CTX_NOT_FOUND` (450) - Context not found
  - `ASH_CTX_EXPIRED` (451) - Context expired
  - `ASH_CTX_ALREADY_USED` (452) - Replay detected
  - `ASH_BINDING_MISMATCH` (461) - Endpoint mismatch
  - `ASH_PROOF_MISSING` (483) - Missing proof header
  - `ASH_PROOF_INVALID` (460) - Proof verification failed
  - `ASH_CANONICALIZATION_ERROR` (422) - Canonicalization failed
  - `ASH_MODE_VIOLATION` (400) - Mode requirements not met
  - `ASH_UNSUPPORTED_CONTENT_TYPE` (415) - Unsupported content type
  - `ASH_SCOPE_MISMATCH` (473) - Scope hash mismatch (v2.2+)
  - `ASH_CHAIN_BROKEN` (474) - Chain verification failed (v2.3+)
  - `ASH_TIMESTAMP_INVALID` (482) - Timestamp validation failed
- Added `httpStatus()` / `HTTPStatus()` / `GetHttpStatus()` / `get_http_status()` methods to all SDKs
- All middlewares now return semantically appropriate HTTP status codes

#### Cross-SDK Test Vectors

- Comprehensive test vector suite (`tests/cross-sdk/test-vectors.json`)
- 38 total test vectors covering:
  - JSON canonicalization (20 vectors)
  - URL-encoded canonicalization (6 vectors)
  - Binding normalization (7 vectors)
  - Timing-safe comparison (5 vectors)
- Test runners for all 6 SDKs:
  - `run_tests.py` (Python)
  - `run_tests.js` (Node.js)
  - `run_tests.go` (Go)
  - `run_tests.php` (PHP)
  - `run_tests.cs` (.NET)
  - `run_tests.rs` (Rust)

#### Documentation

- `TROUBLESHOOTING.md` - Debugging guide for common issues
- `docs/ERROR_CODE_SPECIFICATION.md` - Unified error code reference
- API documentation for Go, PHP, and .NET SDKs

#### Secure Memory Utilities

**Python** (`ash.core.secure_memory`):
- `SecureBytes` - Secure container for binary data with auto-clear
- `SecureString` - Secure container for string secrets with auto-clear
- `secure_zero_memory()` - Zeros memory using ctypes.memset
- `secure_derive_client_secret()` - Returns SecureString for safe handling
- Context manager support for guaranteed cleanup

**Node.js** (`@3maem/ash-node/utils`):
- `SecureBuffer` - Secure container for Buffer data with auto-clear
- `SecureString` - Secure container for string data with auto-clear
- `secureZeroBuffer()` - Clears buffer with random overwrite + zero fill
- `withSecureBuffer()` / `withSecureString()` - Helper functions with auto-cleanup
- `secureDeriveClientSecret()` - Returns SecureString for safe handling

#### Security Assurance Pack

- Comprehensive security test suite (134+ tests)
- Cross-language implementations (Python, Node.js, Go)
- Test categories: Unit, Cryptographic, Security, Integration, Performance, Fuzz

#### Integration Examples

- Express.js (Node.js)
- Flask (Python)
- ASP.NET Core (C#)
- Gin (Go)
- Laravel (PHP)
- Actix-web (Rust)

#### CI/CD Workflows

- `test-all-sdks.yml` - Tests all 6 SDK implementations
- `security-scan.yml` - Security scanning with CodeQL, cargo-audit, npm audit, etc.

#### Documentation

- `SECURITY.md` - Security policy and vulnerability reporting
- `reports/security-audit/SECURITY_AUDIT_REPORT.md` - Full security audit
- `reports/benchmarks/BENCHMARK_REPORT.md` - Performance benchmarks
- `tests/SECURITY_ASSURANCE_PACK.md` - Test documentation

### Changed

- Security rating increased from 8.5/10 to 10/10
- Added CI badges to main README and all SDK READMEs
- Fixed repository URL typos (3meam → 3maem) across all files
- Fixed .NET Package ID to `Ash.Core`
- Updated main README with "What's New in v2.3" section

### Performance

- Python proof generation: ~348,000 ops/sec
- Sub-millisecond latencies for all cryptographic operations
- Concurrent throughput: ~248,000 ops/sec (4 workers)

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

### Changed

- Protocol version prefix updated to `ASHv2.3`

## [2.2.0] - 2025-12-01

### Added

- ASH v2.2 protocol support
- Context scoping with `scope` parameter
- `extractScopedFields()` function
- `buildProofV21Scoped()` and `verifyProofV21Scoped()` functions

## [2.1.0] - 2025-11-15

### Added

- ASH v2.1 protocol support
- Derived client secret (`deriveClientSecret()`)
- HMAC-SHA256 proof generation (`buildProofV21()`)
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

## Migration Guides

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
proof = build_proof_v21(client_secret, timestamp, binding, body_hash)
```

### v1.x to v2.x

Complete rewrite required. See migration documentation.
