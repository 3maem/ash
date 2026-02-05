# ASH SDK

[![Build Status](https://img.shields.io/github/actions/workflow/status/3maem/ash/test-all-sdks.yml?branch=main&label=build)](https://github.com/3maem/ash/actions/workflows/test-all-sdks.yml)
[![Cross-SDK Tests](https://img.shields.io/badge/cross--SDK-passing-brightgreen)](tests/cross-sdk/)
[![Security Rating](https://img.shields.io/badge/security-10%2F10-brightgreen)](reports/security-audit/SECURITY_AUDIT_REPORT.md)
[![Tests](https://img.shields.io/badge/tests-134%20passed-brightgreen)](tests/security_assurance/)
[![License](https://img.shields.io/badge/license-ASAL--1.0-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.3.3-blue)](CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-available-blue)](docs/)

**Developed by 3maem Co. | شركة عمائم**

---

## What's New in v2.3

**ASH v2.3 Unified Proof** introduces advanced security features while maintaining backward compatibility:

- **Context Scoping** - Protect specific fields while allowing others to change
- **Request Chaining** - Cryptographically link sequential operations for workflow integrity
- **Server-Side Scope Policies** - Enforce scoping requirements at the server level
- **Unified Error Codes** - Consistent error handling across all 6 SDKs
- **Cross-SDK Test Vectors** - Comprehensive interoperability testing
- **Cross-SDK Input Validation** - All SDKs validate inputs identically (SEC-014, BUG-004, SEC-CTX-001)

See the [CHANGELOG](CHANGELOG.md) for complete release notes.

---

## Introduction

**ASH** is an acronym for **Application Security Hash**.

ASH is a security software development kit (SDK) created to address a
specific, narrowly scoped security problem:
**ensuring the integrity and single-use validity of individual HTTP requests**.

ASH was developed in response to a recurring gap observed in modern web
architectures, where existing security mechanisms focus primarily on
transport security, identity verification, and access control, while
leaving the **request itself** vulnerable to reuse, duplication, or
manipulation within short attack windows.

---

## Purpose and Motivation

ASH was developed to solve the following problem:

> Even when HTTPS, authentication, and authorization are correctly
> implemented, application requests can still be **captured, replayed,
> duplicated, or misused** without being altered in a detectable way.

ASH does **not** attempt to prevent attacks by analyzing intent,
validating business logic, inspecting input semantics, or detecting
malicious behavior.

Instead, ASH focuses exclusively on **verifying that a request is
authentic, unmodified, context-bound, and valid for a single use**.

This intentionally narrow scope is fundamental to ASH's design.

---

## What ASH Is — and Is Not

ASH is **not**:

- An authentication mechanism
- An authorization or access-control framework
- A transport security protocol
- A firewall or intrusion detection system
- An input validation or injection prevention solution
- A replacement for any existing security library or standard

ASH does **not** replace:
- TLS / HTTPS
- JWT, OAuth, sessions, or API keys
- Secure coding practices
- Application-layer security controls

ASH is designed as an **additional, complementary security layer**
within a **defense-in-depth architecture**.

---

## How ASH Works (Conceptual Overview)

ASH operates at the **request level**, not the user or session level.

For each protected operation:

1. The server issues a short-lived context identifier.
2. The client generates a deterministic cryptographic proof.
3. The proof is bound to:
   - The HTTP method
   - The target endpoint
   - The issued context identifier
   - A strict time-to-live (TTL)
   - A canonical representation of the request payload
4. The server verifies the proof before processing the request.
5. Once validated, the proof is immediately invalidated and cannot be reused.

This mechanism allows the server to determine whether a request:
- Has been modified
- Has been replayed
- Has been reused outside its intended context
- Has expired or already been consumed

---

## Terminology

This section defines key terms used throughout ASH documentation.
All terms are used consistently across SDKs.

### Context

A short-lived, server-issued identifier (`contextId`) that defines
the valid scope and lifetime of a protected request.

A context is:
- Issued by the server
- Bound to a specific HTTP method and endpoint
- Limited by a strict TTL
- Consumable once

### Context Store

A server-side storage mechanism responsible for:
- Issuing contexts
- Tracking context state
- Enforcing expiration and single-use constraints

The store may be in-memory or persistent, depending on deployment.

### Proof

A deterministic value derived from:
- HTTP method
- Endpoint binding
- contextId
- Canonicalized request payload
- Mode-specific rules

A proof:
- Is generated per request
- Is valid for a single use
- Cannot be reversed or reused
- Does not contain claims or identity information

### Binding

The explicit association between a context/proof and a specific
HTTP method and endpoint.

Bindings prevent cross-endpoint or cross-method reuse of requests.

### Canonicalization

A deterministic process that converts request payloads into a
byte-stable representation before proof generation.

Canonicalization ensures that logically identical payloads
produce identical proofs across SDKs and platforms.

### Mode

A predefined configuration that controls how proofs are derived
(e.g., performance vs. strictness trade-offs).

Modes are agreed upon by client and server during context issuance.

### TTL (Time-To-Live)

A strict time window during which a context and its associated
proofs are considered valid.

Once expired, a context and all proofs derived from it are invalid.

### Single-Use Enforcement

A rule that ensures a proof or context cannot be successfully
verified more than once.

This mechanism provides request-level anti-replay protection.

### Verification

The server-side process of validating:
- Proof correctness
- Context validity
- Binding consistency
- TTL compliance
- Single-use constraints

---

## API Naming Convention

All public APIs use the `ash` prefix for consistency and to avoid naming conflicts.

### Functions

| Function | Purpose |
|----------|---------|
| `ashInit()` | Initialize the library |
| `ashCanonicalizeJson()` | Canonicalize JSON to deterministic form |
| `ashCanonicalizeUrlencoded()` | Canonicalize URL-encoded form data |
| `ashBuildProof()` | Generate cryptographic proof |
| `ashVerifyProof()` | Verify proof matches expected value |
| `ashNormalizeBinding()` | Normalize HTTP method and path |
| `ashTimingSafeEqual()` | Constant-time string comparison |
| `ashVersion()` | Get protocol version (e.g., "ASHv1") |
| `ashLibraryVersion()` | Get library semantic version |

### Types and Interfaces

| Type | Purpose |
|------|---------|
| `AshMode` | Security mode: `minimal`, `balanced`, `strict` |
| `AshContext` | Context object with ID, binding, expiry, mode |
| `AshContextOptions` | Options for creating a new context |
| `AshVerifyResult` | Verification result with status and error info |
| `AshContextStore` | Interface for context storage backends |

### Classes

| Class | Purpose |
|-------|---------|
| `AshMemoryStore` | In-memory context store (development/testing) |
| `AshRedisStore` | Redis-backed context store (production) |
| `AshSqlStore` | SQL database context store |

### Middleware

| Middleware | Purpose |
|------------|---------|
| `ashExpressMiddleware()` | Express.js request verification |
| `ashFastifyPlugin()` | Fastify request verification |
| `AshLaravelMiddleware` | Laravel request verification |
| `AshFilter` | CodeIgniter request verification |
| `WordPressHandler` | WordPress REST API verification |

This naming convention applies across all SDKs (Node.js, Python, Go, .NET, PHP, Rust).

### Configuration

ASH supports environment-based configuration for deployment flexibility across all SDKs:

| Variable | Default | Description |
|----------|---------|-------------|
| `ASH_TRUST_PROXY` | `false` | Enable X-Forwarded-For handling |
| `ASH_TRUSTED_PROXIES` | (empty) | Comma-separated trusted proxy IPs |
| `ASH_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `ASH_RATE_LIMIT_MAX` | `10` | Max contexts per window per IP |
| `ASH_TIMESTAMP_TOLERANCE` | `30` | Acceptable clock skew in seconds |

#### IP and User Binding Guards

All ASH middlewares support optional IP and user binding verification to prevent context theft:

| SDK | IP Binding | User Binding | Syntax |
|-----|------------|--------------|--------|
| **PHP Laravel** | `enforce_ip` | `enforce_user` | `middleware('ash:enforce_ip,enforce_user')` |
| **PHP CodeIgniter** | `enforce_ip` | `enforce_user` | `['before' => ['api/*' => ['enforce_ip']]]` |
| **PHP WordPress** | `enforce_ip` | `enforce_user` | `['enforce_ip' => true]` |
| **Node.js** | `enforceIp` | `enforceUser` | `ashExpressMiddleware({ enforceIp: true })` |
| **Python Flask** | `enforce_ip` | `enforce_user` | `@middleware.flask(store, enforce_ip=True)` |
| **Go Gin** | `EnforceIP` | `EnforceUser` | `AshGinMiddleware(&AshMiddlewareOptions{EnforceIP: true})` |
| **.NET Core** | `EnforceIp` | `EnforceUser` | `UseAsh(ash, new AshMiddlewareOptions { EnforceIp = true })` |

When enabled, the middleware verifies that the current request's IP address and/or authenticated user matches the values stored in the context metadata. If mismatched, returns HTTP 461 (`ASH_BINDING_MISMATCH`).

**Environment Configuration Examples:**

```bash
# .env file
ASH_TRUST_PROXY=true
ASH_TRUSTED_PROXIES=10.0.0.1,10.0.0.2
ASH_RATE_LIMIT_WINDOW=60
ASH_RATE_LIMIT_MAX=100
ASH_TIMESTAMP_TOLERANCE=30
```

**PHP with IP Binding:**
```php
// Store client IP when creating context
$ctx = $store->create([
    'binding' => 'POST /api/transfer',
    'metadata' => ['ip' => $_SERVER['REMOTE_ADDR'], 'user_id' => $userId]
]);

// Verify IP in middleware
Route::post('/api/transfer', ...)
    ->middleware('ash:enforce_ip,enforce_user');
```

**Node.js with User Binding:**
```javascript
// Store user ID in context
const ctx = await store.create({
    binding: 'POST /api/transfer',
    metadata: { user_id: req.user.id }
});

// Verify user in middleware
app.post('/api/transfer',
    ashExpressMiddleware({ 
        store, 
        enforceUser: true,
        userIdExtractor: (req) => req.user?.id 
    }),
    handler
);
```

**Go with IP and User Binding:**
```go
// Store metadata when creating context
ctx, _ := store.Create(ash.ContextConfig{
    Binding:  "POST /api/transfer",
    Metadata: map[string]string{
        "ip":       c.ClientIP(),
        "user_id":  userID,
    },
})

// Verify in middleware
router.POST("/api/transfer", ash.AshGinMiddleware(&ash.AshMiddlewareOptions{
    Store:       store,
    EnforceIP:   true,
    EnforceUser: true,
}))
```

---

## Security Scope and Explicit Boundaries

ASH provides deterministic validation that request inputs have not been
modified in transit and are used only once within their intended context.

By enforcing strict request integrity and single-use constraints, ASH
may reduce the feasibility or impact of certain attack scenarios that
depend on request tampering or replay.

However, ASH is not designed, represented, or intended to function as
an attack prevention, attack detection, or threat mitigation system.

ASH must not be relied upon as a standalone security control for
protecting applications against cybersecurity attacks.

---

## Intended Role in a Secure Architecture

ASH is intended to be deployed **alongside** existing security controls.

A typical secure architecture includes:

- TLS for transport-level security
- Authentication and authorization mechanisms for identity and access
- Secure coding practices and input validation
- ASH for request integrity and replay protection

This layered approach ensures that ASH enhances overall security
without assuming responsibilities beyond its defined scope.

---

## Quick Start

### Server (Node.js / Express)

```javascript
import express from 'express';
import { ashInit, AshMemoryStore, ashExpressMiddleware } from '@3maem/ash-node';

ashInit();
const app = express();
const store = new AshMemoryStore();

app.use(express.json());

// Issue context
app.post('/ash/context', async (req, res) => {
  const ctx = await store.create({
    binding: 'POST /api/transfer',
    ttlMs: 30000,
    mode: 'balanced'
  });
  res.json({ contextId: ctx.id, mode: ctx.mode });
});

// Protected endpoint
app.post(
  '/api/transfer',
  ashExpressMiddleware({ store, expectedBinding: 'POST /api/transfer' }),
  (req, res) => {
    // Request verified — safe to process
    res.json({ success: true });
  }
);

app.listen(3000);
```

### Client (Browser / Node.js)

```javascript
import { ashInit, ashCanonicalizeJson, ashBuildProof } from '@3maem/ash-node';

ashInit();

// 1. Get context
const { contextId, mode } = await fetch('/ash/context', {
  method: 'POST'
}).then(r => r.json());

// 2. Prepare payload
const payload = { amount: 100, to: 'account123' };
const canonical = ashCanonicalizeJson(JSON.stringify(payload));

// 3. Build proof
const proof = ashBuildProof(
  mode,
  'POST /api/transfer',
  contextId,
  null,
  canonical
);

// 4. Send protected request
await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ASH-Context-ID': contextId,
    'X-ASH-Proof': proof
  },
  body: JSON.stringify(payload)
});
```

---

## Secure Memory Utilities

For high-security environments, ASH provides secure memory handling to prevent secrets from lingering in memory.

### Python

```python
from ash.core import SecureString, secure_derive_client_secret

# Automatic cleanup with context manager
with secure_derive_client_secret(nonce, context_id, binding) as secret:
    proof = build_proof_v21(secret.get(), timestamp, binding, body_hash)
# Memory automatically zeroed here
```

### Node.js

```typescript
import { withSecureString, secureDeriveClientSecret } from '@3maem/ash-node';

// Automatic cleanup with helper function
const proof = await withSecureString(clientSecret, (secret) => {
  return buildProofV21(secret, timestamp, binding, bodyHash);
});
// Memory automatically cleared
```

---

## Integration Examples

Ready-to-use examples for popular web frameworks:

| Framework | Language | Location |
|-----------|----------|----------|
| **Express** | Node.js | [`examples/express/`](examples/express/) |
| **Flask** | Python | [`examples/flask/`](examples/flask/) |
| **ASP.NET Core** | C# | [`examples/aspnet/`](examples/aspnet/) |
| **Gin** | Go | [`examples/gin/`](examples/gin/) |
| **Laravel** | PHP | [`examples/laravel/`](examples/laravel/) |
| **Actix-web** | Rust | [`examples/actix/`](examples/actix/) |

Each example includes server implementation, client usage, and setup instructions.

---

## Error Reference

This section defines common error conditions returned by ASH
during request verification. Error codes are prefixed with `ASH_`
for consistent handling across SDKs.

**v2.3.3+**: ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

### Error Code Quick Reference

| Code | HTTP | Category | Description |
|------|------|----------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Context | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Seal | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Binding | Endpoint mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Verification | Scope hash mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Verification | Chain verification failed |
| `ASH_TIMESTAMP_INVALID` | 482 | Format | Invalid timestamp |
| `ASH_PROOF_MISSING` | 483 | Format | Missing proof header |
| `ASH_CANONICALIZATION_ERROR` | 422 | Standard | Canonicalization failed |
| `ASH_MODE_VIOLATION` | 400 | Standard | Mode requirements not met |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Standard | Content type not supported |
| `ASH_VALIDATION_ERROR` | 400 | Standard | Input validation failed |

### Context Errors (450-459)

#### ASH_CTX_NOT_FOUND (HTTP 450)

The provided `contextId` does not exist or is unknown to the server.

**Possible causes:**
- Invalid or malformed contextId
- Context already consumed
- Context store reset

#### ASH_CTX_EXPIRED (HTTP 451)

The context exists but has exceeded its TTL.

**Possible causes:**
- Request sent after expiration
- Client/server clock drift beyond tolerance

#### ASH_CTX_ALREADY_USED (HTTP 452)

The context or proof has already been successfully consumed.

**Possible causes:**
- Replay attempt
- Duplicate request submission
- Network retry without new context

### Seal/Proof Errors (460-469)

#### ASH_PROOF_INVALID (HTTP 460)

The provided proof does not match the expected value.

**Possible causes:**
- Payload modification
- Canonicalization mismatch
- Incorrect mode or binding
- Implementation mismatch across SDKs

### Binding Errors (461)

#### ASH_BINDING_MISMATCH (HTTP 461)

The request does not match the binding associated with the context.

**Possible causes:**
- Different endpoint
- Different HTTP method
- Context reused for another operation

#### ASH_SCOPE_MISMATCH (HTTP 473)

The scope hash does not match the expected value for scoped fields.

**Possible causes:**
- Scoped field values were modified
- Scope header mismatch between client and server
- Server-side scope policy violation

#### ASH_CHAIN_BROKEN (HTTP 474)

The chain hash verification failed for linked requests.

**Possible causes:**
- Invalid previous proof reference
- Chain sequence disrupted
- Missing chain hash header

### Format/Protocol Errors (480-489)

#### ASH_TIMESTAMP_INVALID (HTTP 482)

The timestamp validation failed.

**Possible causes:**
- Timestamp outside allowed drift window
- Invalid timestamp format

#### ASH_PROOF_MISSING (HTTP 483)

The request did not include a required proof value.

**Possible causes:**
- Client integration error
- Missing headers

### Standard HTTP Errors

#### ASH_CANONICALIZATION_ERROR (HTTP 422)

The payload could not be canonicalized deterministically.

**Possible causes:**
- Unsupported payload structure
- Invalid JSON
- Non-deterministic serialization

#### ASH_MODE_VIOLATION (HTTP 400)

The request does not meet the requirements of the specified security mode.

**Possible causes:**
- Required fields missing for strict mode
- Mode-specific constraints not satisfied

#### ASH_UNSUPPORTED_CONTENT_TYPE (HTTP 415)

The request content type is not supported for canonicalization.

**Possible causes:**
- Unknown or unsupported Content-Type header
- Binary content without proper handling
- Missing Content-Type header

For complete error code documentation, see [Error Code Specification](docs/ERROR_CODE_SPECIFICATION.md).

---

## Available SDKs

| Language | Package | Install |
|----------|---------|---------|
| **Node.js** | [`@3maem/ash-node`](https://www.npmjs.com/package/@3maem/ash-node) | `npm install @3maem/ash-node` |
| **Python** | [`ash-sdk`](https://pypi.org/project/ash-sdk/) | `pip install ash-sdk` |
| **Go** | [`github.com/3maem/ash-go`](https://github.com/3maem/ash-go) | `go get github.com/3maem/ash-go` |
| **PHP** | [`3maem/ash-sdk-php`](https://packagist.org/packages/3maem/ash-sdk-php) | `composer require 3maem/ash-sdk-php` |
| **.NET** | [`Ash.Core`](https://www.nuget.org/packages/Ash.Core) | `dotnet add package Ash.Core` |
| **Rust** | [`ash-core`](https://crates.io/crates/ash-core) | `cargo add ash-core` |
| **Rust WASM** | [`ash-wasm`](https://crates.io/crates/ash-wasm) | `cargo add ash-wasm` |

---

## Documentation

| Document | Description |
|----------|-------------|
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [Error Code Specification](docs/ERROR_CODE_SPECIFICATION.md) | Unified error codes across all SDKs |
| [Troubleshooting Guide](TROUBLESHOOTING.md) | Common issues and debugging tips |
| [Cross-SDK Test Vectors](tests/cross-sdk/) | Interoperability test suite |
| [Security Audit](reports/security-audit/SECURITY_AUDIT_REPORT.md) | Full security audit report |
| [Benchmarks](reports/benchmarks/BENCHMARK_REPORT.md) | Performance benchmarks |
| [Security Tests](tests/SECURITY_ASSURANCE_PACK.md) | Security test documentation |

---

## Cross-SDK Testing

ASH includes comprehensive test vectors to ensure interoperability across all SDKs.

```bash
# Run Python test vectors
python tests/cross-sdk/run_tests.py

# Run Node.js test vectors
node tests/cross-sdk/run_tests.js

# Run Go test vectors
go run tests/cross-sdk/run_tests.go

# Run PHP test vectors
php tests/cross-sdk/run_tests.php

# Run .NET test vectors
dotnet run --project tests/cross-sdk/run_tests.csproj

# Run Rust test vectors
cargo run --bin run_tests
```

Test vectors cover:
- JSON canonicalization (20 vectors)
- URL-encoded canonicalization (6 vectors)
- Binding normalization (7 vectors)
- Timing-safe comparison (5 vectors)

---

## Contributing

1. Fork the repository
2. Install pre-commit hooks: `pip install pre-commit && pre-commit install`
3. Make your changes
4. Run tests: `pytest tests/security_assurance/`
5. Run cross-SDK tests to verify interoperability
6. Submit a pull request

---

## Legal and Operational Notice

ASH does not provide attack prevention, attack detection, or threat
mitigation capabilities.

Its purpose is strictly limited to validating request integrity and
enforcing single-use request constraints. Any security benefit beyond
this scope is incidental and must not be relied upon.

---

## License

**ASH Source-Available License (ASAL-1.0)**

See [LICENSE](LICENSE) for full terms.

© 3maem Co. | شركة عمائم

---

## Trademark

"ASH" is a trademark of 3maem Co.
Forks may not use the ASH name or logo without permission.
