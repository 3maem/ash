# Middleware Tests

**Version:** 2.3.3
**Last Updated:** January 2026

This document defines tests for ASH middleware implementations that integrate with HTTP frameworks.

---

## Table of Contents

1. [HTTP Method Tests](#1-http-method-tests)
2. [Framework Integration Tests](#2-framework-integration-tests)
3. [Request Signing Tests](#3-request-signing-tests)
4. [Request Verification Tests](#4-request-verification-tests)
5. [Content Type Handling](#5-content-type-handling)
6. [Error Scenarios](#6-error-scenarios)
7. [Security Tests](#7-security-tests)
8. [Advanced Penetration Tests](#8-advanced-penetration-tests)

---

## 1. HTTP Method Tests

All middlewares must correctly sign and verify requests for all standard HTTP methods.

### 1.1 Supported Methods

| Method | Has Body | Test |
|--------|----------|------|
| GET | No | Sign and verify with empty body hash |
| POST | Yes | Sign and verify with body content |
| PUT | Yes | Sign and verify with body content |
| PATCH | Yes | Sign and verify with body content |
| DELETE | Optional | Sign and verify with or without body |
| HEAD | No | Sign and verify with empty body hash |
| OPTIONS | No | Sign and verify (preflight handling) |

### 1.2 Test Cases

- [ ] Sign and verify GET request with query parameters
- [ ] Sign and verify POST request with JSON body
- [ ] Sign and verify POST request with form data
- [ ] Sign and verify PUT request with full replacement body
- [ ] Sign and verify PATCH request with partial update
- [ ] Sign and verify DELETE request without body
- [ ] Sign and verify DELETE request with body (where supported)
- [ ] Sign and verify HEAD request
- [ ] Handle OPTIONS preflight (may skip verification)

---

## 2. Framework Integration Tests

### 2.1 Express.js Middleware (Node.js)

**File:** `middleware/express.ts`

```typescript
import { createAshMiddleware } from 'ash-node/middleware';

app.use(createAshMiddleware({
  store: new AshMemoryStore(),
  headerName: 'X-ASH-Proof',
}));
```

#### Tests

- [ ] Middleware initializes without error
- [ ] Accepts valid signed request
- [ ] Rejects request with missing proof header
- [ ] Rejects request with invalid proof
- [ ] Rejects request with wrong binding
- [ ] Rejects request with tampered body
- [ ] Rejects replay attack (same proof twice)
- [ ] Handles async verification correctly
- [ ] Passes to next middleware on success
- [ ] Returns 401/403 on verification failure
- [ ] Attaches context to request object

### 2.2 Fastify Plugin (Node.js)

**File:** `middleware/fastify.ts`

```typescript
import { ashFastifyPlugin } from 'ash-node/middleware';

fastify.register(ashFastifyPlugin, {
  store: new AshMemoryStore(),
});
```

#### Tests

- [ ] Plugin registers without error
- [ ] Decorates request with ASH context
- [ ] Validates requests in preHandler hook
- [ ] Handles errors with Fastify error format

### 2.3 Go HTTP Middleware

```go
import "github.com/anthropic/ash-go/middleware"

handler := middleware.AshHandler(store, nextHandler)
```

#### Tests

- [ ] Middleware wraps handler correctly
- [ ] Attaches context to request context
- [ ] Returns proper HTTP status on failure

### 2.4 Python ASGI/WSGI Middleware

```python
from ash_python.middleware import AshMiddleware

app = AshMiddleware(app, store=memory_store)
```

#### Tests

- [ ] Works with ASGI (Starlette, FastAPI)
- [ ] Works with WSGI (Flask, Django)
- [ ] Async verification for ASGI

### 2.5 PHP PSR-15 Middleware

```php
$middleware = new AshMiddleware($store);
```

#### Tests

- [ ] Implements PSR-15 MiddlewareInterface
- [ ] Works with Slim, Laravel, Symfony

### 2.6 .NET Middleware

```csharp
app.UseAshVerification(options => {
    options.Store = new AshMemoryStore();
});
```

#### Tests

- [ ] ASP.NET Core middleware pattern
- [ ] DI integration

---

## 3. Request Signing Tests

### 3.1 Client-Side Signing (Fetch Interceptor)

```typescript
const signedFetch = createAshFetch(store);
const response = await signedFetch('/api/data', {
  method: 'POST',
  body: JSON.stringify({ data: 'value' }),
});
```

#### Tests

- [ ] Automatically creates context
- [ ] Adds proof header to request
- [ ] Adds timestamp header
- [ ] Adds context ID header
- [ ] Computes correct body hash
- [ ] Handles request without body
- [ ] Handles FormData body
- [ ] Handles URLSearchParams body

### 3.2 Header Configuration

| Header | Default Name | Configurable |
|--------|--------------|--------------|
| Proof | `X-ASH-Proof` | Yes |
| Timestamp | `X-ASH-Timestamp` | Yes |
| Context ID | `X-ASH-Context-Id` | Yes |
| Scope Hash | `X-ASH-Scope-Hash` | Yes |
| Chain Hash | `X-ASH-Chain-Hash` | Yes |

#### Tests

- [ ] Uses default header names
- [ ] Respects custom header configuration
- [ ] Headers are case-insensitive on read

---

## 4. Request Verification Tests

### 4.1 Basic Verification Flow

```
1. Extract proof from header
2. Extract timestamp from header
3. Extract context ID from header
4. Look up context in store
5. Consume context (single-use)
6. Compute body hash
7. Build expected proof
8. Compare proofs (timing-safe)
9. Return success/failure
```

#### Tests

- [ ] Full flow completes successfully for valid request
- [ ] Returns false if context not found
- [ ] Returns false if context already consumed
- [ ] Returns false if timestamp expired
- [ ] Returns false if proof mismatch
- [ ] Returns false if binding mismatch

### 4.2 Scoped Verification (v2.2)

- [ ] Extracts scope hash from header
- [ ] Verifies only scoped fields
- [ ] Ignores changes to non-scoped fields
- [ ] Fails on scoped field modification

### 4.3 Chained Verification (v2.3)

- [ ] Extracts chain hash from header
- [ ] Verifies chain integrity
- [ ] Supports multi-step workflows
- [ ] Fails on broken chain

---

## 5. Content Type Handling

### 5.1 JSON (`application/json`)

- [ ] Parse body as JSON
- [ ] Canonicalize JSON
- [ ] Hash canonicalized JSON

### 5.2 Form Data (`application/x-www-form-urlencoded`)

- [ ] Parse as URL-encoded
- [ ] Canonicalize URL-encoded body
- [ ] `+` treated as literal plus (%2B)

### 5.3 Multipart (`multipart/form-data`)

- [ ] Hash raw body (no canonicalization)
- [ ] Handle file uploads correctly

### 5.4 Plain Text (`text/plain`)

- [ ] Hash body as-is
- [ ] Handle UTF-8 encoding

### 5.5 Binary

- [ ] Hash raw bytes
- [ ] No encoding transformation

### 5.6 Empty Body

- [ ] GET requests have empty body
- [ ] Empty body hash is SHA-256 of empty string

---

## 6. Error Scenarios

### 6.1 Missing Headers

| Scenario | Expected Response |
|----------|-------------------|
| Missing proof header | 401 Unauthorized |
| Missing timestamp header | 401 Unauthorized |
| Missing context ID header | 401 Unauthorized |

### 6.2 Invalid Headers

| Scenario | Expected Response |
|----------|-------------------|
| Invalid proof format | 401 Unauthorized |
| Invalid timestamp format | 401 Unauthorized |
| Unknown context ID | 401 Unauthorized |

### 6.3 Expired/Replayed

| Scenario | Expected Response |
|----------|-------------------|
| Expired timestamp | 401 Unauthorized |
| Replayed request | 401 Unauthorized |
| Context already consumed | 401 Unauthorized |

### 6.4 Tampered Request

| Scenario | Expected Response |
|----------|-------------------|
| Modified body | 401 Unauthorized |
| Modified path | 401 Unauthorized |
| Modified query | 401 Unauthorized |
| Modified method | 401 Unauthorized |

### 6.5 Error Response Format

```json
{
  "error": "PROOF_VERIFICATION_FAILED",
  "message": "Request signature verification failed"
}
```

- [ ] Error response does not leak expected proof
- [ ] Error response does not leak nonce
- [ ] Error response includes error code

---

## 7. Security Tests

### 7.1 Replay Attack Prevention

```
1. Client sends valid signed request
2. Attacker intercepts and replays exact request
3. Middleware rejects replay (context consumed)
```

- [ ] Same request fails on second attempt
- [ ] Context consumption is atomic
- [ ] No race condition in consume

### 7.2 Tampering Detection

```
1. Client sends valid signed request
2. Attacker modifies body
3. Middleware rejects (proof mismatch)
```

- [ ] Body modification detected
- [ ] Path modification detected
- [ ] Query modification detected
- [ ] Method modification detected
- [ ] Header modification detected (for signed headers)

### 7.3 Timestamp Manipulation

- [ ] Reject timestamp too far in past
- [ ] Reject timestamp too far in future
- [ ] Prevent time-based attacks

### 7.4 Context Isolation

- [ ] Context from one binding cannot be used for another
- [ ] Context from one user cannot be used by another
- [ ] No context leakage between requests

---

## 8. Advanced Penetration Tests

### 8.1 Protocol-Level Attacks

#### Binding Confusion Attack

```
Attacker tries to:
1. Get context for GET /api/users
2. Use it for POST /api/users
```

- [ ] Binding mismatch detected
- [ ] Method verified
- [ ] Path verified
- [ ] Query verified

#### Method Override Attack

```
Attacker tries:
X-HTTP-Method-Override: DELETE
with GET binding
```

- [ ] Actual method used for binding, not override header
- [ ] Override headers ignored for verification

#### Path Normalization Bypass

```
Attacker tries:
/api/../api/admin
/api/./admin
/api//admin
```

- [ ] Path normalized before verification
- [ ] No bypass via path manipulation

#### Query Parameter Pollution

```
Attacker tries:
?admin=false&admin=true
```

- [ ] Query canonicalized (sorted, deduplicated)
- [ ] Parameter pollution detected

### 8.2 Encoding Attacks

#### Double Encoding

```
Attacker tries:
%252F instead of %2F
```

- [ ] Double encoding preserved (not decoded)
- [ ] Consistent handling across sign and verify

#### Case Sensitivity

```
Attacker tries:
%2f instead of %2F
```

- [ ] Hex uppercase normalized
- [ ] Consistent case handling

#### Unicode Normalization

```
Attacker tries:
café (NFC) vs cafe + combining accent (NFD)
```

- [ ] Unicode normalized to NFC
- [ ] Canonically equivalent strings match

### 8.3 Timing Attacks

- [ ] Proof comparison is constant-time
- [ ] No early exit on mismatch
- [ ] No timing leakage on valid vs invalid

### 8.4 Resource Exhaustion

- [ ] Large body handling (within limits)
- [ ] Many concurrent requests
- [ ] Store size limits enforced

---

## Middleware Checklist

### Implementing a New Middleware

1. **Basic Flow**
   - [ ] Extract headers
   - [ ] Look up context
   - [ ] Consume context
   - [ ] Verify proof
   - [ ] Return result

2. **Error Handling**
   - [ ] Return proper HTTP status
   - [ ] Safe error messages
   - [ ] Log securely (no secrets)

3. **Configuration**
   - [ ] Configurable header names
   - [ ] Configurable store
   - [ ] Configurable error handler

4. **Integration**
   - [ ] Framework-idiomatic API
   - [ ] Async support (where applicable)
   - [ ] Context propagation

5. **Security**
   - [ ] Timing-safe comparison
   - [ ] No information leakage
   - [ ] Proper cleanup

---

## Supported Frameworks

| Language | Framework | Middleware Type |
|----------|-----------|-----------------|
| Node.js | Express | Middleware function |
| Node.js | Fastify | Plugin |
| Node.js | Koa | Middleware function |
| Go | net/http | Handler wrapper |
| Go | Gin | HandlerFunc |
| Go | Echo | Middleware |
| Python | FastAPI | Middleware (ASGI) |
| Python | Flask | Decorator/before_request |
| Python | Django | Middleware class |
| PHP | Laravel | Middleware class |
| PHP | Slim | PSR-15 Middleware |
| PHP | Symfony | Event listener |
| C# | ASP.NET Core | Middleware |

---

*This document defines requirements for HTTP middleware integrations.*
