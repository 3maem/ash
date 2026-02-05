# ASH Error Code Specification

**Version:** 2.3.4
**Date:** 2026-02-05

This document defines the standard error codes used across all ASH SDK implementations to ensure interoperability and consistent error handling.

## What's New in v2.3.4

**Complete Error Code Coverage**: All SDKs now implement the full set of error codes with unique HTTP status codes (450-499 range):

- `ASH_TIMESTAMP_INVALID` (HTTP 482) — Timestamp validation failures
- `ASH_VALIDATION_ERROR` (HTTP 400) — Input validation failures
- `ASH_INTERNAL_ERROR` (HTTP 500) — Internal server errors

**Benefits:**
- Better monitoring and alerting
- Targeted retry strategies
- Faster debugging and root cause analysis

---

## Overview

All ASH SDKs MUST implement the error codes defined in this specification. Error codes are used to communicate specific failure conditions during request verification.

## Error Code Format

All error codes MUST:
- Use the `ASH_` prefix
- Use `SCREAMING_SNAKE_CASE` format
- Be returned as strings in API responses

Example: `ASH_CONTEXT_EXPIRED`

---

## Standard Error Codes

## Error Categories

ASH error codes are organized into categories with dedicated HTTP status code ranges:

| Category | HTTP Range | Purpose |
|----------|------------|---------|
| Context errors | 450-459 | Context lifecycle issues |
| Seal/Proof errors | 460-469 | Cryptographic verification failures |
| Binding errors | 461 | Endpoint/IP/user binding mismatch |
| Verification errors | 473-479 | Request scope/chain issues |
| Format/Protocol errors | 480-489 | Malformed requests |

---

## Context Errors (450-459)

### ASH_CTX_NOT_FOUND

**HTTP Status:** 450

The provided `contextId` does not exist or is unknown to the server.

**Possible Causes:**
- Invalid or malformed contextId
- Context already consumed (single-use)
- Context store reset or cleared
- Typo in contextId

**Client Action:** Request a new context

---

### ASH_CTX_EXPIRED

**HTTP Status:** 451

The context exists but has exceeded its TTL (time-to-live).

**Possible Causes:**
- Request sent after context expiration
- Client/server clock drift beyond tolerance
- Network latency caused delay

**Client Action:** Request a new context with appropriate TTL

---

### ASH_CTX_ALREADY_USED

**HTTP Status:** 452

The context or proof has already been successfully consumed.

**Possible Causes:**
- Replay attack attempt
- Duplicate request submission (e.g., double-click)
- Network retry without obtaining new context

**Client Action:** Request a new context for each request

---

## Seal/Proof Errors (460-469)

### ASH_PROOF_INVALID

**HTTP Status:** 460

The provided proof does not match the expected value.

**Possible Causes:**
- Payload modified after proof generation
- Canonicalization mismatch between client and server
- Incorrect mode or binding used
- Wrong client secret
- Timestamp mismatch

**Client Action:** Verify proof generation matches server expectations

---

## Binding Errors (461)

### ASH_BINDING_MISMATCH

**HTTP Status:** 461

The request does not match the binding associated with the context.

**Possible Causes:**
- Request sent to different endpoint than context was issued for
- HTTP method mismatch (e.g., POST vs PUT)
- Query string mismatch
- Context reused for another operation

**Client Action:** Ensure context binding matches request endpoint

### ASH_SCOPE_MISMATCH

**HTTP Status:** 473

The scope hash does not match the expected scoped fields (v2.2+).

**Possible Causes:**
- Scoped fields modified
- Incorrect scope specification
- Scope hash calculation error

**Client Action:** Verify scoped fields match server policy

---

### ASH_CHAIN_BROKEN

**HTTP Status:** 474

The request chain verification failed (v2.3+).

**Possible Causes:**
- Previous proof missing or invalid
- Chain hash mismatch
- Out-of-order request in chain

**Client Action:** Ensure correct previous proof is provided

---

## Format/Protocol Errors (480-489)

### ASH_TIMESTAMP_INVALID

**HTTP Status:** 482

The timestamp validation failed.

**Possible Causes:**
- Timestamp outside allowed drift window
- Invalid timestamp format
- Client/server clock drift

**Client Action:** Ensure timestamps are synchronized

---

### ASH_PROOF_MISSING

**HTTP Status:** 483

The request did not include a required proof value.

**Possible Causes:**
- Missing `X-ASH-Proof` header
- Client integration error
- Middleware misconfiguration

**Client Action:** Include proof in request headers

---

## Standard HTTP Errors (Preserved)

### ASH_CANONICALIZATION_ERROR

**HTTP Status:** 422 Unprocessable Entity

The payload could not be canonicalized deterministically.

**Possible Causes:**
- Invalid JSON syntax
- Unsupported payload structure
- Non-deterministic serialization
- Character encoding issues

**Client Action:** Verify payload is valid and use SDK canonicalization functions

---

### ASH_MODE_VIOLATION

**HTTP Status:** 400 Bad Request

The request violates the security mode constraints.

**Possible Causes:**
- Strict mode requires nonce but none provided
- Mode mismatch between client and server
- Invalid mode value

**Client Action:** Use correct security mode settings

---

### ASH_UNSUPPORTED_CONTENT_TYPE

**HTTP Status:** 415 Unsupported Media Type

The request content type is not supported for ASH verification.

**Possible Causes:**
- Content-Type header missing or invalid
- Unsupported media type (not JSON or form-urlencoded)

**Client Action:** Use supported content type (application/json or application/x-www-form-urlencoded)

---

## HTTP Status Code Summary

| Error Code | HTTP Status | Category |
|------------|-------------|----------|
| `ASH_CTX_NOT_FOUND` | 450 | Context |
| `ASH_CTX_EXPIRED` | 451 | Context |
| `ASH_CTX_ALREADY_USED` | 452 | Context |
| `ASH_PROOF_INVALID` | 460 | Seal |
| `ASH_BINDING_MISMATCH` | 461 | Binding |
| `ASH_SCOPE_MISMATCH` | 473 | Verification |
| `ASH_CHAIN_BROKEN` | 474 | Verification |
| `ASH_TIMESTAMP_INVALID` | 482 | Format |
| `ASH_PROOF_MISSING` | 483 | Format |
| `ASH_CANONICALIZATION_ERROR` | 422 | Standard |
| `ASH_MODE_VIOLATION` | 400 | Standard |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Standard |
| `ASH_VALIDATION_ERROR` | 400 | Standard |
| `ASH_INTERNAL_ERROR` | 500 | Standard |

---

## Language-Specific Implementation Guidelines

### Error Code Constants

Each SDK MUST define constants/enums for all error codes:

**Rust:**
```rust
pub enum AshErrorCode {
    CtxNotFound,           // HTTP 450
    CtxExpired,            // HTTP 451
    CtxAlreadyUsed,        // HTTP 452
    ProofInvalid,          // HTTP 460
    BindingMismatch,       // HTTP 461
    ScopeMismatch,         // HTTP 473
    ChainBroken,           // HTTP 474
    TimestampInvalid,      // HTTP 482
    ProofMissing,          // HTTP 483
    CanonicalizationError, // HTTP 422
    ModeViolation,         // HTTP 400
    UnsupportedContentType,// HTTP 415
    ValidationError,       // HTTP 400
    InternalError,         // HTTP 500
}
```

**TypeScript/JavaScript:**
```typescript
type AshErrorCode =
  | 'ASH_CTX_NOT_FOUND'           // HTTP 450
  | 'ASH_CTX_EXPIRED'             // HTTP 451
  | 'ASH_CTX_ALREADY_USED'        // HTTP 452
  | 'ASH_PROOF_INVALID'           // HTTP 460
  | 'ASH_BINDING_MISMATCH'        // HTTP 461
  | 'ASH_SCOPE_MISMATCH'          // HTTP 473
  | 'ASH_CHAIN_BROKEN'            // HTTP 474
  | 'ASH_TIMESTAMP_INVALID'       // HTTP 482
  | 'ASH_PROOF_MISSING'           // HTTP 483
  | 'ASH_CANONICALIZATION_ERROR'  // HTTP 422
  | 'ASH_MODE_VIOLATION'          // HTTP 400
  | 'ASH_UNSUPPORTED_CONTENT_TYPE'// HTTP 415
  | 'ASH_VALIDATION_ERROR'        // HTTP 400
  | 'ASH_INTERNAL_ERROR';         // HTTP 500
```

**Python:**
```python
class AshErrorCode(str, Enum):
    CTX_NOT_FOUND = "ASH_CTX_NOT_FOUND"              # HTTP 450
    CTX_EXPIRED = "ASH_CTX_EXPIRED"                  # HTTP 451
    CTX_ALREADY_USED = "ASH_CTX_ALREADY_USED"        # HTTP 452
    PROOF_INVALID = "ASH_PROOF_INVALID"              # HTTP 460
    BINDING_MISMATCH = "ASH_BINDING_MISMATCH"        # HTTP 461
    SCOPE_MISMATCH = "ASH_SCOPE_MISMATCH"            # HTTP 473
    CHAIN_BROKEN = "ASH_CHAIN_BROKEN"                # HTTP 474
    TIMESTAMP_INVALID = "ASH_TIMESTAMP_INVALID"      # HTTP 482
    PROOF_MISSING = "ASH_PROOF_MISSING"              # HTTP 483
    CANONICALIZATION_ERROR = "ASH_CANONICALIZATION_ERROR"  # HTTP 422
    MODE_VIOLATION = "ASH_MODE_VIOLATION"            # HTTP 400
    UNSUPPORTED_CONTENT_TYPE = "ASH_UNSUPPORTED_CONTENT_TYPE"  # HTTP 415
    VALIDATION_ERROR = "ASH_VALIDATION_ERROR"        # HTTP 400
    INTERNAL_ERROR = "ASH_INTERNAL_ERROR"            # HTTP 500
```

**Go:**
```go
type AshErrorCode string

const (
    ErrCtxNotFound            AshErrorCode = "ASH_CTX_NOT_FOUND"            // HTTP 450
    ErrCtxExpired             AshErrorCode = "ASH_CTX_EXPIRED"              // HTTP 451
    ErrCtxAlreadyUsed         AshErrorCode = "ASH_CTX_ALREADY_USED"         // HTTP 452
    ErrProofInvalid           AshErrorCode = "ASH_PROOF_INVALID"            // HTTP 460
    ErrBindingMismatch        AshErrorCode = "ASH_BINDING_MISMATCH"         // HTTP 461
    ErrScopeMismatch          AshErrorCode = "ASH_SCOPE_MISMATCH"           // HTTP 473
    ErrChainBroken            AshErrorCode = "ASH_CHAIN_BROKEN"             // HTTP 474
    ErrTimestampInvalid       AshErrorCode = "ASH_TIMESTAMP_INVALID"        // HTTP 482
    ErrProofMissing           AshErrorCode = "ASH_PROOF_MISSING"            // HTTP 483
    ErrCanonicalizationError  AshErrorCode = "ASH_CANONICALIZATION_ERROR"   // HTTP 422
    ErrModeViolation          AshErrorCode = "ASH_MODE_VIOLATION"           // HTTP 400
    ErrUnsupportedContentType AshErrorCode = "ASH_UNSUPPORTED_CONTENT_TYPE" // HTTP 415
    ErrValidationError        AshErrorCode = "ASH_VALIDATION_ERROR"         // HTTP 400
    ErrInternalError          AshErrorCode = "ASH_INTERNAL_ERROR"           // HTTP 500
)
```

**PHP:**
```php
enum AshErrorCode: string
{
    case CtxNotFound = 'ASH_CTX_NOT_FOUND';              // HTTP 450
    case CtxExpired = 'ASH_CTX_EXPIRED';                 // HTTP 451
    case CtxAlreadyUsed = 'ASH_CTX_ALREADY_USED';        // HTTP 452
    case ProofInvalid = 'ASH_PROOF_INVALID';             // HTTP 460
    case BindingMismatch = 'ASH_BINDING_MISMATCH';       // HTTP 461
    case ScopeMismatch = 'ASH_SCOPE_MISMATCH';           // HTTP 473
    case ChainBroken = 'ASH_CHAIN_BROKEN';               // HTTP 474
    case TimestampInvalid = 'ASH_TIMESTAMP_INVALID';     // HTTP 482
    case ProofMissing = 'ASH_PROOF_MISSING';             // HTTP 483
    case CanonicalizationError = 'ASH_CANONICALIZATION_ERROR';  // HTTP 422
    case ModeViolation = 'ASH_MODE_VIOLATION';           // HTTP 400
    case UnsupportedContentType = 'ASH_UNSUPPORTED_CONTENT_TYPE';  // HTTP 415
    case ValidationError = 'ASH_VALIDATION_ERROR';       // HTTP 400
    case InternalError = 'ASH_INTERNAL_ERROR';           // HTTP 500
}
```

**C#:**
```csharp
public static class AshErrorCode
{
    public const string CtxNotFound = "ASH_CTX_NOT_FOUND";              // HTTP 450
    public const string CtxExpired = "ASH_CTX_EXPIRED";                 // HTTP 451
    public const string CtxAlreadyUsed = "ASH_CTX_ALREADY_USED";        // HTTP 452
    public const string ProofInvalid = "ASH_PROOF_INVALID";             // HTTP 460
    public const string BindingMismatch = "ASH_BINDING_MISMATCH";       // HTTP 461
    public const string ScopeMismatch = "ASH_SCOPE_MISMATCH";           // HTTP 473
    public const string ChainBroken = "ASH_CHAIN_BROKEN";               // HTTP 474
    public const string TimestampInvalid = "ASH_TIMESTAMP_INVALID";     // HTTP 482
    public const string ProofMissing = "ASH_PROOF_MISSING";             // HTTP 483
    public const string CanonicalizationError = "ASH_CANONICALIZATION_ERROR";  // HTTP 422
    public const string ModeViolation = "ASH_MODE_VIOLATION";           // HTTP 400
    public const string UnsupportedContentType = "ASH_UNSUPPORTED_CONTENT_TYPE";  // HTTP 415
    public const string ValidationError = "ASH_VALIDATION_ERROR";       // HTTP 400
    public const string InternalError = "ASH_INTERNAL_ERROR";           // HTTP 500
}
```

---

## Error Response Format

SDKs SHOULD return errors in this JSON format:

```json
{
  "error": {
    "code": "ASH_CTX_EXPIRED",
    "message": "Context has expired",
    "details": {
      "contextId": "ash_abc123",
      "expiredAt": "2026-01-28T12:00:00Z"
    }
  }
}
```

**Fields:**
- `code` (required): One of the standard error codes
- `message` (required): Human-readable error description
- `details` (optional): Additional context-specific information

---

## Security Considerations

### Error Message Disclosure

- **Server-side logging**: Log detailed error information including contextId, binding, timestamps
- **Client-facing responses**: Return only the error code and generic message
- **Never expose**: Internal state, nonces, or cryptographic details in error responses

### Timing Attack Prevention

Error responses SHOULD be returned in constant time to prevent timing-based information disclosure about:
- Whether a contextId exists
- How close a proof was to being valid
- The stage at which verification failed

---

## Migration Notes

### From Legacy Error Codes

If your SDK uses different error codes, map them to the standard codes:

| Legacy (Node.js) | Standard |
|------------------|----------|
| `MISSING_CONTEXT_ID` | `ASH_CTX_NOT_FOUND` |
| `CONTEXT_USED` | `ASH_CTX_ALREADY_USED` |
| `INVALID_CONTEXT` | `ASH_CTX_NOT_FOUND` |
| `PROOF_MISMATCH` | `ASH_PROOF_INVALID` |

| Legacy (Python/Go) | Standard |
|--------------------|----------|
| `ASH_INVALID_CONTEXT` | `ASH_CTX_NOT_FOUND` |
| `ASH_REPLAY_DETECTED` | `ASH_CTX_ALREADY_USED` |
| `ASH_INTEGRITY_FAILED` | `ASH_PROOF_INVALID` |
| `ASH_ENDPOINT_MISMATCH` | `ASH_BINDING_MISMATCH` |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.3.4 | 2026-02-05 | Added ASH_VALIDATION_ERROR, ASH_TIMESTAMP_INVALID, ASH_INTERNAL_ERROR |
| 2.0.0 | 2026-02-02 | Unique HTTP status codes (450-499 range) for all ASH errors |
| 1.1.0 | 2026-01-29 | Updated HTTP status codes for better semantics |
| 1.0.0 | 2026-01-28 | Initial specification |

---

**Document maintained by:** 3maem Co. | شركة عمائم
