# ASH SDK for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/3maem/ash-go/v2.svg)](https://pkg.go.dev/github.com/3maem/ash-go/v2)
[![Go](https://img.shields.io/badge/go-%3E%3D1.24.13-brightgreen)](https://golang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../../LICENSE)
[![Version](https://img.shields.io/badge/version-2.3.4-blue)](../../CHANGELOG.md)

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package offers JCS canonicalization, proof generation, and constant-time comparison utilities for Go applications.

## Installation

```bash
go get github.com/3maem/ash-go/v2@v2.3.4
```

**Requirements:** Go 1.24.13 or later

## Quick Start

### Canonicalize JSON

```go
package main

import (
    "fmt"
    ash "github.com/3maem/ash-go/v2"
)

func main() {
    // Canonicalize from Go value
    payload := map[string]interface{}{
        "z": 1,
        "a": 2,
        "name": "John",
    }
    canonical, err := ash.CanonicalizeJSON(payload)
    if err != nil {
        panic(err)
    }
    fmt.Println(canonical) // {"a":2,"name":"John","z":1}

    // Parse and canonicalize JSON string
    canonical, err = ash.ParseJSON(`{"z": 1, "a": 2}`)
    if err != nil {
        panic(err)
    }
    fmt.Println(canonical) // {"a":2,"z":1}
}
```

### Build a Proof

```go
package main

import (
    "fmt"
    ash "github.com/3maem/ash-go/v2"
)

func main() {
    // Canonicalize payload
    payload := map[string]interface{}{
        "username": "test",
        "password": "secret",
    }
    canonical, err := ash.CanonicalizeJSON(payload)
    if err != nil {
        panic(err)
    }

    // Build proof
    proof := ash.BuildProof(ash.BuildProofInput{
        Mode:             ash.ModeBalanced,
        Binding:          ash.NormalizeBinding("POST", "/api/login"),
        ContextID:        "ctx_abc123",
        Nonce:            "",  // Optional: for server-assisted mode
        CanonicalPayload: canonical,
    })

    fmt.Println("Proof:", proof)
}
```

### Verify a Proof

```go
package main

import (
    "fmt"
    ash "github.com/3maem/ash-go/v2"
)

func main() {
    expectedProof := "abc123..."
    receivedProof := "abc123..."

    // Use timing-safe comparison to prevent timing attacks
    if ash.TimingSafeCompare(expectedProof, receivedProof) {
        fmt.Println("Proof verified successfully")
    } else {
        fmt.Println("Proof verification failed")
    }
}
```

## API Reference

### Canonicalization

#### `CanonicalizeJSON(value interface{}) (string, error)`

Canonicalizes any Go value to a deterministic JSON string.

**Rules (RFC 8785 JCS):**
- Object keys sorted lexicographically (UTF-16 code units)
- No whitespace
- Unicode NFC normalized
- Minimal JSON escaping (only \b, \t, \n, \f, \r, \", \\)
- Numbers normalized (no scientific notation, no trailing zeros)
- NaN and Infinity values are rejected

```go
canonical, err := ash.CanonicalizeJSON(map[string]interface{}{
    "z": 1,
    "a": 2,
})
// Result: {"a":2,"z":1}
```

#### `ParseJSON(jsonStr string) (string, error)`

Parses a JSON string and returns its canonical form.

```go
canonical, err := ash.ParseJSON(`{"b": 2, "a": 1}`)
// Result: {"a":1,"b":2}
```

#### `CanonicalizeURLEncoded(input string) (string, error)`

Canonicalizes URL-encoded form data.

```go
canonical, err := ash.CanonicalizeURLEncoded("b=2&a=1")
// Result: a=1&b=2
```

#### `CanonicalizeURLEncodedFromMap(data map[string][]string) string`

Canonicalizes URL-encoded data from a map.

```go
canonical := ash.CanonicalizeURLEncodedFromMap(map[string][]string{
    "b": {"2"},
    "a": {"1"},
})
// Result: a=1&b=2
```

### Proof Generation

#### `BuildProof(input BuildProofInput) string`

Builds a cryptographic proof from the given inputs.

```go
type BuildProofInput struct {
    Mode             AshMode  // Security mode
    Binding          string   // Canonical binding: "METHOD /path"
    ContextID        string   // Server-issued context ID
    Nonce            string   // Optional server-issued nonce
    CanonicalPayload string   // Canonicalized payload string
}

proof := ash.BuildProof(ash.BuildProofInput{
    Mode:             ash.ModeBalanced,
    Binding:          "POST /api/endpoint",
    ContextID:        "ctx_abc123",
    Nonce:            "nonce_xyz",  // Optional
    CanonicalPayload: `{"key":"value"}`,
})
```

### Binding Normalization

#### `NormalizeBinding(method, path string) string`

Normalizes a binding string to canonical form.

**Rules:**
- Method uppercased
- Path starts with /
- Query string excluded
- Duplicate slashes collapsed
- Trailing slash removed (except for root)

```go
binding := ash.NormalizeBinding("post", "/api//test/?foo=bar")
// Result: "POST /api/test"
```

### Secure Comparison

#### `TimingSafeCompare(a, b string) bool`

Compares two strings in constant time to prevent timing attacks.

```go
equal := ash.TimingSafeCompare(proof1, proof2)
```

#### `TimingSafeCompareBytes(a, b []byte) bool`

Compares two byte slices in constant time.

```go
equal := ash.TimingSafeCompareBytes(bytes1, bytes2)
```

### Encoding Utilities

#### `Base64URLEncode(data []byte) string`

Encodes data as Base64URL without padding (RFC 4648 Section 5).

```go
encoded := ash.Base64URLEncode(hash[:])
```

#### `Base64URLDecode(input string) ([]byte, error)`

Decodes a Base64URL string to bytes.

```go
decoded, err := ash.Base64URLDecode(encoded)
```

## Security Modes

| Mode | Constant | Description |
|------|----------|-------------|
| Minimal | `ModeMinimal` | Basic integrity checking |
| Balanced | `ModeBalanced` | Recommended for most applications |
| Strict | `ModeStrict` | Maximum security with nonce requirement |

## Input Validation (v2.3.4)

All SDKs now implement consistent input validation in `AshDeriveClientSecret`. Invalid inputs are rejected with descriptive errors.

### Validation Rules

| Parameter | Rule | Error |
|-----------|------|-------|
| `nonce` | Minimum 32 hex characters | `ErrProofInvalid` |
| `nonce` | Maximum 128 characters | `ErrProofInvalid` |
| `nonce` | Hexadecimal only (0-9, a-f, A-F) | `ErrProofInvalid` |
| `contextID` | Cannot be empty | `ErrProofInvalid` |
| `contextID` | Maximum 256 characters | `ErrProofInvalid` |
| `contextID` | Alphanumeric, underscore, hyphen, dot only | `ErrProofInvalid` |
| `binding` | Maximum 8192 bytes | `ErrProofInvalid` |

### Breaking Change (v2.3.4)

**Important:** Functions that previously returned only a value now also return an error:

```go
// Before v2.3.4 (DEPRECATED)
secret := ash.AshDeriveClientSecretUnsafe(nonce, contextID, binding)

// After v2.3.4 (RECOMMENDED)
secret, err := ash.AshDeriveClientSecret(nonce, contextID, binding)
if err != nil {
    // Handle validation error
}
```

The `*Unsafe` variants are provided for backward compatibility but are deprecated.

### Validation Constants

```go
const (
    MinNonceHexChars   = 32    // Minimum nonce length
    MaxNonceLength     = 128   // Maximum nonce length
    MaxContextIDLength = 256   // Maximum context ID length
    MaxBindingLength   = 8192  // Maximum binding length (8KB)
)
```

## Error Handling

The SDK uses typed errors for precise error handling:

```go
canonical, err := ash.CanonicalizeJSON(data)
if err != nil {
    if ashErr, ok := err.(*ash.AshError); ok {
        switch ashErr.Code {
        case ash.ErrCanonicalizationFailed:
            // Handle canonicalization error
        case ash.ErrModeViolation:
            // Handle mode violation
        default:
            // Handle other ASH errors
        }
    }
}
```

### Error Codes (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

| Code | HTTP | Description |
|------|------|-------------|
| `ErrCtxNotFound` | 450 | Context not found |
| `ErrCtxExpired` | 451 | Context has expired |
| `ErrCtxAlreadyUsed` | 452 | Replay attack detected |
| `ErrProofInvalid` | 460 | Proof verification failed |
| `ErrBindingMismatch` | 461 | Endpoint binding mismatch |
| `ErrScopeMismatch` | 473 | Scope hash mismatch |
| `ErrChainBroken` | 474 | Chain verification failed |
| `ErrProofMissing` | 483 | Missing proof header |
| `ErrCanonicalizationError` | 422 | Canonicalization failed |
| `ErrModeViolation` | 400 | Security mode violation |
| `ErrUnsupportedContentType` | 415 | Content type not supported |

## Types

### StoredContext

```go
type StoredContext struct {
    ContextID  string    // Unique context identifier
    Binding    string    // Canonical binding: "METHOD /path"
    Mode       AshMode   // Security mode
    IssuedAt   int64     // Timestamp when issued (ms epoch)
    ExpiresAt  int64     // Timestamp when expires (ms epoch)
    Nonce      string    // Optional nonce
    ConsumedAt int64     // Timestamp when consumed (0 if not)
}
```

### ContextPublicInfo

```go
type ContextPublicInfo struct {
    ContextID string  `json:"contextId"`
    ExpiresAt int64   `json:"expiresAt"`
    Mode      AshMode `json:"mode"`
    Nonce     string  `json:"nonce,omitempty"`
}
```

## Complete Example

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"

    ash "github.com/3maem/ash-go/v2"
)

// Client-side: Build proof for a request
func buildRequest() {
    payload := map[string]interface{}{
        "action": "update",
        "value":  42,
    }

    canonical, _ := ash.CanonicalizeJSON(payload)

    proof := ash.BuildProof(ash.BuildProofInput{
        Mode:             ash.ModeBalanced,
        Binding:          "POST /api/update",
        ContextID:        "ctx_received_from_server",
        CanonicalPayload: canonical,
    })

    // Add headers to your HTTP request
    req, _ := http.NewRequest("POST", "https://api.example.com/api/update", nil)
    req.Header.Set("X-ASH-Context-ID", "ctx_received_from_server")
    req.Header.Set("X-ASH-Proof", proof)
    req.Header.Set("Content-Type", "application/json")
}

// Server-side: Verify proof
func verifyRequest(contextID, receivedProof, binding, payload string) bool {
    // Canonicalize the received payload
    var data interface{}
    json.Unmarshal([]byte(payload), &data)
    canonical, _ := ash.CanonicalizeJSON(data)

    // Build expected proof (using stored context info)
    expectedProof := ash.BuildProof(ash.BuildProofInput{
        Mode:             ash.ModeBalanced,
        Binding:          binding,
        ContextID:        contextID,
        CanonicalPayload: canonical,
    })

    // Verify using timing-safe comparison
    return ash.TimingSafeCompare(expectedProof, receivedProof)
}

func main() {
    fmt.Println("ASH Go SDK v" + ash.Version)
}
```

## Gin Middleware

The SDK includes a ready-to-use middleware for the [Gin](https://github.com/gin-gonic/gin) web framework.

### Basic Usage

```go
package main

import (
    "github.com/gin-gonic/gin"
    ash "github.com/3maem/ash-go/v2"
)

func main() {
    r := gin.Default()
    store := ash.NewAshMemoryStore()

    // Protected endpoint
    r.POST("/api/transfer", ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
        Store: store,
    }), func(c *gin.Context) {
        c.JSON(200, gin.H{"success": true})
    })

    r.Run(":8080")
}
```

### With Unified Verification (v2.3 Scoping + Chaining)

```go
r.POST("/api/transfer", ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
    Store:         store,
    EnableUnified: true,
}), func(c *gin.Context) {
    // Access verified scope from context
    scope, _ := c.Get("ashScope")
    chainHash, _ := c.Get("ashChainHash")

    c.JSON(200, gin.H{
        "success": true,
        "scope":   scope,
    })
})
```

### Middleware Options

```go
type AshGinMiddlewareOptions struct {
    // Store is the context store instance (required)
    Store AshContextStore

    // ExpectedBinding overrides the binding computed from request (optional)
    ExpectedBinding string

    // EnableUnified enables v2.3 unified verification (scoping + chaining)
    EnableUnified bool

    // MaxTimestampAgeSeconds is the maximum age for timestamps (default: 300)
    MaxTimestampAgeSeconds int

    // Skip is a function to skip verification for certain requests
    Skip func(c *gin.Context) bool

    // OnError is a custom error handler (optional)
    OnError func(c *gin.Context, err *AshVerifyError)

    // EnforceIP verifies the client IP matches the context metadata (v2.3.4)
    EnforceIP bool

    // EnforceUser verifies the user ID matches the context metadata (v2.3.4)
    EnforceUser bool
}
```

### Skip Verification for Certain Paths

```go
r.Use(ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
    Store: store,
    Skip: func(c *gin.Context) bool {
        // Skip health checks and public endpoints
        path := c.Request.URL.Path
        return path == "/health" || path == "/public"
    },
}))
```

### Custom Error Handler

```go
r.POST("/api/secure", ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
    Store: store,
    OnError: func(c *gin.Context, err *ash.AshVerifyError) {
        c.AbortWithStatusJSON(err.StatusCode, gin.H{
            "status":    "error",
            "code":      err.Code,
            "message":   err.Message,
            "timestamp": time.Now().Unix(),
        })
    },
}), handler)
```

### Custom Context Store

Implement the `AshContextStore` interface for custom storage backends (Redis, database, etc.):

```go
type AshContextStore interface {
    Get(id string) (*AshMiddlewareContext, error)
    Consume(id string) error
    Store(ctx *AshMiddlewareContext) error
}

// Example Redis implementation
type RedisStore struct {
    client *redis.Client
}

func (s *RedisStore) Get(id string) (*ash.AshMiddlewareContext, error) {
    // Fetch from Redis
}

func (s *RedisStore) Consume(id string) error {
    // Mark as used in Redis with atomic operation
}

func (s *RedisStore) Store(ctx *ash.AshMiddlewareContext) error {
    // Store in Redis with TTL
}
```

### IP and User Binding (v2.3.4)

Enforce that the client IP address and/or authenticated user matches the values stored in the context metadata:

```go
// Store client IP and user ID when creating context
ctx, _ := store.Store(&ash.AshMiddlewareContext{
    ID:       "ctx_abc123",
    Binding:  "POST /api/transfer",
    Metadata: map[string]string{
        "ip":       c.ClientIP(),
        "user_id":  "user_123",
    },
})

// Verify IP and user binding in middleware
r.POST("/api/transfer", ash.AshGinMiddleware(ash.AshGinMiddlewareOptions{
    Store:       store,
    EnforceIP:   true,
    EnforceUser: true,
}), func(c *gin.Context) {
    c.JSON(200, gin.H{"success": true})
})
```

If the IP or user doesn't match, the middleware returns HTTP 461 (`ASH_BINDING_MISMATCH`).

### Environment Configuration (v2.3.4)

The SDK supports environment-based configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `ASH_TRUST_PROXY` | `false` | Enable X-Forwarded-For handling |
| `ASH_TRUSTED_PROXIES` | (empty) | Comma-separated trusted proxy IPs |
| `ASH_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `ASH_RATE_LIMIT_MAX` | `10` | Max contexts per window per IP |
| `ASH_TIMESTAMP_TOLERANCE` | `30` | Clock skew tolerance in seconds |

```go
// Load configuration from environment
config := ash.AshLoadConfig()

// Get client IP with proxy support
clientIP := ash.AshGetClientIP(c.Request)
```

### Accessing Verified Context

After successful verification, the middleware stores metadata in the Gin context:

```go
func handler(c *gin.Context) {
    // Get the verified ASH context
    ctx, _ := c.Get("ashContext")
    ashCtx := ctx.(*ash.AshMiddlewareContext)

    // Get verified scope (v2.3)
    scope, _ := c.Get("ashScope")

    // Get chain hash (v2.3)
    chainHash, _ := c.Get("ashChainHash")

    // Get server scope policy (if any)
    policy, _ := c.Get("ashScopePolicy")

    // Get client IP (v2.3.4)
    clientIP, _ := c.Get("ashClientIP")
}
```

### Error Codes (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

| Code | HTTP Status | Category | Description |
|------|-------------|----------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context | Context ID not found |
| `ASH_CTX_EXPIRED` | 451 | Context | Context has expired |
| `ASH_CTX_ALREADY_USED` | 452 | Context | Replay attack detected |
| `ASH_PROOF_INVALID` | 460 | Seal | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Binding | Endpoint binding mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Verification | Scope hash mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Verification | Chain verification failed |
| `ASH_TIMESTAMP_INVALID` | 482 | Format | Invalid or expired timestamp |
| `ASH_PROOF_MISSING` | 483 | Format | Missing X-ASH-Proof header |
| `ASH_CANONICALIZATION_ERROR` | 422 | Standard | Canonicalization failed |
| `ASH_MODE_VIOLATION` | 400 | Standard | Mode configuration error |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Standard | Content type not supported |

## License

**Apache License 2.0**

See the [LICENSE](https://github.com/3maem/ash/blob/main/LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
