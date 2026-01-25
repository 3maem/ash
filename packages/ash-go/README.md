# ASH SDK for Go

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package offers JCS canonicalization, proof generation, and constant-time comparison utilities for Go applications.

## Installation

```bash
go get github.com/3maem/ash-go/v2@v2.3.3
```

**Requirements:** Go 1.21 or later

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

**Rules:**
- Object keys sorted lexicographically
- No whitespace
- Unicode NFC normalized
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

### Error Codes

| Code | Description |
|------|-------------|
| `ErrInvalidContext` | Invalid context ID |
| `ErrContextExpired` | Context has expired |
| `ErrReplayDetected` | Replay attack detected |
| `ErrIntegrityFailed` | Integrity verification failed |
| `ErrEndpointMismatch` | Endpoint binding mismatch |
| `ErrModeViolation` | Security mode violation |
| `ErrCanonicalizationFailed` | Canonicalization failed |

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

## License

**ASH Source-Available License (ASAL-1.0)**

See the [LICENSE](https://github.com/3maem/ash/blob/main/LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
