# ASH Protocol for Go

**Authenticity & Stateless Hardening Protocol** - Tamper-proof, replay-resistant API requests.

```bash
go get github.com/3maem/ash-go
```

## Quick Start

```go
package main

import (
    "fmt"
    ash "github.com/3maem/ash-go"
)

func main() {
    // Canonicalize JSON payload
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
        ContextID:        "ctx_12345",
        CanonicalPayload: canonical,
    })

    fmt.Println("Proof:", proof)
}
```

## Features

- **Deterministic Canonicalization** - JSON and URL-encoded data
- **Cryptographic Proofs** - SHA-256 based integrity verification
- **Timing-Safe Comparison** - Constant-time string and byte comparison
- **Unicode Normalization** - NFC normalization for consistent hashing
- **Zero Dependencies** - Only standard library + golang.org/x/text

## API Reference

### Proof Generation

```go
// Build a cryptographic proof
proof := ash.BuildProof(ash.BuildProofInput{
    Mode:             ash.ModeBalanced,
    Binding:          "POST /api/endpoint",
    ContextID:        "ctx_abc123",
    Nonce:            "nonce_xyz",  // Optional
    CanonicalPayload: `{"key":"value"}`,
})
```

### JSON Canonicalization

```go
// Canonicalize any Go value to deterministic JSON
canonical, err := ash.CanonicalizeJSON(map[string]interface{}{
    "z": 1,
    "a": 2,
})
// Result: {"a":2,"z":1}

// Parse and canonicalize a JSON string
canonical, err := ash.ParseJSON(`{"b": 2, "a": 1}`)
// Result: {"a":1,"b":2}
```

### URL-Encoded Canonicalization

```go
// Canonicalize URL-encoded string
canonical, err := ash.CanonicalizeURLEncoded("b=2&a=1")
// Result: a=1&b=2

// Canonicalize from map
canonical := ash.CanonicalizeURLEncodedFromMap(map[string][]string{
    "b": {"2"},
    "a": {"1"},
})
// Result: a=1&b=2
```

### Binding Normalization

```go
binding := ash.NormalizeBinding("post", "/api//test/?foo=bar")
// Result: "POST /api/test"
```

### Secure Comparison

```go
// Timing-safe string comparison
equal := ash.TimingSafeCompare(proof1, proof2)

// Timing-safe byte comparison
equal := ash.TimingSafeCompareBytes(bytes1, bytes2)
```

## Security Modes

| Mode | Description |
|------|-------------|
| `ModeMinimal` | Basic integrity checking |
| `ModeBalanced` | Recommended for most applications |
| `ModeStrict` | Maximum security with nonce requirement |

## Error Handling

```go
canonical, err := ash.CanonicalizeJSON(data)
if err != nil {
    if ashErr, ok := err.(*ash.AshError); ok {
        switch ashErr.Code {
        case ash.ErrCanonicalizationFailed:
            // Handle canonicalization error
        default:
            // Handle other ASH errors
        }
    }
}
```

## ASH Protocol Availability

| Language | Package | Status |
|----------|---------|--------|
| JavaScript/TypeScript | `@3maem/ash-server`, `@3maem/ash-client-web` | Available |
| Python | `ash-protocol` | Available |
| Go | `github.com/3maem/ash-go` | Available |
| PHP | `3maem/ash-php` | Coming soon |
| Java/Kotlin | `com.3maem:ash-java` | Planned |
| C#/.NET | `3maem.Ash` | Planned |
| Rust | `ash-protocol` | Planned |

## License

Proprietary - 3maem
