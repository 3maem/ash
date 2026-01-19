# ash-core

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) Core - Request integrity and anti-replay protection library for Rust.

## Features

- **Tamper Detection**: Cryptographic proof ensures payload integrity
- **Replay Prevention**: One-time contexts prevent request replay
- **Deterministic**: Byte-identical output across all platforms
- **WASM Compatible**: Works in browsers and server environments

## Installation

```bash
cargo add ash-core
```

## Quick Start

```rust
use ash_core::{canonicalize_json, build_proof, verify_proof, AshMode, VerifyInput};

// Canonicalize a JSON payload
let canonical = canonicalize_json(r#"{"z":1,"a":2}"#).unwrap();
assert_eq!(canonical, r#"{"a":2,"z":1}"#);

// Build a proof
let proof = build_proof(
    AshMode::Balanced,
    "POST /api/update",
    "context-id-123",
    None,
    &canonical,
).unwrap();

// Verify a proof
let expected = proof.clone();
let input = VerifyInput::new(&expected, &proof);
assert!(verify_proof(&input));
```

## API

### Canonicalization

- `canonicalize_json(input: &str)` - Canonicalize JSON to deterministic form
- `canonicalize_urlencoded(input: &str)` - Canonicalize URL-encoded form data

### Proof Generation

- `build_proof(mode, binding, context_id, nonce, payload)` - Generate cryptographic proof
- `verify_proof(input: &VerifyInput)` - Verify proof matches expected value

### Utilities

- `normalize_binding(method, path)` - Normalize HTTP method and path
- `timing_safe_equal(a, b)` - Constant-time byte comparison

### Types

- `AshMode` - Security mode: `Minimal`, `Balanced`, `Strict`
- `AshError` - Error type with code and message
- `BuildProofInput` - Structured input for proof building
- `VerifyInput` - Input for proof verification

## Security Notes

ASH verifies **what** is being submitted, not **who** is submitting it.
It should be used alongside authentication systems (JWT, OAuth, etc.).

## License

ASH Source-Available License (ASAL-1.0)

See [LICENSE](../../LICENSE) for full terms.

© 3maem Co. | شركة عمائم
