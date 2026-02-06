# ash-wasm

[![Crates.io](https://img.shields.io/crates/v/ash-wasm.svg)](https://crates.io/crates/ash-wasm)
[![npm](https://img.shields.io/npm/v/@3maem/ash-wasm)](https://www.npmjs.com/package/@3maem/ash-wasm)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../../LICENSE)

**Developed by 3maem Co. | شركة عمائم**

WebAssembly bindings for ASH (Application Security Hash) - enabling universal access to ASH functionality from any WASM-compatible environment.

## Overview

ASH WASM provides browser and cross-platform access to the ASH protocol through WebAssembly. It wraps the Rust `ash-core` implementation for use in:

- **Browsers** (Chrome, Firefox, Safari, Edge)
- **Node.js** (via WASM)
- **Deno**
- **Any WASM runtime** (Python, Go, .NET, PHP)

## Features

- **RFC 8785 Compliant**: JSON Canonicalization Scheme (JCS) for deterministic serialization
- **Browser Compatible**: Works in browsers via WebAssembly
- **Server-Signed Seals**: Cryptographic proof ensures payload integrity without client secrets
- **Zero Client Secrets**: No sensitive keys stored or transmitted by clients
- **Same API**: Consistent with ash-core Rust API
- **Minimal Bundle Size**: Optimized for web delivery (~45KB gzipped)

## Installation

### npm (Node.js / Browsers)

```bash
npm install @3maem/ash-wasm
```

### Cargo (Rust projects using WASM)

```bash
cargo add ash-wasm
```

### Building from Source

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for bundlers (webpack, vite, etc.)
wasm-pack build --target bundler

# Build for Node.js
wasm-pack build --target nodejs

# Build for browsers (no bundler)
wasm-pack build --target web
```

## Quick Start

### Browser / Bundler

```javascript
import * as ash from '@3maem/ash-wasm';

// Initialize (call once)
ash.ashInit();

// Canonicalize JSON
const canonical = ash.ashCanonicalizeJson('{"z":1,"a":2}');
// => '{"a":2,"z":1}'

// Build a proof
const proof = ash.ashBuildProof(
  'balanced',           // mode
  'POST /api/transfer', // binding
  'ctx_abc123',         // contextId
  null,                 // nonce (optional)
  canonical             // payload
);
```

### Node.js

```javascript
const ash = require('@3maem/ash-wasm');

ash.ashInit();

const canonical = ash.ashCanonicalizeJson(JSON.stringify({ amount: 100 }));
console.log(canonical);
```

### Full Client-Server Flow (v2.1)

```javascript
import * as ash from '@3maem/ash-wasm';

ash.ashInit();

// 1. Get context from server (server generates nonce internally)
const { contextId, clientSecret } = await fetch('/ash/context', {
  method: 'POST',
  body: JSON.stringify({ binding: 'POST|/api/transfer|' })
}).then(r => r.json());

// 2. Prepare request
const payload = { amount: 100, to: 'account123' };
const canonical = ash.ashCanonicalizeJson(JSON.stringify(payload));
const bodyHash = ash.ashHashBody(canonical);
const timestamp = Date.now().toString();
const binding = ash.ashNormalizeBinding('POST', '/api/transfer', '');

// 3. Build proof (use ashBuildProofHmac, ashBuildProofV21 is deprecated)
const proof = ash.ashBuildProofHmac(clientSecret, bodyHash, timestamp, binding);

// 4. Send protected request
const response = await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ASH-Context-ID': contextId,
    'X-ASH-Proof': proof,
    'X-ASH-Timestamp': timestamp
  },
  body: JSON.stringify(payload)
});
```

## API Reference

### Initialization

| Function | Description |
|----------|-------------|
| `ashInit()` | Initialize the WASM module (call once) |

### Canonicalization

| Function | Description |
|----------|-------------|
| `ashCanonicalizeJson(input)` | Canonicalize JSON to RFC 8785 form |
| `ashCanonicalizeUrlencoded(input)` | Canonicalize URL-encoded form data |
| `ashCanonicalizeQuery(query)` | Canonicalize URL query string |

### Proof Functions (v1)

| Function | Description |
|----------|-------------|
| `ashBuildProof(mode, binding, contextId, nonce, payload)` | Build legacy proof |
| `ashVerifyProof(expected, actual)` | Constant-time proof comparison |

### Proof Functions (v2.1)

| Function | Description |
|----------|-------------|
| `ashGenerateNonce(bytes?)` | Generate cryptographic nonce |
| `ashGenerateContextId()` | Generate unique context ID |
| `ashDeriveClientSecret(nonce, contextId, binding)` | Derive client secret |
| `ashBuildProofHmac(secret, bodyHash, timestamp, binding)` | Build HMAC-SHA256 proof |
| `ashVerifyProofHmac(nonce, contextId, proof, bodyHash, timestamp, binding)` | Verify proof |
| `ashHashBody(body)` | SHA-256 hash of body |

### Proof Functions (v2.2 - Scoping)

| Function | Description |
|----------|-------------|
| `ashBuildProofScoped(secret, timestamp, binding, payload, scope)` | Build scoped proof |
| `ashVerifyProofScoped(...)` | Verify scoped proof |
| `ashHashScopedBody(payload, scope)` | Hash scoped fields |

### Proof Functions (v2.3 - Unified)

| Function | Description |
|----------|-------------|
| `ashBuildProofUnified(secret, timestamp, binding, payload, scope, previousProof)` | Build unified proof |
| `ashVerifyProofUnified(...)` | Verify unified proof |
| `ashHashProof(proof)` | Hash proof for chaining |

### Binding & Utilities

| Function | Description |
|----------|-------------|
| `ashNormalizeBinding(method, path, query)` | Normalize endpoint binding |
| `ashNormalizeBindingFromUrl(method, fullPath)` | Normalize from full URL |
| `ashTimingSafeEqual(a, b)` | Constant-time string comparison |
| `ashVersion()` | Get protocol version |
| `ashLibraryVersion()` | Get library version |

### Legacy Functions (Deprecated)

These functions work but will be removed in v3.0. Use the recommended versions:

| Deprecated | Use Instead |
|------------|-------------|
| `canonicalizeJson()` | `ashCanonicalizeJson()` |
| `canonicalizeUrlencoded()` | `ashCanonicalizeUrlencoded()` |
| `buildProof()` | `ashBuildProof()` |
| `verifyProof()` | `ashVerifyProof()` |
| `normalizeBinding()` | `ashNormalizeBinding()` |
| `canonicalizeQuery()` | `ashCanonicalizeQuery()` |
| `ashBuildProofV21()` | `ashBuildProofHmac()` |
| `ashVerifyProofV21()` | `ashVerifyProofHmac()` |

## TypeScript Support

Type definitions are included:

```typescript
import * as ash from '@3maem/ash-wasm';

const canonical: string = ash.ashCanonicalizeJson('{"a":1}');
const isValid: boolean = ash.ashVerifyProof(expected, actual);
```

## Error Handling (v2.3.4 - Unique HTTP Status Codes)

Functions that can fail throw JavaScript errors. ASH uses unique HTTP status codes (450-499) for precise error identification:

| Code | HTTP | Category | Description |
|------|------|----------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Context | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Seal | Proof invalid |
| `ASH_BINDING_MISMATCH` | 461 | Binding | Binding mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Verification | Scope mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Verification | Chain broken |
| `ASH_TIMESTAMP_INVALID` | 482 | Format | Timestamp invalid |
| `ASH_PROOF_MISSING` | 483 | Format | Proof missing |

```javascript
try {
  const canonical = ash.ashCanonicalizeJson('invalid json');
} catch (e) {
  console.error('Canonicalization failed:', e.message);
}
```

## Browser Compatibility

| Browser | Version | Notes |
|---------|---------|-------|
| Chrome | 57+ | Full support |
| Firefox | 52+ | Full support |
| Safari | 11+ | Full support |
| Edge | 16+ | Full support |

## Bundle Size

| Build | Size (gzip) |
|-------|-------------|
| Bundler | ~45KB |
| Web | ~50KB |
| Node.js | ~48KB |

## Performance

WASM provides near-native performance:

| Operation | WASM | Native Rust |
|-----------|------|-------------|
| JSON canonicalization | ~60μs | ~50μs |
| Proof generation | ~4μs | ~3μs |
| Proof verification | ~8μs | ~6μs |

## Input Validation (v2.3.4)

All SDKs now implement consistent input validation. Invalid inputs throw JavaScript errors with descriptive messages.

### Validation Rules

| Parameter | Rule |
|-----------|------|
| `nonce` | Minimum 32 hex characters |
| `nonce` | Maximum 128 characters |
| `nonce` | Hexadecimal only (0-9, a-f, A-F) |
| `contextId` | Cannot be empty |
| `contextId` | Maximum 256 characters |
| `contextId` | Alphanumeric, underscore, hyphen, dot only |
| `binding` | Maximum 8192 bytes |

### Example

```javascript
try {
  const secret = ash.ashDeriveClientSecret(nonce, contextId, binding);
} catch (e) {
  console.error('Validation failed:', e.message);
}
```

## Security Notes

- All cryptographic operations use the same Rust implementation as native SDKs
- Constant-time comparison prevents timing attacks
- WASM sandbox provides memory isolation
- No sensitive data is logged or exposed
- Input validation prevents weak nonces and malformed context IDs

## Building for Different Targets

```bash
# For webpack/vite/rollup
wasm-pack build --target bundler --out-dir pkg-bundler

# For Node.js require()
wasm-pack build --target nodejs --out-dir pkg-node

# For <script> tag (no bundler)
wasm-pack build --target web --out-dir pkg-web

# For Deno
wasm-pack build --target deno --out-dir pkg-deno
```

## Related Packages

- [`ash-core`](https://crates.io/crates/ash-core) - Core Rust implementation
- [`@3maem/ash-node`](https://www.npmjs.com/package/@3maem/ash-node) - Native Node.js SDK

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
- [npm Package](https://www.npmjs.com/package/@3maem/ash-wasm)
- [Security Policy](../../SECURITY.md)

© 3maem Co. | شركة عمائم
