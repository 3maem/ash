# ASH WASM

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package provides WebAssembly bindings for browser environments.

## Features

- **RFC 8785 Compliant**: JSON Canonicalization Scheme (JCS) for deterministic serialization
- **Browser Compatible**: Works in browsers via WebAssembly
- **Server-Signed Seals**: Cryptographic proof ensures payload integrity without client secrets
- **Zero Client Secrets**: No sensitive keys stored or transmitted by clients
- **Same API**: Consistent with ash-core Rust API
- **Minimal Bundle Size**: Optimized for web delivery

## Installation

```bash
cargo add ash-wasm
```

## Usage

This crate provides WebAssembly bindings for the ash-core library, allowing you to use ASH in browser environments.

```javascript
import init, { canonicalize_json, build_proof } from 'ash-wasm';

await init();

const canonical = canonicalize_json('{"z":1,"a":2}');
console.log(canonical); // {"a":2,"z":1}
```

## License

ASH Source-Available License (ASAL-1.0)

See [LICENSE](../../LICENSE) for full terms.

© 3maem Co. | شركة عمائم
