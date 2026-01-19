# ash-wasm

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) WebAssembly bindings - Request integrity and anti-replay protection library.

## Features

- **Browser Compatible**: Works in browsers via WebAssembly
- **Same API**: Consistent with ash-core Rust API
- **Zero Dependencies**: Minimal bundle size

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
