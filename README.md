# ASH — Application Security Hash

**Version:** 2.3.4

Request integrity and replay protection for modern applications.

ASH ensures that every request is:

- Authentic
- Unmodified
- Single-use
- Bound to its endpoint

---

## Why ASH?

HTTPS protects transport.
Authentication verifies identity.
Authorization controls access.

But requests themselves can still be replayed or reused.

ASH adds a dedicated integrity layer.

---

## How It Works

```
Client → Sign → Send → Verify → Consume
```

Each request includes a cryptographic proof that becomes invalid after use.

---

## Quick Example

### Server (Node.js)

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
    binding: 'POST|/api/transfer|',
    ttlMs: 30000,
    mode: 'balanced'
  });
  res.json({
    contextId: ctx.id,
    nonce: ctx.nonce
  });
});

// Protected endpoint
app.post(
  '/api/transfer',
  ashExpressMiddleware({ store, expectedBinding: 'POST|/api/transfer|' }),
  (req, res) => {
    res.json({ success: true });
  }
);

app.listen(3000);
```

### Client

```javascript
import {
  ashInit,
  ashCanonicalizeJson,
  ashDeriveClientSecret,
  ashHashBody,
  ashBuildProofHmac,
  ashNormalizeBinding
} from '@3maem/ash-node';

ashInit();

// 1. Get context from server
const { contextId, nonce } = await fetch('/ash/context', {
  method: 'POST'
}).then(r => r.json());

// 2. Prepare request
const payload = { amount: 100, to: 'account123' };
const binding = ashNormalizeBinding('POST', '/api/transfer', '');
const canonical = ashCanonicalizeJson(JSON.stringify(payload));
const bodyHash = ashHashBody(canonical);
const timestamp = Date.now().toString();

// 3. Derive secret and build proof
const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
const proof = ashBuildProofHmac(clientSecret, bodyHash, timestamp, binding);

// 4. Send protected request
await fetch('/api/transfer', {
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

---

## What ASH is NOT

ASH is not authentication.
ASH is not authorization.
ASH is not a firewall.

It is an additional security layer.

---

## Available SDKs

| Language | Package | Install |
|----------|---------|---------|
| **Node.js** | `@3maem/ash-node` | `npm install @3maem/ash-node` |
| **Python** | `ash-sdk` | `pip install ash-sdk` |
| **Go** | `github.com/3maem/ash-go` | `go get github.com/3maem/ash-go` |
| **PHP** | `3maem/ash-sdk-php` | `composer require 3maem/ash-sdk-php` |
| **Rust** | `ash-core` | `cargo add ash-core` |
| **WASM** | `@3maem/ash-wasm` | `npm install @3maem/ash-wasm` |

---

## Documentation

- [Security Guide](docs/security/security-checklist.md)
- [Architecture](docs/security/architecture.md)
- [Error Codes](docs/reference/error-codes.md)
- [API Reference](docs/reference/)
- [Middleware Reference](docs/reference/middleware.md)

---

## Troubleshooting

Common integration issues and solutions are documented here:

[docs/troubleshooting.md](docs/troubleshooting.md)

---

## License

Apache 2.0

See [LICENSE](LICENSE) for full terms.

---

**Developed by 3maem Co. | شركة عمائم**
