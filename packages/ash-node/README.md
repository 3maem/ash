# ASH SDK for Node.js

[![npm](https://img.shields.io/npm/v/@3maem/ash-node.svg)](https://www.npmjs.com/package/@3maem/ash-node)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-ASAL--1.0-blue)](../../LICENSE)
[![Version](https://img.shields.io/badge/version-2.3.4-blue)](../../CHANGELOG.md)

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package provides JCS canonicalization, proof generation, and middleware for Express and Fastify.

## Installation

```bash
npm install @3maem/ash-node
```

**Requirements:** Node.js 18.0.0 or later

## Quick Start

### Initialize the Library

```typescript
import { ashInit } from '@3maem/ash-node';

// Call once before using other functions
ashInit();
```

### Canonicalize JSON

```typescript
import { ashCanonicalizeJson, ashInit } from '@3maem/ash-node';

ashInit();

// Canonicalize JSON to deterministic form
const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
console.log(canonical); // {"a":2,"z":1}
```

### Build a Proof

```typescript
import { ashInit, ashCanonicalizeJson, ashBuildProof } from '@3maem/ash-node';

ashInit();

// Canonicalize payload
const payload = JSON.stringify({ username: 'test', action: 'login' });
const canonical = ashCanonicalizeJson(payload);

// Build proof
const proof = ashBuildProof(
  'balanced',           // mode
  'POST /api/login',    // binding
  'ctx_abc123',         // contextId
  null,                 // nonce (optional)
  canonical             // canonicalPayload
);

console.log(`Proof: ${proof}`);
```

### Verify a Proof

```typescript
import { ashInit, ashVerifyProof } from '@3maem/ash-node';

ashInit();

const expectedProof = 'abc123...';
const receivedProof = 'abc123...';

// Use timing-safe comparison to prevent timing attacks
if (ashVerifyProof(expectedProof, receivedProof)) {
  console.log('Proof verified successfully');
} else {
  console.log('Proof verification failed');
}
```

## Express Integration

```typescript
import express from 'express';
import {
  ashInit,
  ashExpressMiddleware,
  AshMemoryStore,
} from '@3maem/ash-node';

ashInit();

const app = express();
const store = new AshMemoryStore();

app.use(express.json());

// Issue context endpoint
app.post('/ash/context', async (req, res) => {
  const context = await store.create({
    binding: 'POST /api/update',
    ttlMs: 30000,
    mode: 'balanced',
  });

  res.json({
    contextId: context.id,
    expiresAt: context.expiresAt,
    mode: context.mode,
  });
});

// Protected endpoint with middleware
app.post(
  '/api/update',
  ashExpressMiddleware({
    store,
    expectedBinding: 'POST /api/update',
  }),
  (req, res) => {
    // Request verified - safe to process
    res.json({ status: 'success' });
  }
);

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Fastify Integration

```typescript
import Fastify from 'fastify';
import {
  ashInit,
  ashFastifyPlugin,
  AshMemoryStore,
} from '@3maem/ash-node';

ashInit();

const fastify = Fastify();
const store = new AshMemoryStore();

// Register ASH plugin
fastify.register(ashFastifyPlugin, {
  store,
  protectedPaths: ['/api/*'],
});

// Issue context endpoint
fastify.post('/ash/context', async (request, reply) => {
  const context = await store.create({
    binding: 'POST /api/update',
    ttlMs: 30000,
    mode: 'balanced',
  });

  return {
    contextId: context.id,
    expiresAt: context.expiresAt,
    mode: context.mode,
  };
});

// Protected endpoint
fastify.post('/api/update', async (request, reply) => {
  // Request verified by plugin
  return { status: 'success' };
});

fastify.listen({ port: 3000 });
```

## API Reference

### Initialization

#### `ashInit(): void`

Initialize the ASH library. Call once before using other functions.

```typescript
import { ashInit } from '@3maem/ash-node';

ashInit();
```

### Canonicalization

#### `ashCanonicalizeJson(input: string): string`

Canonicalizes JSON to deterministic form per RFC 8785 (JCS).

**Rules:**
- Object keys sorted lexicographically (UTF-16 code units)
- No whitespace
- Unicode NFC normalized
- Minimal JSON escaping (only \b, \t, \n, \f, \r, \", \\)
- Numbers normalized (no leading zeros, no trailing decimal zeros)

```typescript
const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
// Result: '{"a":2,"z":1}'
```

#### `ashCanonicalizeUrlencoded(input: string): string`

Canonicalizes URL-encoded form data.

```typescript
const canonical = ashCanonicalizeUrlencoded('z=1&a=2');
// Result: 'a=2&z=1'
```

### Proof Generation

#### `ashBuildProof(mode, binding, contextId, nonce, canonicalPayload): string`

Builds a cryptographic proof for request integrity.

```typescript
const proof = ashBuildProof(
  'balanced',           // mode: 'minimal' | 'balanced' | 'strict'
  'POST /api/update',   // binding
  'ctx_abc123',         // contextId
  null,                 // nonce (optional)
  '{"name":"John"}'     // canonicalPayload
);
```

#### `ashVerifyProof(expected: string, actual: string): boolean`

Verifies two proofs match using constant-time comparison.

```typescript
const isValid = ashVerifyProof(expectedProof, receivedProof);
```

### Binding Normalization

#### `ashNormalizeBinding(method: string, path: string): string`

Normalizes a binding string to canonical form.

**Rules:**
- Method uppercased
- Path starts with /
- Query string excluded
- Duplicate slashes collapsed
- Trailing slash removed (except for root)

```typescript
const binding = ashNormalizeBinding('post', '/api//test/');
// Result: 'POST /api/test'
```

### Secure Comparison

#### `ashTimingSafeEqual(a: string, b: string): boolean`

Constant-time string comparison to prevent timing attacks.

```typescript
const isEqual = ashTimingSafeEqual('secret1', 'secret2');
```

### Version Information

#### `ashVersion(): string`

Returns the ASH protocol version (e.g., "ASHv1").

#### `ashLibraryVersion(): string`

Returns the library semantic version.

## Types

### AshMode

```typescript
type AshMode = 'minimal' | 'balanced' | 'strict';
```

| Mode | Description |
|------|-------------|
| `minimal` | Basic integrity checking |
| `balanced` | Recommended for most applications |
| `strict` | Maximum security with nonce requirement |

### AshContext

```typescript
interface AshContext {
  id: string;                          // Unique context identifier
  binding: string;                     // Endpoint binding
  expiresAt: number;                   // Expiration timestamp (Unix ms)
  mode: AshMode;                       // Security mode
  used: boolean;                       // Whether context has been used
  nonce?: string;                      // Optional server-generated nonce
  metadata?: Record<string, unknown>;  // Optional metadata
}
```

### AshVerifyResult

```typescript
interface AshVerifyResult {
  valid: boolean;                      // Whether verification succeeded
  errorCode?: string;                  // Error code if failed
  errorMessage?: string;               // Error message if failed
  metadata?: Record<string, unknown>;  // Context metadata (on success)
}
```

### AshContextStore

```typescript
interface AshContextStore {
  create(options: AshContextOptions): Promise<AshContext>;
  get(id: string): Promise<AshContext | null>;
  consume(id: string): Promise<boolean>;
  cleanup(): Promise<number>;
}
```

## Context Stores

### AshMemoryStore

In-memory store for development and testing.

```typescript
import { AshMemoryStore } from '@3maem/ash-node';

const store = new AshMemoryStore();
```

### AshRedisStore

Production-ready store with atomic operations.

```typescript
import { AshRedisStore } from '@3maem/ash-node';
import Redis from 'ioredis';

const redis = new Redis('redis://localhost:6379');
const store = new AshRedisStore(redis);
```

### AshSqlStore

SQL-based store for relational databases.

```typescript
import { AshSqlStore } from '@3maem/ash-node';

const store = new AshSqlStore(databaseConnection);
```

## Environment Configuration (v2.3.4)

The SDK supports environment-based configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `ASH_TRUST_PROXY` | `false` | Enable X-Forwarded-For handling |
| `ASH_TRUSTED_PROXIES` | (empty) | Comma-separated trusted proxy IPs |
| `ASH_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `ASH_RATE_LIMIT_MAX` | `10` | Max contexts per window per IP |
| `ASH_TIMESTAMP_TOLERANCE` | `30` | Clock skew tolerance in seconds |

```typescript
// Configuration is automatically loaded from environment
// Access via the DEFAULT_* constants
import { 
  DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
  DEFAULT_RATE_LIMIT_MAX_CONTEXTS,
  DEFAULT_TIMESTAMP_TOLERANCE_SECONDS 
} from '@3maem/ash-node';
```

## Express Middleware

### `ashExpressMiddleware(options: AshExpressOptions): RequestHandler`

Creates ASH verification middleware for Express.

```typescript
interface AshExpressOptions {
  store: AshContextStore;              // Context store instance (required)
  expectedBinding?: string;            // Expected endpoint binding
  mode?: AshMode;                      // Security mode (default: balanced)
  onError?: (error, req, res, next) => void;  // Custom error handler
  skip?: (req) => boolean;             // Skip verification condition
  enforceIp?: boolean;                 // Verify client IP matches context (v2.3.4)
  enforceUser?: boolean;               // Verify user matches context (v2.3.4)
  userIdExtractor?: (req) => string;   // Extract user ID from request (v2.3.4)
}
```

### IP and User Binding (v2.3.4)

Enforce that the client IP address and/or authenticated user matches the values stored in the context metadata:

```typescript
// Store client IP and user ID when creating context
app.post('/ash/context', async (req, res) => {
  const context = await store.create({
    binding: 'POST /api/transfer',
    ttlMs: 30000,
    mode: 'balanced',
    metadata: { 
      ip: req.ip,
      user_id: req.user?.id 
    },
  });
  res.json({ contextId: context.id });
});

// Verify IP and user binding in middleware
app.post(
  '/api/transfer',
  ashExpressMiddleware({
    store,
    expectedBinding: 'POST /api/transfer',
    enforceIp: true,
    enforceUser: true,
    userIdExtractor: (req) => req.user?.id,
  }),
  handler
);
```

If the IP or user doesn't match, the middleware returns HTTP 461 (`ASH_BINDING_MISMATCH`).

### Usage

```typescript
import express from 'express';
import { ashExpressMiddleware, AshMemoryStore } from '@3maem/ash-node';

const app = express();
const store = new AshMemoryStore();

// Apply to specific route
app.post(
  '/api/update',
  ashExpressMiddleware({
    store,
    expectedBinding: 'POST /api/update',
  }),
  handler
);

// Custom error handling
app.post(
  '/api/sensitive',
  ashExpressMiddleware({
    store,
    onError: (error, req, res, next) => {
      console.error('ASH verification failed:', error);
      res.status(403).json({ error: error.code });
    },
  }),
  handler
);

// Skip verification conditionally
app.post(
  '/api/data',
  ashExpressMiddleware({
    store,
    skip: (req) => req.headers['x-internal'] === 'true',
  }),
  handler
);
```

## Client Usage

For Node.js clients making requests to ASH-protected endpoints:

```typescript
import { ashInit, ashCanonicalizeJson, ashBuildProof } from '@3maem/ash-node';
import axios from 'axios';

ashInit();

async function makeProtectedRequest() {
  // 1. Get context from server
  const { data: context } = await axios.post('https://api.example.com/ash/context');

  // 2. Prepare payload
  const payload = { name: 'John', action: 'update' };
  const canonical = ashCanonicalizeJson(JSON.stringify(payload));

  // 3. Build proof
  const proof = ashBuildProof(
    context.mode,
    'POST /api/update',
    context.contextId,
    context.nonce ?? null,
    canonical
  );

  // 4. Make protected request
  const response = await axios.post(
    'https://api.example.com/api/update',
    payload,
    {
      headers: {
        'X-ASH-Context-ID': context.contextId,
        'X-ASH-Proof': proof,
        'Content-Type': 'application/json',
      },
    }
  );

  return response.data;
}
```

## Complete Server Example

```typescript
import express from 'express';
import {
  ashInit,
  ashExpressMiddleware,
  ashNormalizeBinding,
  AshMemoryStore,
} from '@3maem/ash-node';

ashInit();

const app = express();
const store = new AshMemoryStore();

app.use(express.json());

// Issue context endpoint
app.post('/ash/context', async (req, res) => {
  const { binding = 'POST /api/update', ttlMs = 30000 } = req.body;

  const context = await store.create({
    binding,
    ttlMs,
    mode: 'balanced',
    metadata: { userId: req.headers['x-user-id'] },
  });

  res.json({
    contextId: context.id,
    expiresAt: context.expiresAt,
    mode: context.mode,
  });
});

// Protected endpoints
app.post(
  '/api/update',
  ashExpressMiddleware({
    store,
    expectedBinding: 'POST /api/update',
  }),
  (req, res) => {
    // Access context metadata
    const ashContext = (req as any).ashContext;
    console.log('User ID:', ashContext.metadata?.userId);

    res.json({ status: 'success' });
  }
);

// Global protection for /api/* routes
app.use(
  '/api',
  ashExpressMiddleware({
    store,
    // Derive binding from request
    expectedBinding: undefined,
  })
);

// Cleanup expired contexts periodically
setInterval(async () => {
  const cleaned = await store.cleanup();
  console.log(`Cleaned up ${cleaned} expired contexts`);
}, 60000);

app.listen(3000, () => {
  console.log('ASH-protected server running on port 3000');
});
```

## Input Validation (v2.3.4)

All SDKs now implement consistent input validation in client secret derivation functions. Invalid inputs throw errors with descriptive messages.

### Validation Rules

| Parameter | Rule | Code |
|-----------|------|------|
| `nonce` | Minimum 32 hex characters | SEC-014 |
| `nonce` | Maximum 128 characters | SEC-NONCE-001 |
| `nonce` | Hexadecimal only (0-9, a-f, A-F) | BUG-004 |
| `contextId` | Cannot be empty | BUG-041 |
| `contextId` | Maximum 256 characters | SEC-CTX-001 |
| `contextId` | Alphanumeric, underscore, hyphen, dot only | SEC-CTX-001 |
| `binding` | Maximum 8192 bytes | SEC-AUDIT-004 |

### Validation Constants

```typescript
export const MIN_NONCE_HEX_CHARS = 32;    // Minimum nonce length
export const MAX_NONCE_LENGTH = 128;      // Maximum nonce length
export const MAX_CONTEXT_ID_LENGTH = 256; // Maximum context ID length
export const MAX_BINDING_LENGTH = 8192;   // Maximum binding length (8KB)
```

## Error Codes (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

| Code | HTTP | Category | Description |
|------|------|----------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Context | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Seal | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Verification | IP/User binding mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Verification | Scope hash mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Verification | Chain verification failed |
| `ASH_TIMESTAMP_INVALID` | 482 | Format | Invalid timestamp |
| `ASH_PROOF_MISSING` | 483 | Format | Missing X-ASH-Proof header |
| `ASH_CANONICALIZATION_ERROR` | 422 | Standard | Canonicalization failed |
| `ASH_MALFORMED_REQUEST` | 400 | Standard | Malformed request |
| `ASH_MODE_VIOLATION` | 400 | Standard | Mode violation |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Standard | Content type not supported |
| `ASH_VALIDATION_ERROR` | 400 | Standard | Input validation failed |

## License

**ASH Source-Available License (ASAL-1.0)**

See the [LICENSE](https://github.com/3maem/ash/blob/main/LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
- [npm Package](https://www.npmjs.com/package/@3maem/ash-node)
