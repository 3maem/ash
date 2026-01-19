# ASH SDK for Node.js

**Developed by 3maem Co. | شركة عمائم**

ASH SDK provides request integrity and anti-replay protection for web applications. This SDK provides request integrity protection, anti-replay mechanisms, and middleware for Express and Fastify.

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

Canonicalizes JSON to deterministic form.

**Rules:**
- Object keys sorted lexicographically
- No whitespace
- Unicode NFC normalized

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

## Express Middleware

### `ashExpressMiddleware(options: AshExpressOptions): RequestHandler`

Creates ASH verification middleware for Express.

```typescript
interface AshExpressOptions {
  store: AshContextStore;              // Context store instance
  expectedBinding?: string;            // Expected endpoint binding
  mode?: AshMode;                      // Security mode (default: balanced)
  onError?: (error, req, res, next) => void;  // Custom error handler
  skip?: (req) => boolean;             // Skip verification condition
}
```

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

## Error Codes

| Code | Description |
|------|-------------|
| `MISSING_CONTEXT_ID` | Missing X-ASH-Context-ID header |
| `MISSING_PROOF` | Missing X-ASH-Proof header |
| `INVALID_CONTEXT` | Invalid or expired context |
| `CONTEXT_EXPIRED` | Context has expired |
| `CONTEXT_USED` | Context already used (replay detected) |
| `BINDING_MISMATCH` | Endpoint binding mismatch |
| `PROOF_MISMATCH` | Proof verification failed |
| `CANONICALIZATION_FAILED` | Failed to canonicalize payload |

## License

MIT License

## Links

- [Main Repository](https://github.com/3maem/ash)
- [ASH Protocol Specification](https://github.com/3maem/ash/blob/main/SPEC.md)
- [npm Package](https://www.npmjs.com/package/@3maem/ash-node)
