# ASH SDK

**Developed by 3maem Co. | شركة عمائم**

---

## Introduction

**ASH** is an acronym for **Application Security Hash**.

ASH is a security software development kit (SDK) created to address a
specific, narrowly scoped security problem:
**ensuring the integrity and single-use validity of individual HTTP requests**.

ASH was developed in response to a recurring gap observed in modern web
architectures, where existing security mechanisms focus primarily on
transport security, identity verification, and access control, while
leaving the **request itself** vulnerable to reuse, duplication, or
manipulation within short attack windows.

---

## Purpose and Motivation

ASH was developed to solve the following problem:

> Even when HTTPS, authentication, and authorization are correctly
> implemented, application requests can still be **captured, replayed,
> duplicated, or misused** without being altered in a detectable way.

ASH does **not** attempt to prevent attacks by analyzing intent,
validating business logic, inspecting input semantics, or detecting
malicious behavior.

Instead, ASH focuses exclusively on **verifying that a request is
authentic, unmodified, context-bound, and valid for a single use**.

This intentionally narrow scope is fundamental to ASH's design.

---

## What ASH Is — and Is Not

ASH is **not**:

- An authentication mechanism
- An authorization or access-control framework
- A transport security protocol
- A firewall or intrusion detection system
- An input validation or injection prevention solution
- A replacement for any existing security library or standard

ASH does **not** replace:
- TLS / HTTPS
- JWT, OAuth, sessions, or API keys
- Secure coding practices
- Application-layer security controls

ASH is designed as an **additional, complementary security layer**
within a **defense-in-depth architecture**.

---

## How ASH Works (Conceptual Overview)

ASH operates at the **request level**, not the user or session level.

For each protected operation:

1. The server issues a short-lived context identifier.
2. The client generates a deterministic cryptographic proof.
3. The proof is bound to:
   - The HTTP method
   - The target endpoint
   - The issued context identifier
   - A strict time-to-live (TTL)
   - A canonical representation of the request payload
4. The server verifies the proof before processing the request.
5. Once validated, the proof is immediately invalidated and cannot be reused.

This mechanism allows the server to determine whether a request:
- Has been modified
- Has been replayed
- Has been reused outside its intended context
- Has expired or already been consumed

---

## Terminology

This section defines key terms used throughout ASH documentation.
All terms are used consistently across SDKs.

### Context

A short-lived, server-issued identifier (`contextId`) that defines
the valid scope and lifetime of a protected request.

A context is:
- Issued by the server
- Bound to a specific HTTP method and endpoint
- Limited by a strict TTL
- Consumable once

### Context Store

A server-side storage mechanism responsible for:
- Issuing contexts
- Tracking context state
- Enforcing expiration and single-use constraints

The store may be in-memory or persistent, depending on deployment.

### Proof

A deterministic value derived from:
- HTTP method
- Endpoint binding
- contextId
- Canonicalized request payload
- Mode-specific rules

A proof:
- Is generated per request
- Is valid for a single use
- Cannot be reversed or reused
- Does not contain claims or identity information

### Binding

The explicit association between a context/proof and a specific
HTTP method and endpoint.

Bindings prevent cross-endpoint or cross-method reuse of requests.

### Canonicalization

A deterministic process that converts request payloads into a
byte-stable representation before proof generation.

Canonicalization ensures that logically identical payloads
produce identical proofs across SDKs and platforms.

### Mode

A predefined configuration that controls how proofs are derived
(e.g., performance vs. strictness trade-offs).

Modes are agreed upon by client and server during context issuance.

### TTL (Time-To-Live)

A strict time window during which a context and its associated
proofs are considered valid.

Once expired, a context and all proofs derived from it are invalid.

### Single-Use Enforcement

A rule that ensures a proof or context cannot be successfully
verified more than once.

This mechanism provides request-level anti-replay protection.

### Verification

The server-side process of validating:
- Proof correctness
- Context validity
- Binding consistency
- TTL compliance
- Single-use constraints

---

## API Naming Convention

All public APIs use the `ash` prefix for consistency and to avoid naming conflicts.

### Functions

| Function | Purpose |
|----------|---------|
| `ashInit()` | Initialize the library |
| `ashCanonicalizeJson()` | Canonicalize JSON to deterministic form |
| `ashCanonicalizeUrlencoded()` | Canonicalize URL-encoded form data |
| `ashBuildProof()` | Generate cryptographic proof |
| `ashVerifyProof()` | Verify proof matches expected value |
| `ashNormalizeBinding()` | Normalize HTTP method and path |
| `ashTimingSafeEqual()` | Constant-time string comparison |
| `ashVersion()` | Get protocol version (e.g., "ASHv1") |
| `ashLibraryVersion()` | Get library semantic version |

### Types and Interfaces

| Type | Purpose |
|------|---------|
| `AshMode` | Security mode: `minimal`, `balanced`, `strict` |
| `AshContext` | Context object with ID, binding, expiry, mode |
| `AshContextOptions` | Options for creating a new context |
| `AshVerifyResult` | Verification result with status and error info |
| `AshContextStore` | Interface for context storage backends |

### Classes

| Class | Purpose |
|-------|---------|
| `AshMemoryStore` | In-memory context store (development/testing) |
| `AshRedisStore` | Redis-backed context store (production) |
| `AshSqlStore` | SQL database context store |

### Middleware

| Middleware | Purpose |
|------------|---------|
| `ashExpressMiddleware()` | Express.js request verification |
| `ashFastifyPlugin()` | Fastify request verification |

This naming convention applies across all SDKs (Node.js, Python, Go, .NET, PHP, Rust).

---

## Security Scope and Explicit Boundaries

ASH provides deterministic validation that request inputs have not been
modified in transit and are used only once within their intended context.

By enforcing strict request integrity and single-use constraints, ASH
may reduce the feasibility or impact of certain attack scenarios that
rely on request tampering or replay.

However, ASH is not designed, represented, or intended to function as
an attack prevention, detection, or mitigation system.

ASH must not be relied upon as a standalone security control for
protecting applications against cybersecurity attacks.

---

## Intended Role in a Secure Architecture

ASH is intended to be deployed **alongside** existing security controls.

A typical secure architecture includes:

- TLS for transport-level security
- Authentication and authorization mechanisms for identity and access
- Secure coding practices and input validation
- ASH for request integrity and replay protection

This layered approach ensures that ASH enhances overall security
without assuming responsibilities beyond its defined scope.

---

## Quick Start

### Server (Node.js / Express)

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
    binding: 'POST /api/transfer',
    ttlMs: 30000,
    mode: 'balanced'
  });
  res.json({ contextId: ctx.id, mode: ctx.mode });
});

// Protected endpoint
app.post(
  '/api/transfer',
  ashExpressMiddleware({ store, expectedBinding: 'POST /api/transfer' }),
  (req, res) => {
    // Request verified — safe to process
    res.json({ success: true });
  }
);

app.listen(3000);
```

### Client (Browser / Node.js)

```javascript
import { ashInit, ashCanonicalizeJson, ashBuildProof } from '@3maem/ash-node';

ashInit();

// 1. Get context
const { contextId, mode } = await fetch('/ash/context', {
  method: 'POST'
}).then(r => r.json());

// 2. Prepare payload
const payload = { amount: 100, to: 'account123' };
const canonical = ashCanonicalizeJson(JSON.stringify(payload));

// 3. Build proof
const proof = ashBuildProof(
  mode,
  'POST /api/transfer',
  contextId,
  null,
  canonical
);

// 4. Send protected request
await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ASH-Context-ID': contextId,
    'X-ASH-Proof': proof
  },
  body: JSON.stringify(payload)
});
```

---

## Error Reference

This section defines common error conditions returned by ASH
during request verification. Error codes are prefixed with `ASH_`
for consistent handling across SDKs.

### ASH_CTX_NOT_FOUND

The provided `contextId` does not exist or is unknown to the server.

**Possible causes:**
- Invalid or malformed contextId
- Context already consumed
- Context store reset

### ASH_CTX_EXPIRED

The context exists but has exceeded its TTL.

**Possible causes:**
- Request sent after expiration
- Client/server clock drift beyond tolerance

### ASH_CTX_ALREADY_USED

The context or proof has already been successfully consumed.

**Possible causes:**
- Replay attempt
- Duplicate request submission
- Network retry without new context

### ASH_BINDING_MISMATCH

The request does not match the binding associated with the context.

**Possible causes:**
- Different endpoint
- Different HTTP method
- Context reused for another operation

### ASH_PROOF_MISSING

The request did not include a required proof value.

**Possible causes:**
- Client integration error
- Missing headers

### ASH_PROOF_INVALID

The provided proof does not match the expected value.

**Possible causes:**
- Payload modification
- Canonicalization mismatch
- Incorrect mode or binding
- Implementation mismatch across SDKs

### ASH_CANONICALIZATION_ERROR

The payload could not be canonicalized deterministically.

**Possible causes:**
- Unsupported payload structure
- Invalid JSON
- Non-deterministic serialization

### ASH_VERIFICATION_FAILED

A generic verification failure when a more specific error
cannot be safely disclosed.

**Recommended usage:**
- Return a generic client-facing error
- Log detailed diagnostics server-side only

---

## Available SDKs

| Language | Package | Install |
|----------|---------|---------|
| **Node.js** | `@3maem/ash-node` | `npm install @3maem/ash-node` |
| **Python** | `ash-sdk` | `pip install ash-sdk` |
| **Go** | `github.com/3maem/ash-go` | `go get github.com/3maem/ash-go` |
| **PHP** | `3maem/ash-sdk` | `composer require 3maem/ash-sdk` |
| **.NET** | `Ash.Security` | `dotnet add package Ash.Security` |
| **Rust** | `ash-core` | `cargo add ash-core` |

---

## Legal and Operational Notice

ASH does not provide attack prevention, attack detection, or threat
mitigation capabilities.

Its purpose is strictly limited to validating request integrity and
enforcing single-use request constraints. Any security benefit beyond
this scope is incidental and must not be relied upon.

---

## License

**Proprietary - All Rights Reserved**

© 3maem Co. | شركة عمائم
