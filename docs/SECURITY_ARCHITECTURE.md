# ASH Security Architecture

This document explains the system-level security architecture of ASH and how its components interact to provide request integrity and replay protection.

For cryptographic and protocol details, see:
👉 [SECURITY_TECHNICAL_DETAILS.md](SECURITY_TECHNICAL_DETAILS.md)

---

## High-Level Architecture

ASH operates as a protocol-layer integrity system placed between the client and server.

It validates that:

- Requests are authentic
- Requests were not modified
- Requests are not replayed
- Requests are bound to a specific endpoint

---

## Core Components

### Client SDK

Responsible for:

- Context creation
- Nonce generation
- Request hashing
- Proof generation (HMAC)
- Secure secret handling

---

### Verification Server

Responsible for:

- Proof verification
- Replay detection
- TTL enforcement
- Endpoint binding validation
- Context consumption

---

### Context Store (Redis / SQL)

Responsible for:

- Single-use enforcement
- Atomic consumption
- TTL expiration
- Distributed consistency

---

## System Flow

```
Client SDK
   ↓ create context
   ↓ sign request
Internet (untrusted)
   ↓
Server Verification
   ↓ validate proof
   ↓ consume context
Context Store
```

If tampered or replayed → verification fails.

---

## Trust Boundaries

Security assumptions change across:

1. Client → Internet
2. Internet → Server
3. Server → Context Store

All boundaries are treated as hostile environments.

---

## Security Responsibilities by Layer

| Layer | Responsibility |
|-------|----------------|
| TLS | Confidentiality |
| Authentication | Identity |
| Authorization | Permissions |
| ASH | Integrity + Replay protection |

ASH complements — not replaces — these controls.

---

## Deployment Patterns

### Recommended

- HTTPS only
- Redis with TLS
- Short TTLs
- Rate limiting
- Synchronized clocks

### Avoid

- Shared memory stores
- Long-lived contexts
- Unsynchronized distributed state

---

## Design Principles

ASH architecture follows:

- Minimal attack surface
- Stateless verification where possible
- Single-use guarantees
- Deterministic cryptography
- Defense-in-depth

---

## Summary

ASH adds a dedicated integrity layer between client and server.

It strengthens request security without interfering with existing authentication or authorization systems.
