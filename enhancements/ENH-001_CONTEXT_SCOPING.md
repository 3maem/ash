# ENH-001: Context Scoping
**Version:** 2.2 | **Status:** Implemented

## Summary
Selective field protection - protect only specified fields, ignore others.

## Formula
```
scopeHash = SHA256(scope.join(","))
bodyHash = SHA256(canonicalize(scopedPayload))
proof = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash)
```

## Functions
- `extractScopedFields(payload, scope)` - Extract specified fields
- `buildProofV21Scoped(clientSecret, timestamp, binding, payload, scope)` - Build scoped proof
- `verifyProofV21Scoped(nonce, contextId, binding, timestamp, payload, scope, scopeHash, clientProof)` - Verify
- `hashScopedBody(payload, scope)` - Hash scoped fields

## Features
- Dot notation: `user.address.city`
- Scope hash prevents tampering
- Empty scope = full payload

## Use Cases
- Payment: Protect `amount`, ignore `notes`
- Forms: Protect critical fields, ignore analytics

---

## Update (2026-01-18): Binding Format

Per tutorial_15, binding now uses pipe-separated format with canonical query:

**Old:** `METHOD /path`
**New:** `METHOD|PATH|CANONICAL_QUERY`

**Example:**
```
POST|/api/transfer|amount=100&recipient=user123
```

**Scoped Proof with New Binding:**
```
proof = HMAC-SHA256(clientSecret, timestamp|METHOD|PATH|QUERY|bodyHash|scopeHash)
```
