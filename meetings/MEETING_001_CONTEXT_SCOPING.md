# ASH Team Meeting #001
## Enhancement: Context Scoping (v2.2)

**Date:** January 2026
**Status:** Completed
**Attendees:** ASH Development Team

---

## Agenda

1. Review Enhancement #1: Context Scoping proposal
2. Technical design discussion
3. Implementation across all SDKs
4. Testing and validation

---

## Enhancement Overview

### Problem Statement
Current ASH v2.1 protects the entire request payload. However, some use cases require:
- Protecting only critical fields (e.g., `amount`, `recipient`)
- Ignoring dynamic fields (e.g., `timestamp`, `analytics_id`)
- Reducing payload size for proof calculation

### Solution: Context Scoping (v2.2)
Selective field protection - specify which fields to include in the proof, ignore others.

---

## Technical Specification

### New Functions Added

| Function | Purpose |
|----------|---------|
| `extractScopedFields()` | Extract only specified fields from payload |
| `buildProofV21Scoped()` | Build proof with scoped fields |
| `verifyProofV21Scoped()` | Verify proof with scoped fields |
| `hashScopedBody()` | Hash only scoped fields |

### Cryptographic Formula

```
scopeHash = SHA256(scope.join(","))
bodyHash = SHA256(canonicalize(scopedPayload))
proof = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash)
```

### Features

1. **Dot Notation Support**: Access nested fields like `user.address.city`
2. **Scope Hash**: Cryptographic signature of scope prevents tampering with field selection
3. **Empty Scope**: If scope is empty, defaults to full payload (backward compatible)

---

## Implementation Status

| SDK | Language | Status | Notes |
|-----|----------|--------|-------|
| ash-core | Rust | Completed | Core implementation |
| ash-wasm | WebAssembly | Completed | WASM bindings added |
| ash-php | PHP | Completed | Full implementation |
| ash-node | TypeScript | Completed | Full implementation |
| ash-python | Python | Completed | Full implementation |
| ash-go | Go | Completed | Full implementation |
| ash-dotnet | C# | Completed | ProofV22 class added |

---

## Code Examples

### PHP Example
```php
$scope = ['amount', 'recipient', 'user.id'];
$payload = [
    'amount' => 100,
    'recipient' => 'user@example.com',
    'user' => ['id' => 123, 'name' => 'John'],
    'analytics_id' => 'xyz123'  // ignored
];

$result = Proof::buildV21Scoped($clientSecret, $timestamp, $binding, $payload, $scope);
// Returns: ['proof' => '...', 'scopeHash' => '...']
```

### TypeScript Example
```typescript
const scope = ['amount', 'recipient', 'user.id'];
const payload = {
    amount: 100,
    recipient: 'user@example.com',
    user: { id: 123, name: 'John' },
    analytics_id: 'xyz123'  // ignored
};

const result = ashBuildProofV21Scoped(clientSecret, timestamp, binding, payload, scope);
// Returns: { proof: '...', scopeHash: '...' }
```

### Python Example
```python
scope = ['amount', 'recipient', 'user.id']
payload = {
    'amount': 100,
    'recipient': 'user@example.com',
    'user': {'id': 123, 'name': 'John'},
    'analytics_id': 'xyz123'  # ignored
}

proof, scope_hash = build_proof_v21_scoped(client_secret, timestamp, binding, payload, scope)
```

---

## Security Considerations

1. **Scope Hash Validation**: Server MUST validate scope hash matches expected scope
2. **Scope Tampering Prevention**: Client cannot modify scope without invalidating proof
3. **Field Existence**: Missing fields are silently ignored (not an error)
4. **Canonical Order**: Scoped fields are serialized in deterministic order

---

## Use Cases

1. **Payment Forms**: Protect `amount`, `currency`, `recipient` but ignore `notes`
2. **User Registration**: Protect `email`, `password` but ignore `referral_code`
3. **API Requests**: Protect critical parameters, ignore tracking/analytics fields
4. **Form Submissions**: Protect business-critical fields, ignore UI state

---

## Commits

- `14dfaf1` - feat: add Context Scoping (v2.2) - selective field protection

---

## Action Items

- [x] Implement in Rust core
- [x] Add WASM bindings
- [x] Implement in PHP SDK
- [x] Implement in Node.js SDK
- [x] Implement in Python SDK
- [x] Implement in Go SDK
- [x] Implement in C# SDK
- [ ] Add documentation to main docs
- [ ] Add integration tests
- [ ] Update framework integrations (Laravel, Django, etc.)

---

## Next Steps

Proceed to Enhancement #2: Request Chaining (pending approval)

---

*Meeting notes recorded by ASH Development Team*
