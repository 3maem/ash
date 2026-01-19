# ASH Team Meeting #002
## Enhancement: Request Chaining (v2.3)

**Date:** January 2026
**Status:** Pending Approval
**Attendees:** ASH Development Team

---

## Agenda

1. Review Enhancement #2: Request Chaining proposal
2. Security threat analysis
3. Technical design discussion
4. Implementation plan across all SDKs
5. Seek approval for implementation

---

## Problem Statement

### Attack Scenario: Step-Skipping
Attackers can bypass multi-step workflows by directly accessing later steps:

```
Normal Flow:     Login → Verify Email → Dashboard
Attack:          [Skip] → [Skip] → Dashboard (direct access)

Normal Flow:     Add to Cart → Checkout → Payment → Confirm
Attack:          [Skip] → [Skip] → Payment (manipulated amount)
```

### Current Limitation
ASH v2.1/v2.2 validates each request independently. There's no cryptographic link between sequential requests in a workflow.

### Real-World Examples

| Scenario | Attack | Impact |
|----------|--------|--------|
| E-commerce checkout | Skip cart, go to payment | Price manipulation |
| User registration | Skip email verification | Unverified accounts |
| Password reset | Skip identity verification | Account takeover |
| Multi-step forms | Skip validation steps | Data integrity loss |
| Approval workflows | Skip approval chain | Unauthorized actions |

---

## Solution: Request Chaining (v2.3)

Cryptographically link sequential requests so each step proves the previous step was completed.

### Core Concept

```
Request 1: proof₁ = HMAC(clientSecret, timestamp|binding|bodyHash)
Request 2: proof₂ = HMAC(clientSecret, timestamp|binding|bodyHash|hash(proof₁))
Request 3: proof₃ = HMAC(clientSecret, timestamp|binding|bodyHash|hash(proof₂))
```

Each proof includes a hash of the previous proof, creating an unbreakable chain.

---

## Technical Specification

### New Functions

| Function | Purpose |
|----------|---------|
| `buildProofV21Chained()` | Build proof linked to previous proof |
| `verifyProofV21Chained()` | Verify proof and chain continuity |
| `hashProof()` | Hash a proof for chaining |

### Cryptographic Formula

```
prevProofHash = SHA256(previousProof)
proof = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|prevProofHash)
```

### Function Signatures

**Build Chained Proof (Client-side)**
```
buildProofV21Chained(
    clientSecret: string,
    timestamp: string,
    binding: string,
    bodyHash: string,
    previousProof: string | null  // null for first request in chain
) -> { proof: string, chainHash: string }
```

**Verify Chained Proof (Server-side)**
```
verifyProofV21Chained(
    nonce: string,
    contextId: string,
    binding: string,
    timestamp: string,
    bodyHash: string,
    previousProof: string | null,
    clientProof: string
) -> boolean
```

### Chain Initialization

- First request in chain: `previousProof = null` or empty string
- Chain hash for first request: `SHA256("")` (hash of empty string)
- This allows seamless start of new chains

---

## Implementation Plan

### Files to Modify

| SDK | File | Changes |
|-----|------|---------|
| ash-core | `src/proof.rs` | Add chaining functions |
| ash-wasm | `src/lib.rs` | Add WASM bindings |
| ash-php | `src/Core/Proof.php` | Add PHP implementation |
| ash-node | `src/index.ts` | Add TypeScript implementation |
| ash-python | `src/ash/core/proof.py` | Add Python implementation |
| ash-go | `ash.go` | Add Go implementation |
| ash-dotnet | `src/Ash.Core/Proof.cs` | Add C# implementation (ProofV23) |

### Implementation Order

1. Rust (ash-core) - Core implementation
2. WASM (ash-wasm) - Browser bindings
3. PHP (ash-php) - Server SDK
4. Node.js (ash-node) - Server SDK
5. Python (ash-python) - Server SDK
6. Go (ash-go) - Server SDK
7. C# (ash-dotnet) - Server SDK

---

## Code Examples

### PHP Server Example
```php
// Step 1: User adds item to cart
$proof1 = Ash::verify($request); // Returns proof after validation
$_SESSION['last_proof'] = $proof1;

// Step 2: User proceeds to checkout (must have valid cart proof)
$previousProof = $_SESSION['last_proof'];
$isValid = Proof::verifyV21Chained(
    $nonce,
    $contextId,
    'POST /checkout',
    $timestamp,
    $bodyHash,
    $previousProof,
    $clientProof
);

if (!$isValid) {
    throw new ChainBrokenError('Invalid request chain - checkout requires valid cart');
}
```

### TypeScript Client Example
```typescript
// Step 1: Add to cart
const cartResult = await fetch('/api/cart', {
    headers: {
        'X-ASH-Proof': ashBuildProofV21(clientSecret, timestamp, binding, bodyHash)
    }
});
const cartProof = cartResult.headers.get('X-ASH-Chain-Proof');

// Step 2: Checkout (chain to cart proof)
const checkoutProof = ashBuildProofV21Chained(
    clientSecret,
    timestamp,
    'POST /checkout',
    bodyHash,
    cartProof  // Link to previous step
);

await fetch('/api/checkout', {
    headers: {
        'X-ASH-Proof': checkoutProof.proof,
        'X-ASH-Chain-Hash': checkoutProof.chainHash
    }
});
```

### Python Server Example
```python
# Verify chained request
is_valid = verify_proof_v21_chained(
    nonce=stored_context.nonce,
    context_id=context_id,
    binding="POST /payment",
    timestamp=request_timestamp,
    body_hash=body_hash,
    previous_proof=session['checkout_proof'],  # From previous step
    client_proof=request.headers['X-ASH-Proof']
)

if not is_valid:
    raise ChainBrokenError("Payment requires valid checkout step")
```

---

## Security Analysis

### Threats Mitigated

| Threat | How Chaining Prevents |
|--------|----------------------|
| Step skipping | Each step requires proof of previous step |
| Replay across chains | Chain hash is unique per flow |
| Parameter tampering | Body hash included in each proof |
| Session hijacking | Chain bound to original context |

### Security Properties

1. **Unforgeability**: Cannot create valid chain without completing previous steps
2. **Non-repudiation**: Chain proves sequence of actions taken
3. **Integrity**: Any modification breaks the chain
4. **Freshness**: Timestamps prevent replay of old chains

### Edge Cases

| Case | Handling |
|------|----------|
| First request | `previousProof = null`, valid chain start |
| Broken chain | Reject with `ChainBrokenError` |
| Expired chain | Timestamps still validated per-request |
| Parallel requests | Each maintains separate chain |

---

## API Changes

### New HTTP Headers

| Header | Direction | Purpose |
|--------|-----------|---------|
| `X-ASH-Chain-Hash` | Request | Hash of previous proof |
| `X-ASH-Chain-Proof` | Response | Current proof for next chain |

### New Error Codes

| Code | Name | Description |
|------|------|-------------|
| `ASH_CHAIN_BROKEN` | Chain Broken | Previous proof invalid or missing |
| `ASH_CHAIN_EXPIRED` | Chain Expired | Chain timeout exceeded |

---

## Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     REQUEST CHAINING FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CLIENT                           SERVER                        │
│    │                                │                           │
│    │  Step 1: Add to Cart           │                           │
│    │  proof₁ = HMAC(secret,         │                           │
│    │           ts|bind|body)        │                           │
│    ├───────────────────────────────>│                           │
│    │                                │  Verify proof₁            │
│    │                                │  Store proof₁ in session  │
│    │<───────────────────────────────┤                           │
│    │  X-ASH-Chain-Proof: proof₁     │                           │
│    │                                │                           │
│    │  Step 2: Checkout              │                           │
│    │  proof₂ = HMAC(secret,         │                           │
│    │           ts|bind|body|        │                           │
│    │           hash(proof₁))        │                           │
│    ├───────────────────────────────>│                           │
│    │  X-ASH-Chain-Hash: hash(p₁)    │  Verify proof₂            │
│    │                                │  Verify chain links to p₁ │
│    │<───────────────────────────────┤                           │
│    │  X-ASH-Chain-Proof: proof₂     │                           │
│    │                                │                           │
│    │  Step 3: Payment               │                           │
│    │  proof₃ = HMAC(secret,         │                           │
│    │           ts|bind|body|        │                           │
│    │           hash(proof₂))        │                           │
│    ├───────────────────────────────>│                           │
│    │  X-ASH-Chain-Hash: hash(p₂)    │  Verify proof₃            │
│    │                                │  Verify chain links to p₂ │
│    │<───────────────────────────────┤                           │
│    │  Success: Payment Complete     │                           │
│    │                                │                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Compatibility

### Backward Compatibility
- Existing v2.1/v2.2 functions unchanged
- Chaining is opt-in per endpoint
- Non-chained requests still work normally

### Framework Integration
- Laravel: Middleware can enforce chains on route groups
- Django: Decorator for chained views
- Express: Middleware with chain validation

---

## Testing Plan

1. **Unit Tests**: Each SDK function tested independently
2. **Cross-SDK Tests**: Verify chain created in one SDK validates in another
3. **Integration Tests**: Full workflow tests with multiple steps
4. **Security Tests**: Attempt chain forgery, step skipping, replay

---

## Team Approval Status

| Team Member | Role | Approval |
|-------------|------|----------|
| Core Dev | Rust Implementation | Pending |
| SDK Lead | Multi-language SDKs | Pending |
| Security | Cryptographic Review | Pending |
| QA | Testing Strategy | Pending |
| **Project Lead** | **Final Approval** | **Pending** |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Implementation complexity | Medium | Medium | Clear spec, test vectors |
| Breaking existing flows | Low | High | Backward compatible design |
| Performance overhead | Low | Low | Single hash operation per request |
| Developer confusion | Medium | Medium | Clear documentation, examples |

---

## Estimated Scope

- **New functions per SDK**: 3 (build, verify, hash)
- **New error types**: 2 (ChainBroken, ChainExpired)
- **New headers**: 2 (X-ASH-Chain-Hash, X-ASH-Chain-Proof)
- **Total files modified**: 7 (one per SDK)

---

## Action Items (Post-Approval)

- [ ] Implement in Rust core (ash-core)
- [ ] Add WASM bindings (ash-wasm)
- [ ] Implement in PHP SDK
- [ ] Implement in Node.js SDK
- [ ] Implement in Python SDK
- [ ] Implement in Go SDK
- [ ] Implement in C# SDK
- [ ] Create test vectors for cross-SDK validation
- [ ] Update documentation
- [ ] Update framework integrations

---

## Decision Required

**Enhancement #2: Request Chaining (v2.3)**

This enhancement adds cryptographic linking between sequential requests to prevent step-skipping attacks in multi-step workflows.

**Awaiting final approval from Project Lead to proceed with implementation.**

---

*Meeting notes recorded by ASH Development Team*
