# ASH Team Meeting #002
## Enhancement: Unified Proof Functions (v2.3)

**Date:** January 2026
**Status:** Implemented
**Attendees:** ASH Development Team

---

## Agenda

1. Review unified approach combining scoping and chaining
2. Technical design discussion
3. Implementation across all SDKs
4. Testing and validation

---

## Decision: Unified Function Approach

### Original Proposal
Separate functions for scoping and chaining:
- `buildProofV21Scoped()` - Scoping only
- `buildProofV21Chained()` - Chaining only

### Approved Approach
Single unified function with optional parameters:
- `buildProofUnified()` - Supports both scoping AND chaining

### Rationale
| Aspect | Separate Functions | Unified Function |
|--------|-------------------|------------------|
| API simplicity | 3+ functions | 1 function |
| Use both features | Manual | Built-in |
| Code duplication | High | Low |
| Future enhancements | New function each | Add optional param |

---

## Technical Specification

### Unified Formula
```
scopeHash  = scope.length > 0 ? SHA256(scope.join(",")) : ""
bodyHash   = SHA256(canonicalize(scopedPayload))
chainHash  = previousProof ? SHA256(previousProof) : ""
proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
```

### Function Signatures

**Build (Client-side)**
```
buildProofUnified(
    clientSecret,
    timestamp,
    binding,
    payload,
    scope = [],           // Optional: empty = full payload
    previousProof = null  // Optional: null = no chaining
) -> { proof, scopeHash, chainHash }
```

**Verify (Server-side)**
```
verifyProofUnified(
    nonce,
    contextId,
    binding,
    timestamp,
    payload,
    clientProof,
    scope = [],
    scopeHash = "",
    previousProof = null,
    chainHash = ""
) -> boolean
```

---

## Implementation Status

| SDK | Language | Status | New Functions |
|-----|----------|--------|---------------|
| ash-core | Rust | Completed | `build_proof_v21_unified`, `verify_proof_v21_unified`, `hash_proof` |
| ash-wasm | WebAssembly | Completed | `ashBuildProofUnified`, `ashVerifyProofUnified`, `ashHashProof` |
| ash-php | PHP | Completed | `Proof::buildUnified`, `Proof::verifyUnified`, `Proof::hashProof` |
| ash-node | TypeScript | Completed | `ashBuildProofUnified`, `ashVerifyProofUnified`, `ashHashProof` |
| ash-python | Python | Completed | `build_proof_unified`, `verify_proof_unified`, `hash_proof` |
| ash-go | Go | Completed | `BuildProofUnified`, `VerifyProofUnified`, `HashProof` |
| ash-dotnet | C# | Completed | `ProofV23.BuildProofUnified`, `ProofV23.VerifyProofUnified`, `ProofV23.HashProof` |

---

## Usage Examples

### Basic (No scoping, no chaining)
```php
$result = Proof::buildUnified($secret, $ts, $binding, $payload);
```

### Scoping Only
```php
$result = Proof::buildUnified($secret, $ts, $binding, $payload,
    scope: ['amount', 'recipient']
);
```

### Chaining Only
```php
$result = Proof::buildUnified($secret, $ts, $binding, $payload,
    previousProof: $lastProof
);
```

### Full (Scoping + Chaining)
```php
$result = Proof::buildUnified($secret, $ts, $binding, $payload,
    scope: ['amount'],
    previousProof: $lastProof
);
```

---

## Return Value Structure

```json
{
    "proof": "a1b2c3...",      // The cryptographic proof
    "scopeHash": "d4e5f6...",  // Empty string if no scoping
    "chainHash": "g7h8i9..."   // Empty string if no chaining
}
```

---

## Security Properties

1. **Backward Compatible**: Empty scope/null previousProof = standard v2.1 behavior
2. **Scope Protection**: Scope hash prevents attackers from modifying protected fields
3. **Chain Integrity**: Chain hash ensures workflow sequence integrity
4. **Timing-Safe**: All comparisons use constant-time algorithms

---

## Files Modified

### Core Implementation
- `ash-core/src/proof.rs` - Rust unified functions + `UnifiedProofResult` struct
- `ash-core/src/lib.rs` - Export new functions

### SDK Bindings
- `ash-wasm/src/lib.rs` - WASM bindings
- `ash-php/src/Core/Proof.php` - PHP implementation
- `ash-node/src/index.ts` - TypeScript implementation
- `ash-python/src/ash/core/proof.py` - Python implementation
- `ash-python/src/ash/core/__init__.py` - Python exports
- `ash-go/ash.go` - Go implementation
- `ash-dotnet/src/Ash.Core/Proof.cs` - C# implementation (ProofV23 class)

---

## Action Items

- [x] Implement unified functions in Rust core
- [x] Add WASM bindings
- [x] Implement in PHP SDK
- [x] Implement in Node.js SDK
- [x] Implement in Python SDK
- [x] Implement in Go SDK
- [x] Implement in C# SDK
- [x] Run Rust tests (62 tests passed)
- [x] Update enhancement specification
- [x] Add documentation to main docs (`docs/UNIFIED_PROOF_API.md`)
- [x] Add integration tests (`tests/unified_proof_integration.rs` - 8 tests)
- [x] Update framework integrations:
  - [x] Laravel middleware (scoping + chaining headers)
  - [x] Express middleware (enableUnified option)
  - [x] Fastify plugin (enableUnified option)

---

## Next Steps

- Update documentation with unified function examples
- Add cross-SDK test vectors
- Consider Enhancement #3: Proof of Work (future)

---

*Meeting notes recorded by ASH Development Team*
