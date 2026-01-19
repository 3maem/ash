# ENH-002: Request Chaining
**Version:** 2.3 | **Status:** Pending Approval

## Summary
Cryptographically link sequential requests to prevent step-skipping attacks.

## Problem
Attackers bypass multi-step workflows by directly accessing later steps:
```
Attack: [Skip Cart] → [Skip Checkout] → Payment (with manipulated amount)
```

## Formula
```
prevProofHash = SHA256(previousProof)
proof = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|prevProofHash)
```

## Functions
| Function | Purpose |
|----------|---------|
| `buildProofV21Chained()` | Build proof linked to previous |
| `verifyProofV21Chained()` | Verify proof and chain continuity |
| `hashProof()` | Hash proof for chaining |

## Function Signatures

### Build (Client)
```
buildProofV21Chained(
    clientSecret: string,
    timestamp: string,
    binding: string,
    bodyHash: string,
    previousProof: string | null
) -> { proof, chainHash }
```

### Verify (Server)
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

## HTTP Headers
| Header | Direction | Purpose |
|--------|-----------|---------|
| `X-ASH-Chain-Hash` | Request | Hash of previous proof |
| `X-ASH-Chain-Proof` | Response | Proof for next chain |

## Error Codes
- `ASH_CHAIN_BROKEN` - Previous proof invalid/missing
- `ASH_CHAIN_EXPIRED` - Chain timeout exceeded

## Files to Modify
1. `ash-core/src/proof.rs`
2. `ash-wasm/src/lib.rs`
3. `ash-php/src/Core/Proof.php`
4. `ash-node/src/index.ts`
5. `ash-python/src/ash/core/proof.py`
6. `ash-go/ash.go`
7. `ash-dotnet/src/Ash.Core/Proof.cs`

## Use Cases
- E-commerce: Cart → Checkout → Payment
- Auth: Login → 2FA → Dashboard
- Workflows: Submit → Review → Approve
