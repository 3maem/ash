// Package ash provides request integrity verification and anti-replay protection
// for Go applications using the ASH (Application Security Hash) protocol.
//
// ASH ensures that HTTP requests are:
//   - Authentic (payload not modified)
//   - Single-use (cannot be replayed)
//   - Context-bound (tied to specific endpoint)
//
// # Quick Start
//
// Canonicalize JSON payloads:
//
//	canonical, err := ash.CanonicalizeJson(`{"z":1,"a":2}`)
//	// canonical = `{"a":2,"z":1}`
//
// Generate and verify proofs (v2.1):
//
//	// Server generates nonce and context
//	nonce := ash.GenerateNonce(32)
//	contextId := ash.GenerateContextId()
//	binding := "POST|/api/transfer|"
//
//	// Derive client secret
//	clientSecret := ash.DeriveClientSecret(nonce, contextId, binding)
//
//	// Build proof
//	bodyHash := ash.HashBody(canonical)
//	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
//	proof := ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash)
//
//	// Verify proof
//	valid := ash.VerifyProofV21(nonce, contextId, binding, timestamp, bodyHash, proof)
//
// # Security Modes
//
// ASH supports three security modes:
//   - Minimal: Development/testing (fastest)
//   - Balanced: General production use (recommended)
//   - Strict: High-security transactions
//
// # Error Handling
//
// ASH uses typed errors for different failure conditions:
//   - ErrInvalidContext: Context not found or invalid
//   - ErrContextExpired: Context TTL exceeded
//   - ErrReplayDetected: Context already consumed
//   - ErrBindingMismatch: Endpoint binding mismatch
//   - ErrProofInvalid: Proof verification failed
//
// # Protocol Versions
//
//   - v1: Legacy SHA-256 based proofs
//   - v2.1: HMAC-SHA256 with derived secrets
//   - v2.2: Field scoping support
//   - v2.3: Request chaining support
//
// For more information, see https://github.com/3maem/ash
package ash
