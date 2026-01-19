//! Proof generation and verification.
//!
//! Proofs are deterministic integrity tokens derived from:
//! - Context ID
//! - Binding (endpoint)
//! - Canonical payload
//! - Optional nonce (server-assisted mode)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use crate::compare::timing_safe_equal;
use crate::errors::AshError;
use crate::types::{AshMode, BuildProofInput, VerifyInput};

/// Protocol version identifier.
const ASH_VERSION: &str = "ASHv1";

/// Build a cryptographic proof for request integrity.
///
/// The proof is computed as:
/// ```text
/// proof = BASE64URL(SHA256(
///   "ASHv1\n" +
///   mode + "\n" +
///   binding + "\n" +
///   contextId + "\n" +
///   (nonce + "\n" if present) +
///   canonicalPayload
/// ))
/// ```
///
/// # Arguments
///
/// * `mode` - Security mode (minimal, balanced, strict)
/// * `binding` - Canonical binding (e.g., "POST /api/update")
/// * `context_id` - Context ID from server
/// * `nonce` - Optional nonce for server-assisted mode
/// * `canonical_payload` - Canonicalized payload string
///
/// # Example
///
/// ```rust
/// use ash_core::{build_proof, AshMode};
///
/// let proof = build_proof(
///     AshMode::Balanced,
///     "POST /api/profile",
///     "ctx_abc123",
///     None,
///     r#"{"name":"John"}"#,
/// ).unwrap();
///
/// println!("Proof: {}", proof);
/// ```
pub fn build_proof(
    mode: AshMode,
    binding: &str,
    context_id: &str,
    nonce: Option<&str>,
    canonical_payload: &str,
) -> Result<String, AshError> {
    // Build the proof input string
    let mut input = String::new();

    // Version
    input.push_str(ASH_VERSION);
    input.push('\n');

    // Mode
    input.push_str(&mode.to_string());
    input.push('\n');

    // Binding
    input.push_str(binding);
    input.push('\n');

    // Context ID
    input.push_str(context_id);
    input.push('\n');

    // Nonce (if present)
    if let Some(n) = nonce {
        input.push_str(n);
        input.push('\n');
    }

    // Canonical payload
    input.push_str(canonical_payload);

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    // Encode as Base64URL without padding
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Build proof from a structured input.
///
/// Convenience wrapper around `build_proof` that accepts `BuildProofInput`.
#[allow(dead_code)]
pub fn ash_build_proof(input: &BuildProofInput) -> Result<String, AshError> {
    build_proof(
        input.mode,
        &input.binding,
        &input.context_id,
        input.nonce.as_deref(),
        &input.canonical_payload,
    )
}

/// Verify a proof using constant-time comparison.
///
/// # Security Note
///
/// This function uses constant-time comparison to prevent timing attacks.
/// The comparison time does not depend on where differences occur.
///
/// # Example
///
/// ```rust
/// use ash_core::{build_proof, verify_proof, AshMode, VerifyInput};
///
/// let expected = build_proof(
///     AshMode::Balanced,
///     "POST /api/profile",
///     "ctx_abc123",
///     None,
///     r#"{"name":"John"}"#,
/// ).unwrap();
///
/// let input = VerifyInput::new(&expected, &expected);
/// assert!(verify_proof(&input));
/// ```
pub fn verify_proof(input: &VerifyInput) -> bool {
    timing_safe_equal(
        input.expected_proof.as_bytes(),
        input.actual_proof.as_bytes(),
    )
}

/// Verify that two proofs match.
///
/// Convenience function for direct string comparison.
#[allow(dead_code)]
pub fn ash_verify_proof(expected: &str, actual: &str) -> bool {
    timing_safe_equal(expected.as_bytes(), actual.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_proof_deterministic() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_different_payload() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":2}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_different_context() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx456",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_different_binding() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "PUT /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_with_nonce() {
        let proof_without = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof_with = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            Some("nonce456"),
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof_without, proof_with);
    }

    #[test]
    fn test_build_proof_different_mode() {
        let proof1 = build_proof(
            AshMode::Minimal,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Strict,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        assert_ne!(proof1, proof2);
    }

    #[test]
    fn test_verify_proof_match() {
        let proof = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let input = VerifyInput::new(&proof, &proof);
        assert!(verify_proof(&input));
    }

    #[test]
    fn test_verify_proof_mismatch() {
        let proof1 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        let proof2 = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":2}"#,
        )
        .unwrap();

        let input = VerifyInput::new(&proof1, &proof2);
        assert!(!verify_proof(&input));
    }

    #[test]
    fn test_proof_is_base64url() {
        let proof = build_proof(
            AshMode::Balanced,
            "POST /api/test",
            "ctx123",
            None,
            r#"{"a":1}"#,
        )
        .unwrap();

        // Base64URL should not contain + / =
        assert!(!proof.contains('+'));
        assert!(!proof.contains('/'));
        assert!(!proof.contains('='));

        // Should be 43 characters (256 bits / 6 bits per char, no padding)
        assert_eq!(proof.len(), 43);
    }
}

// =========================================================================
// ASH v2.1 - Derived Client Secret & Cryptographic Proof
// =========================================================================

use hmac::{Hmac, Mac};
use sha2::Sha256 as HmacSha256;

type HmacSha256Type = Hmac<HmacSha256>;

/// ASH v2.1 protocol version.
#[allow(dead_code)]
const ASH_VERSION_V21: &str = "ASHv2.1";

/// Generate a cryptographically secure random nonce.
///
/// # Arguments
/// * `bytes` - Number of bytes (default 32)
///
/// # Returns
/// Hex-encoded nonce (64 chars for 32 bytes)
pub fn generate_nonce(bytes: usize) -> String {
    use getrandom::getrandom;
    let mut buf = vec![0u8; bytes];
    getrandom(&mut buf).expect("Failed to generate random bytes");
    hex::encode(buf)
}

/// Generate a unique context ID with "ash_" prefix.
pub fn generate_context_id() -> String {
    format!("ash_{}", generate_nonce(16))
}

/// Derive client secret from server nonce (v2.1).
///
/// SECURITY PROPERTIES:
/// - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
/// - Context-bound: Unique per contextId + binding combination
/// - Safe to expose: Client can use it but cannot forge other contexts
///
/// Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
pub fn derive_client_secret(nonce: &str, context_id: &str, binding: &str) -> String {
    let mut mac =
        HmacSha256Type::new_from_slice(nonce.as_bytes()).expect("HMAC can take key of any size");
    mac.update(format!("{}|{}", context_id, binding).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build v2.1 cryptographic proof (client-side).
///
/// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
pub fn build_proof_v21(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    body_hash: &str,
) -> String {
    let message = format!("{}|{}|{}", timestamp, binding, body_hash);
    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify v2.1 proof (server-side).
pub fn verify_proof_v21(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    body_hash: &str,
    client_proof: &str,
) -> bool {
    let client_secret = derive_client_secret(nonce, context_id, binding);
    let expected_proof = build_proof_v21(&client_secret, timestamp, binding, body_hash);
    timing_safe_equal(expected_proof.as_bytes(), client_proof.as_bytes())
}

/// Compute SHA-256 hash of canonical body.
pub fn hash_body(canonical_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_body.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests_v21 {
    use super::*;

    #[test]
    fn test_derive_client_secret_deterministic() {
        let secret1 = derive_client_secret("nonce123", "ctx_abc", "POST /login");
        let secret2 = derive_client_secret("nonce123", "ctx_abc", "POST /login");
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_derive_client_secret_different_inputs() {
        let secret1 = derive_client_secret("nonce123", "ctx_abc", "POST /login");
        let secret2 = derive_client_secret("nonce456", "ctx_abc", "POST /login");
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_build_proof_v21_deterministic() {
        let proof1 = build_proof_v21("secret", "1234567890", "POST /login", "bodyhash");
        let proof2 = build_proof_v21("secret", "1234567890", "POST /login", "bodyhash");
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_verify_proof_v21() {
        let nonce = "nonce123";
        let context_id = "ctx_abc";
        let binding = "POST /login";
        let timestamp = "1234567890";
        let body_hash = "bodyhash123";

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let proof = build_proof_v21(&client_secret, timestamp, binding, body_hash);

        assert!(verify_proof_v21(
            nonce, context_id, binding, timestamp, body_hash, &proof
        ));
    }

    #[test]
    fn test_hash_body() {
        let hash = hash_body(r#"{"name":"John"}"#);
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }
}

// =========================================================================
// ASH v2.2 - Context Scoping (Selective Field Protection)
// =========================================================================

use serde_json::{Map, Value};

/// Extract scoped fields from a JSON value.
pub fn extract_scoped_fields(payload: &Value, scope: &[&str]) -> Result<Value, AshError> {
    if scope.is_empty() {
        return Ok(payload.clone());
    }

    let mut result = Map::new();

    for field_path in scope {
        let value = get_nested_value(payload, field_path);
        if let Some(v) = value {
            set_nested_value(&mut result, field_path, v);
        }
    }

    Ok(Value::Object(result))
}

fn get_nested_value(payload: &Value, path: &str) -> Option<Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = payload;

    for part in parts {
        let (key, index) = parse_array_notation(part);

        match current {
            Value::Object(map) => {
                current = map.get(key)?;
                if let Some(idx) = index {
                    if let Value::Array(arr) = current {
                        current = arr.get(idx)?;
                    } else {
                        return None;
                    }
                }
            }
            Value::Array(arr) => {
                let idx: usize = key.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }

    Some(current.clone())
}

fn parse_array_notation(part: &str) -> (&str, Option<usize>) {
    if let Some(bracket_start) = part.find('[') {
        if let Some(bracket_end) = part.find(']') {
            let key = &part[..bracket_start];
            let index_str = &part[bracket_start + 1..bracket_end];
            if let Ok(index) = index_str.parse::<usize>() {
                return (key, Some(index));
            }
        }
    }
    (part, None)
}

fn set_nested_value(result: &mut Map<String, Value>, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.len() == 1 {
        let (key, _) = parse_array_notation(parts[0]);
        result.insert(key.to_string(), value);
        return;
    }

    let (first_key, _) = parse_array_notation(parts[0]);
    let remaining_path = parts[1..].join(".");

    let nested = result
        .entry(first_key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));

    if let Value::Object(nested_map) = nested {
        set_nested_value(nested_map, &remaining_path, value);
    }
}
/// Build v2.2 cryptographic proof with scoped fields.
pub fn build_proof_v21_scoped(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    payload: &str,
    scope: &[&str],
) -> Result<(String, String), AshError> {
    let json_payload: Value = serde_json::from_str(payload)
        .map_err(|e| AshError::canonicalization_failed(&format!("Invalid JSON: {}", e)))?;

    let scoped_payload = extract_scoped_fields(&json_payload, scope)?;

    let canonical_scoped = serde_json::to_string(&scoped_payload)
        .map_err(|e| AshError::canonicalization_failed(&format!("Failed to serialize: {}", e)))?;

    let body_hash = hash_body(&canonical_scoped);

    let scope_str = scope.join(",");
    let scope_hash = hash_body(&scope_str);

    let message = format!("{}|{}|{}|{}", timestamp, binding, body_hash, scope_hash);
    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let proof = hex::encode(mac.finalize().into_bytes());

    Ok((proof, scope_hash))
}

/// Verify v2.2 proof with scoped fields.
pub fn verify_proof_v21_scoped(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    payload: &str,
    scope: &[&str],
    scope_hash: &str,
    client_proof: &str,
) -> Result<bool, AshError> {
    let scope_str = scope.join(",");
    let expected_scope_hash = hash_body(&scope_str);
    if !timing_safe_equal(expected_scope_hash.as_bytes(), scope_hash.as_bytes()) {
        return Ok(false);
    }

    let client_secret = derive_client_secret(nonce, context_id, binding);

    let (expected_proof, _) =
        build_proof_v21_scoped(&client_secret, timestamp, binding, payload, scope)?;

    Ok(timing_safe_equal(
        expected_proof.as_bytes(),
        client_proof.as_bytes(),
    ))
}

/// Hash scoped payload for client-side use.
pub fn hash_scoped_body(payload: &str, scope: &[&str]) -> Result<String, AshError> {
    let json_payload: Value = serde_json::from_str(payload)
        .map_err(|e| AshError::canonicalization_failed(&format!("Invalid JSON: {}", e)))?;

    let scoped_payload = extract_scoped_fields(&json_payload, scope)?;

    let canonical_scoped = serde_json::to_string(&scoped_payload)
        .map_err(|e| AshError::canonicalization_failed(&format!("Failed to serialize: {}", e)))?;

    Ok(hash_body(&canonical_scoped))
}

#[cfg(test)]
mod tests_v22_scoping {
    use super::*;

    #[test]
    fn test_build_verify_scoped_proof() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1","notes":"hi"}"#;
        let scope = vec!["amount", "recipient"];

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let (proof, scope_hash) =
            build_proof_v21_scoped(&client_secret, timestamp, binding, payload, &scope).unwrap();

        let is_valid = verify_proof_v21_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_scoped_proof_ignores_unscoped_changes() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let scope = vec!["amount", "recipient"];

        let client_secret = derive_client_secret(nonce, context_id, binding);

        let payload1 = r#"{"amount":1000,"recipient":"user1","notes":"hello"}"#;
        let (proof, scope_hash) =
            build_proof_v21_scoped(&client_secret, timestamp, binding, payload1, &scope).unwrap();

        let payload2 = r#"{"amount":1000,"recipient":"user1","notes":"world"}"#;

        let is_valid = verify_proof_v21_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload2,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_scoped_proof_detects_scoped_changes() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let scope = vec!["amount", "recipient"];

        let client_secret = derive_client_secret(nonce, context_id, binding);

        let payload1 = r#"{"amount":1000,"recipient":"user1","notes":"hello"}"#;
        let (proof, scope_hash) =
            build_proof_v21_scoped(&client_secret, timestamp, binding, payload1, &scope).unwrap();

        let payload2 = r#"{"amount":9999,"recipient":"user1","notes":"hello"}"#;

        let is_valid = verify_proof_v21_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload2,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(!is_valid);
    }
}

// =========================================================================
// ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
// =========================================================================

/// Result from unified proof generation.
#[derive(Debug, Clone, PartialEq)]
pub struct UnifiedProofResult {
    /// The cryptographic proof.
    pub proof: String,
    /// Hash of the scope (empty if no scoping).
    pub scope_hash: String,
    /// Hash of the previous proof (empty if no chaining).
    pub chain_hash: String,
}

/// Hash a proof for chaining purposes.
///
/// Used to create chain links between sequential requests.
pub fn hash_proof(proof: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(proof.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build unified v2.3 cryptographic proof (client-side).
///
/// Supports optional scoping and chaining:
/// - `scope`: Fields to protect (empty = full payload)
/// - `previous_proof`: Previous proof in chain (None = no chaining)
///
/// Formula:
/// ```text
/// scopeHash  = scope.len() > 0 ? SHA256(scope.join(",")) : ""
/// bodyHash   = SHA256(canonicalize(scopedPayload))
/// chainHash  = previous_proof.is_some() ? SHA256(previous_proof) : ""
/// proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
/// ```
pub fn build_proof_v21_unified(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    payload: &str,
    scope: &[&str],
    previous_proof: Option<&str>,
) -> Result<UnifiedProofResult, AshError> {
    // Parse and scope the payload
    let json_payload: Value = serde_json::from_str(payload)
        .map_err(|e| AshError::canonicalization_failed(&format!("Invalid JSON: {}", e)))?;

    let scoped_payload = extract_scoped_fields(&json_payload, scope)?;

    let canonical_scoped = serde_json::to_string(&scoped_payload)
        .map_err(|e| AshError::canonicalization_failed(&format!("Failed to serialize: {}", e)))?;

    let body_hash = hash_body(&canonical_scoped);

    // Compute scope hash (empty string if no scope)
    let scope_hash = if scope.is_empty() {
        String::new()
    } else {
        hash_body(&scope.join(","))
    };

    // Compute chain hash (empty string if no previous proof)
    let chain_hash = match previous_proof {
        Some(prev) if !prev.is_empty() => hash_proof(prev),
        _ => String::new(),
    };

    // Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
    let message = format!(
        "{}|{}|{}|{}|{}",
        timestamp, binding, body_hash, scope_hash, chain_hash
    );

    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let proof = hex::encode(mac.finalize().into_bytes());

    Ok(UnifiedProofResult {
        proof,
        scope_hash,
        chain_hash,
    })
}

/// Verify unified v2.3 proof (server-side).
///
/// Validates proof with optional scoping and chaining.
pub fn verify_proof_v21_unified(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    payload: &str,
    client_proof: &str,
    scope: &[&str],
    scope_hash: &str,
    previous_proof: Option<&str>,
    chain_hash: &str,
) -> Result<bool, AshError> {
    // Validate scope hash if scoping is used
    if !scope.is_empty() {
        let expected_scope_hash = hash_body(&scope.join(","));
        if !timing_safe_equal(expected_scope_hash.as_bytes(), scope_hash.as_bytes()) {
            return Ok(false);
        }
    }

    // Validate chain hash if chaining is used
    if let Some(prev) = previous_proof {
        if !prev.is_empty() {
            let expected_chain_hash = hash_proof(prev);
            if !timing_safe_equal(expected_chain_hash.as_bytes(), chain_hash.as_bytes()) {
                return Ok(false);
            }
        }
    }

    // Derive client secret and compute expected proof
    let client_secret = derive_client_secret(nonce, context_id, binding);

    let result = build_proof_v21_unified(
        &client_secret,
        timestamp,
        binding,
        payload,
        scope,
        previous_proof,
    )?;

    Ok(timing_safe_equal(
        result.proof.as_bytes(),
        client_proof.as_bytes(),
    ))
}

#[cfg(test)]
mod tests_v23_unified {
    use super::*;

    #[test]
    fn test_unified_basic() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";
        let payload = r#"{"name":"John","age":30}"#;

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let result = build_proof_v21_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[],  // No scoping
            None, // No chaining
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let is_valid = verify_proof_v21_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            None,
            "",
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_scoped_only() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1","notes":"hi"}"#;
        let scope = vec!["amount", "recipient"];

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let result = build_proof_v21_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &scope,
            None, // No chaining
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(!result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let is_valid = verify_proof_v21_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &scope,
            &result.scope_hash,
            None,
            "",
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_chained_only() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /checkout";
        let timestamp = "1234567890";
        let payload = r#"{"cart_id":"cart_123"}"#;
        let previous_proof = "abc123def456";

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let result = build_proof_v21_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[], // No scoping
            Some(previous_proof),
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());

        let is_valid = verify_proof_v21_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            Some(previous_proof),
            &result.chain_hash,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_full() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /payment";
        let timestamp = "1234567890";
        let payload = r#"{"amount":500,"currency":"USD","notes":"tip"}"#;
        let scope = vec!["amount", "currency"];
        let previous_proof = "checkout_proof_xyz";

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let result = build_proof_v21_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &scope,
            Some(previous_proof),
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(!result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());

        let is_valid = verify_proof_v21_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &scope,
            &result.scope_hash,
            Some(previous_proof),
            &result.chain_hash,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_chain_broken() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /payment";
        let timestamp = "1234567890";
        let payload = r#"{"amount":500}"#;
        let previous_proof = "original_proof";

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let result = build_proof_v21_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[],
            Some(previous_proof),
        )
        .unwrap();

        // Try to verify with wrong previous proof
        let is_valid = verify_proof_v21_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            Some("tampered_proof"), // Wrong previous proof
            &result.chain_hash,
        )
        .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_unified_scope_tampered() {
        let nonce = "test_nonce_12345";
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1"}"#;
        let scope = vec!["amount"];

        let client_secret = derive_client_secret(nonce, context_id, binding);
        let result =
            build_proof_v21_unified(&client_secret, timestamp, binding, payload, &scope, None)
                .unwrap();

        // Try to verify with different scope
        let tampered_scope = vec!["recipient"];
        let is_valid = verify_proof_v21_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &tampered_scope,    // Different scope
            &result.scope_hash, // Original scope hash
            None,
            "",
        )
        .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_hash_proof() {
        let proof = "test_proof_123";
        let hash1 = hash_proof(proof);
        let hash2 = hash_proof(proof);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
    }
}
