//! Integration tests for ASH WASM bindings.
//! These tests use ash_core directly since wasm_bindgen functions can't run on native targets.

use ash_core;

// ============================================================================
// FULL WORKFLOW TESTS
// ============================================================================

#[test]
fn full_workflow_basic() {
    // 1. Generate nonce and context
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();

    // 2. Normalize binding
    let binding = ash_core::ash_normalize_binding("POST", "/api/users", "").unwrap();

    // 3. Canonicalize and hash body
    let body = r#"{"name":"Alice","email":"alice@example.com"}"#;
    let canonical_body = ash_core::ash_canonicalize_json(body).unwrap();
    let body_hash = ash_core::ash_hash_body(&canonical_body);

    // 4. Derive client secret
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();

    // 5. Build proof
    let timestamp = "1234567890";
    let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

    // 6. Verify proof
    let result = ash_core::ash_verify_proof(&nonce, &ctx, &binding, timestamp, &body_hash, &proof).unwrap();

    assert!(result);
    assert_eq!(proof.len(), 64);
}

#[test]
fn full_workflow_with_query_params() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();

    // Binding with query parameters
    let binding = ash_core::ash_normalize_binding("GET", "/api/search", "q=test&page=1&limit=10").unwrap();

    let body_hash = ash_core::ash_hash_body("");  // GET requests often have empty body
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let timestamp = "1234567890";
    let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, &ctx, &binding, timestamp, &body_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn full_workflow_url_encoded_body() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/login", "").unwrap();

    // URL-encoded form body
    let body = "username=alice&password=secret123";
    let canonical_body = ash_core::ash_canonicalize_urlencoded(body).unwrap();
    let body_hash = ash_core::ash_hash_body(&canonical_body);

    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let timestamp = "1234567890";
    let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

    let result = ash_core::ash_verify_proof(&nonce, &ctx, &binding, timestamp, &body_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn full_workflow_scoped() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/transfer", "").unwrap();

    let body = r#"{"amount":1000,"recipient":"bob","memo":"payment"}"#;
    let timestamp = "1234567890";
    let scope = &["amount", "recipient"];

    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, &binding, body, scope).unwrap();

    let result = ash_core::ash_verify_proof_scoped(&nonce, &ctx, &binding, timestamp, body, scope, &scope_hash, &proof).unwrap();
    assert!(result);
}

#[test]
fn full_workflow_unified() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/action", "").unwrap();

    let body = r#"{"action":"process","data":{"value":42}}"#;
    let timestamp = "1234567890";

    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let result = ash_core::ash_build_proof_unified(&secret, timestamp, &binding, body, &[], None).unwrap();

    let verified = ash_core::ash_verify_proof_unified(
        &nonce, &ctx, &binding, timestamp, body,
        &result.proof, &[], &result.scope_hash, None, &result.chain_hash
    ).unwrap();
    assert!(verified);
}

#[test]
fn full_workflow_unified_with_chain() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/workflow", "").unwrap();
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();

    // Step 1
    let body1 = r#"{"step":1,"status":"started"}"#;
    let result1 = ash_core::ash_build_proof_unified(&secret, "1000000001", &binding, body1, &[], None).unwrap();

    // Step 2 - chained
    let body2 = r#"{"step":2,"status":"processing"}"#;
    let result2 = ash_core::ash_build_proof_unified(&secret, "1000000002", &binding, body2, &[], Some(&result1.proof)).unwrap();

    // Step 3 - chained
    let body3 = r#"{"step":3,"status":"completed"}"#;
    let result3 = ash_core::ash_build_proof_unified(&secret, "1000000003", &binding, body3, &[], Some(&result2.proof)).unwrap();

    // Verify all steps
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000001", body1, &result1.proof, &[], &result1.scope_hash, None, &result1.chain_hash).unwrap());
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000002", body2, &result2.proof, &[], &result2.scope_hash, Some(&result1.proof), &result2.chain_hash).unwrap());
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000003", body3, &result3.proof, &[], &result3.scope_hash, Some(&result2.proof), &result3.chain_hash).unwrap());
}

// ============================================================================
// MULTI-REQUEST TESTS
// ============================================================================

#[test]
fn multiple_requests_same_context() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();

    // Multiple different API calls with same context
    let endpoints = [
        ("GET", "/api/users", ""),
        ("POST", "/api/users", r#"{"name":"Alice"}"#),
        ("GET", "/api/users/1", ""),
        ("PUT", "/api/users/1", r#"{"name":"Bob"}"#),
        ("DELETE", "/api/users/1", ""),
    ];

    for (i, (method, path, body)) in endpoints.iter().enumerate() {
        let binding = ash_core::ash_normalize_binding(method, path, "").unwrap();
        let body_hash = if body.is_empty() {
            ash_core::ash_hash_body("")
        } else {
            ash_core::ash_hash_body(&ash_core::ash_canonicalize_json(body).unwrap())
        };

        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        let timestamp = format!("{}", 1000000000 + i);
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        let result = ash_core::ash_verify_proof(&nonce, &ctx, &binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(result, "Failed for endpoint: {} {}", method, path);
    }
}

#[test]
fn multiple_requests_different_contexts() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/action", "").unwrap();
    let body_hash = ash_core::ash_hash_body(r#"{"data":"test"}"#);
    let timestamp = "1234567890";

    // Each context produces different proofs
    let mut proofs = Vec::new();
    for _ in 0..10 {
        let ctx = ash_core::ash_generate_context_id().unwrap();
        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

        // Each proof should be unique
        assert!(!proofs.contains(&proof));
        proofs.push(proof);
    }
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn error_invalid_json() {
    let result = ash_core::ash_canonicalize_json("{invalid}");
    assert!(result.is_err());
}

#[test]
fn error_empty_json() {
    let result = ash_core::ash_canonicalize_json("");
    assert!(result.is_err());
}

#[test]
fn error_empty_method() {
    let result = ash_core::ash_normalize_binding("", "/api", "");
    assert!(result.is_err());
}

#[test]
fn error_empty_proof_hash() {
    let result = ash_core::ash_hash_proof("");
    assert!(result.is_err());
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

#[test]
fn determinism_json_canonicalization() {
    let input = r#"{"z":3,"a":1,"m":2}"#;

    for _ in 0..10 {
        let result = ash_core::ash_canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"a":1,"m":2,"z":3}"#);
    }
}

#[test]
fn determinism_urlencoded_canonicalization() {
    let input = "z=3&a=1&m=2";

    for _ in 0..10 {
        let result = ash_core::ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(result, "a=1&m=2&z=3");
    }
}

#[test]
fn determinism_binding_normalization() {
    for _ in 0..10 {
        let result = ash_core::ash_normalize_binding("post", "/api//test/", "b=2&a=1").unwrap();
        assert_eq!(result, "POST|/api/test|a=1&b=2");
    }
}

#[test]
fn determinism_hash() {
    let input = "test content";

    let first_hash = ash_core::ash_hash_body(input);
    for _ in 0..10 {
        let hash = ash_core::ash_hash_body(input);
        assert_eq!(hash, first_hash);
    }
}

#[test]
fn determinism_secret_derivation() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";

    let first_secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    for _ in 0..10 {
        let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
        assert_eq!(secret, first_secret);
    }
}

#[test]
fn determinism_proof_generation() {
    let nonce = "a".repeat(64);
    let ctx = "ctx_test";
    let binding = "POST|/api|";
    let timestamp = "1234567890";
    let body_hash = ash_core::ash_hash_body("test");

    let secret = ash_core::ash_derive_client_secret(&nonce, ctx, binding).unwrap();
    let first_proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    for _ in 0..10 {
        let proof = ash_core::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        assert_eq!(proof, first_proof);
    }
}

// ============================================================================
// REAL-WORLD SCENARIO TESTS
// ============================================================================

#[test]
fn scenario_user_registration() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/v1/users/register", "").unwrap();

    let body = r#"{"username":"newuser","email":"user@example.com","password":"securePass123!"}"#;
    let canonical = ash_core::ash_canonicalize_json(body).unwrap();
    let body_hash = ash_core::ash_hash_body(&canonical);

    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let timestamp = "1234567890";
    let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

    assert!(ash_core::ash_verify_proof(&nonce, &ctx, &binding, timestamp, &body_hash, &proof).unwrap());
}

#[test]
fn scenario_payment_transfer() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/v1/payments/transfer", "").unwrap();

    let body = r#"{"from_account":"ACC123","to_account":"ACC456","amount":1000.50,"currency":"USD","memo":"Payment for services"}"#;
    let scope = &["from_account", "to_account", "amount", "currency"];  // Protect critical fields

    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let timestamp = "1234567890";
    let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, timestamp, &binding, body, scope).unwrap();

    assert!(ash_core::ash_verify_proof_scoped(&nonce, &ctx, &binding, timestamp, body, scope, &scope_hash, &proof).unwrap());
}

#[test]
fn scenario_api_search() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("GET", "/api/v1/products/search", "category=electronics&min_price=100&max_price=500&sort=price_asc").unwrap();

    let body_hash = ash_core::ash_hash_body("");  // Empty body for GET
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
    let timestamp = "1234567890";
    let proof = ash_core::ash_build_proof(&secret, timestamp, &binding, &body_hash).unwrap();

    assert!(ash_core::ash_verify_proof(&nonce, &ctx, &binding, timestamp, &body_hash, &proof).unwrap());
}

#[test]
fn scenario_multi_step_checkout() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/v1/checkout", "").unwrap();
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();

    // Step 1: Initialize cart
    let body1 = r#"{"step":"init","cart_id":"CART123"}"#;
    let result1 = ash_core::ash_build_proof_unified(&secret, "1000000001", &binding, body1, &[], None).unwrap();

    // Step 2: Add items (chained)
    let body2 = r#"{"step":"add_items","items":[{"id":"ITEM1","qty":2},{"id":"ITEM2","qty":1}]}"#;
    let result2 = ash_core::ash_build_proof_unified(&secret, "1000000002", &binding, body2, &[], Some(&result1.proof)).unwrap();

    // Step 3: Apply payment (chained, scoped)
    let body3 = r#"{"step":"payment","method":"credit_card","amount":299.99,"card_last4":"1234"}"#;
    let result3 = ash_core::ash_build_proof_unified(&secret, "1000000003", &binding, body3, &["amount", "method"], Some(&result2.proof)).unwrap();

    // Step 4: Confirm (chained)
    let body4 = r#"{"step":"confirm","order_id":"ORD123"}"#;
    let result4 = ash_core::ash_build_proof_unified(&secret, "1000000004", &binding, body4, &[], Some(&result3.proof)).unwrap();

    // Verify entire chain
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000001", body1, &result1.proof, &[], &result1.scope_hash, None, &result1.chain_hash).unwrap());
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000002", body2, &result2.proof, &[], &result2.scope_hash, Some(&result1.proof), &result2.chain_hash).unwrap());
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000003", body3, &result3.proof, &["amount", "method"], &result3.scope_hash, Some(&result2.proof), &result3.chain_hash).unwrap());
    assert!(ash_core::ash_verify_proof_unified(&nonce, &ctx, &binding, "1000000004", body4, &result4.proof, &[], &result4.scope_hash, Some(&result3.proof), &result4.chain_hash).unwrap());
}

// ============================================================================
// STRESS TESTS
// ============================================================================

#[test]
fn stress_full_workflow_100() {
    for i in 0..100 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        let ctx = ash_core::ash_generate_context_id().unwrap();
        let binding = ash_core::ash_normalize_binding("POST", &format!("/api/resource/{}", i), "").unwrap();

        let body = format!(r#"{{"id":{},"data":"test_{}"}}"#, i, i);
        let canonical = ash_core::ash_canonicalize_json(&body).unwrap();
        let body_hash = ash_core::ash_hash_body(&canonical);

        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        let timestamp = format!("{}", 1000000000 + i);
        let proof = ash_core::ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        assert!(ash_core::ash_verify_proof(&nonce, &ctx, &binding, &timestamp, &body_hash, &proof).unwrap());
    }
}

#[test]
fn stress_scoped_workflow_50() {
    for i in 0..50 {
        let nonce = ash_core::ash_generate_nonce(32).unwrap();
        let ctx = ash_core::ash_generate_context_id().unwrap();
        let binding = ash_core::ash_normalize_binding("POST", "/api/transfer", "").unwrap();

        let body = format!(r#"{{"amount":{},"recipient":"user_{}","memo":"test"}}"#, i * 100, i);
        let scope = &["amount", "recipient"];

        let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();
        let timestamp = format!("{}", 1000000000 + i);
        let (proof, scope_hash) = ash_core::ash_build_proof_scoped(&secret, &timestamp, &binding, &body, scope).unwrap();

        assert!(ash_core::ash_verify_proof_scoped(&nonce, &ctx, &binding, &timestamp, &body, scope, &scope_hash, &proof).unwrap());
    }
}

#[test]
fn stress_chain_workflow_20() {
    let nonce = ash_core::ash_generate_nonce(32).unwrap();
    let ctx = ash_core::ash_generate_context_id().unwrap();
    let binding = ash_core::ash_normalize_binding("POST", "/api/workflow", "").unwrap();
    let secret = ash_core::ash_derive_client_secret(&nonce, &ctx, &binding).unwrap();

    let mut previous_proof: Option<String> = None;
    let mut chain = Vec::new();

    // Build chain
    for i in 0..20 {
        let body = format!(r#"{{"step":{}}}"#, i);
        let timestamp = format!("{}", 1000000000 + i);
        let result = ash_core::ash_build_proof_unified(&secret, &timestamp, &binding, &body, &[], previous_proof.as_deref()).unwrap();

        chain.push((timestamp, body, result.proof.clone(), result.scope_hash.clone(), result.chain_hash.clone()));
        previous_proof = Some(result.proof);
    }

    // Verify entire chain
    for i in 0..20 {
        let (timestamp, body, proof, scope_hash, chain_hash) = &chain[i];
        let prev = if i > 0 { Some(chain[i - 1].2.as_str()) } else { None };

        let verified = ash_core::ash_verify_proof_unified(
            &nonce, &ctx, &binding, timestamp, body, proof,
            &[], scope_hash, prev, chain_hash
        ).unwrap();

        assert!(verified, "Chain verification failed at step {}", i);
    }
}
