"""
API Integration Pattern Tests.

Tests for common API integration patterns including authentication flows,
payment processing, form submissions, and multi-step workflows.
"""

import pytest
import time
from ash.core.proof import (
    ash_build_proof_hmac,
    ash_build_proof_scoped,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_verify_proof,
    ash_verify_proof_scoped,
    ash_verify_proof_unified,
)
from ash.core.canonicalize import (
    ash_canonicalize_json,
    ash_normalize_binding,
)


class TestAuthenticationFlows:
    """Authentication flow integration tests."""

    def test_login_flow_basic(self):
        """Should handle basic login flow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/auth/login")
        timestamp = str(int(time.time() * 1000))

        payload = {"username": "user@example.com", "password": "secret123"}
        canonical = ash_canonicalize_json(payload)
        body_hash = ash_hash_body(canonical)

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        # Verify
        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True

    def test_login_flow_with_mfa(self):
        """Should handle login flow with MFA step."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()

        # Step 1: Initial login
        binding1 = ash_normalize_binding("POST", "/api/auth/login")
        timestamp1 = str(int(time.time() * 1000))
        payload1 = {"username": "user@example.com", "password": "secret123"}
        client_secret1 = ash_derive_client_secret(nonce, context_id, binding1)
        proof1, _, _ = ash_build_proof_unified(
            client_secret1, timestamp1, binding1, payload1
        )

        # Step 2: MFA verification (chained)
        binding2 = ash_normalize_binding("POST", "/api/auth/mfa")
        timestamp2 = str(int(time.time() * 1000))
        payload2 = {"code": "123456"}
        client_secret2 = ash_derive_client_secret(nonce, context_id, binding2)
        proof2, _, chain_hash2 = ash_build_proof_unified(
            client_secret2, timestamp2, binding2, payload2, None, proof1
        )

        # Verify chained proof
        result = ash_verify_proof_unified(
            nonce, context_id, binding2, timestamp2, payload2, proof2,
            None, "", proof1, chain_hash2
        )
        assert result is True

    def test_oauth_authorization_flow(self):
        """Should handle OAuth authorization flow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()

        # Authorization request
        binding = ash_normalize_binding("POST", "/api/oauth/authorize")
        timestamp = str(int(time.time() * 1000))
        payload = {
            "client_id": "app_12345",
            "redirect_uri": "https://app.example.com/callback",
            "scope": "read write",
            "state": "random_state_value"
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_token_refresh_flow(self):
        """Should handle token refresh flow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/auth/refresh")
        timestamp = str(int(time.time() * 1000))

        payload = {"refresh_token": "rt_abc123xyz789"}
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True


class TestPaymentProcessing:
    """Payment processing integration tests."""

    def test_payment_initiation(self):
        """Should handle payment initiation."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/payments")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "amount": 10000,  # cents
            "currency": "USD",
            "recipient": "acct_12345",
            "description": "Payment for services"
        }
        # Protect critical fields
        scope = ["amount", "currency", "recipient"]
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload, scope
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof,
            scope, scope_hash
        )
        assert result is True

    def test_payment_confirmation_chain(self):
        """Should handle payment confirmation chained to initiation."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()

        # Step 1: Initiate
        binding1 = ash_normalize_binding("POST", "/api/payments/initiate")
        timestamp1 = str(int(time.time() * 1000))
        payload1 = {"amount": 10000, "currency": "USD", "recipient": "acct_12345"}
        client_secret1 = ash_derive_client_secret(nonce, context_id, binding1)
        proof1, _, _ = ash_build_proof_unified(
            client_secret1, timestamp1, binding1, payload1
        )

        # Step 2: Confirm (chained)
        binding2 = ash_normalize_binding("POST", "/api/payments/confirm")
        timestamp2 = str(int(time.time() * 1000))
        payload2 = {"confirmed": True, "otp": "123456"}
        client_secret2 = ash_derive_client_secret(nonce, context_id, binding2)
        proof2, _, chain_hash2 = ash_build_proof_unified(
            client_secret2, timestamp2, binding2, payload2, None, proof1
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding2, timestamp2, payload2, proof2,
            None, "", proof1, chain_hash2
        )
        assert result is True

    def test_refund_processing(self):
        """Should handle refund processing."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/payments/refund")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "payment_id": "pay_abc123",
            "amount": 5000,
            "reason": "Customer request"
        }
        scope = ["payment_id", "amount"]
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload, scope
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof,
            scope, scope_hash
        )
        assert result is True

    def test_subscription_update(self):
        """Should handle subscription update."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("PUT", "/api/subscriptions/sub_12345")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "plan": "premium",
            "billing_cycle": "annual",
            "prorate": True
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True


class TestFormSubmissions:
    """Form submission integration tests."""

    def test_contact_form(self):
        """Should handle contact form submission."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/contact")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "name": "John Doe",
            "email": "john@example.com",
            "subject": "Inquiry",
            "message": "Hello, I have a question..."
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_user_registration(self):
        """Should handle user registration form."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/users/register")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "name": "New User",
            "agreed_to_terms": True
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_profile_update(self):
        """Should handle profile update form."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("PUT", "/api/users/profile")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "name": "Updated Name",
            "bio": "Updated bio text",
            "location": "New York",
            "website": "https://example.com"
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_file_upload_metadata(self):
        """Should handle file upload metadata."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/files/upload")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "filename": "document.pdf",
            "content_type": "application/pdf",
            "size": 1234567,
            "checksum": "sha256:abc123..."
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True


class TestMultiStepWorkflows:
    """Multi-step workflow integration tests."""

    def test_checkout_workflow(self):
        """Should handle e-commerce checkout workflow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()

        # Step 1: Add to cart
        binding1 = ash_normalize_binding("POST", "/api/cart/items")
        timestamp1 = str(int(time.time() * 1000))
        payload1 = {"product_id": "prod_123", "quantity": 2}
        client_secret1 = ash_derive_client_secret(nonce, context_id, binding1)
        proof1, _, _ = ash_build_proof_unified(
            client_secret1, timestamp1, binding1, payload1
        )

        # Step 2: Set shipping (chained)
        binding2 = ash_normalize_binding("POST", "/api/cart/shipping")
        timestamp2 = str(int(time.time() * 1000))
        payload2 = {"address_id": "addr_456", "method": "express"}
        client_secret2 = ash_derive_client_secret(nonce, context_id, binding2)
        proof2, _, chain_hash2 = ash_build_proof_unified(
            client_secret2, timestamp2, binding2, payload2, None, proof1
        )

        # Step 3: Place order (chained)
        binding3 = ash_normalize_binding("POST", "/api/orders")
        timestamp3 = str(int(time.time() * 1000))
        payload3 = {"payment_method_id": "pm_789", "notes": "Leave at door"}
        client_secret3 = ash_derive_client_secret(nonce, context_id, binding3)
        proof3, _, chain_hash3 = ash_build_proof_unified(
            client_secret3, timestamp3, binding3, payload3, None, proof2
        )

        # Verify final proof in chain
        result = ash_verify_proof_unified(
            nonce, context_id, binding3, timestamp3, payload3, proof3,
            None, "", proof2, chain_hash3
        )
        assert result is True

    def test_document_approval_workflow(self):
        """Should handle document approval workflow."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()

        # Step 1: Submit document
        binding1 = ash_normalize_binding("POST", "/api/documents/submit")
        timestamp1 = str(int(time.time() * 1000))
        payload1 = {"document_id": "doc_123", "title": "Contract"}
        client_secret1 = ash_derive_client_secret(nonce, context_id, binding1)
        proof1, _, _ = ash_build_proof_unified(
            client_secret1, timestamp1, binding1, payload1
        )

        # Step 2: First approval (chained)
        binding2 = ash_normalize_binding("POST", "/api/documents/approve")
        timestamp2 = str(int(time.time() * 1000))
        payload2 = {"approved": True, "approver": "manager_1"}
        client_secret2 = ash_derive_client_secret(nonce, context_id, binding2)
        proof2, _, chain_hash2 = ash_build_proof_unified(
            client_secret2, timestamp2, binding2, payload2, None, proof1
        )

        # Step 3: Final approval (chained)
        binding3 = ash_normalize_binding("POST", "/api/documents/finalize")
        timestamp3 = str(int(time.time() * 1000))
        payload3 = {"finalized": True, "signature": "sig_abc"}
        client_secret3 = ash_derive_client_secret(nonce, context_id, binding3)
        proof3, _, chain_hash3 = ash_build_proof_unified(
            client_secret3, timestamp3, binding3, payload3, None, proof2
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding3, timestamp3, payload3, proof3,
            None, "", proof2, chain_hash3
        )
        assert result is True


class TestAPIVersioning:
    """API versioning integration tests."""

    def test_versioned_endpoint_v1(self):
        """Should handle v1 API endpoint."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("GET", "/api/v1/users")
        timestamp = str(int(time.time() * 1000))

        payload = {}
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_versioned_endpoint_v2(self):
        """Should handle v2 API endpoint."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("GET", "/api/v2/users")
        timestamp = str(int(time.time() * 1000))

        payload = {}
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_version_in_header_vs_path(self):
        """Different version paths should produce different proofs."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        timestamp = str(int(time.time() * 1000))
        payload = {}

        # V1
        binding_v1 = ash_normalize_binding("GET", "/api/v1/users")
        client_secret_v1 = ash_derive_client_secret(nonce, context_id, binding_v1)
        proof_v1, _, _ = ash_build_proof_unified(
            client_secret_v1, timestamp, binding_v1, payload
        )

        # V2
        binding_v2 = ash_normalize_binding("GET", "/api/v2/users")
        client_secret_v2 = ash_derive_client_secret(nonce, context_id, binding_v2)
        proof_v2, _, _ = ash_build_proof_unified(
            client_secret_v2, timestamp, binding_v2, payload
        )

        assert proof_v1 != proof_v2


class TestQueryStringBindings:
    """Query string binding integration tests."""

    def test_search_with_query_params(self):
        """Should include query params in binding."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("GET", "/api/search", "q=test&page=1&limit=10")
        timestamp = str(int(time.time() * 1000))

        payload = {}
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_filter_with_multiple_params(self):
        """Should handle multiple filter parameters."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("GET", "/api/products", "category=electronics&min_price=100&max_price=500&in_stock=true")
        timestamp = str(int(time.time() * 1000))

        payload = {}
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_query_param_order_independent(self):
        """Query param order should not affect verification."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        timestamp = str(int(time.time() * 1000))
        payload = {}

        # Build with one order
        binding1 = ash_normalize_binding("GET", "/api/search", "a=1&b=2&c=3")
        client_secret1 = ash_derive_client_secret(nonce, context_id, binding1)
        proof1, _, _ = ash_build_proof_unified(
            client_secret1, timestamp, binding1, payload
        )

        # Build with different order
        binding2 = ash_normalize_binding("GET", "/api/search", "c=3&a=1&b=2")
        client_secret2 = ash_derive_client_secret(nonce, context_id, binding2)
        proof2, _, _ = ash_build_proof_unified(
            client_secret2, timestamp, binding2, payload
        )

        # Should produce same proof due to normalization
        assert proof1 == proof2


class TestBatchOperations:
    """Batch operation integration tests."""

    def test_batch_create(self):
        """Should handle batch create operations."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/items/batch")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "items": [
                {"name": "Item 1", "price": 100},
                {"name": "Item 2", "price": 200},
                {"name": "Item 3", "price": 300}
            ]
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_batch_update(self):
        """Should handle batch update operations."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("PATCH", "/api/items/batch")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "updates": [
                {"id": "item_1", "price": 150},
                {"id": "item_2", "price": 250}
            ]
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True

    def test_batch_delete(self):
        """Should handle batch delete operations."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("DELETE", "/api/items/batch")
        timestamp = str(int(time.time() * 1000))

        payload = {
            "ids": ["item_1", "item_2", "item_3"]
        }
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, _, _ = ash_build_proof_unified(
            client_secret, timestamp, binding, payload
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof
        )
        assert result is True
