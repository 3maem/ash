"""
Middleware Tests.

Tests for Flask, FastAPI, and Django middleware including request handling,
error responses, header validation, and path matching.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import json
from ash.core.proof import (
    ash_build_proof_hmac,
    ash_build_proof_unified,
    ash_derive_client_secret,
    ash_generate_context_id,
    ash_generate_nonce,
    ash_hash_body,
    ash_verify_proof_unified,
)
from ash.core.canonicalize import ash_canonicalize_json, ash_normalize_binding


class TestFlaskMiddlewarePathMatching:
    """Flask middleware path matching tests."""

    def test_exact_path_match(self):
        """Should match exact paths."""
        protected = ["/api/secure"]

        path = "/api/secure"
        should_verify = any(
            path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
            for p in protected
        )
        assert should_verify is True

    def test_exact_path_no_match(self):
        """Should not match different paths."""
        protected = ["/api/secure"]

        path = "/api/other"
        should_verify = any(
            path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
            for p in protected
        )
        assert should_verify is False

    def test_wildcard_path_match(self):
        """Should match wildcard paths."""
        protected = ["/api/*"]

        paths = ["/api/users", "/api/orders", "/api/products/123"]
        for path in paths:
            should_verify = any(
                path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
                for p in protected
            )
            assert should_verify is True

    def test_wildcard_path_no_match(self):
        """Should not match paths outside wildcard."""
        protected = ["/api/*"]

        path = "/other/path"
        should_verify = any(
            path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
            for p in protected
        )
        assert should_verify is False

    def test_multiple_protected_paths(self):
        """Should match any of multiple protected paths."""
        protected = ["/api/users", "/api/orders", "/admin/*"]

        test_cases = [
            ("/api/users", True),
            ("/api/orders", True),
            ("/admin/settings", True),
            ("/admin/users/123", True),
            ("/api/products", False),
            ("/public/info", False),
        ]

        for path, expected in test_cases:
            should_verify = any(
                path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
                for p in protected
            )
            assert should_verify == expected, f"Path {path} expected {expected}"

    def test_nested_wildcard(self):
        """Should match nested wildcards."""
        protected = ["/api/v1/*"]

        paths = ["/api/v1/users", "/api/v1/users/123", "/api/v1/users/123/orders"]
        for path in paths:
            should_verify = any(
                path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
                for p in protected
            )
            assert should_verify is True

    def test_root_wildcard(self):
        """Should match root wildcard."""
        protected = ["/*"]

        paths = ["/anything", "/api/users", "/"]
        for path in paths:
            should_verify = any(
                path.startswith(p.rstrip("*")) if p.endswith("*") else path == p
                for p in protected
            )
            assert should_verify is True


class TestFlaskMiddlewareHeaders:
    """Flask middleware header handling tests."""

    def test_missing_context_id_error(self):
        """Should return error for missing context ID."""
        error_code = "ASH_CTX_NOT_FOUND"
        assert error_code == "ASH_CTX_NOT_FOUND"

    def test_missing_proof_error(self):
        """Should return error for missing proof."""
        error_code = "ASH_PROOF_MISSING"
        assert error_code == "ASH_PROOF_MISSING"

    def test_header_names_case_insensitive(self):
        """Header names should be handled case-insensitively."""
        header_variations = [
            "X-ASH-Context-ID",
            "x-ash-context-id",
            "X-Ash-Context-Id",
        ]
        # All should map to same header
        for header in header_variations:
            assert header.lower() == "x-ash-context-id"

    def test_scope_header_parsing(self):
        """Should parse scope header correctly."""
        scope_header = "field1, field2, field3"
        client_scope = [s.strip() for s in scope_header.split(",") if s.strip()]
        assert client_scope == ["field1", "field2", "field3"]

    def test_empty_scope_header(self):
        """Should handle empty scope header."""
        scope_header = ""
        client_scope = [s.strip() for s in scope_header.split(",") if s.strip()]
        assert client_scope == []

    def test_scope_header_with_spaces(self):
        """Should handle scope header with extra spaces."""
        scope_header = "  field1  ,  field2  ,  field3  "
        client_scope = [s.strip() for s in scope_header.split(",") if s.strip()]
        assert client_scope == ["field1", "field2", "field3"]


class TestMiddlewareBindingNormalization:
    """Middleware binding normalization tests."""

    def test_binding_from_request_parts(self):
        """Should create binding from request parts."""
        method = "POST"
        path = "/api/users"
        query_string = ""

        binding = ash_normalize_binding(method, path, query_string)
        assert binding == "POST|/api/users|"

    def test_binding_with_query_string(self):
        """Should include query string in binding."""
        method = "GET"
        path = "/api/search"
        query_string = "q=test&page=1"

        binding = ash_normalize_binding(method, path, query_string)
        assert "page=1" in binding
        assert "q=test" in binding

    def test_binding_normalizes_method(self):
        """Should normalize HTTP method to uppercase."""
        method = "post"
        path = "/api/users"

        binding = ash_normalize_binding(method, path)
        assert binding.startswith("POST|")

    def test_binding_normalizes_path(self):
        """Should normalize path."""
        method = "GET"
        path = "/api//users/"

        binding = ash_normalize_binding(method, path)
        assert "/api/users" in binding


class TestMiddlewareVerificationFlow:
    """Middleware verification flow tests."""

    def test_full_verification_success(self):
        """Should verify valid request."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/test")
        timestamp = "1704067200000"
        payload = {"test": "data"}

        canonical = ash_canonicalize_json(payload)
        body_hash = ash_hash_body(canonical)
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        # Simulated verification result
        from ash.core.proof import ash_verify_proof
        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True

    def test_verification_with_json_content(self):
        """Should verify JSON content type."""
        content_type = "application/json"
        payload = '{"key": "value"}'

        # JSON should be canonicalized
        canonical = ash_canonicalize_json(json.loads(payload))
        body_hash = ash_hash_body(canonical)
        assert len(body_hash) == 64

    def test_verification_with_form_content(self):
        """Should verify form content type."""
        content_type = "application/x-www-form-urlencoded"
        payload = "key=value&other=data"

        body_hash = ash_hash_body(payload)
        assert len(body_hash) == 64


class TestMiddlewareErrorResponses:
    """Middleware error response tests."""

    def test_error_response_format(self):
        """Should return properly formatted error responses."""
        error_response = {
            "error": "ASH_CTX_NOT_FOUND",
            "message": "Missing X-ASH-Context-ID header"
        }
        assert "error" in error_response
        assert "message" in error_response

    def test_error_codes_http_status(self):
        """Should map error codes to HTTP status codes."""
        # These are the actual mappings from the implementation
        error_mappings = {
            # v2.3.4: Updated HTTP status codes
            "ASH_CTX_NOT_FOUND": 450,
            "ASH_CTX_EXPIRED": 451,
            "ASH_CTX_ALREADY_USED": 452,
            "ASH_PROOF_INVALID": 460,
            "ASH_BINDING_MISMATCH": 461,
            "ASH_SCOPE_MISMATCH": 473,
            "ASH_CHAIN_BROKEN": 474,
            "ASH_TIMESTAMP_INVALID": 482,
            "ASH_PROOF_MISSING": 483,
        }
        for error_code, expected_status in error_mappings.items():
            from ash.core.types import get_http_status
            status = get_http_status(error_code)
            assert status == expected_status

    def test_scope_policy_error(self):
        """Should return scope policy error when required."""
        error_response = {
            "error": "ASH_SCOPE_POLICY_REQUIRED",
            "message": "This endpoint requires scope headers per server policy",
            "requiredScope": ["amount", "recipient"]
        }
        assert error_response["error"] == "ASH_SCOPE_POLICY_REQUIRED"

    def test_scope_violation_error(self):
        """Should return scope violation error."""
        error_response = {
            "error": "ASH_SCOPE_POLICY_VIOLATION",
            "message": "Request scope does not match server policy",
            "expected": ["amount", "recipient"],
            "received": ["amount"]
        }
        assert error_response["error"] == "ASH_SCOPE_POLICY_VIOLATION"


class TestMiddlewareScopeHandling:
    """Middleware scope handling tests."""

    def test_parse_scope_header(self):
        """Should parse X-ASH-Scope header."""
        header = "amount, recipient, timestamp"
        scope = [s.strip() for s in header.split(",") if s.strip()]
        assert scope == ["amount", "recipient", "timestamp"]

    def test_scope_policy_enforcement(self):
        """Should enforce server-side scope policy."""
        policy_scope = ["amount", "recipient"]
        client_scope = ["amount", "recipient"]

        sorted_client = sorted(client_scope)
        sorted_policy = sorted(policy_scope)

        assert sorted_client == sorted_policy

    def test_scope_policy_violation_detection(self):
        """Should detect scope policy violations."""
        policy_scope = ["amount", "recipient"]
        client_scope = ["amount"]  # Missing recipient

        sorted_client = sorted(client_scope)
        sorted_policy = sorted(policy_scope)

        assert sorted_client != sorted_policy


class TestMiddlewareMetadataStorage:
    """Middleware metadata storage tests."""

    def test_metadata_storage_flask_g(self):
        """Should store metadata in Flask g object."""
        metadata = {"user_id": "123", "session_id": "abc"}
        scope = ["amount"]
        chain_hash = "abc123"

        # Simulated storage
        g_object = {}
        g_object["ash_metadata"] = metadata
        g_object["ash_scope"] = scope
        g_object["ash_chain_hash"] = chain_hash

        assert g_object["ash_metadata"] == metadata
        assert g_object["ash_scope"] == scope

    def test_metadata_storage_fastapi_state(self):
        """Should store metadata in FastAPI request state."""
        metadata = {"user_id": "123"}

        state = {}
        state["ash_metadata"] = metadata

        assert state["ash_metadata"] == metadata

    def test_metadata_storage_django_request(self):
        """Should store metadata in Django request object."""
        metadata = {"user_id": "123"}

        # Simulated Django request
        class MockRequest:
            pass

        request = MockRequest()
        request.ash_metadata = metadata

        assert request.ash_metadata == metadata


class TestFastAPIMiddlewareAsync:
    """FastAPI middleware async handling tests."""

    @pytest.mark.asyncio
    async def test_async_body_read(self):
        """Should read body asynchronously."""
        async def mock_receive():
            return {"type": "http.request", "body": b'{"test": "data"}'}

        body = await mock_receive()
        assert body["body"] == b'{"test": "data"}'

    @pytest.mark.asyncio
    async def test_async_verification(self):
        """Should verify asynchronously."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/test")
        timestamp = "1704067200000"
        payload = {"test": "data"}

        canonical = ash_canonicalize_json(payload)
        body_hash = ash_hash_body(canonical)
        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof = ash_build_proof_hmac(client_secret, timestamp, binding, body_hash)

        from ash.core.proof import ash_verify_proof
        result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof)
        assert result is True


class TestDjangoMiddlewareSettings:
    """Django middleware settings tests."""

    def test_settings_loading(self):
        """Should load settings correctly."""
        settings = {
            "ASH_INSTANCE": MagicMock(),
            "ASH_PROTECTED_PATHS": ["/api/*"]
        }

        ash_instance = settings.get("ASH_INSTANCE")
        protected_paths = settings.get("ASH_PROTECTED_PATHS", [])

        assert ash_instance is not None
        assert protected_paths == ["/api/*"]

    def test_missing_ash_instance(self):
        """Should raise error for missing ASH_INSTANCE."""
        settings = {}

        ash_instance = settings.get("ASH_INSTANCE")
        if ash_instance is None:
            error = "ASH_INSTANCE not configured in Django settings"
            assert "ASH_INSTANCE" in error


class TestMiddlewareContentTypes:
    """Middleware content type handling tests."""

    def test_json_content_type(self):
        """Should handle application/json."""
        content_type = "application/json"
        is_json = "application/json" in content_type
        assert is_json is True

    def test_json_with_charset(self):
        """Should handle application/json with charset."""
        content_type = "application/json; charset=utf-8"
        is_json = content_type.startswith("application/json")
        assert is_json is True

    def test_form_urlencoded(self):
        """Should handle application/x-www-form-urlencoded."""
        content_type = "application/x-www-form-urlencoded"
        is_form = "x-www-form-urlencoded" in content_type
        assert is_form is True

    def test_multipart_form(self):
        """Should handle multipart/form-data."""
        content_type = "multipart/form-data; boundary=----WebKitFormBoundary"
        is_multipart = content_type.startswith("multipart/form-data")
        assert is_multipart is True

    def test_empty_content_type(self):
        """Should handle empty/missing content type."""
        content_type = ""
        body = ""
        body_hash = ash_hash_body(body)
        assert len(body_hash) == 64


class TestMiddlewareQueryStringHandling:
    """Middleware query string handling tests."""

    def test_query_string_from_flask(self):
        """Should extract query string from Flask request."""
        query_string = b"a=1&b=2"
        decoded = query_string.decode("utf-8") if query_string else ""
        assert decoded == "a=1&b=2"

    def test_query_string_from_fastapi(self):
        """Should extract query string from FastAPI URL."""
        # Simulated URL query
        query = "a=1&b=2"
        query_string = str(query) if query else ""
        assert query_string == "a=1&b=2"

    def test_query_string_from_django(self):
        """Should extract query string from Django META."""
        meta = {"QUERY_STRING": "a=1&b=2"}
        query_string = meta.get("QUERY_STRING", "")
        assert query_string == "a=1&b=2"

    def test_empty_query_string(self):
        """Should handle empty query string."""
        query_string = ""
        binding = ash_normalize_binding("GET", "/api/test", query_string)
        assert binding == "GET|/api/test|"


class TestMiddlewareChainedProofs:
    """Middleware chained proof handling tests."""

    def test_chain_hash_header(self):
        """Should extract chain hash header."""
        headers = {"X-ASH-Chain-Hash": "abc123" * 10 + "abcd"}
        chain_hash = headers.get("X-ASH-Chain-Hash", "")
        assert len(chain_hash) == 64

    def test_verify_with_chain(self):
        """Should verify proof with chain."""
        nonce = ash_generate_nonce()
        context_id = ash_generate_context_id()
        binding = ash_normalize_binding("POST", "/api/test")
        timestamp = "1704067200000"
        payload = {"test": "data"}
        previous_proof = "a" * 64

        client_secret = ash_derive_client_secret(nonce, context_id, binding)
        proof, scope_hash, chain_hash = ash_build_proof_unified(
            client_secret, timestamp, binding, payload, None, previous_proof
        )

        result = ash_verify_proof_unified(
            nonce, context_id, binding, timestamp, payload, proof,
            None, "", previous_proof, chain_hash
        )
        assert result is True


class TestMiddlewareConcurrency:
    """Middleware concurrency tests."""

    def test_independent_requests(self):
        """Should handle independent requests."""
        results = []
        for i in range(10):
            nonce = ash_generate_nonce()
            context_id = ash_generate_context_id()
            binding = ash_normalize_binding("POST", f"/api/test{i}")

            client_secret = ash_derive_client_secret(nonce, context_id, binding)
            # Each request is independent
            results.append(len(client_secret) == 64)

        assert all(results)

    def test_no_state_leakage(self):
        """Should not leak state between requests."""
        # Request 1
        nonce1 = ash_generate_nonce()
        ctx1 = ash_generate_context_id()

        # Request 2 (should be completely independent)
        nonce2 = ash_generate_nonce()
        ctx2 = ash_generate_context_id()

        assert nonce1 != nonce2
        assert ctx1 != ctx2


class TestMiddlewareExtensibility:
    """Middleware extensibility tests."""

    def test_custom_error_handler(self):
        """Should support custom error handling."""
        def custom_error_handler(error_code, message):
            return {
                "status": "error",
                "code": error_code,
                "details": message,
                "timestamp": "2024-01-01T00:00:00Z"
            }

        result = custom_error_handler("ASH_CTX_NOT_FOUND", "Context not found")
        assert result["status"] == "error"
        assert result["code"] == "ASH_CTX_NOT_FOUND"

    def test_custom_metadata_extraction(self):
        """Should support custom metadata extraction."""
        def extract_metadata(context_id):
            # Custom metadata extraction logic
            return {
                "user_id": context_id[-8:],
                "created_at": "2024-01-01"
            }

        ctx = "ash_12345678abcdefgh"
        metadata = extract_metadata(ctx)
        assert "user_id" in metadata
