package ash

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// API INTEGRATION TESTS
// Tests simulating real API integration scenarios
// ============================================================================

// --- REST API Scenarios ---

func TestAPIIntegrationRESTGet(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "api_client"
	method := "GET"
	path := "/api/v1/users/123"
	query := ""

	binding := NormalizeBinding(method, path, query)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("REST GET should verify")
	}
}

func TestAPIIntegrationRESTPost(t *testing.T) {
	nonce := strings.Repeat("b", 64)
	contextID := "api_client"
	method := "POST"
	path := "/api/v1/users"
	query := ""

	body := `{"name":"John","email":"john@example.com"}`
	canonical, _ := CanonicalizeJSON(map[string]interface{}{
		"name":  "John",
		"email": "john@example.com",
	})

	binding := NormalizeBinding(method, path, query)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Errorf("REST POST should verify: %s", body)
	}
}

func TestAPIIntegrationRESTPut(t *testing.T) {
	nonce := strings.Repeat("c", 64)
	contextID := "api_client"
	method := "PUT"
	path := "/api/v1/users/123"
	query := ""

	canonical, _ := CanonicalizeJSON(map[string]interface{}{
		"name":  "John Updated",
		"email": "john.updated@example.com",
	})

	binding := NormalizeBinding(method, path, query)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("REST PUT should verify")
	}
}

func TestAPIIntegrationRESTDelete(t *testing.T) {
	nonce := strings.Repeat("d", 64)
	contextID := "api_client"
	method := "DELETE"
	path := "/api/v1/users/123"
	query := ""

	binding := NormalizeBinding(method, path, query)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("REST DELETE should verify")
	}
}

func TestAPIIntegrationRESTPatch(t *testing.T) {
	nonce := strings.Repeat("e", 64)
	contextID := "api_client"
	method := "PATCH"
	path := "/api/v1/users/123"
	query := ""

	canonical, _ := CanonicalizeJSON(map[string]interface{}{
		"name": "John Patched",
	})

	binding := NormalizeBinding(method, path, query)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("REST PATCH should verify")
	}
}

// --- Query Parameter Scenarios ---

func TestAPIIntegrationPagination(t *testing.T) {
	nonce := strings.Repeat("f", 64)
	contextID := "api_client"

	pages := []struct {
		page  int
		limit int
	}{
		{1, 10},
		{2, 10},
		{1, 50},
		{5, 20},
	}

	for _, p := range pages {
		query := fmt.Sprintf("page=%d&limit=%d", p.page, p.limit)
		binding := NormalizeBinding("GET", "/api/v1/users", query)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Pagination page=%d limit=%d should verify", p.page, p.limit)
		}
	}
}

func TestAPIIntegrationFiltering(t *testing.T) {
	nonce := strings.Repeat("g", 64)
	contextID := "api_client"

	filters := []string{
		"status=active",
		"status=active&type=premium",
		"category=electronics&min_price=100&max_price=500",
		"search=keyword&sort=name&order=asc",
	}

	for _, filter := range filters {
		binding := NormalizeBinding("GET", "/api/v1/products", filter)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Filter %s should verify", filter)
		}
	}
}

// --- Authentication Flow Scenarios ---

func TestAPIIntegrationLoginFlow(t *testing.T) {
	nonce := strings.Repeat("h", 64)
	contextID := "auth_session"
	binding := NormalizeBinding("POST", "/api/v1/auth/login", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	credentials, _ := CanonicalizeJSON(map[string]interface{}{
		"username": "testuser",
		"password": "hashedpassword",
	})
	bodyHash := HashBody(credentials)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Login flow should verify")
	}
}

func TestAPIIntegrationLogoutFlow(t *testing.T) {
	nonce := strings.Repeat("i", 64)
	contextID := "auth_session"
	binding := NormalizeBinding("POST", "/api/v1/auth/logout", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Logout flow should verify")
	}
}

func TestAPIIntegrationTokenRefresh(t *testing.T) {
	nonce := strings.Repeat("j", 64)
	contextID := "auth_session"
	binding := NormalizeBinding("POST", "/api/v1/auth/refresh", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	refreshPayload, _ := CanonicalizeJSON(map[string]interface{}{
		"refresh_token": "rt_1234567890",
	})
	bodyHash := HashBody(refreshPayload)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Token refresh should verify")
	}
}

// --- File Upload Scenarios ---

func TestAPIIntegrationFileUploadMetadata(t *testing.T) {
	nonce := strings.Repeat("k", 64)
	contextID := "upload_client"
	binding := NormalizeBinding("POST", "/api/v1/files/upload", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	metadata, _ := CanonicalizeJSON(map[string]interface{}{
		"filename":     "document.pdf",
		"content_type": "application/pdf",
		"size":         1024000,
		"checksum":     "sha256:abc123",
	})
	bodyHash := HashBody(metadata)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("File upload metadata should verify")
	}
}

func TestAPIIntegrationFileDownload(t *testing.T) {
	nonce := strings.Repeat("l", 64)
	contextID := "download_client"
	binding := NormalizeBinding("GET", "/api/v1/files/12345/download", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("File download should verify")
	}
}

// --- Webhook Scenarios ---

func TestAPIIntegrationWebhookReceive(t *testing.T) {
	nonce := strings.Repeat("m", 64)
	contextID := "webhook_endpoint"
	binding := NormalizeBinding("POST", "/webhooks/payment", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	webhookPayload, _ := CanonicalizeJSON(map[string]interface{}{
		"event": "payment.completed",
		"data": map[string]interface{}{
			"payment_id": "pay_123",
			"amount":     1000,
			"currency":   "USD",
		},
	})
	bodyHash := HashBody(webhookPayload)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Webhook receive should verify")
	}
}

// --- Batch Request Scenarios ---

func TestAPIIntegrationBatchOperations(t *testing.T) {
	nonce := strings.Repeat("n", 64)
	contextID := "batch_client"
	binding := NormalizeBinding("POST", "/api/v1/batch", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	batchPayload, _ := CanonicalizeJSON(map[string]interface{}{
		"operations": []interface{}{
			map[string]interface{}{"method": "GET", "path": "/users/1"},
			map[string]interface{}{"method": "GET", "path": "/users/2"},
			map[string]interface{}{"method": "POST", "path": "/users", "body": map[string]interface{}{"name": "New"}},
		},
	})
	bodyHash := HashBody(batchPayload)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Batch operations should verify")
	}
}

// --- GraphQL Scenarios ---

func TestAPIIntegrationGraphQLQuery(t *testing.T) {
	nonce := strings.Repeat("o", 64)
	contextID := "graphql_client"
	binding := NormalizeBinding("POST", "/graphql", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	graphqlPayload, _ := CanonicalizeJSON(map[string]interface{}{
		"query": `query GetUser($id: ID!) { user(id: $id) { id name email } }`,
		"variables": map[string]interface{}{
			"id": "123",
		},
	})
	bodyHash := HashBody(graphqlPayload)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("GraphQL query should verify")
	}
}

func TestAPIIntegrationGraphQLMutation(t *testing.T) {
	nonce := strings.Repeat("p", 64)
	contextID := "graphql_client"
	binding := NormalizeBinding("POST", "/graphql", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	graphqlPayload, _ := CanonicalizeJSON(map[string]interface{}{
		"query": `mutation CreateUser($input: CreateUserInput!) { createUser(input: $input) { id } }`,
		"variables": map[string]interface{}{
			"input": map[string]interface{}{
				"name":  "New User",
				"email": "new@example.com",
			},
		},
	})
	bodyHash := HashBody(graphqlPayload)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("GraphQL mutation should verify")
	}
}

// --- Versioned API Scenarios ---

func TestAPIIntegrationVersionedEndpoints(t *testing.T) {
	nonce := strings.Repeat("q", 64)
	contextID := "versioned_client"

	versions := []string{"v1", "v2", "v3"}

	for _, version := range versions {
		binding := NormalizeBinding("GET", fmt.Sprintf("/api/%s/users", version), "")
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("API version %s should verify", version)
		}
	}
}

// --- Multi-tenant Scenarios ---

func TestAPIIntegrationMultiTenant(t *testing.T) {
	nonce := strings.Repeat("r", 64)

	tenants := []string{"tenant_a", "tenant_b", "tenant_c"}

	for _, tenant := range tenants {
		binding := NormalizeBinding("GET", "/api/v1/data", "")
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, tenant, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		// Should verify only with correct tenant
		valid := VerifyProofV21(nonce, tenant, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Tenant %s should verify", tenant)
		}

		// Should fail with different tenant
		for _, otherTenant := range tenants {
			if otherTenant == tenant {
				continue
			}
			valid := VerifyProofV21(nonce, otherTenant, binding, timestamp, bodyHash, proof)
			if valid {
				t.Errorf("Tenant %s proof should not verify with tenant %s", tenant, otherTenant)
			}
		}
	}
}

// --- Error Response Scenarios ---

func TestAPIIntegrationErrorResponses(t *testing.T) {
	nonce := strings.Repeat("s", 64)
	contextID := "error_client"

	// Test various error scenarios
	errorEndpoints := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/api/v1/notfound", 404},
		{"POST", "/api/v1/unauthorized", 401},
		{"PUT", "/api/v1/forbidden", 403},
		{"DELETE", "/api/v1/error", 500},
	}

	for _, ep := range errorEndpoints {
		binding := NormalizeBinding(ep.method, ep.path, "")
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		// Proof generation should work regardless of expected status
		if len(proof) != 64 {
			t.Errorf("Proof for %s %s should be generated", ep.method, ep.path)
		}
	}
}

// --- Rate Limiting Scenarios ---

func TestAPIIntegrationRateLimitingHeaders(t *testing.T) {
	nonce := strings.Repeat("t", 64)
	contextID := "rate_limited_client"

	// Simulate multiple rapid requests
	for i := 0; i < 10; i++ {
		binding := NormalizeBinding("GET", "/api/v1/resource", "")
		timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if len(proof) != 64 {
			t.Errorf("Request %d proof should be valid", i)
		}
	}
}

// --- Content Negotiation Scenarios ---

func TestAPIIntegrationContentTypes(t *testing.T) {
	nonce := strings.Repeat("u", 64)
	contextID := "content_client"

	contentTypes := []struct {
		contentType string
		body        string
	}{
		{"application/json", `{"key":"value"}`},
		{"application/x-www-form-urlencoded", "key=value"},
		{"text/plain", "plain text content"},
	}

	for _, ct := range contentTypes {
		binding := NormalizeBinding("POST", "/api/v1/data", "")
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody(ct.body)

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Content type %s should verify", ct.contentType)
		}
	}
}

// --- CORS Preflight Scenarios ---

func TestAPIIntegrationCORSPreflight(t *testing.T) {
	nonce := strings.Repeat("v", 64)
	contextID := "cors_client"
	binding := NormalizeBinding("OPTIONS", "/api/v1/resource", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("OPTIONS preflight should verify")
	}
}

// --- Conditional Request Scenarios ---

func TestAPIIntegrationConditionalRequests(t *testing.T) {
	nonce := strings.Repeat("w", 64)
	contextID := "conditional_client"

	// ETag-based conditional request
	binding := NormalizeBinding("GET", "/api/v1/resource/123", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Conditional request should verify")
	}
}

// --- Streaming Scenarios ---

func TestAPIIntegrationStreamingEndpoint(t *testing.T) {
	nonce := strings.Repeat("x", 64)
	contextID := "streaming_client"
	binding := NormalizeBinding("GET", "/api/v1/stream/events", "")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Streaming endpoint should verify")
	}
}

// --- Long Polling Scenarios ---

func TestAPIIntegrationLongPolling(t *testing.T) {
	nonce := strings.Repeat("y", 64)
	contextID := "longpoll_client"
	binding := NormalizeBinding("GET", "/api/v1/poll", "timeout=30000")
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Long polling should verify")
	}
}

// --- Health Check Scenarios ---

func TestAPIIntegrationHealthCheck(t *testing.T) {
	nonce := strings.Repeat("z", 64)
	contextID := "health_client"

	healthEndpoints := []string{
		"/health",
		"/api/health",
		"/api/v1/health/live",
		"/api/v1/health/ready",
	}

	for _, endpoint := range healthEndpoints {
		binding := NormalizeBinding("GET", endpoint, "")
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Health endpoint %s should verify", endpoint)
		}
	}
}
