package ash

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// PRODUCTION EDGE CASES - Real-world scenarios
// ============================================================================

// --- Financial Transaction Scenarios ---

func TestProductionTransferFlow(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "user_12345"
	binding := "POST|/api/v1/transfer|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	body := `{"from":"account_a","to":"account_b","amount":1000.50,"currency":"USD"}`
	bodyHash := HashBody(body)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Transfer flow should verify")
	}
}

func TestProductionPaymentWithMetadata(t *testing.T) {
	nonce := strings.Repeat("b", 64)
	contextID := "merchant_789"
	binding := "POST|/api/payments|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload := map[string]interface{}{
		"amount":      99.99,
		"currency":    "EUR",
		"reference":   "ORDER-12345",
		"description": "Product purchase",
		"metadata": map[string]interface{}{
			"product_id": "SKU-789",
			"quantity":   2,
		},
	}

	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		t.Fatalf("Failed to canonicalize: %v", err)
	}
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Payment proof should be 64 chars")
	}
}

// --- Authentication Scenarios ---

func TestProductionLoginFlow(t *testing.T) {
	nonce := strings.Repeat("c", 64)
	contextID := "auth_session_abc"
	binding := "POST|/api/auth/login|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// Login payload (password hashed client-side)
	body := `{"username":"user@example.com","password_hash":"e3b0c44298fc..."}`
	bodyHash := HashBody(body)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Login flow should verify")
	}
}

func TestProductionTokenRefresh(t *testing.T) {
	nonce := strings.Repeat("d", 64)
	contextID := "refresh_token_xyz"
	binding := "POST|/api/auth/refresh|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Refresh proof should be 64 chars")
	}
}

// --- API Gateway Scenarios ---

func TestProductionAPIGatewayRouting(t *testing.T) {
	routes := []struct {
		method string
		path   string
		query  string
	}{
		{"GET", "/api/v1/users", "page=1&limit=10"},
		{"GET", "/api/v1/users/123", ""},
		{"POST", "/api/v1/users", ""},
		{"PUT", "/api/v1/users/123", ""},
		{"DELETE", "/api/v1/users/123", ""},
		{"PATCH", "/api/v1/users/123", ""},
	}

	nonce := strings.Repeat("e", 64)
	contextID := "api_gateway"

	for _, route := range routes {
		binding := NormalizeBinding(route.method, route.path, route.query)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Route %s %s should verify", route.method, route.path)
		}
	}
}

// --- Multi-tenant Scenarios ---

func TestProductionMultiTenant(t *testing.T) {
	tenants := []string{"tenant_a", "tenant_b", "tenant_c"}
	nonce := strings.Repeat("f", 64)
	binding := "POST|/api/data|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody(`{"data":"test"}`)

	proofs := make(map[string]string)

	for _, tenant := range tenants {
		secret := DeriveClientSecret(nonce, tenant, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)
		proofs[tenant] = proof
	}

	// Each tenant should have unique proof
	for i, t1 := range tenants {
		for j, t2 := range tenants {
			if i != j && proofs[t1] == proofs[t2] {
				t.Error("Different tenants should have different proofs")
			}
		}
	}

	// Cross-tenant verification should fail
	for _, tenant := range tenants {
		for _, otherTenant := range tenants {
			if tenant == otherTenant {
				continue
			}
			valid := VerifyProofV21(nonce, otherTenant, binding, timestamp, bodyHash, proofs[tenant])
			if valid {
				t.Error("Cross-tenant verification should fail")
			}
		}
	}
}

// --- Webhook Scenarios ---

func TestProductionWebhookSignature(t *testing.T) {
	nonce := strings.Repeat("g", 64)
	contextID := "webhook_endpoint"
	binding := "POST|/webhooks/payment|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	webhookPayload := map[string]interface{}{
		"event":     "payment.completed",
		"timestamp": time.Now().Unix(),
		"data": map[string]interface{}{
			"payment_id": "pay_123",
			"amount":     100,
			"status":     "completed",
		},
	}

	canonical, _ := CanonicalizeJSON(webhookPayload)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Webhook signature should verify")
	}
}

// --- Form Submission Scenarios ---

func TestProductionFormSubmission(t *testing.T) {
	nonce := strings.Repeat("h", 64)
	contextID := "form_session"
	binding := "POST|/api/forms/contact|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	formData := "name=John+Doe&email=john%40example.com&message=Hello+World"
	canonical, _ := CanonicalizeURLEncoded(formData)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Form submission proof should be 64 chars")
	}
}

// --- File Upload Scenarios ---

func TestProductionFileUploadMetadata(t *testing.T) {
	nonce := strings.Repeat("i", 64)
	contextID := "upload_session"
	binding := "POST|/api/files/upload|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	metadata := map[string]interface{}{
		"filename":     "document.pdf",
		"content_type": "application/pdf",
		"size":         1024000,
		"checksum":     "abc123def456",
	}

	canonical, _ := CanonicalizeJSON(metadata)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("File upload proof should be 64 chars")
	}
}

// --- Batch Operation Scenarios ---

func TestProductionBatchRequest(t *testing.T) {
	nonce := strings.Repeat("j", 64)
	contextID := "batch_context"
	binding := "POST|/api/batch|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	batchPayload := map[string]interface{}{
		"requests": []interface{}{
			map[string]interface{}{"method": "GET", "path": "/api/users/1"},
			map[string]interface{}{"method": "GET", "path": "/api/users/2"},
			map[string]interface{}{"method": "GET", "path": "/api/users/3"},
		},
	}

	canonical, _ := CanonicalizeJSON(batchPayload)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Batch request should verify")
	}
}

// --- GraphQL Scenarios ---

func TestProductionGraphQLQuery(t *testing.T) {
	nonce := strings.Repeat("k", 64)
	contextID := "graphql_session"
	binding := "POST|/graphql|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	graphqlPayload := map[string]interface{}{
		"query": `query GetUser($id: ID!) {
			user(id: $id) {
				id
				name
				email
			}
		}`,
		"variables": map[string]interface{}{
			"id": "123",
		},
	}

	canonical, _ := CanonicalizeJSON(graphqlPayload)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("GraphQL proof should be 64 chars")
	}
}

// --- Real-time Scenarios ---

func TestProductionWebSocketAuth(t *testing.T) {
	nonce := strings.Repeat("l", 64)
	contextID := "websocket_channel"
	binding := "GET|/ws/connect|channel=updates"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody("")

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("WebSocket auth should verify")
	}
}

// --- International Content Scenarios ---

func TestProductionInternationalContent(t *testing.T) {
	nonce := strings.Repeat("m", 64)
	contextID := "i18n_session"
	binding := "POST|/api/content|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	internationalPayload := map[string]interface{}{
		"title_en": "Hello World",
		"title_ja": "こんにちは世界",
		"title_zh": "你好世界",
		"title_ar": "مرحبا بالعالم",
		"title_ru": "Привет мир",
		"emoji":    "👋🌍",
	}

	canonical, err := CanonicalizeJSON(internationalPayload)
	if err != nil {
		t.Fatalf("Failed to canonicalize international content: %v", err)
	}
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("International content should verify")
	}
}

// --- High Precision Number Scenarios ---

func TestProductionHighPrecisionNumbers(t *testing.T) {
	nonce := strings.Repeat("n", 64)
	contextID := "precision_context"
	binding := "POST|/api/finance|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	financialPayload := map[string]interface{}{
		"amount":        1234567890.123456,
		"exchange_rate": 0.00001234,
		"large_int":     float64(9007199254740991), // Max safe integer
	}

	canonical, _ := CanonicalizeJSON(financialPayload)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("High precision proof should be 64 chars")
	}
}

// --- Chain Request Scenarios ---

func TestProductionRequestChain(t *testing.T) {
	nonce := strings.Repeat("o", 64)
	contextID := "chain_context"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	// First request - get user
	binding1 := "GET|/api/users/123|"
	bodyHash1 := HashBody("")
	secret1 := DeriveClientSecret(nonce, contextID, binding1)
	proof1 := BuildProofV21(secret1, timestamp, binding1, bodyHash1)

	// Second request - update user (chained)
	binding2 := "PUT|/api/users/123|"
	_ = HashBody(`{"name":"Updated"}`) // hash for reference
	secret2 := DeriveClientSecret(nonce, contextID, binding2)

	result := BuildProofUnified(secret2, timestamp, binding2,
		map[string]interface{}{"name": "Updated"}, nil, proof1)

	if len(result.Proof) != 64 {
		t.Error("Chain proof should be 64 chars")
	}
}

// --- Error Recovery Scenarios ---

func TestProductionRetryWithSameTimestamp(t *testing.T) {
	nonce := strings.Repeat("p", 64)
	contextID := "retry_context"
	binding := "POST|/api/action|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	bodyHash := HashBody(`{"action":"retry"}`)

	secret := DeriveClientSecret(nonce, contextID, binding)

	// Generate same proof multiple times (for retry)
	proof1 := BuildProofV21(secret, timestamp, binding, bodyHash)
	proof2 := BuildProofV21(secret, timestamp, binding, bodyHash)
	proof3 := BuildProofV21(secret, timestamp, binding, bodyHash)

	if proof1 != proof2 || proof2 != proof3 {
		t.Error("Retry proofs with same params should be identical")
	}
}

// --- Large Scale Scenarios ---

func TestProductionLargeArrayPayload(t *testing.T) {
	nonce := strings.Repeat("q", 64)
	contextID := "large_array_context"
	binding := "POST|/api/bulk|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	items := make([]interface{}, 100)
	for i := 0; i < 100; i++ {
		items[i] = map[string]interface{}{
			"id":    i,
			"name":  fmt.Sprintf("Item %d", i),
			"value": i * 10,
		}
	}

	payload := map[string]interface{}{
		"items": items,
	}

	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		t.Fatalf("Failed to canonicalize large array: %v", err)
	}
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Large array proof should be 64 chars")
	}
}

// --- Scoped Proof Scenarios ---

func TestProductionScopedTransfer(t *testing.T) {
	secret := strings.Repeat("r", 64)
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	binding := "POST|/api/transfer|"

	payload := map[string]interface{}{
		"from":       "account_123",
		"to":         "account_456",
		"amount":     1000,
		"currency":   "USD",
		"reference":  "TX-" + timestamp,
		"metadata":   map[string]interface{}{"note": "test"},
	}

	// Only scope amount and to fields
	scope := []string{"amount", "to"}

	result := BuildProofUnified(secret, timestamp, binding, payload, scope, "")

	if len(result.Proof) != 64 {
		t.Error("Scoped proof should be 64 chars")
	}

	if len(result.ScopeHash) != 64 {
		t.Error("Scope hash should be 64 chars")
	}
}

// --- Query String Edge Cases ---

func TestProductionComplexQueryString(t *testing.T) {
	nonce := strings.Repeat("s", 64)
	contextID := "query_context"

	queries := []string{
		"filter[status]=active&filter[type]=premium&sort=-created_at",
		"ids[]=1&ids[]=2&ids[]=3",
		"search=hello+world&page=1&limit=20",
		"q=test%20query&lang=en-US&region=NA",
	}

	for _, query := range queries {
		binding := NormalizeBinding("GET", "/api/search", query)
		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		bodyHash := HashBody("")

		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
		if !valid {
			t.Errorf("Query %s should verify", query)
		}
	}
}

// --- Empty and Null Scenarios ---

func TestProductionEmptyPayload(t *testing.T) {
	nonce := strings.Repeat("t", 64)
	contextID := "empty_context"
	binding := "POST|/api/ping|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	emptyPayloads := []string{
		"",
		"{}",
		"[]",
		"null",
	}

	for _, payload := range emptyPayloads {
		bodyHash := HashBody(payload)
		secret := DeriveClientSecret(nonce, contextID, binding)
		proof := BuildProofV21(secret, timestamp, binding, bodyHash)

		if len(proof) != 64 {
			t.Errorf("Empty payload %q proof should be 64 chars", payload)
		}
	}
}

func TestProductionNullFields(t *testing.T) {
	nonce := strings.Repeat("u", 64)
	contextID := "null_context"
	binding := "POST|/api/data|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload := map[string]interface{}{
		"required": "value",
		"optional": nil,
		"nested": map[string]interface{}{
			"present": "yes",
			"absent":  nil,
		},
	}

	canonical, _ := CanonicalizeJSON(payload)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	valid := VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
	if !valid {
		t.Error("Null fields should verify")
	}
}

// --- Boolean Edge Cases ---

func TestProductionBooleanValues(t *testing.T) {
	nonce := strings.Repeat("v", 64)
	contextID := "bool_context"
	binding := "POST|/api/flags|"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	payload := map[string]interface{}{
		"enabled":  true,
		"disabled": false,
		"flags": map[string]interface{}{
			"feature_a": true,
			"feature_b": false,
		},
	}

	canonical, _ := CanonicalizeJSON(payload)
	bodyHash := HashBody(canonical)

	secret := DeriveClientSecret(nonce, contextID, binding)
	proof := BuildProofV21(secret, timestamp, binding, bodyHash)

	if len(proof) != 64 {
		t.Error("Boolean proof should be 64 chars")
	}
}
