package ash

import (
	"reflect"
	"testing"
)

func TestRegisterAndGetScopePolicy(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("POST|/api/transfer|", []string{"amount", "recipient"})

	scope := GetScopePolicy("POST|/api/transfer|")
	expected := []string{"amount", "recipient"}

	if !reflect.DeepEqual(scope, expected) {
		t.Errorf("Expected %v, got %v", expected, scope)
	}
}

func TestGetScopePolicyNoMatch(t *testing.T) {
	ClearScopePolicies()

	scope := GetScopePolicy("GET|/api/users|")
	if len(scope) != 0 {
		t.Errorf("Expected empty slice, got %v", scope)
	}
}

func TestHasScopePolicy(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("POST|/api/transfer|", []string{"amount"})

	if !HasScopePolicy("POST|/api/transfer|") {
		t.Error("Expected HasScopePolicy to return true")
	}

	if HasScopePolicy("GET|/api/users|") {
		t.Error("Expected HasScopePolicy to return false")
	}
}

func TestPatternMatchingFlaskStyle(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("PUT|/api/users/<id>|", []string{"role", "permissions"})

	scope := GetScopePolicy("PUT|/api/users/123|")
	expected := []string{"role", "permissions"}

	if !reflect.DeepEqual(scope, expected) {
		t.Errorf("Expected %v, got %v", expected, scope)
	}
}

func TestPatternMatchingExpressStyle(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("PUT|/api/users/:id|", []string{"role"})

	scope := GetScopePolicy("PUT|/api/users/456|")
	expected := []string{"role"}

	if !reflect.DeepEqual(scope, expected) {
		t.Errorf("Expected %v, got %v", expected, scope)
	}
}

func TestPatternMatchingLaravelStyle(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("PUT|/api/users/{id}|", []string{"email"})

	scope := GetScopePolicy("PUT|/api/users/789|")
	expected := []string{"email"}

	if !reflect.DeepEqual(scope, expected) {
		t.Errorf("Expected %v, got %v", expected, scope)
	}
}

func TestPatternMatchingSingleWildcard(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("POST|/api/*/transfer|", []string{"amount"})

	scope := GetScopePolicy("POST|/api/v1/transfer|")
	expected := []string{"amount"}

	if !reflect.DeepEqual(scope, expected) {
		t.Errorf("Expected %v, got %v", expected, scope)
	}
}

func TestPatternMatchingDoubleWildcard(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("POST|/api/**/transfer|", []string{"amount"})

	scope := GetScopePolicy("POST|/api/v1/users/transfer|")
	expected := []string{"amount"}

	if !reflect.DeepEqual(scope, expected) {
		t.Errorf("Expected %v, got %v", expected, scope)
	}
}

func TestClearPolicies(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("POST|/api/transfer|", []string{"amount"})

	if !HasScopePolicy("POST|/api/transfer|") {
		t.Error("Expected policy to exist before clear")
	}

	ClearScopePolicies()

	if HasScopePolicy("POST|/api/transfer|") {
		t.Error("Expected policy to be cleared")
	}
}

func TestRegisterScopePoliciesBulk(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicies(map[string][]string{
		"POST|/api/transfer|": {"amount", "recipient"},
		"POST|/api/payment|":  {"amount", "card_last4"},
	})

	scope1 := GetScopePolicy("POST|/api/transfer|")
	scope2 := GetScopePolicy("POST|/api/payment|")

	if !reflect.DeepEqual(scope1, []string{"amount", "recipient"}) {
		t.Errorf("Expected transfer policy, got %v", scope1)
	}
	if !reflect.DeepEqual(scope2, []string{"amount", "card_last4"}) {
		t.Errorf("Expected payment policy, got %v", scope2)
	}
}

func TestGetAllScopePolicies(t *testing.T) {
	ClearScopePolicies()
	RegisterScopePolicy("POST|/api/transfer|", []string{"amount"})
	RegisterScopePolicy("POST|/api/payment|", []string{"card"})

	all := GetAllScopePolicies()

	if len(all) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(all))
	}

	if !reflect.DeepEqual(all["POST|/api/transfer|"], []string{"amount"}) {
		t.Error("Missing or incorrect transfer policy")
	}
	if !reflect.DeepEqual(all["POST|/api/payment|"], []string{"card"}) {
		t.Error("Missing or incorrect payment policy")
	}
}
