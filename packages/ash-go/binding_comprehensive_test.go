package ash

import (
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// COMPREHENSIVE BINDING NORMALIZATION TESTS
// ============================================================================

// --- HTTP Method Tests ---

func TestBindingHTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			binding := NormalizeBindingFromURL(method, "/api/test")
			if !strings.HasPrefix(binding, method+"|") {
				t.Errorf("Binding should start with %s|, got %s", method, binding)
			}
		})
	}
}

func TestBindingMethodCaseNormalization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"get", "GET"},
		{"Get", "GET"},
		{"gEt", "GET"},
		{"post", "POST"},
		{"Post", "POST"},
		{"pOsT", "POST"},
		{"put", "PUT"},
		{"delete", "DELETE"},
		{"patch", "PATCH"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			binding := NormalizeBindingFromURL(tc.input, "/api")
			if !strings.HasPrefix(binding, tc.expected+"|") {
				t.Errorf("Expected method %s, got binding %s", tc.expected, binding)
			}
		})
	}
}

// --- Path Normalization Tests ---

func TestBindingPathLeadingSlash(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{"/api", "/api"},
		{"api", "/api"},
		{"api/test", "/api/test"},
		{"/", "/"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			parts := strings.Split(binding, "|")
			if len(parts) < 2 {
				t.Fatalf("Invalid binding format: %s", binding)
			}
			if parts[1] != tc.expected {
				t.Errorf("Expected path %s, got %s", tc.expected, parts[1])
			}
		})
	}
}

func TestBindingTrailingSlash(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{"/api/", "/api"},
		{"/api/test/", "/api/test"},
		{"/", "/"},
		{"/api/v1/users/", "/api/v1/users"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			parts := strings.Split(binding, "|")
			if len(parts) < 2 {
				t.Fatalf("Invalid binding format: %s", binding)
			}
			if parts[1] != tc.expected {
				t.Errorf("Expected path %s, got %s", tc.expected, parts[1])
			}
		})
	}
}

func TestBindingDoubleSlashes(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{"/api//test", "/api/test"},
		{"//api/test", "/api/test"},
		{"/api///test", "/api/test"},
		{"/api/test//", "/api/test"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			parts := strings.Split(binding, "|")
			if len(parts) < 2 {
				t.Fatalf("Invalid binding format: %s", binding)
			}
			if parts[1] != tc.expected {
				t.Errorf("Expected path %s, got %s", tc.expected, parts[1])
			}
		})
	}
}

// --- Query String Tests ---

func TestBindingQuerySorting(t *testing.T) {
	testCases := []struct {
		name     string
		path     string
		contains string
	}{
		{"alphabetical", "/api?z=1&a=2", "a=2&z=1"},
		{"numbers_first", "/api?a=1&1=2", "1=2&a=1"},
		{"same_key", "/api?a=2&a=1", "a=1&a=2"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			if !strings.Contains(binding, tc.contains) {
				t.Errorf("Binding should contain %s, got %s", tc.contains, binding)
			}
		})
	}
}

func TestBindingQueryEncoding(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"space_encoded", "/api?name=john%20doe"},
		{"plus_sign", "/api?name=john+doe"},
		{"special_chars", "/api?data=%21%40%23"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

func TestBindingQueryEmptyValues(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"empty_value", "/api?key="},
		{"no_equals", "/api?key"},
		{"multiple_empty", "/api?a=&b="},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

// --- Fragment Handling Tests ---

func TestBindingFragmentRemoval(t *testing.T) {
	testCases := []struct {
		path        string
		shouldNotHave string
	}{
		{"/api#section", "#section"},
		{"/api?q=1#section", "#section"},
		{"/api#", "#"},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			if strings.Contains(binding, tc.shouldNotHave) {
				t.Errorf("Binding should not contain %s, got %s", tc.shouldNotHave, binding)
			}
		})
	}
}

// --- Path Segment Tests ---

func TestBindingPathSegments(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"simple", "/api"},
		{"two_segments", "/api/users"},
		{"three_segments", "/api/users/123"},
		{"many_segments", "/api/v1/users/123/posts/456"},
		{"with_extension", "/api/data.json"},
		{"with_dots", "/api/v1.0/users"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

// --- Special Characters in Path ---

func TestBindingSpecialCharsInPath(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"hyphen", "/api/my-resource"},
		{"underscore", "/api/my_resource"},
		{"tilde", "/api/~user"},
		{"dot", "/api/file.txt"},
		{"encoded_space", "/api/my%20resource"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", tc.path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

// --- Real-World Path Patterns ---

func TestBindingRESTPatterns(t *testing.T) {
	patterns := []struct {
		method string
		path   string
	}{
		{"GET", "/api/users"},
		{"GET", "/api/users/123"},
		{"POST", "/api/users"},
		{"PUT", "/api/users/123"},
		{"PATCH", "/api/users/123"},
		{"DELETE", "/api/users/123"},
		{"GET", "/api/users/123/posts"},
		{"GET", "/api/users/123/posts/456"},
	}

	for _, p := range patterns {
		t.Run(fmt.Sprintf("%s_%s", p.method, p.path), func(t *testing.T) {
			binding := NormalizeBindingFromURL(p.method, p.path)
			if !strings.HasPrefix(binding, p.method+"|") {
				t.Errorf("Binding should start with method")
			}
		})
	}
}

func TestBindingAPIVersionPatterns(t *testing.T) {
	patterns := []string{
		"/v1/users",
		"/v2/users",
		"/api/v1/users",
		"/api/v2.0/users",
		"/api/v1.2.3/users",
	}

	for _, path := range patterns {
		t.Run(path, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

// --- Binding Format Tests ---

func TestBindingFormat(t *testing.T) {
	binding := NormalizeBindingFromURL("POST", "/api/test?a=1")
	parts := strings.Split(binding, "|")

	if len(parts) < 2 {
		t.Fatalf("Binding should have at least 2 parts separated by |")
	}

	if parts[0] != "POST" {
		t.Errorf("First part should be method, got %s", parts[0])
	}

	if !strings.HasPrefix(parts[1], "/") {
		t.Errorf("Second part should start with /, got %s", parts[1])
	}
}

func TestBindingConsistency(t *testing.T) {
	testCases := []struct {
		method1 string
		path1   string
		method2 string
		path2   string
		same    bool
	}{
		{"GET", "/api", "GET", "/api", true},
		{"GET", "/api", "get", "/api", true},
		{"GET", "/api/", "GET", "/api", true},
		{"GET", "/api", "POST", "/api", false},
		{"GET", "/api", "GET", "/api2", false},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			b1 := NormalizeBindingFromURL(tc.method1, tc.path1)
			b2 := NormalizeBindingFromURL(tc.method2, tc.path2)

			if tc.same && b1 != b2 {
				t.Errorf("Bindings should be same: %s != %s", b1, b2)
			}
			if !tc.same && b1 == b2 {
				t.Errorf("Bindings should be different: %s == %s", b1, b2)
			}
		})
	}
}

// --- Determinism Tests ---

func TestBindingDeterminism(t *testing.T) {
	paths := []string{
		"/api/users?b=2&a=1",
		"/api//test///path",
		"/API/Test/",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			b1 := NormalizeBindingFromURL("GET", path)
			for i := 0; i < 100; i++ {
				b2 := NormalizeBindingFromURL("GET", path)
				if b1 != b2 {
					t.Errorf("Non-deterministic: %s != %s", b1, b2)
				}
			}
		})
	}
}

// --- Complex Query Strings ---

func TestBindingComplexQueries(t *testing.T) {
	queries := []string{
		"?a=1&b=2&c=3",
		"?filter[name]=john&filter[age]=30",
		"?ids[]=1&ids[]=2&ids[]=3",
		"?search=hello+world",
		"?data=%7B%22key%22%3A%22value%22%7D",
	}

	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", "/api"+q)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

// --- Unicode in Paths ---

func TestBindingUnicodePaths(t *testing.T) {
	paths := []string{
		"/api/用户",
		"/api/пользователи",
		"/api/משתמשים",
		"/api/🚀",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			binding := NormalizeBindingFromURL("GET", path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}

// --- Edge Cases ---

func TestBindingEdgeCases(t *testing.T) {
	testCases := []struct {
		name   string
		method string
		path   string
	}{
		{"root_only", "GET", "/"},
		{"very_long_path", "GET", "/api" + strings.Repeat("/segment", 50)},
		{"many_query_params", "GET", "/api?" + strings.Repeat("k=v&", 50) + "last=1"},
		{"empty_query", "GET", "/api?"},
		{"question_only", "GET", "/api?"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding := NormalizeBindingFromURL(tc.method, tc.path)
			if binding == "" {
				t.Error("Binding should not be empty")
			}
		})
	}
}
