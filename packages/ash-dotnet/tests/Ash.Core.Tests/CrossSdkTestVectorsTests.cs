// Cross-SDK Test Vectors for ASH v2.3.2
//
// These test vectors MUST produce identical results across all SDK implementations.
// Any SDK that fails these tests is not compliant with the ASH specification.

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Cross-SDK test vectors for ASH v2.3.2.
/// All SDKs must produce identical results for these tests.
/// </summary>
public class CrossSdkTestVectorsTests
{
    // Fixed test vectors - DO NOT MODIFY
    private const string TestNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string TestContextId = "ash_test_ctx_12345";
    private const string TestBinding = "POST|/api/transfer|";
    private const string TestTimestamp = "1704067200000"; // 2024-01-01 00:00:00 UTC in ms

    #region JSON Canonicalization Tests (RFC 8785 JCS)

    [Fact]
    public void JsonCanonicalize_SimpleObject_SortsKeys()
    {
        var input = new Dictionary<string, object?> { { "z", 1 }, { "a", 2 }, { "m", 3 } };
        var expected = "{\"a\":2,\"m\":3,\"z\":1}";
        var result = Canonicalize.Json(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void JsonCanonicalize_NestedObject_SortsAllKeys()
    {
        var input = new Dictionary<string, object?>
        {
            { "outer", new Dictionary<string, object?> { { "z", 1 }, { "a", 2 } } },
            { "inner", new Dictionary<string, object?> { { "b", 2 }, { "a", 1 } } }
        };
        var expected = "{\"inner\":{\"a\":1,\"b\":2},\"outer\":{\"a\":2,\"z\":1}}";
        var result = Canonicalize.Json(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void JsonCanonicalize_Array_PreservesOrder()
    {
        var input = new Dictionary<string, object?> { { "arr", new object[] { 3, 1, 2 } } };
        var expected = "{\"arr\":[3,1,2]}";
        var result = Canonicalize.Json(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void JsonCanonicalize_EmptyValues()
    {
        Assert.Equal("null", Canonicalize.Json("null"));
        Assert.Equal("true", Canonicalize.Json("true"));
        Assert.Equal("false", Canonicalize.Json("false"));
        Assert.Equal("{}", Canonicalize.Json("{}"));
        Assert.Equal("[]", Canonicalize.Json("[]"));
    }

    #endregion

    #region Query String Canonicalization Tests

    [Fact]
    public void QueryCanonicalize_Sorted()
    {
        var result = Canonicalize.Query("z=1&a=2&m=3");
        Assert.Equal("a=2&m=3&z=1", result);
    }

    [Fact]
    public void QueryCanonicalize_StripLeadingQuestionMark()
    {
        var result = Canonicalize.Query("?a=1&b=2");
        Assert.Equal("a=1&b=2", result);
    }

    [Fact]
    public void QueryCanonicalize_StripFragment()
    {
        var result = Canonicalize.Query("a=1&b=2#section");
        Assert.Equal("a=1&b=2", result);
    }

    [Fact]
    public void QueryCanonicalize_UppercaseHex()
    {
        var result = Canonicalize.Query("a=%2f&b=%2F");
        Assert.Equal("a=%2F&b=%2F", result);
    }

    [Fact]
    public void QueryCanonicalize_PreserveEmptyValues()
    {
        var result = Canonicalize.Query("a=&b=1");
        Assert.Equal("a=&b=1", result);
    }

    [Fact]
    public void QueryCanonicalize_DuplicateKeysSortedByValue()
    {
        // Per ASH spec: sort by key first, then by value for duplicate keys
        var result = Canonicalize.Query("a=z&a=a&a=m");
        Assert.Equal("a=a&a=m&a=z", result);
    }

    #endregion

    #region URL-Encoded Canonicalization Tests

    [Fact]
    public void UrlEncodedCanonicalize_Sorted()
    {
        var result = Canonicalize.UrlEncoded("b=2&a=1");
        Assert.Equal("a=1&b=2", result);
    }

    [Fact]
    public void UrlEncodedCanonicalize_PlusAsLiteral()
    {
        // ASH protocol treats + as literal plus, not space
        var result = Canonicalize.UrlEncoded("a=hello+world");
        Assert.Equal("a=hello%2Bworld", result);
    }

    [Fact]
    public void UrlEncodedCanonicalize_UppercaseHex()
    {
        var result = Canonicalize.UrlEncoded("a=hello%2fworld");
        Assert.Equal("a=hello%2Fworld", result);
    }

    [Fact]
    public void UrlEncodedCanonicalize_DuplicateKeysSortedByValue()
    {
        // Per ASH spec: sort by key first, then by value for duplicate keys
        var result = Canonicalize.UrlEncoded("a=z&a=a&a=m");
        Assert.Equal("a=a&a=m&a=z", result);
    }

    #endregion

    #region Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)

    [Fact]
    public void BindingNormalize_Simple()
    {
        var result = Canonicalize.Binding("POST", "/api/test");
        Assert.Equal("POST|/api/test|", result);
    }

    [Fact]
    public void BindingNormalize_LowercaseMethod()
    {
        var result = Canonicalize.Binding("post", "/api/test");
        Assert.Equal("POST|/api/test|", result);
    }

    [Fact]
    public void BindingNormalize_WithQuery()
    {
        var result = Canonicalize.Binding("GET", "/api/users", "page=1&sort=name");
        Assert.Equal("GET|/api/users|page=1&sort=name", result);
    }

    [Fact]
    public void BindingNormalize_QuerySorted()
    {
        var result = Canonicalize.Binding("GET", "/api/users", "z=1&a=2");
        Assert.Equal("GET|/api/users|a=2&z=1", result);
    }

    [Fact]
    public void BindingNormalize_CollapseSlashes()
    {
        var result = Canonicalize.Binding("GET", "/api//test///path");
        Assert.Equal("GET|/api/test/path|", result);
    }

    [Fact]
    public void BindingNormalize_RemoveTrailingSlash()
    {
        var result = Canonicalize.Binding("GET", "/api/test/");
        Assert.Equal("GET|/api/test|", result);
    }

    [Fact]
    public void BindingNormalize_PreserveRoot()
    {
        var result = Canonicalize.Binding("GET", "/");
        Assert.Equal("GET|/|", result);
    }

    #endregion

    #region Hash Body Tests (SHA-256 lowercase hex)

    [Fact]
    public void HashBody_KnownValue()
    {
        var result = ProofV21.HashBody("test");
        Assert.Equal("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", result);
    }

    [Fact]
    public void HashBody_Empty()
    {
        var result = ProofV21.HashBody("");
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result);
    }

    [Fact]
    public void HashBody_Format()
    {
        var result = ProofV21.HashBody("{\"amount\":100,\"recipient\":\"user123\"}");
        Assert.Equal(64, result.Length);
        Assert.Equal(result, result.ToLowerInvariant());
    }

    #endregion

    #region Client Secret Derivation Tests (v2.1)

    [Fact]
    public void DeriveClientSecret_Deterministic()
    {
        var secret1 = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var secret2 = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        Assert.Equal(secret1, secret2);
    }

    [Fact]
    public void DeriveClientSecret_Format()
    {
        var secret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        Assert.Equal(64, secret.Length);
        Assert.Equal(secret, secret.ToLowerInvariant());
    }

    [Fact]
    public void DeriveClientSecret_DifferentInputs()
    {
        var secret1 = ProofV21.DeriveClientSecret(TestNonce, "ctx_a", TestBinding);
        var secret2 = ProofV21.DeriveClientSecret(TestNonce, "ctx_b", TestBinding);
        Assert.NotEqual(secret1, secret2);
    }

    #endregion

    #region v2.1 Proof Tests

    [Fact]
    public void BuildProofV21_Deterministic()
    {
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var bodyHash = ProofV21.HashBody("{\"amount\":100}");

        var proof1 = ProofV21.BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash);
        var proof2 = ProofV21.BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash);

        Assert.Equal(proof1, proof2);
    }

    [Fact]
    public void BuildProofV21_Format()
    {
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var bodyHash = ProofV21.HashBody("{\"amount\":100}");

        var proof = ProofV21.BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash);

        Assert.Equal(64, proof.Length);
        Assert.Equal(proof, proof.ToLowerInvariant());
    }

    [Fact]
    public void VerifyProofV21_Valid()
    {
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var bodyHash = ProofV21.HashBody("{\"amount\":100}");
        var proof = ProofV21.BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash);

        var valid = ProofV21.VerifyProofV21(TestNonce, TestContextId, TestBinding, TestTimestamp, bodyHash, proof);

        Assert.True(valid);
    }

    [Fact]
    public void VerifyProofV21_InvalidProof()
    {
        var bodyHash = ProofV21.HashBody("{\"amount\":100}");
        var wrongProof = new string('0', 64);

        var valid = ProofV21.VerifyProofV21(TestNonce, TestContextId, TestBinding, TestTimestamp, bodyHash, wrongProof);

        Assert.False(valid);
    }

    [Fact]
    public void VerifyProofV21_WrongBody()
    {
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var bodyHash1 = ProofV21.HashBody("{\"amount\":100}");
        var bodyHash2 = ProofV21.HashBody("{\"amount\":200}");
        var proof = ProofV21.BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash1);

        var valid = ProofV21.VerifyProofV21(TestNonce, TestContextId, TestBinding, TestTimestamp, bodyHash2, proof);

        Assert.False(valid);
    }

    #endregion

    #region v2.3 Unified Proof Tests (with Scoping and Chaining)

    [Fact]
    public void BuildProofUnified_BasicNoScopeNoChain()
    {
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var payload = new Dictionary<string, object?> { { "amount", 100 }, { "note", "test" } };

        var result = ProofV23.BuildProofUnified(clientSecret, TestTimestamp, TestBinding, payload);

        Assert.Equal(64, result.Proof.Length);
        Assert.Equal("", result.ScopeHash);
        Assert.Equal("", result.ChainHash);

        // Verify
        var valid = ProofV23.VerifyProofUnified(TestNonce, TestContextId, TestBinding, TestTimestamp, payload, result.Proof);
        Assert.True(valid);
    }

    [Fact]
    public void BuildProofUnified_WithScope()
    {
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, TestBinding);
        var payload = new Dictionary<string, object?> { { "amount", 100 }, { "note", "test" }, { "recipient", "user123" } };
        var scope = new[] { "amount", "recipient" };

        var result = ProofV23.BuildProofUnified(clientSecret, TestTimestamp, TestBinding, payload, scope);

        Assert.NotEqual("", result.ScopeHash);
        Assert.Equal("", result.ChainHash);

        // Verify
        var valid = ProofV23.VerifyProofUnified(TestNonce, TestContextId, TestBinding, TestTimestamp, payload, result.Proof, scope, result.ScopeHash);
        Assert.True(valid);
    }

    [Fact]
    public void BuildProofUnified_WithChain()
    {
        var binding = "POST|/api/confirm|";
        var clientSecret = ProofV21.DeriveClientSecret(TestNonce, TestContextId, binding);
        var payload = new Dictionary<string, object?> { { "confirmed", true } };
        var previousProof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        var result = ProofV23.BuildProofUnified(clientSecret, TestTimestamp, binding, payload, Array.Empty<string>(), previousProof);

        Assert.Equal("", result.ScopeHash);
        Assert.NotEqual("", result.ChainHash);
        Assert.Equal(ProofV23.HashProof(previousProof), result.ChainHash);

        // Verify
        var valid = ProofV23.VerifyProofUnified(TestNonce, TestContextId, binding, TestTimestamp, payload, result.Proof, Array.Empty<string>(), "", previousProof, result.ChainHash);
        Assert.True(valid);
    }

    #endregion

    #region Scoped Field Extraction Tests (ENH-003)

    [Fact]
    public void ExtractScopedFields_Simple()
    {
        var payload = new Dictionary<string, object?> { { "amount", 100 }, { "note", "test" }, { "recipient", "user123" } };
        var scope = new[] { "amount", "recipient" };

        var result = ProofV22.ExtractScopedFields(payload, scope);

        Assert.Equal(100, result["amount"]);
        Assert.Equal("user123", result["recipient"]);
        Assert.False(result.ContainsKey("note"));
    }

    [Fact]
    public void ExtractScopedFields_Nested()
    {
        var payload = new Dictionary<string, object?>
        {
            { "user", new Dictionary<string, object?> { { "name", "John" }, { "email", "john@example.com" } } },
            { "amount", 100 }
        };
        var scope = new[] { "user.name", "amount" };

        var result = ProofV22.ExtractScopedFields(payload, scope);

        Assert.Equal(100, result["amount"]);
        var userDict = (Dictionary<string, object?>)result["user"]!;
        Assert.Equal("John", userDict["name"]);
        Assert.False(userDict.ContainsKey("email"));
    }

    #endregion

    #region Hash Proof Tests (for Chaining)

    [Fact]
    public void HashProof_Deterministic()
    {
        var proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        var hash1 = ProofV23.HashProof(proof);
        var hash2 = ProofV23.HashProof(proof);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashProof_Format()
    {
        var proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        var hash = ProofV23.HashProof(proof);
        Assert.Equal(64, hash.Length);
        Assert.Equal(hash, hash.ToLowerInvariant());
    }

    #endregion

    #region Timing-Safe Comparison Tests

    [Fact]
    public void TimingSafe_Equal()
    {
        Assert.True(Compare.TimingSafe("hello", "hello"));
        Assert.True(Compare.TimingSafe("", ""));
    }

    [Fact]
    public void TimingSafe_NotEqual()
    {
        Assert.False(Compare.TimingSafe("hello", "world"));
        Assert.False(Compare.TimingSafe("hello", "hello!"));
        Assert.False(Compare.TimingSafe("hello", ""));
    }

    #endregion

    #region Fixed Test Vectors

    [Fact]
    public void FixedVector_ClientSecret()
    {
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ash_fixed_test_001";
        var binding = "POST|/api/test|";

        var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);

        Assert.Equal(64, secret.Length);
        var secret2 = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        Assert.Equal(secret, secret2);
    }

    [Fact]
    public void FixedVector_BodyHash()
    {
        var payload = new Dictionary<string, object?> { { "amount", 100 }, { "recipient", "user123" } };
        var canonical = Canonicalize.Json(payload);
        var hash = ProofV21.HashBody(canonical);

        Assert.Equal("{\"amount\":100,\"recipient\":\"user123\"}", canonical);
        Assert.Equal(64, hash.Length);
    }

    #endregion
}
