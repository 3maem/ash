// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Extended stress tests for maximum coverage.
/// </summary>
public class ExtendedStressTests
{
    #region JSON Stress Extended

    [Fact]
    public void JsonStressExtended1() { for (int i = 0; i < 100; i++) Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "k", i } })); }
    [Fact]
    public void JsonStressExtended2() { for (int i = 100; i < 200; i++) Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "k", i } })); }
    [Fact]
    public void JsonStressExtended3() { for (int i = 200; i < 300; i++) Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "k", i } })); }
    [Fact]
    public void JsonStressExtended4() { for (int i = 300; i < 400; i++) Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "k", i } })); }
    [Fact]
    public void JsonStressExtended5() { for (int i = 400; i < 500; i++) Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "k", i } })); }

    #endregion

    #region Hash Stress Extended

    [Fact]
    public void HashStressExtended1() { for (int i = 0; i < 100; i++) Assert.Equal(64, ProofV21.HashBody($"b{i}").Length); }
    [Fact]
    public void HashStressExtended2() { for (int i = 100; i < 200; i++) Assert.Equal(64, ProofV21.HashBody($"b{i}").Length); }
    [Fact]
    public void HashStressExtended3() { for (int i = 200; i < 300; i++) Assert.Equal(64, ProofV21.HashBody($"b{i}").Length); }
    [Fact]
    public void HashStressExtended4() { for (int i = 300; i < 400; i++) Assert.Equal(64, ProofV21.HashBody($"b{i}").Length); }
    [Fact]
    public void HashStressExtended5() { for (int i = 400; i < 500; i++) Assert.Equal(64, ProofV21.HashBody($"b{i}").Length); }

    #endregion

    #region Proof Stress Extended

    [Fact]
    public void ProofStressExtended1() { for (int i = 0; i < 50; i++) Assert.Equal(64, ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h").Length); }
    [Fact]
    public void ProofStressExtended2() { for (int i = 50; i < 100; i++) Assert.Equal(64, ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h").Length); }
    [Fact]
    public void ProofStressExtended3() { for (int i = 100; i < 150; i++) Assert.Equal(64, ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h").Length); }
    [Fact]
    public void ProofStressExtended4() { for (int i = 150; i < 200; i++) Assert.Equal(64, ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h").Length); }
    [Fact]
    public void ProofStressExtended5() { for (int i = 200; i < 250; i++) Assert.Equal(64, ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h").Length); }

    #endregion

    #region Secret Stress Extended

    [Fact]
    public void SecretStressExtended1() { for (int i = 0; i < 50; i++) Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b").Length); }
    [Fact]
    public void SecretStressExtended2() { for (int i = 50; i < 100; i++) Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b").Length); }
    [Fact]
    public void SecretStressExtended3() { for (int i = 100; i < 150; i++) Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b").Length); }
    [Fact]
    public void SecretStressExtended4() { for (int i = 150; i < 200; i++) Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b").Length); }
    [Fact]
    public void SecretStressExtended5() { for (int i = 200; i < 250; i++) Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b").Length); }

    #endregion

    #region Binding Stress Extended

    [Fact]
    public void BindingStressExtended1() { for (int i = 0; i < 100; i++) Assert.Contains("GET", Canonicalize.Binding("GET", $"/p{i}")); }
    [Fact]
    public void BindingStressExtended2() { for (int i = 100; i < 200; i++) Assert.Contains("POST", Canonicalize.Binding("POST", $"/p{i}")); }
    [Fact]
    public void BindingStressExtended3() { for (int i = 200; i < 300; i++) Assert.Contains("PUT", Canonicalize.Binding("PUT", $"/p{i}")); }
    [Fact]
    public void BindingStressExtended4() { for (int i = 300; i < 400; i++) Assert.Contains("DELETE", Canonicalize.Binding("DELETE", $"/p{i}")); }
    [Fact]
    public void BindingStressExtended5() { for (int i = 400; i < 500; i++) Assert.Contains("PATCH", Canonicalize.Binding("PATCH", $"/p{i}")); }

    #endregion

    #region Compare Stress Extended

    [Fact]
    public void CompareStressExtended1() { for (int i = 0; i < 100; i++) { var s = $"str{i}"; Assert.True(Compare.TimingSafe(s, s)); } }
    [Fact]
    public void CompareStressExtended2() { for (int i = 100; i < 200; i++) { var s = $"str{i}"; Assert.True(Compare.TimingSafe(s, s)); } }
    [Fact]
    public void CompareStressExtended3() { for (int i = 200; i < 300; i++) { var s = $"str{i}"; Assert.True(Compare.TimingSafe(s, s)); } }
    [Fact]
    public void CompareStressExtended4() { for (int i = 300; i < 400; i++) { var s = $"str{i}"; Assert.True(Compare.TimingSafe(s, s)); } }
    [Fact]
    public void CompareStressExtended5() { for (int i = 400; i < 500; i++) { var s = $"str{i}"; Assert.True(Compare.TimingSafe(s, s)); } }

    #endregion

    #region Query Stress Extended

    [Fact]
    public void QueryStressExtended1() { for (int i = 0; i < 100; i++) Assert.NotEmpty(Canonicalize.Query($"a={i}&b={i+1}")); }
    [Fact]
    public void QueryStressExtended2() { for (int i = 100; i < 200; i++) Assert.NotEmpty(Canonicalize.Query($"a={i}&b={i+1}")); }
    [Fact]
    public void QueryStressExtended3() { for (int i = 200; i < 300; i++) Assert.NotEmpty(Canonicalize.Query($"a={i}&b={i+1}")); }
    [Fact]
    public void QueryStressExtended4() { for (int i = 300; i < 400; i++) Assert.NotEmpty(Canonicalize.Query($"a={i}&b={i+1}")); }
    [Fact]
    public void QueryStressExtended5() { for (int i = 400; i < 500; i++) Assert.NotEmpty(Canonicalize.Query($"a={i}&b={i+1}")); }

    #endregion

    #region Base64 Stress Extended

    [Fact]
    public void Base64StressExtended1() { var r = new Random(1); for (int i = 0; i < 100; i++) { var b = new byte[32]; r.NextBytes(b); Assert.Equal(b, Proof.Base64UrlDecode(Proof.Base64UrlEncode(b))); } }
    [Fact]
    public void Base64StressExtended2() { var r = new Random(2); for (int i = 0; i < 100; i++) { var b = new byte[32]; r.NextBytes(b); Assert.Equal(b, Proof.Base64UrlDecode(Proof.Base64UrlEncode(b))); } }
    [Fact]
    public void Base64StressExtended3() { var r = new Random(3); for (int i = 0; i < 100; i++) { var b = new byte[32]; r.NextBytes(b); Assert.Equal(b, Proof.Base64UrlDecode(Proof.Base64UrlEncode(b))); } }
    [Fact]
    public void Base64StressExtended4() { var r = new Random(4); for (int i = 0; i < 100; i++) { var b = new byte[32]; r.NextBytes(b); Assert.Equal(b, Proof.Base64UrlDecode(Proof.Base64UrlEncode(b))); } }
    [Fact]
    public void Base64StressExtended5() { var r = new Random(5); for (int i = 0; i < 100; i++) { var b = new byte[32]; r.NextBytes(b); Assert.Equal(b, Proof.Base64UrlDecode(Proof.Base64UrlEncode(b))); } }

    #endregion

    #region Verify Stress Extended

    [Fact]
    public void VerifyStressExtended1()
    {
        for (int i = 0; i < 20; i++)
        {
            var n = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var c = $"c{i}";
            var b = $"POST|/api/{i}|";
            var t = $"{1000000000 + i}";
            var h = ProofV21.HashBody($"body{i}");
            var s = ProofV21.DeriveClientSecret(n, c, b);
            var p = ProofV21.AshBuildProofHmac(s, t, b, h);
            Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
        }
    }

    [Fact]
    public void VerifyStressExtended2()
    {
        for (int i = 20; i < 40; i++)
        {
            var n = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var c = $"c{i}";
            var b = $"POST|/api/{i}|";
            var t = $"{1000000000 + i}";
            var h = ProofV21.HashBody($"body{i}");
            var s = ProofV21.DeriveClientSecret(n, c, b);
            var p = ProofV21.AshBuildProofHmac(s, t, b, h);
            Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
        }
    }

    [Fact]
    public void VerifyStressExtended3()
    {
        for (int i = 40; i < 60; i++)
        {
            var n = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var c = $"c{i}";
            var b = $"GET|/api/{i}|";
            var t = $"{1000000000 + i}";
            var h = ProofV21.HashBody($"body{i}");
            var s = ProofV21.DeriveClientSecret(n, c, b);
            var p = ProofV21.AshBuildProofHmac(s, t, b, h);
            Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
        }
    }

    [Fact]
    public void VerifyStressExtended4()
    {
        for (int i = 60; i < 80; i++)
        {
            var n = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var c = $"c{i}";
            var b = $"PUT|/api/{i}|";
            var t = $"{1000000000 + i}";
            var h = ProofV21.HashBody($"body{i}");
            var s = ProofV21.DeriveClientSecret(n, c, b);
            var p = ProofV21.AshBuildProofHmac(s, t, b, h);
            Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
        }
    }

    [Fact]
    public void VerifyStressExtended5()
    {
        for (int i = 80; i < 100; i++)
        {
            var n = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var c = $"c{i}";
            var b = $"DELETE|/api/{i}|";
            var t = $"{1000000000 + i}";
            var h = ProofV21.HashBody($"body{i}");
            var s = ProofV21.DeriveClientSecret(n, c, b);
            var p = ProofV21.AshBuildProofHmac(s, t, b, h);
            Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
        }
    }

    #endregion

    #region Uniqueness Extended

    [Fact]
    public void HashUniquenessExtended() { var h = new HashSet<string>(); for (int i = 0; i < 500; i++) h.Add(ProofV21.HashBody($"u{i}")); Assert.Equal(500, h.Count); }

    [Fact]
    public void SecretUniquenessExtended() { var s = new HashSet<string>(); for (int i = 0; i < 500; i++) s.Add(ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b")); Assert.Equal(500, s.Count); }

    [Fact]
    public void ProofUniquenessExtended() { var p = new HashSet<string>(); for (int i = 0; i < 500; i++) p.Add(ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h")); Assert.Equal(500, p.Count); }

    [Fact]
    public void NonceUniquenessExtended() { var n = new HashSet<string>(); for (int i = 0; i < 500; i++) n.Add(ProofV21.GenerateNonce()); Assert.Equal(500, n.Count); }

    [Fact]
    public void ContextIdUniquenessExtended() { var c = new HashSet<string>(); for (int i = 0; i < 500; i++) c.Add(ProofV21.GenerateContextId()); Assert.Equal(500, c.Count); }

    #endregion

    #region Full Workflow Extended

    [Fact]
    public void FullWorkflowExtended1()
    {
        for (int i = 0; i < 50; i++)
        {
            var payload = new Dictionary<string, object?> { { "action", "update" }, { "id", i } };
            var canonical = Canonicalize.Json(payload);
            var binding = Canonicalize.Binding("POST", $"/api/resource/{i}");
            var bodyHash = ProofV21.HashBody(canonical);
            var nonce = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var contextId = $"ctx_{i}";
            var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
            var timestamp = $"{1000000000 + i}";
            var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);
            Assert.True(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof));
        }
    }

    [Fact]
    public void FullWorkflowExtended2()
    {
        for (int i = 50; i < 100; i++)
        {
            var payload = new Dictionary<string, object?> { { "action", "delete" }, { "id", i } };
            var canonical = Canonicalize.Json(payload);
            var binding = Canonicalize.Binding("DELETE", $"/api/resource/{i}");
            var bodyHash = ProofV21.HashBody(canonical);
            var nonce = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var contextId = $"ctx_{i}";
            var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
            var timestamp = $"{1000000000 + i}";
            var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);
            Assert.True(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof));
        }
    }

    #endregion
}
