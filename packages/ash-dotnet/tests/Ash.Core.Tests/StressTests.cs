// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive stress tests.
/// </summary>
public class StressTests
{
    #region JSON Canonicalization Stress

    [Fact]
    public void JsonStress1000Objects()
    {
        for (int i = 0; i < 1000; i++)
        {
            var input = new Dictionary<string, object?> { { "key", i }, { "nested", new Dictionary<string, object?> { { "value", i * 2 } } } };
            var result = Canonicalize.Json(input);
            Assert.NotEmpty(result);
        }
    }

    [Fact]
    public void JsonStressDeepNesting()
    {
        for (int depth = 1; depth <= 30; depth++)
        {
            var input = new Dictionary<string, object?> { { "value", "deep" } };
            for (int i = 0; i < depth; i++)
            {
                input = new Dictionary<string, object?> { { "level", input } };
            }
            var result = Canonicalize.Json(input);
            Assert.Contains("deep", result);
        }
    }

    [Fact]
    public void JsonStressWideObjects()
    {
        for (int width = 10; width <= 100; width += 10)
        {
            var input = new Dictionary<string, object?>();
            for (int i = 0; i < width; i++)
            {
                input[$"key_{i}"] = i;
            }
            var result = Canonicalize.Json(input);
            Assert.NotEmpty(result);
        }
    }

    [Fact]
    public void JsonStressLongStrings()
    {
        var lengths = new[] { 100, 500, 1000, 5000 };
        foreach (var len in lengths)
        {
            var input = new Dictionary<string, object?> { { "data", new string('a', len) } };
            var result = Canonicalize.Json(input);
            Assert.Contains(new string('a', len), result);
        }
    }

    [Fact]
    public void JsonStressArrays()
    {
        for (int i = 0; i < 100; i++)
        {
            var arr = Enumerable.Range(0, 50).Cast<object>().ToArray();
            var input = new Dictionary<string, object?> { { "array", arr } };
            var result = Canonicalize.Json(input);
            Assert.NotEmpty(result);
        }
    }

    #endregion

    #region Binding Normalization Stress

    [Fact]
    public void BindingStress1000()
    {
        var methods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH" };
        for (int i = 0; i < 1000; i++)
        {
            var method = methods[i % methods.Length];
            var path = $"/api/v1/resource/{i}";
            var query = $"page={i}&limit=10";
            var result = Canonicalize.Binding(method, path, query);
            Assert.Contains(method, result);
        }
    }

    [Fact]
    public void BindingStressLongPaths()
    {
        for (int segments = 1; segments <= 50; segments++)
        {
            var path = "/" + string.Join("/", Enumerable.Repeat("segment", segments));
            var result = Canonicalize.Binding("GET", path);
            Assert.StartsWith("GET|/", result);
        }
    }

    [Fact]
    public void BindingStressManyQueryParams()
    {
        for (int count = 10; count <= 100; count += 10)
        {
            var query = string.Join("&", Enumerable.Range(0, count).Select(i => $"param_{i}=value_{i}"));
            var result = Canonicalize.Binding("GET", "/path", query);
            Assert.NotEmpty(result);
        }
    }

    #endregion

    #region Hash Stress

    [Fact]
    public void HashStress1000()
    {
        for (int i = 0; i < 1000; i++)
        {
            var hash = ProofV21.HashBody($"body content {i}");
            Assert.Equal(64, hash.Length);
        }
    }

    [Fact]
    public void HashStressLargeBody()
    {
        var sizes = new[] { 1000, 5000, 10000, 50000 };
        foreach (var size in sizes)
        {
            var body = new string('a', size);
            var hash = ProofV21.HashBody(body);
            Assert.Equal(64, hash.Length);
        }
    }

    [Fact]
    public void HashStressUniqueness()
    {
        var hashes = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            hashes.Add(ProofV21.HashBody($"unique_input_{i}"));
        }
        Assert.Equal(1000, hashes.Count);
    }

    #endregion

    #region Proof Stress

    [Fact]
    public void ProofStress500()
    {
        for (int i = 0; i < 500; i++)
        {
            var proof = ProofV21.AshBuildProofHmac($"secret_{i}", $"{1000000000 + i}", $"POST|/api/{i}|", ProofV21.HashBody($"body_{i}"));
            Assert.Equal(64, proof.Length);
        }
    }

    [Fact]
    public void ProofVerifyStress100()
    {
        for (int i = 0; i < 100; i++)
        {
            var nonce = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var contextId = $"ctx_{i}";
            var binding = $"POST|/api/resource/{i}|";
            var timestamp = $"{1000000000 + i}";
            var bodyHash = ProofV21.HashBody($"content_{i}");

            var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
            var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

            Assert.True(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof));
        }
    }

    [Fact]
    public void ProofUniqueness500()
    {
        var proofs = new HashSet<string>();
        for (int i = 0; i < 500; i++)
        {
            var proof = ProofV21.AshBuildProofHmac($"secret_{i}", "1234567890", "POST|/api|", "abc123");
            proofs.Add(proof);
        }
        Assert.Equal(500, proofs.Count);
    }

    #endregion

    #region Secret Derivation Stress

    [Fact]
    public void SecretDerivationStress500()
    {
        for (int i = 0; i < 500; i++)
        {
            var secret = ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding");
            Assert.Equal(64, secret.Length);
        }
    }

    [Fact]
    public void SecretDerivationUniqueness()
    {
        var secrets = new HashSet<string>();
        for (int i = 0; i < 500; i++)
        {
            secrets.Add(ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding"));
        }
        Assert.Equal(500, secrets.Count);
    }

    #endregion

    #region Compare Stress

    [Fact]
    public void CompareStress1000Equal()
    {
        for (int i = 0; i < 1000; i++)
        {
            var str = ProofV21.HashBody($"test_{i}");
            Assert.True(Compare.TimingSafe(str, str));
        }
    }

    [Fact]
    public void CompareStress500Unequal()
    {
        for (int i = 0; i < 500; i++)
        {
            var str1 = ProofV21.HashBody($"test_{i}");
            var str2 = ProofV21.HashBody($"different_{i}");
            Assert.False(Compare.TimingSafe(str1, str2));
        }
    }

    #endregion

    #region Base64Url Stress

    [Fact]
    public void Base64UrlRoundTripStress500()
    {
        var random = new Random(42);
        for (int i = 0; i < 500; i++)
        {
            var original = new byte[32 + (i % 100)];
            random.NextBytes(original);
            var encoded = Proof.Base64UrlEncode(original);
            var decoded = Proof.Base64UrlDecode(encoded);
            Assert.Equal(original, decoded);
        }
    }

    #endregion

    #region Full Workflow Stress

    [Fact]
    public void FullWorkflowStress100()
    {
        for (int i = 0; i < 100; i++)
        {
            // Canonicalize JSON
            var payload = new Dictionary<string, object?> { { "action", "update" }, { "id", i }, { "data", $"value_{i}" } };
            var canonical = Canonicalize.Json(payload);

            // Normalize binding
            var binding = Canonicalize.Binding("POST", $"/api/resource/{i}", $"version={i}");

            // Hash body
            var bodyHash = ProofV21.HashBody(canonical);

            // Derive secret
            var nonce = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var contextId = $"ctx_{i}";
            var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);

            // Build proof
            var timestamp = $"{1000000000 + i}";
            var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

            // Verify proof
            Assert.True(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof));
        }
    }

    #endregion

    #region Memory Stress

    [Fact]
    public void MemoryStressLargePayload()
    {
        for (int i = 0; i < 10; i++)
        {
            var input = new Dictionary<string, object?>();
            for (int j = 0; j < 1000; j++)
            {
                input[$"key_{j}"] = $"{new string('v', 10)}_{j}";
            }
            var canonical = Canonicalize.Json(input);
            var hash = ProofV21.HashBody(canonical);
            Assert.Equal(64, hash.Length);
        }
    }

    #endregion

    #region Concurrent Simulation Stress

    [Fact]
    public void ConcurrentProofGenerationSimulation()
    {
        var results = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            var proof = ProofV21.AshBuildProofHmac($"secret_thread_{i}", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), "POST|/api/concurrent|", ProofV21.HashBody($"body_{i}"));
            results.Add(proof);
        }
        Assert.Equal(100, results.Count);
    }

    #endregion
}
