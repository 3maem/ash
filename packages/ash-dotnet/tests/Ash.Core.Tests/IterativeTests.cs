// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Iterative tests to increase coverage.
/// </summary>
public class IterativeTests
{
    #region JSON 100 Different Objects

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    [InlineData(40)]
    [InlineData(50)]
    [InlineData(60)]
    [InlineData(70)]
    [InlineData(80)]
    [InlineData(90)]
    public void Json_DifferentObjects(int start)
    {
        for (int i = start; i < start + 10; i++)
        {
            var input = new Dictionary<string, object?> { { "id", i }, { "name", $"item{i}" } };
            var result = Canonicalize.Json(input);
            Assert.NotEmpty(result);
        }
    }

    #endregion

    #region Query 100 Different Queries

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    [InlineData(40)]
    [InlineData(50)]
    [InlineData(60)]
    [InlineData(70)]
    [InlineData(80)]
    [InlineData(90)]
    public void Query_DifferentQueries(int start)
    {
        for (int i = start; i < start + 10; i++)
        {
            var result = Canonicalize.Query($"id={i}&name=item{i}");
            Assert.NotEmpty(result);
        }
    }

    #endregion

    #region Binding 100 Different Paths

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    [InlineData(40)]
    [InlineData(50)]
    [InlineData(60)]
    [InlineData(70)]
    [InlineData(80)]
    [InlineData(90)]
    public void Binding_DifferentPaths(int start)
    {
        for (int i = start; i < start + 10; i++)
        {
            var result = Canonicalize.Binding("GET", $"/api/v{i}/resource");
            Assert.NotEmpty(result);
        }
    }

    #endregion

    #region Proof 100 Different Secrets

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    [InlineData(40)]
    [InlineData(50)]
    [InlineData(60)]
    [InlineData(70)]
    [InlineData(80)]
    [InlineData(90)]
    public void Proof_DifferentSecrets(int start)
    {
        var proofs = new HashSet<string>();
        for (int i = start; i < start + 10; i++)
        {
            var proof = ProofV21.AshBuildProofHmac($"secret_{i}", "1234567890", "POST|/api|", "abc123");
            proofs.Add(proof);
        }
        Assert.Equal(10, proofs.Count);
    }

    #endregion

    #region Hash 100 Different Inputs

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    [InlineData(40)]
    [InlineData(50)]
    [InlineData(60)]
    [InlineData(70)]
    [InlineData(80)]
    [InlineData(90)]
    public void Hash_DifferentInputs(int start)
    {
        var hashes = new HashSet<string>();
        for (int i = start; i < start + 10; i++)
        {
            hashes.Add(ProofV21.HashBody($"input_{i}"));
        }
        Assert.Equal(10, hashes.Count);
    }

    #endregion

    #region Secret Derivation 100 Different Inputs

    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(20)]
    [InlineData(30)]
    [InlineData(40)]
    [InlineData(50)]
    [InlineData(60)]
    [InlineData(70)]
    [InlineData(80)]
    [InlineData(90)]
    public void Secret_DifferentInputs(int start)
    {
        var secrets = new HashSet<string>();
        for (int i = start; i < start + 10; i++)
        {
            secrets.Add(ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding"));
        }
        Assert.Equal(10, secrets.Count);
    }

    #endregion

    #region All Methods Different Parameters

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    [InlineData("OPTIONS")]
    [InlineData("HEAD")]
    public void Binding_AllMethods(string method)
    {
        var result = Canonicalize.Binding(method, "/path");
        Assert.StartsWith(method, result);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/api")]
    [InlineData("/api/v1")]
    [InlineData("/api/v1/users")]
    [InlineData("/api/v1/users/123")]
    [InlineData("/api/v1/users/123/profile")]
    public void Binding_DifferentDepths(string path)
    {
        var result = Canonicalize.Binding("GET", path);
        Assert.Contains("|", result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a=1")]
    [InlineData("a=1&b=2")]
    [InlineData("a=1&b=2&c=3")]
    [InlineData("z=1&a=2&m=3")]
    public void Binding_DifferentQueryStrings(string query)
    {
        var result = Canonicalize.Binding("GET", "/path", query);
        Assert.NotEmpty(result);
    }

    #endregion

    #region JSON Different Types

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(42)]
    [InlineData(999999)]
    public void Json_IntegerValues(int value)
    {
        var input = new Dictionary<string, object?> { { "num", value } };
        var result = Canonicalize.Json(input);
        Assert.Contains(value.ToString(), result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("hello")]
    [InlineData("hello world")]
    [InlineData("test with spaces")]
    public void Json_StringValues(string value)
    {
        var input = new Dictionary<string, object?> { { "str", value } };
        var result = Canonicalize.Json(input);
        Assert.Contains("str", result);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Json_BooleanValues(bool value)
    {
        var input = new Dictionary<string, object?> { { "bool", value } };
        var result = Canonicalize.Json(input);
        Assert.Contains(value.ToString().ToLower(), result);
    }

    #endregion

    #region Hash Different Lengths

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(10000)]
    public void Hash_DifferentLengths(int length)
    {
        var hash = ProofV21.HashBody(new string('a', length));
        Assert.Equal(64, hash.Length);
    }

    #endregion

    #region Base64Url Different Lengths

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(10)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(100)]
    public void Base64Url_DifferentLengths(int length)
    {
        var original = new byte[length];
        for (int i = 0; i < length; i++) original[i] = (byte)(i % 256);
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(original, decoded);
    }

    #endregion

    #region Compare Different Lengths

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(1000)]
    public void Compare_DifferentLengths(int length)
    {
        var str = new string('a', length);
        Assert.True(Compare.TimingSafe(str, str));
    }

    #endregion

    #region Nonce Different Sizes

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void Nonce_DifferentSizes(int bytes)
    {
        var nonce = ProofV21.GenerateNonce(bytes);
        Assert.Equal(bytes * 2, nonce.Length);
    }

    #endregion
}
