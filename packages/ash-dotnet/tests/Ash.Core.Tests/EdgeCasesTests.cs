// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive edge case tests.
/// </summary>
public class EdgeCasesTests
{
    #region JSON Null Edge Cases

    [Fact]
    public void Json_NullTopLevel() => Assert.Equal("null", Canonicalize.Json("null"));

    [Fact]
    public void Json_NullInObject()
    {
        var input = new Dictionary<string, object?> { { "key", null } };
        Assert.Equal("{\"key\":null}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_NullInArray()
    {
        var input = new Dictionary<string, object?> { { "arr", new object?[] { null, null, null } } };
        Assert.Contains("null", Canonicalize.Json(input));
    }

    #endregion

    #region JSON Empty Value Edge Cases

    [Fact]
    public void Json_EmptyString()
    {
        var input = new Dictionary<string, object?> { { "str", "" } };
        Assert.Equal("{\"str\":\"\"}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_EmptyArray() => Assert.Equal("[]", Canonicalize.Json("[]"));

    [Fact]
    public void Json_EmptyObject() => Assert.Equal("{}", Canonicalize.Json("{}"));

    [Fact]
    public void Json_StringWithOnlySpaces()
    {
        var input = new Dictionary<string, object?> { { "str", "   " } };
        var result = Canonicalize.Json(input);
        Assert.Contains("   ", result);
    }

    #endregion

    #region JSON Boolean Edge Cases

    [Fact]
    public void Json_TrueStandalone() => Assert.Equal("true", Canonicalize.Json("true"));

    [Fact]
    public void Json_FalseStandalone() => Assert.Equal("false", Canonicalize.Json("false"));

    [Fact]
    public void Json_BooleanInObject()
    {
        var input = new Dictionary<string, object?> { { "active", true }, { "deleted", false } };
        var result = Canonicalize.Json(input);
        Assert.Contains("true", result);
        Assert.Contains("false", result);
    }

    #endregion

    #region JSON Number Edge Cases

    [Fact]
    public void Json_Zero()
    {
        var input = new Dictionary<string, object?> { { "num", 0 } };
        Assert.Equal("{\"num\":0}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_NegativeNumber()
    {
        var input = new Dictionary<string, object?> { { "num", -42 } };
        Assert.Equal("{\"num\":-42}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_LargeNumber()
    {
        var input = new Dictionary<string, object?> { { "num", 9999999999L } };
        var result = Canonicalize.Json(input);
        Assert.Contains("9999999999", result);
    }

    #endregion

    #region Binding Edge Cases

    [Fact]
    public void Binding_RootPath() => Assert.Equal("GET|/|", Canonicalize.Binding("GET", "/"));

    [Fact]
    public void Binding_PathWithOnlySlashes() => Assert.Equal("GET|/|", Canonicalize.Binding("GET", "///"));

    [Fact]
    public void Binding_EmptyPath() => Assert.Equal("GET|/|", Canonicalize.Binding("GET", ""));

    [Fact]
    public void Binding_VeryLongPath()
    {
        var path = "/" + new string('a', 1000);
        var result = Canonicalize.Binding("GET", path);
        Assert.StartsWith("GET|/", result);
    }

    [Fact]
    public void Binding_PathWithManySegments()
    {
        var segments = string.Join("/", Enumerable.Repeat("seg", 100));
        var path = "/" + segments;
        var result = Canonicalize.Binding("GET", path);
        Assert.Contains("GET|/", result);
    }

    #endregion

    #region Proof Edge Cases

    [Fact]
    public void Proof_EmptySecret()
    {
        var proof = ProofV21.AshBuildProofHmac("", "1234567890", "POST|/api|", "abc123");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void Proof_EmptyTimestamp()
    {
        var proof = ProofV21.AshBuildProofHmac("secret", "", "POST|/api|", "abc123");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void Proof_EmptyBinding()
    {
        var proof = ProofV21.AshBuildProofHmac("secret", "1234567890", "", "abc123");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void Proof_EmptyBodyHash()
    {
        var proof = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void Proof_AllEmpty()
    {
        var proof = ProofV21.AshBuildProofHmac("", "", "", "");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void Proof_UnicodeSecret()
    {
        var proof = ProofV21.AshBuildProofHmac("密码🔐", "1234567890", "POST|/api|", "abc123");
        Assert.Equal(64, proof.Length);
    }

    #endregion

    #region Hash Edge Cases

    [Fact]
    public void Hash_EmptyBody()
    {
        var hash = ProofV21.HashBody("");
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void Hash_SingleByte()
    {
        var hash = ProofV21.HashBody("a");
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void Hash_NullByte()
    {
        var hash1 = ProofV21.HashBody("test\0data");
        var hash2 = ProofV21.HashBody("test");
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Base64Url Edge Cases

    [Fact]
    public void Base64Url_EncodeEmpty() => Assert.Equal("", Proof.Base64UrlEncode(Array.Empty<byte>()));

    [Fact]
    public void Base64Url_EncodeSingleByte()
    {
        var encoded = Proof.Base64UrlEncode(new byte[] { 0x61 });
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(new byte[] { 0x61 }, decoded);
    }

    [Fact]
    public void Base64Url_AllByteValues()
    {
        var original = new byte[256];
        for (int i = 0; i < 256; i++) original[i] = (byte)i;
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(original, decoded);
    }

    #endregion

    #region Compare Edge Cases

    [Fact]
    public void Compare_EmptyStrings() => Assert.True(Compare.TimingSafe("", ""));

    [Fact]
    public void Compare_OneEmpty() => Assert.False(Compare.TimingSafe("", "notempty"));

    [Fact]
    public void Compare_SingleChar()
    {
        Assert.True(Compare.TimingSafe("a", "a"));
        Assert.False(Compare.TimingSafe("a", "b"));
    }

    #endregion

    #region Query Edge Cases

    [Fact]
    public void Query_EmptyString() => Assert.Equal("", Canonicalize.Query(""));

    [Fact]
    public void Query_SingleParam() => Assert.Equal("key=value", Canonicalize.Query("key=value"));

    [Fact]
    public void Query_NoValue() => Assert.NotEmpty(Canonicalize.Query("key"));

    [Fact]
    public void Query_EmptyValue() => Assert.Equal("key=", Canonicalize.Query("key="));

    #endregion

    #region Determinism Edge Cases

    [Fact]
    public void Proof_Determinism100()
    {
        var proofs = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            proofs.Add(ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123"));
        }
        Assert.Single(proofs);
    }

    [Fact]
    public void Hash_Determinism100()
    {
        var hashes = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            hashes.Add(ProofV21.HashBody("test"));
        }
        Assert.Single(hashes);
    }

    [Fact]
    public void Binding_Determinism100()
    {
        var bindings = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            bindings.Add(Canonicalize.Binding("POST", "/api/update", "z=3&a=1"));
        }
        Assert.Single(bindings);
    }

    [Fact]
    public void Json_Determinism100()
    {
        var results = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            results.Add(Canonicalize.Json(new Dictionary<string, object?> { { "z", 26 }, { "a", 1 }, { "m", 13 } }));
        }
        Assert.Single(results);
    }

    #endregion
}
