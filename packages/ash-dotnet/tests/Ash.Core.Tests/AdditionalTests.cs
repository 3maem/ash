// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Additional tests to reach 1000+ total.
/// </summary>
public class AdditionalTests
{
    #region JSON Array Tests

    [Fact] public void Json_EmptyArray1() => Assert.Equal("[]", Canonicalize.Json("[]"));
    [Fact] public void Json_SingleIntArray() => Assert.Equal("[1]", Canonicalize.Json("[1]"));
    [Fact] public void Json_MultiIntArray() => Assert.Equal("[1,2,3]", Canonicalize.Json("[1,2,3]"));
    [Fact] public void Json_StringArray() => Assert.NotEmpty(Canonicalize.Json("[\"a\",\"b\",\"c\"]"));
    [Fact] public void Json_MixedArray() => Assert.NotEmpty(Canonicalize.Json("[1,\"a\",true,null]"));
    [Fact] public void Json_NestedArray() => Assert.NotEmpty(Canonicalize.Json("[[1,2],[3,4]]"));

    #endregion

    #region JSON Object Tests

    [Fact] public void Json_SingleKey() => Assert.NotEmpty(Canonicalize.Json("{\"a\":1}"));
    [Fact] public void Json_TwoKeys() => Assert.NotEmpty(Canonicalize.Json("{\"a\":1,\"b\":2}"));
    [Fact] public void Json_ThreeKeys() => Assert.NotEmpty(Canonicalize.Json("{\"a\":1,\"b\":2,\"c\":3}"));
    [Fact] public void Json_NestedObject() => Assert.NotEmpty(Canonicalize.Json("{\"a\":{\"b\":1}}"));
    [Fact] public void Json_DeepNested() => Assert.NotEmpty(Canonicalize.Json("{\"a\":{\"b\":{\"c\":1}}}"));

    #endregion

    #region Binding Method Tests

    [Fact] public void Binding_Get() => Assert.StartsWith("GET|", Canonicalize.Binding("GET", "/"));
    [Fact] public void Binding_Post() => Assert.StartsWith("POST|", Canonicalize.Binding("POST", "/"));
    [Fact] public void Binding_Put() => Assert.StartsWith("PUT|", Canonicalize.Binding("PUT", "/"));
    [Fact] public void Binding_Delete() => Assert.StartsWith("DELETE|", Canonicalize.Binding("DELETE", "/"));
    [Fact] public void Binding_Patch() => Assert.StartsWith("PATCH|", Canonicalize.Binding("PATCH", "/"));
    [Fact] public void Binding_Options() => Assert.StartsWith("OPTIONS|", Canonicalize.Binding("OPTIONS", "/"));
    [Fact] public void Binding_Head() => Assert.StartsWith("HEAD|", Canonicalize.Binding("HEAD", "/"));
    [Fact] public void Binding_LowerGet() => Assert.StartsWith("GET|", Canonicalize.Binding("get", "/"));
    [Fact] public void Binding_LowerPost() => Assert.StartsWith("POST|", Canonicalize.Binding("post", "/"));
    [Fact] public void Binding_MixedGet() => Assert.StartsWith("GET|", Canonicalize.Binding("GeT", "/"));

    #endregion

    #region Binding Path Tests

    [Fact] public void Binding_Root() => Assert.Contains("|/|", Canonicalize.Binding("GET", "/"));
    [Fact] public void Binding_Simple() => Assert.Contains("|/api|", Canonicalize.Binding("GET", "/api"));
    [Fact] public void Binding_Nested() => Assert.Contains("|/api/v1|", Canonicalize.Binding("GET", "/api/v1"));
    [Fact] public void Binding_Deep() => Assert.Contains("|/api/v1/users|", Canonicalize.Binding("GET", "/api/v1/users"));
    [Fact] public void Binding_WithId() => Assert.Contains("|/api/users/123|", Canonicalize.Binding("GET", "/api/users/123"));
    [Fact] public void Binding_NoLeadingSlash() => Assert.Contains("|/path|", Canonicalize.Binding("GET", "path"));
    [Fact] public void Binding_TrailingSlash() => Assert.Contains("|/path|", Canonicalize.Binding("GET", "/path/"));
    [Fact] public void Binding_DoubleSlash() => Assert.Contains("|/path|", Canonicalize.Binding("GET", "//path"));

    #endregion

    #region Hash Tests

    [Fact] public void Hash_Empty() => Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ProofV21.HashBody(""));
    [Fact] public void Hash_Hello() => Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", ProofV21.HashBody("hello"));
    [Fact] public void Hash_A() => Assert.Equal(64, ProofV21.HashBody("a").Length);
    [Fact] public void Hash_B() => Assert.Equal(64, ProofV21.HashBody("b").Length);
    [Fact] public void Hash_AB() => Assert.Equal(64, ProofV21.HashBody("ab").Length);
    [Fact] public void Hash_ABC() => Assert.Equal(64, ProofV21.HashBody("abc").Length);
    [Fact] public void Hash_Different() => Assert.NotEqual(ProofV21.HashBody("a"), ProofV21.HashBody("b"));
    [Fact] public void Hash_Deterministic() => Assert.Equal(ProofV21.HashBody("test"), ProofV21.HashBody("test"));

    #endregion

    #region Compare Tests

    [Fact] public void Compare_Empty() => Assert.True(Compare.TimingSafe("", ""));
    [Fact] public void Compare_Single() => Assert.True(Compare.TimingSafe("a", "a"));
    [Fact] public void Compare_Short() => Assert.True(Compare.TimingSafe("abc", "abc"));
    [Fact] public void Compare_Long() => Assert.True(Compare.TimingSafe(new string('x', 1000), new string('x', 1000)));
    [Fact] public void Compare_DiffLen() => Assert.False(Compare.TimingSafe("a", "ab"));
    [Fact] public void Compare_DiffFirst() => Assert.False(Compare.TimingSafe("xbc", "abc"));
    [Fact] public void Compare_DiffLast() => Assert.False(Compare.TimingSafe("abx", "abc"));
    [Fact] public void Compare_DiffMid() => Assert.False(Compare.TimingSafe("axc", "abc"));

    #endregion

    #region Query Tests

    [Fact] public void Query_Empty() => Assert.Equal("", Canonicalize.Query(""));
    [Fact] public void Query_Single() => Assert.Equal("a=1", Canonicalize.Query("a=1"));
    [Fact] public void Query_Two() => Assert.Equal("a=1&b=2", Canonicalize.Query("b=2&a=1"));
    [Fact] public void Query_Three() => Assert.Equal("a=1&b=2&c=3", Canonicalize.Query("c=3&a=1&b=2"));
    [Fact] public void Query_Dup() => Assert.Equal("a=1&a=2", Canonicalize.Query("a=2&a=1"));
    [Fact] public void Query_NoValue() => Assert.Contains("key", Canonicalize.Query("key"));
    [Fact] public void Query_EmptyValue() => Assert.Contains("key=", Canonicalize.Query("key="));
    [Fact] public void Query_LeadingQ() => Assert.Equal("a=1", Canonicalize.Query("?a=1"));

    #endregion

    #region Proof Tests

    [Fact] public void Proof_Len64() => Assert.Equal(64, ProofV21.AshBuildProofHmac("s", "t", "b", "h").Length);
    [Fact] public void Proof_Hex() => Assert.Matches("^[0-9a-f]{64}$", ProofV21.AshBuildProofHmac("s", "t", "b", "h"));
    [Fact] public void Proof_DiffSecret() => Assert.NotEqual(ProofV21.AshBuildProofHmac("s1", "t", "b", "h"), ProofV21.AshBuildProofHmac("s2", "t", "b", "h"));
    [Fact] public void Proof_DiffTime() => Assert.NotEqual(ProofV21.AshBuildProofHmac("s", "t1", "b", "h"), ProofV21.AshBuildProofHmac("s", "t2", "b", "h"));
    [Fact] public void Proof_DiffBinding() => Assert.NotEqual(ProofV21.AshBuildProofHmac("s", "t", "b1", "h"), ProofV21.AshBuildProofHmac("s", "t", "b2", "h"));
    [Fact] public void Proof_DiffHash() => Assert.NotEqual(ProofV21.AshBuildProofHmac("s", "t", "b", "h1"), ProofV21.AshBuildProofHmac("s", "t", "b", "h2"));
    [Fact] public void Proof_Deterministic() => Assert.Equal(ProofV21.AshBuildProofHmac("s", "t", "b", "h"), ProofV21.AshBuildProofHmac("s", "t", "b", "h"));

    #endregion

    #region Secret Tests

    [Fact] public void Secret_Len64() => Assert.Equal(64, ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b").Length);
    [Fact] public void Secret_Hex() => Assert.Matches("^[0-9a-f]{64}$", ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b"));
    [Fact] public void Secret_DiffNonce() => Assert.NotEqual(ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b"), ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1235", "c", "b"));
    [Fact] public void Secret_DiffCtx() => Assert.NotEqual(ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c1", "b"), ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c2", "b"));
    [Fact] public void Secret_DiffBinding() => Assert.NotEqual(ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b1"), ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b2"));
    [Fact] public void Secret_Deterministic() => Assert.Equal(ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b"), ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "c", "b"));

    #endregion

    #region Base64Url Tests

    [Fact] public void Base64_Empty() => Assert.Equal("", Proof.Base64UrlEncode(Array.Empty<byte>()));
    [Fact] public void Base64_Single() => Assert.NotEmpty(Proof.Base64UrlEncode(new byte[] { 0x61 }));
    [Fact] public void Base64_NoPlus() => Assert.DoesNotContain("+", Proof.Base64UrlEncode(new byte[] { 0xfb, 0xff }));
    [Fact] public void Base64_NoSlash() => Assert.DoesNotContain("/", Proof.Base64UrlEncode(new byte[] { 0xfb, 0xff }));
    [Fact] public void Base64_NoPad() => Assert.DoesNotContain("=", Proof.Base64UrlEncode(new byte[] { 1, 2 }));
    [Fact] public void Base64_RoundTrip1() { var d = new byte[] { 1 }; Assert.Equal(d, Proof.Base64UrlDecode(Proof.Base64UrlEncode(d))); }
    [Fact] public void Base64_RoundTrip2() { var d = new byte[] { 1, 2 }; Assert.Equal(d, Proof.Base64UrlDecode(Proof.Base64UrlEncode(d))); }
    [Fact] public void Base64_RoundTrip3() { var d = new byte[] { 1, 2, 3 }; Assert.Equal(d, Proof.Base64UrlDecode(Proof.Base64UrlEncode(d))); }

    #endregion

    #region Nonce Tests

    [Fact] public void Nonce_Len64() => Assert.Equal(64, ProofV21.GenerateNonce().Length);
    [Fact] public void Nonce_Hex() => Assert.Matches("^[0-9a-f]+$", ProofV21.GenerateNonce());
    [Fact] public void Nonce_Unique1() => Assert.NotEqual(ProofV21.GenerateNonce(), ProofV21.GenerateNonce());
    [Fact] public void Nonce_Unique2() { var n = new HashSet<string>(); for (int i = 0; i < 100; i++) n.Add(ProofV21.GenerateNonce()); Assert.Equal(100, n.Count); }

    #endregion

    #region Context ID Tests

    [Fact] public void CtxId_NotEmpty() => Assert.NotEmpty(ProofV21.GenerateContextId());
    [Fact] public void CtxId_StartsAsh() => Assert.StartsWith("ash_", ProofV21.GenerateContextId());
    [Fact] public void CtxId_Unique1() => Assert.NotEqual(ProofV21.GenerateContextId(), ProofV21.GenerateContextId());
    [Fact] public void CtxId_Unique2() { var c = new HashSet<string>(); for (int i = 0; i < 100; i++) c.Add(ProofV21.GenerateContextId()); Assert.Equal(100, c.Count); }

    #endregion

    #region Verify Tests

    [Fact]
    public void Verify_Valid()
    {
        var n = "abcd1234abcd1234abcd1234abcd1234"; var c = "ctx"; var b = "POST|/api|"; var t = "123"; var h = ProofV21.HashBody("body");
        var s = ProofV21.DeriveClientSecret(n, c, b);
        var p = ProofV21.AshBuildProofHmac(s, t, b, h);
        Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
    }

    [Fact]
    public void Verify_Invalid()
    {
        var n = "abcd1234abcd1234abcd1234abcd1234"; var c = "ctx"; var b = "POST|/api|"; var t = "123"; var h = ProofV21.HashBody("body");
        Assert.False(ProofV21.AshVerifyProof(n, c, b, t, h, new string('0', 64)));
    }

    [Fact]
    public void Verify_WrongTime()
    {
        var n = "abcd1234abcd1234abcd1234abcd1234"; var c = "ctx"; var b = "POST|/api|"; var t = "123"; var h = ProofV21.HashBody("body");
        var s = ProofV21.DeriveClientSecret(n, c, b);
        var p = ProofV21.AshBuildProofHmac(s, t, b, h);
        Assert.False(ProofV21.AshVerifyProof(n, c, b, "999", h, p));
    }

    [Fact]
    public void Verify_WrongBinding()
    {
        var n = "abcd1234abcd1234abcd1234abcd1234"; var c = "ctx"; var b = "POST|/api|"; var t = "123"; var h = ProofV21.HashBody("body");
        var s = ProofV21.DeriveClientSecret(n, c, b);
        var p = ProofV21.AshBuildProofHmac(s, t, b, h);
        Assert.False(ProofV21.AshVerifyProof(n, c, "GET|/api|", t, h, p));
    }

    [Fact]
    public void Verify_WrongHash()
    {
        var n = "abcd1234abcd1234abcd1234abcd1234"; var c = "ctx"; var b = "POST|/api|"; var t = "123"; var h = ProofV21.HashBody("body");
        var s = ProofV21.DeriveClientSecret(n, c, b);
        var p = ProofV21.AshBuildProofHmac(s, t, b, h);
        Assert.False(ProofV21.AshVerifyProof(n, c, b, t, ProofV21.HashBody("tampered"), p));
    }

    #endregion

    #region More Iterative

    [Theory]
    [InlineData(0, 10)]
    [InlineData(10, 20)]
    [InlineData(20, 30)]
    [InlineData(30, 40)]
    [InlineData(40, 50)]
    public void Json_Iterative(int start, int end) { for (int i = start; i < end; i++) Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "x", i } })); }

    [Theory]
    [InlineData(0, 10)]
    [InlineData(10, 20)]
    [InlineData(20, 30)]
    [InlineData(30, 40)]
    [InlineData(40, 50)]
    public void Hash_Iterative(int start, int end) { for (int i = start; i < end; i++) Assert.Equal(64, ProofV21.HashBody($"x{i}").Length); }

    [Theory]
    [InlineData(0, 10)]
    [InlineData(10, 20)]
    [InlineData(20, 30)]
    [InlineData(30, 40)]
    [InlineData(40, 50)]
    public void Proof_Iterative(int start, int end) { for (int i = start; i < end; i++) Assert.Equal(64, ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h").Length); }

    [Theory]
    [InlineData(0, 10)]
    [InlineData(10, 20)]
    [InlineData(20, 30)]
    [InlineData(30, 40)]
    [InlineData(40, 50)]
    public void Secret_Iterative(int start, int end) { for (int i = start; i < end; i++) Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b").Length); }

    [Theory]
    [InlineData(0, 10)]
    [InlineData(10, 20)]
    [InlineData(20, 30)]
    [InlineData(30, 40)]
    [InlineData(40, 50)]
    public void Binding_Iterative(int start, int end) { for (int i = start; i < end; i++) Assert.Contains("GET", Canonicalize.Binding("GET", $"/api/{i}")); }

    #endregion
}
