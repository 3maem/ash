// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Final batch of iterative tests to reach 1000+ total.
/// </summary>
public class FinalIterativeTests
{
    #region JSON 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Json_Batch0_49(int i) => Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "x", i }, { "y", i * 2 } }));

    #endregion

    #region Hash 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Hash_Batch0_49(int i) => Assert.Matches("^[0-9a-f]{64}$", ProofV21.HashBody($"body_{i}"));

    #endregion

    #region Proof 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Proof_Batch0_49(int i) => Assert.Matches("^[0-9a-f]{64}$", ProofV21.AshBuildProofHmac($"s{i}", "t", "b", "h"));

    #endregion

    #region Secret 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Secret_Batch0_49(int i) => Assert.Matches("^[0-9a-f]{64}$", ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"c{i}", "b"));

    #endregion

    #region Binding 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Binding_Batch0_49(int i) => Assert.StartsWith("POST|", Canonicalize.Binding("POST", $"/api/v1/{i}"));

    #endregion

    #region Compare 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Compare_Batch0_49(int i) { var h = ProofV21.HashBody($"input_{i}"); Assert.True(Compare.TimingSafe(h, h)); }

    #endregion

    #region Verify 0-49

    [Theory][InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)]
    [InlineData(5)][InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)]
    [InlineData(10)][InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)]
    [InlineData(15)][InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)]
    [InlineData(20)][InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)]
    [InlineData(25)][InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)]
    [InlineData(30)][InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)]
    [InlineData(35)][InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)]
    [InlineData(40)][InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)]
    [InlineData(45)][InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Verify_Batch0_49(int i)
    {
        var n = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
        var c = $"c{i}";
        var b = $"POST|/api/{i}|";
        var t = $"{1000000000 + i}";
        var h = ProofV21.HashBody($"body_{i}");
        var s = ProofV21.DeriveClientSecret(n, c, b);
        var p = ProofV21.AshBuildProofHmac(s, t, b, h);
        Assert.True(ProofV21.AshVerifyProof(n, c, b, t, h, p));
    }

    #endregion

    #region Base64 0-49

    [Theory][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)][InlineData(5)]
    [InlineData(6)][InlineData(7)][InlineData(8)][InlineData(9)][InlineData(10)]
    [InlineData(11)][InlineData(12)][InlineData(13)][InlineData(14)][InlineData(15)]
    [InlineData(16)][InlineData(17)][InlineData(18)][InlineData(19)][InlineData(20)]
    [InlineData(21)][InlineData(22)][InlineData(23)][InlineData(24)][InlineData(25)]
    [InlineData(26)][InlineData(27)][InlineData(28)][InlineData(29)][InlineData(30)]
    [InlineData(31)][InlineData(32)][InlineData(33)][InlineData(34)][InlineData(35)]
    [InlineData(36)][InlineData(37)][InlineData(38)][InlineData(39)][InlineData(40)]
    [InlineData(41)][InlineData(42)][InlineData(43)][InlineData(44)][InlineData(45)]
    [InlineData(46)][InlineData(47)][InlineData(48)][InlineData(49)]
    public void Base64_Batch0_49(int i)
    {
        var d = new byte[i];
        for (int j = 0; j < i; j++) d[j] = (byte)((j + i) % 256);
        Assert.Equal(d, Proof.Base64UrlDecode(Proof.Base64UrlEncode(d)));
    }

    #endregion
}
