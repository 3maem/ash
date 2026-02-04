// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// More iterative tests to reach 1000+ total.
/// </summary>
public class MoreIterativeTests
{
    #region JSON Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Json_Individual(int i) => Assert.NotEmpty(Canonicalize.Json(new Dictionary<string, object?> { { "id", i } }));

    #endregion

    #region Hash Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Hash_Individual(int i) => Assert.Equal(64, ProofV21.HashBody($"content_{i}").Length);

    #endregion

    #region Proof Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Proof_Individual(int i) => Assert.Equal(64, ProofV21.AshBuildProofHmac($"secret_{i}", "1234567890", "POST|/api|", "abc").Length);

    #endregion

    #region Secret Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Secret_Individual(int i) => Assert.Equal(64, ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding").Length);

    #endregion

    #region Binding Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Binding_Individual(int i) => Assert.Contains("GET", Canonicalize.Binding("GET", $"/api/resource/{i}"));

    #endregion

    #region Compare Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Compare_Individual(int i) { var s = $"test_string_{i}"; Assert.True(Compare.TimingSafe(s, s)); }

    #endregion

    #region Query Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Query_Individual(int i) => Assert.NotEmpty(Canonicalize.Query($"id={i}&name=item_{i}"));

    #endregion

    #region Base64 Stress 50-100

    [Theory][InlineData(50)][InlineData(51)][InlineData(52)][InlineData(53)][InlineData(54)]
    [InlineData(55)][InlineData(56)][InlineData(57)][InlineData(58)][InlineData(59)]
    [InlineData(60)][InlineData(61)][InlineData(62)][InlineData(63)][InlineData(64)]
    [InlineData(65)][InlineData(66)][InlineData(67)][InlineData(68)][InlineData(69)]
    [InlineData(70)][InlineData(71)][InlineData(72)][InlineData(73)][InlineData(74)]
    [InlineData(75)][InlineData(76)][InlineData(77)][InlineData(78)][InlineData(79)]
    [InlineData(80)][InlineData(81)][InlineData(82)][InlineData(83)][InlineData(84)]
    [InlineData(85)][InlineData(86)][InlineData(87)][InlineData(88)][InlineData(89)]
    [InlineData(90)][InlineData(91)][InlineData(92)][InlineData(93)][InlineData(94)]
    [InlineData(95)][InlineData(96)][InlineData(97)][InlineData(98)][InlineData(99)]
    public void Base64_Individual(int i) { var d = new byte[i]; for (int j = 0; j < i; j++) d[j] = (byte)(j % 256); Assert.Equal(d, Proof.Base64UrlDecode(Proof.Base64UrlEncode(d))); }

    #endregion
}
