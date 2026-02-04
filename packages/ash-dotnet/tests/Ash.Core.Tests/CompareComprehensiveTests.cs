// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive timing-safe comparison tests.
/// </summary>
public class CompareComprehensiveTests
{
    #region Equal Strings Tests

    [Fact]
    public void TimingSafe_IdenticalStrings() => Assert.True(Compare.TimingSafe("hello", "hello"));

    [Fact]
    public void TimingSafe_EmptyStrings() => Assert.True(Compare.TimingSafe("", ""));

    [Fact]
    public void TimingSafe_SingleCharEqual() => Assert.True(Compare.TimingSafe("a", "a"));

    [Fact]
    public void TimingSafe_LongStringsEqual()
    {
        var str = new string('x', 10000);
        Assert.True(Compare.TimingSafe(str, str));
    }

    [Fact]
    public void TimingSafe_HashEqual()
    {
        var hash = ProofV21.HashBody("test");
        Assert.True(Compare.TimingSafe(hash, hash));
    }

    [Fact]
    public void TimingSafe_UnicodeEqual() => Assert.True(Compare.TimingSafe("你好世界", "你好世界"));

    [Fact]
    public void TimingSafe_SpecialCharsEqual() => Assert.True(Compare.TimingSafe("!@#$%^&*()", "!@#$%^&*()"));

    #endregion

    #region Unequal Strings Tests

    [Fact]
    public void TimingSafe_DifferentStrings() => Assert.False(Compare.TimingSafe("hello", "world"));

    [Fact]
    public void TimingSafe_SingleCharDifferent() => Assert.False(Compare.TimingSafe("a", "b"));

    [Fact]
    public void TimingSafe_DifferentLengths() => Assert.False(Compare.TimingSafe("short", "much longer string"));

    [Fact]
    public void TimingSafe_EmptyVsNonEmpty() => Assert.False(Compare.TimingSafe("", "notempty"));

    [Fact]
    public void TimingSafe_NonEmptyVsEmpty() => Assert.False(Compare.TimingSafe("notempty", ""));

    [Fact]
    public void TimingSafe_FirstCharDifferent() => Assert.False(Compare.TimingSafe("abcdefghij", "xbcdefghij"));

    [Fact]
    public void TimingSafe_LastCharDifferent() => Assert.False(Compare.TimingSafe("abcdefghij", "abcdefghix"));

    [Fact]
    public void TimingSafe_MiddleCharDifferent() => Assert.False(Compare.TimingSafe("abcdefghij", "abcdXfghij"));

    [Fact]
    public void TimingSafe_CaseSensitive() => Assert.False(Compare.TimingSafe("HELLO", "hello"));

    [Fact]
    public void TimingSafe_WhitespaceDifferent() => Assert.False(Compare.TimingSafe("hello", "hello "));

    #endregion

    #region Security Tests

    [Fact]
    public void TimingSafe_DetectsSingleBitChange()
    {
        var original = ProofV21.HashBody("secret");
        var modified = original[..32] + "x" + original[33..];
        Assert.False(Compare.TimingSafe(original, modified));
    }

    [Fact]
    public void TimingSafe_DetectsAllPositions()
    {
        var hash = ProofV21.HashBody("test");
        for (int i = 0; i < hash.Length; i++)
        {
            var tampered = hash.ToCharArray();
            tampered[i] = tampered[i] == 'a' ? 'b' : 'a';
            Assert.False(Compare.TimingSafe(hash, new string(tampered)));
        }
    }

    #endregion

    #region Stress Tests

    [Fact]
    public void TimingSafe_StressEqual1000()
    {
        for (int i = 0; i < 1000; i++)
        {
            var str = ProofV21.HashBody($"test_{i}");
            Assert.True(Compare.TimingSafe(str, str));
        }
    }

    [Fact]
    public void TimingSafe_StressUnequal500()
    {
        for (int i = 0; i < 500; i++)
        {
            var str1 = ProofV21.HashBody($"test_{i}");
            var str2 = ProofV21.HashBody($"different_{i}");
            Assert.False(Compare.TimingSafe(str1, str2));
        }
    }

    [Fact]
    public void TimingSafe_StressLongStrings()
    {
        for (int len = 1; len <= 100; len++)
        {
            var str = new string('a', len * 100);
            Assert.True(Compare.TimingSafe(str, str));
        }
    }

    #endregion

    #region Byte Array Tests

    [Fact]
    public void TimingSafe_BytesEqual()
    {
        var bytes1 = new byte[] { 1, 2, 3, 4 };
        var bytes2 = new byte[] { 1, 2, 3, 4 };
        Assert.True(Compare.TimingSafe(bytes1, bytes2));
    }

    [Fact]
    public void TimingSafe_BytesDifferent()
    {
        var bytes1 = new byte[] { 1, 2, 3, 4 };
        var bytes2 = new byte[] { 1, 2, 3, 5 };
        Assert.False(Compare.TimingSafe(bytes1, bytes2));
    }

    [Fact]
    public void TimingSafe_BytesDifferentLength()
    {
        var bytes1 = new byte[] { 1, 2, 3 };
        var bytes2 = new byte[] { 1, 2, 3, 4 };
        Assert.False(Compare.TimingSafe(bytes1, bytes2));
    }

    [Fact]
    public void TimingSafe_EmptyBytes()
    {
        Assert.True(Compare.TimingSafe(Array.Empty<byte>(), Array.Empty<byte>()));
    }

    #endregion
}
