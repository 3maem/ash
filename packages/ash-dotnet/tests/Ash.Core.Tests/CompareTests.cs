// ASH was developed by 3maem Co. | 12/31/2025

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Tests for constant-time comparison.
/// </summary>
public class CompareTests
{
    [Fact]
    public void TimingSafe_EqualStrings_ReturnsTrue()
    {
        var result = Compare.TimingSafe("hello", "hello");
        Assert.True(result);
    }

    [Fact]
    public void TimingSafe_DifferentStrings_ReturnsFalse()
    {
        var result = Compare.TimingSafe("hello", "world");
        Assert.False(result);
    }

    [Fact]
    public void TimingSafe_DifferentLengths_ReturnsFalse()
    {
        var result = Compare.TimingSafe("hello", "hello!");
        Assert.False(result);
    }

    [Fact]
    public void TimingSafe_EmptyStrings_ReturnsTrue()
    {
        var result = Compare.TimingSafe("", "");
        Assert.True(result);
    }

    [Fact]
    public void TimingSafe_OneEmpty_ReturnsFalse()
    {
        var result = Compare.TimingSafe("hello", "");
        Assert.False(result);
    }

    [Fact]
    public void TimingSafe_Bytes_EqualArrays_ReturnsTrue()
    {
        var a = new byte[] { 1, 2, 3, 4 };
        var b = new byte[] { 1, 2, 3, 4 };
        var result = Compare.TimingSafe(a, b);
        Assert.True(result);
    }

    [Fact]
    public void TimingSafe_Bytes_DifferentArrays_ReturnsFalse()
    {
        var a = new byte[] { 1, 2, 3, 4 };
        var b = new byte[] { 1, 2, 3, 5 };
        var result = Compare.TimingSafe(a, b);
        Assert.False(result);
    }

    [Fact]
    public void TimingSafe_Bytes_DifferentLengths_ReturnsFalse()
    {
        var a = new byte[] { 1, 2, 3 };
        var b = new byte[] { 1, 2, 3, 4 };
        var result = Compare.TimingSafe(a, b);
        Assert.False(result);
    }

    [Fact]
    public void TimingSafe_Unicode_ComparesCorrectly()
    {
        var result = Compare.TimingSafe("caf\u00e9", "caf\u00e9");
        Assert.True(result);
    }

    [Fact]
    public void TimingSafe_Unicode_DifferentNormalization_ReturnsFalse()
    {
        // Composed vs decomposed forms have different byte representations
        var composed = "caf\u00e9"; // e with acute
        var decomposed = "cafe\u0301"; // e + combining acute
        var result = Compare.TimingSafe(composed, decomposed);
        Assert.False(result);
    }
}
