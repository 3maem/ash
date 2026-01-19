// ASH was developed by 3maem Co. | 12/31/2025

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Tests for URL-encoded canonicalization.
/// </summary>
public class CanonicalizeUrlEncodedTests
{
    [Fact]
    public void SimplePairs_SortsByKey()
    {
        var result = Canonicalize.UrlEncoded("b=2&a=1");
        Assert.Equal("a=1&b=2", result);
    }

    [Fact]
    public void DictInput_SortsByKey()
    {
        var data = new Dictionary<string, string>
        {
            ["b"] = "2",
            ["a"] = "1"
        };
        var result = Canonicalize.UrlEncoded(data);
        Assert.Equal("a=1&b=2", result);
    }

    [Fact]
    public void DuplicateKeys_PreservesValueOrder()
    {
        var result = Canonicalize.UrlEncoded("a=2&a=1&a=3");
        Assert.Equal("a=2&a=1&a=3", result);
    }

    [Fact]
    public void EmptyValue_PreservesEmptyValue()
    {
        var result = Canonicalize.UrlEncoded("a=&b=2");
        Assert.Equal("a=&b=2", result);
    }

    [Fact]
    public void PlusAsSpace_DecodesAndReencodes()
    {
        var result = Canonicalize.UrlEncoded("a=hello+world");
        Assert.Equal("a=hello%20world", result);
    }

    [Fact]
    public void PercentEncoding_EncodesSpaces()
    {
        var data = new Dictionary<string, string>
        {
            ["a"] = "hello world"
        };
        var result = Canonicalize.UrlEncoded(data);
        Assert.Equal("a=hello%20world", result);
    }

    [Fact]
    public void EmptyInput_ReturnsEmpty()
    {
        var result = Canonicalize.UrlEncoded("");
        Assert.Equal("", result);
    }

    [Fact]
    public void SpecialCharacters_PercentEncoded()
    {
        var data = new Dictionary<string, string>
        {
            ["key"] = "value&with=special"
        };
        var result = Canonicalize.UrlEncoded(data);
        Assert.Equal("key=value%26with%3Dspecial", result);
    }

    [Fact]
    public void MultipleValues_WithDictOfLists()
    {
        var data = new Dictionary<string, IEnumerable<string>>
        {
            ["a"] = new[] { "1", "2" },
            ["b"] = new[] { "3" }
        };
        var result = Canonicalize.UrlEncoded(data);
        Assert.Equal("a=1&a=2&b=3", result);
    }
}
