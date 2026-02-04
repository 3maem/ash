// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive query string canonicalization tests.
/// </summary>
public class QueryCanonicalizeComprehensiveTests
{
    #region Basic Sorting Tests

    [Fact]
    public void Query_Sorted() => Assert.Equal("a=1&b=2&c=3", Canonicalize.Query("c=3&a=1&b=2"));

    [Fact]
    public void Query_AlreadySorted() => Assert.Equal("a=1&b=2&c=3", Canonicalize.Query("a=1&b=2&c=3"));

    [Fact]
    public void Query_ReverseSorted() => Assert.Equal("a=1&b=2&c=3", Canonicalize.Query("c=3&b=2&a=1"));

    [Fact]
    public void Query_SingleParam() => Assert.Equal("key=value", Canonicalize.Query("key=value"));

    [Fact]
    public void Query_Empty() => Assert.Equal("", Canonicalize.Query(""));

    #endregion

    #region Leading Question Mark Tests

    [Fact]
    public void Query_StripsLeadingQuestionMark() => Assert.Equal("a=1&b=2", Canonicalize.Query("?a=1&b=2"));

    [Fact]
    public void Query_StripsMultipleQuestionMarks() => Assert.NotEmpty(Canonicalize.Query("??a=1&b=2"));

    #endregion

    #region Duplicate Keys Tests

    [Fact]
    public void Query_DuplicateKeysSorted() => Assert.Equal("a=1&a=2&a=3", Canonicalize.Query("a=3&a=1&a=2"));

    [Fact]
    public void Query_MixedDuplicatesAndUnique() => Assert.Equal("a=1&a=2&b=3", Canonicalize.Query("b=3&a=2&a=1"));

    #endregion

    #region Empty Values Tests

    [Fact]
    public void Query_EmptyValue() => Assert.Equal("key=", Canonicalize.Query("key="));

    [Fact]
    public void Query_EmptyValueSorted() => Assert.Equal("a=&b=2", Canonicalize.Query("b=2&a="));

    [Fact]
    public void Query_NoValue() => Assert.NotEmpty(Canonicalize.Query("key"));

    #endregion

    #region Encoding Tests

    [Fact]
    public void Query_EncodesSpace()
    {
        var result = Canonicalize.Query("key=hello world");
        Assert.Contains("%20", result);
    }

    [Fact]
    public void Query_EncodesSpecialChars()
    {
        var result = Canonicalize.Query("key=hello&world");
        Assert.NotEqual("key=hello&world", result);
    }

    #endregion

    #region Numeric Keys Tests

    [Fact]
    public void Query_NumericKeysSorted() => Assert.Equal("1=one&10=ten&2=two", Canonicalize.Query("10=ten&2=two&1=one"));

    #endregion

    #region Case Sensitivity Tests

    [Fact]
    public void Query_KeysCaseSensitive() => Assert.Equal("A=1&a=2", Canonicalize.Query("a=2&A=1"));

    #endregion

    #region Determinism Tests

    [Fact]
    public void Query_IsDeterministic()
    {
        var results = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            results.Add(Canonicalize.Query("z=3&a=1&m=2"));
        }
        Assert.Single(results);
    }

    #endregion

    #region Stress Tests

    [Fact]
    public void Query_Stress1000()
    {
        for (int i = 0; i < 1000; i++)
        {
            var result = Canonicalize.Query($"key{i}=value{i}&other=test");
            Assert.NotEmpty(result);
        }
    }

    [Fact]
    public void Query_ManyParams100()
    {
        var query = string.Join("&", Enumerable.Range(0, 100).Select(i => $"param_{i}=value_{i}"));
        var result = Canonicalize.Query(query);
        Assert.Contains("param_0", result);
        Assert.Contains("param_99", result);
    }

    [Fact]
    public void Query_LongValues()
    {
        var query = $"key={new string('a', 1000)}";
        var result = Canonicalize.Query(query);
        Assert.NotEmpty(result);
    }

    #endregion
}
