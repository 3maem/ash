// ASH was developed by 3maem Co. | 12/31/2025

using Ash.Core;
using Ash.Core.Exceptions;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Tests for JSON canonicalization.
/// </summary>
public class CanonicalizeJsonTests
{
    [Fact]
    public void SimpleObject_SortsKeys()
    {
        var result = Canonicalize.Json("{\"b\":2,\"a\":1}");
        Assert.Equal("{\"a\":1,\"b\":2}", result);
    }

    [Fact]
    public void NestedObject_SortsKeysRecursively()
    {
        var result = Canonicalize.Json("{\"z\":{\"b\":2,\"a\":1},\"a\":1}");
        Assert.Equal("{\"a\":1,\"z\":{\"a\":1,\"b\":2}}", result);
    }

    [Fact]
    public void Array_PreservesOrder()
    {
        var result = Canonicalize.Json("[3,1,2]");
        Assert.Equal("[3,1,2]", result);
    }

    [Fact]
    public void Null_ReturnsNull()
    {
        var result = Canonicalize.Json("null");
        Assert.Equal("null", result);
    }

    [Fact]
    public void Boolean_ReturnsLowercase()
    {
        Assert.Equal("true", Canonicalize.Json("true"));
        Assert.Equal("false", Canonicalize.Json("false"));
    }

    [Fact]
    public void String_QuotesCorrectly()
    {
        var result = Canonicalize.Json("\"hello\"");
        Assert.Equal("\"hello\"", result);
    }

    [Fact]
    public void String_EscapesSpecialCharacters()
    {
        var result = Canonicalize.Json("\"hello\\n\\\"world\\\"\"");
        Assert.Equal("\"hello\\n\\\"world\\\"\"", result);
    }

    [Fact]
    public void Number_Integer()
    {
        var result = Canonicalize.Json("42");
        Assert.Equal("42", result);
    }

    [Fact]
    public void Number_Float()
    {
        var result = Canonicalize.Json("3.14");
        Assert.Equal("3.14", result);
    }

    [Fact]
    public void Number_NegativeZero_BecomesZero()
    {
        var result = Canonicalize.Json("-0");
        Assert.Equal("0", result);
    }

    [Fact]
    public void UnicodeNfc_NormalizesDecomposedCharacters()
    {
        // e + combining acute accent should normalize to e with acute
        var decomposed = "caf\u0065\u0301"; // cafe with decomposed e-acute
        var json = $"\"{decomposed}\"";
        var result = Canonicalize.Json(json);
        Assert.Equal("\"caf\u00e9\"", result); // Should be composed e-acute
    }

    [Fact]
    public void EmptyObject_ReturnsEmptyBraces()
    {
        var result = Canonicalize.Json("{}");
        Assert.Equal("{}", result);
    }

    [Fact]
    public void EmptyArray_ReturnsEmptyBrackets()
    {
        var result = Canonicalize.Json("[]");
        Assert.Equal("[]", result);
    }

    [Fact]
    public void ComplexObject_CanonicalizesDeterministically()
    {
        var json = "{\"z\":1,\"a\":{\"c\":3,\"b\":2},\"m\":[3,1,2]}";
        var result = Canonicalize.Json(json);
        Assert.Equal("{\"a\":{\"b\":2,\"c\":3},\"m\":[3,1,2],\"z\":1}", result);
    }
}
