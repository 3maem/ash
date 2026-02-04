// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive JSON canonicalization tests.
/// </summary>
public class JsonCanonicalizeComprehensiveTests
{
    #region Basic Object Tests

    [Fact]
    public void Json_SimpleObject_SortsKeys()
    {
        var input = new Dictionary<string, object?> { { "z", 1 }, { "a", 2 }, { "m", 3 } };
        Assert.Equal("{\"a\":2,\"m\":3,\"z\":1}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_EmptyObject() => Assert.Equal("{}", Canonicalize.Json("{}"));

    [Fact]
    public void Json_SingleKeyObject()
    {
        var input = new Dictionary<string, object?> { { "key", "value" } };
        Assert.Equal("{\"key\":\"value\"}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_MultipleKeysSorted()
    {
        var input = new Dictionary<string, object?> { { "c", 3 }, { "a", 1 }, { "b", 2 } };
        Assert.Equal("{\"a\":1,\"b\":2,\"c\":3}", Canonicalize.Json(input));
    }

    #endregion

    #region Nested Object Tests

    [Fact]
    public void Json_NestedObject_SortsAllLevels()
    {
        var input = new Dictionary<string, object?>
        {
            { "outer", new Dictionary<string, object?> { { "z", 1 }, { "a", 2 } } }
        };
        Assert.Equal("{\"outer\":{\"a\":2,\"z\":1}}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_DeeplyNestedObject()
    {
        var inner = new Dictionary<string, object?> { { "deep", "value" } };
        var middle = new Dictionary<string, object?> { { "inner", inner } };
        var outer = new Dictionary<string, object?> { { "middle", middle } };
        Assert.Contains("deep", Canonicalize.Json(outer));
    }

    #endregion

    #region Array Tests

    [Fact]
    public void Json_EmptyArray() => Assert.Equal("[]", Canonicalize.Json("[]"));

    [Fact]
    public void Json_ArrayPreservesOrder()
    {
        var input = new Dictionary<string, object?> { { "arr", new object[] { 3, 1, 2 } } };
        Assert.Equal("{\"arr\":[3,1,2]}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_ArrayOfObjects()
    {
        var input = new Dictionary<string, object?>
        {
            { "items", new object[] {
                new Dictionary<string, object?> { { "b", 2 }, { "a", 1 } },
                new Dictionary<string, object?> { { "d", 4 }, { "c", 3 } }
            } }
        };
        var result = Canonicalize.Json(input);
        Assert.Contains("\"a\":1", result);
        Assert.Contains("\"b\":2", result);
    }

    #endregion

    #region Primitive Tests

    [Fact]
    public void Json_Null() => Assert.Equal("null", Canonicalize.Json("null"));

    [Fact]
    public void Json_True() => Assert.Equal("true", Canonicalize.Json("true"));

    [Fact]
    public void Json_False() => Assert.Equal("false", Canonicalize.Json("false"));

    [Fact]
    public void Json_Integer()
    {
        var input = new Dictionary<string, object?> { { "num", 42 } };
        Assert.Equal("{\"num\":42}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_String()
    {
        var input = new Dictionary<string, object?> { { "str", "hello" } };
        Assert.Equal("{\"str\":\"hello\"}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_NullValue()
    {
        var input = new Dictionary<string, object?> { { "key", null } };
        Assert.Equal("{\"key\":null}", Canonicalize.Json(input));
    }

    #endregion

    #region String Tests

    [Fact]
    public void Json_EmptyString()
    {
        var input = new Dictionary<string, object?> { { "str", "" } };
        Assert.Equal("{\"str\":\"\"}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_StringWithSpaces()
    {
        var input = new Dictionary<string, object?> { { "str", "hello world" } };
        Assert.Equal("{\"str\":\"hello world\"}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_UnicodeString()
    {
        var input = new Dictionary<string, object?> { { "str", "你好世界" } };
        var result = Canonicalize.Json(input);
        Assert.Contains("你好世界", result);
    }

    [Fact]
    public void Json_EscapedCharacters()
    {
        var input = new Dictionary<string, object?> { { "str", "line1\nline2" } };
        var result = Canonicalize.Json(input);
        Assert.Contains("\\n", result);
    }

    #endregion

    #region Key Sorting Tests

    [Fact]
    public void Json_NumericStringKeys()
    {
        var input = new Dictionary<string, object?> { { "10", "ten" }, { "2", "two" }, { "1", "one" } };
        Assert.Equal("{\"1\":\"one\",\"10\":\"ten\",\"2\":\"two\"}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_MixedCaseKeys()
    {
        var input = new Dictionary<string, object?> { { "B", 2 }, { "a", 1 } };
        Assert.Equal("{\"B\":2,\"a\":1}", Canonicalize.Json(input));
    }

    [Fact]
    public void Json_UnicodeKeys()
    {
        var input = new Dictionary<string, object?> { { "中文", "chinese" }, { "abc", "english" } };
        var result = Canonicalize.Json(input);
        Assert.Contains("abc", result);
    }

    #endregion

    #region Determinism Tests

    [Fact]
    public void Json_IsDeterministic()
    {
        var input = new Dictionary<string, object?> { { "z", 26 }, { "a", 1 }, { "m", 13 } };
        var results = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            results.Add(Canonicalize.Json(input));
        }
        Assert.Single(results);
    }

    [Fact]
    public void Json_ComplexObjectDeterministic()
    {
        var input = new Dictionary<string, object?>
        {
            { "users", new object[] {
                new Dictionary<string, object?> { { "name", "Alice" }, { "age", 30 } },
                new Dictionary<string, object?> { { "name", "Bob" }, { "age", 25 } }
            } },
            { "metadata", new Dictionary<string, object?> { { "version", 1 }, { "active", true } } }
        };
        var result1 = Canonicalize.Json(input);
        var result2 = Canonicalize.Json(input);
        Assert.Equal(result1, result2);
    }

    #endregion

    #region Stress Tests

    [Fact]
    public void Json_StressTest1000()
    {
        for (int i = 0; i < 1000; i++)
        {
            var input = new Dictionary<string, object?> { { "key", i }, { "nested", new Dictionary<string, object?> { { "value", i * 2 } } } };
            var result = Canonicalize.Json(input);
            Assert.NotEmpty(result);
        }
    }

    [Fact]
    public void Json_WideObject100Keys()
    {
        var input = new Dictionary<string, object?>();
        for (int i = 0; i < 100; i++)
        {
            input[$"key_{i}"] = i;
        }
        var result = Canonicalize.Json(input);
        Assert.Contains("key_0", result);
        Assert.Contains("key_99", result);
    }

    [Fact]
    public void Json_DeepNesting20Levels()
    {
        var input = new Dictionary<string, object?> { { "value", "deep" } };
        for (int i = 0; i < 20; i++)
        {
            input = new Dictionary<string, object?> { { "level", input } };
        }
        var result = Canonicalize.Json(input);
        Assert.Contains("deep", result);
    }

    #endregion
}
