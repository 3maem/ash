// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive binding normalization tests.
/// </summary>
public class BindingComprehensiveTests
{
    #region HTTP Method Tests

    [Fact]
    public void Binding_GetMethod() => Assert.Equal("GET|/path|", Canonicalize.Binding("GET", "/path"));

    [Fact]
    public void Binding_PostMethod() => Assert.Equal("POST|/path|", Canonicalize.Binding("POST", "/path"));

    [Fact]
    public void Binding_PutMethod() => Assert.Equal("PUT|/path|", Canonicalize.Binding("PUT", "/path"));

    [Fact]
    public void Binding_DeleteMethod() => Assert.Equal("DELETE|/path|", Canonicalize.Binding("DELETE", "/path"));

    [Fact]
    public void Binding_PatchMethod() => Assert.Equal("PATCH|/path|", Canonicalize.Binding("PATCH", "/path"));

    [Fact]
    public void Binding_OptionsMethod() => Assert.Equal("OPTIONS|/path|", Canonicalize.Binding("OPTIONS", "/path"));

    [Fact]
    public void Binding_HeadMethod() => Assert.Equal("HEAD|/path|", Canonicalize.Binding("HEAD", "/path"));

    [Fact]
    public void Binding_LowercaseMethodUppercased() => Assert.Equal("GET|/path|", Canonicalize.Binding("get", "/path"));

    [Fact]
    public void Binding_MixedCaseMethodUppercased() => Assert.Equal("POST|/path|", Canonicalize.Binding("PoSt", "/path"));

    #endregion

    #region Path Tests

    [Fact]
    public void Binding_SimplePath() => Assert.Equal("GET|/api/users|", Canonicalize.Binding("GET", "/api/users"));

    [Fact]
    public void Binding_RootPath() => Assert.Equal("GET|/|", Canonicalize.Binding("GET", "/"));

    [Fact]
    public void Binding_AddsLeadingSlash() => Assert.Equal("GET|/path|", Canonicalize.Binding("GET", "path"));

    [Fact]
    public void Binding_RemovesTrailingSlash() => Assert.Equal("GET|/path|", Canonicalize.Binding("GET", "/path/"));

    [Fact]
    public void Binding_CollapsesDoubleSlashes() => Assert.Equal("GET|/path/to|", Canonicalize.Binding("GET", "/path//to"));

    [Fact]
    public void Binding_CollapsesMultipleSlashes() => Assert.Equal("GET|/path/to/resource|", Canonicalize.Binding("GET", "///path///to////resource"));

    [Fact]
    public void Binding_NestedPath() => Assert.Equal("GET|/api/v1/users/123|", Canonicalize.Binding("GET", "/api/v1/users/123"));

    [Fact]
    public void Binding_PathWithDash() => Assert.Equal("GET|/api/user-profile|", Canonicalize.Binding("GET", "/api/user-profile"));

    [Fact]
    public void Binding_PathWithUnderscore() => Assert.Equal("GET|/api/user_profile|", Canonicalize.Binding("GET", "/api/user_profile"));

    [Fact]
    public void Binding_PathWithDot() => Assert.Equal("GET|/api/file.json|", Canonicalize.Binding("GET", "/api/file.json"));

    #endregion

    #region Query String Tests

    [Fact]
    public void Binding_QueryAppended() => Assert.Equal("GET|/path|foo=bar", Canonicalize.Binding("GET", "/path", "foo=bar"));

    [Fact]
    public void Binding_QuerySorted() => Assert.Equal("GET|/path|a=1&b=2&c=3", Canonicalize.Binding("GET", "/path", "c=3&a=1&b=2"));

    [Fact]
    public void Binding_DuplicateKeysSorted()
    {
        var result = Canonicalize.Binding("GET", "/path", "a=2&a=1&a=3");
        Assert.Equal("GET|/path|a=1&a=2&a=3", result);
    }

    [Fact]
    public void Binding_EmptyQueryValue() => Assert.Equal("GET|/path|a=&b=2", Canonicalize.Binding("GET", "/path", "b=2&a="));

    [Fact]
    public void Binding_EmptyQueryString() => Assert.Equal("GET|/path|", Canonicalize.Binding("GET", "/path", ""));

    [Fact]
    public void Binding_ManyQueryParams()
    {
        var query = string.Join("&", Enumerable.Range(0, 50).Select(i => $"key{i}=value{i}"));
        var result = Canonicalize.Binding("GET", "/path", query);
        Assert.Contains("key0=value0", result);
    }

    #endregion

    #region Format Validation Tests

    [Fact]
    public void Binding_OutputHasThreeParts()
    {
        var result = Canonicalize.Binding("GET", "/path");
        var parts = result.Split('|');
        Assert.Equal(3, parts.Length);
    }

    [Fact]
    public void Binding_MethodFirst()
    {
        var result = Canonicalize.Binding("POST", "/path");
        Assert.StartsWith("POST|", result);
    }

    [Fact]
    public void Binding_PathSecond()
    {
        var result = Canonicalize.Binding("GET", "/api/users");
        var parts = result.Split('|');
        Assert.Equal("/api/users", parts[1]);
    }

    [Fact]
    public void Binding_QueryThird()
    {
        var result = Canonicalize.Binding("GET", "/path", "a=1");
        var parts = result.Split('|');
        Assert.Equal("a=1", parts[2]);
    }

    #endregion

    #region Determinism Tests

    [Fact]
    public void Binding_IsDeterministic()
    {
        var results = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            results.Add(Canonicalize.Binding("POST", "/api/update", "z=3&a=1"));
        }
        Assert.Single(results);
    }

    #endregion

    #region Stress Tests

    [Fact]
    public void Binding_StressTest500()
    {
        var methods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH" };
        for (int i = 0; i < 500; i++)
        {
            var method = methods[i % methods.Length];
            var result = Canonicalize.Binding(method, $"/api/v1/resource/{i}", $"page={i}&limit=10");
            Assert.Contains(method, result);
        }
    }

    [Fact]
    public void Binding_LongPath()
    {
        var path = "/" + string.Join("/", Enumerable.Repeat("segment", 50));
        var result = Canonicalize.Binding("GET", path);
        Assert.StartsWith("GET|/", result);
    }

    #endregion

    #region Cross-SDK Compatibility Tests

    [Fact]
    public void Binding_CrossSdkVector1() => Assert.Equal("POST|/api/update|", Canonicalize.Binding("POST", "/api/update"));

    [Fact]
    public void Binding_CrossSdkVector2() => Assert.Equal("GET|/api/users|page=1&sort=name", Canonicalize.Binding("GET", "/api/users", "sort=name&page=1"));

    [Fact]
    public void Binding_CrossSdkVector3() => Assert.Equal("DELETE|/api/users/123|", Canonicalize.Binding("delete", "/api/users/123/"));

    #endregion
}
