// ASH was developed by 3maem Co. | 12/31/2025

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Tests for binding normalization.
/// v2.3.1 format: METHOD|PATH|CANONICAL_QUERY
/// </summary>
public class CanonicalizeBindingTests
{
    [Fact]
    public void SimpleBinding_NormalizesCorrectly()
    {
        var result = Canonicalize.Binding("post", "/api/update");
        Assert.Equal("POST|/api/update|", result);
    }

    [Fact]
    public void UppercasesMethod()
    {
        var result = Canonicalize.Binding("get", "/path");
        Assert.Equal("GET|/path|", result);
    }

    [Fact]
    public void RemovesQueryString()
    {
        // Note: query string in path is removed, not preserved
        var result = Canonicalize.Binding("GET", "/path?foo=bar");
        Assert.Equal("GET|/path|", result);
    }

    [Fact]
    public void RemovesFragment()
    {
        var result = Canonicalize.Binding("GET", "/path#section");
        Assert.Equal("GET|/path|", result);
    }

    [Fact]
    public void AddsLeadingSlash()
    {
        var result = Canonicalize.Binding("GET", "path");
        Assert.Equal("GET|/path|", result);
    }

    [Fact]
    public void CollapsesDuplicateSlashes()
    {
        var result = Canonicalize.Binding("GET", "//path///to////resource");
        Assert.Equal("GET|/path/to/resource|", result);
    }

    [Fact]
    public void RemovesTrailingSlash()
    {
        var result = Canonicalize.Binding("GET", "/path/");
        Assert.Equal("GET|/path|", result);
    }

    [Fact]
    public void PreservesRootPath()
    {
        var result = Canonicalize.Binding("GET", "/");
        Assert.Equal("GET|/|", result);
    }

    [Fact]
    public void RemovesQueryStringAndFragment()
    {
        var result = Canonicalize.Binding("POST", "/api/data?query=1#section");
        Assert.Equal("POST|/api/data|", result);
    }

    [Fact]
    public void HandlesComplexPath()
    {
        var result = Canonicalize.Binding("put", "api//v1///users/");
        Assert.Equal("PUT|/api/v1/users|", result);
    }

    [Fact]
    public void WithQueryParameter_IncludesCanonicalQuery()
    {
        var result = Canonicalize.Binding("GET", "/api/users", "page=1&sort=name");
        Assert.Equal("GET|/api/users|page=1&sort=name", result);
    }

    [Fact]
    public void WithQueryParameter_SortsQuery()
    {
        var result = Canonicalize.Binding("GET", "/api/users", "z=3&a=1&b=2");
        Assert.Equal("GET|/api/users|a=1&b=2&z=3", result);
    }

    [Fact]
    public void BindingFromUrl_ExtractsQueryFromPath()
    {
        var result = Canonicalize.BindingFromUrl("GET", "/api/users?page=1&sort=name");
        Assert.Equal("GET|/api/users|page=1&sort=name", result);
    }

    [Fact]
    public void BindingFromUrl_NoQuery()
    {
        var result = Canonicalize.BindingFromUrl("POST", "/api/users");
        Assert.Equal("POST|/api/users|", result);
    }
}
