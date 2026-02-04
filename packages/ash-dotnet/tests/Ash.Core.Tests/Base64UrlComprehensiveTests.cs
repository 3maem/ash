// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive Base64URL encoding tests.
/// </summary>
public class Base64UrlComprehensiveTests
{
    #region Encoding Tests

    [Fact]
    public void Base64Url_EncodeEmpty() => Assert.Equal("", Proof.Base64UrlEncode(Array.Empty<byte>()));

    [Fact]
    public void Base64Url_EncodeSingleByte()
    {
        var encoded = Proof.Base64UrlEncode(new byte[] { 0x61 });
        Assert.NotEmpty(encoded);
    }

    [Fact]
    public void Base64Url_EncodeNoPlus()
    {
        var data = new byte[100];
        new Random(42).NextBytes(data);
        var encoded = Proof.Base64UrlEncode(data);
        Assert.DoesNotContain("+", encoded);
    }

    [Fact]
    public void Base64Url_EncodeNoSlash()
    {
        var data = new byte[100];
        new Random(42).NextBytes(data);
        var encoded = Proof.Base64UrlEncode(data);
        Assert.DoesNotContain("/", encoded);
    }

    [Fact]
    public void Base64Url_EncodeNoPadding()
    {
        for (int len = 1; len <= 10; len++)
        {
            var data = new byte[len];
            var encoded = Proof.Base64UrlEncode(data);
            Assert.DoesNotContain("=", encoded);
        }
    }

    [Fact]
    public void Base64Url_EncodeUrlSafeCharsOnly()
    {
        var data = new byte[] { 0xfb, 0xff, 0xfe };
        var encoded = Proof.Base64UrlEncode(data);
        Assert.Matches("^[A-Za-z0-9_-]*$", encoded);
    }

    #endregion

    #region Decoding Tests

    [Fact]
    public void Base64Url_DecodeEmpty() => Assert.Empty(Proof.Base64UrlDecode(""));

    [Fact]
    public void Base64Url_DecodeHandlesPadding()
    {
        var decoded = Proof.Base64UrlDecode("SGVsbG8=");
        Assert.Equal("Hello", System.Text.Encoding.UTF8.GetString(decoded));
    }

    [Fact]
    public void Base64Url_DecodeHandlesNoPadding()
    {
        var decoded = Proof.Base64UrlDecode("SGVsbG8");
        Assert.Equal("Hello", System.Text.Encoding.UTF8.GetString(decoded));
    }

    [Fact]
    public void Base64Url_DecodeHandlesStandardBase64()
    {
        var standard = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("Test123"));
        var decoded = Proof.Base64UrlDecode(standard);
        Assert.Equal("Test123", System.Text.Encoding.UTF8.GetString(decoded));
    }

    #endregion

    #region Round Trip Tests

    [Fact]
    public void Base64Url_RoundTripEmpty()
    {
        var original = Array.Empty<byte>();
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Base64Url_RoundTripSingleByte()
    {
        var original = new byte[] { 0x61 };
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Base64Url_RoundTripThreeBytes()
    {
        var original = new byte[] { 0x00, 0x01, 0x02 };
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Base64Url_RoundTripAllByteLengths()
    {
        for (int len = 0; len <= 32; len++)
        {
            var original = new byte[len];
            for (int i = 0; i < len; i++) original[i] = (byte)(i % 256);
            var encoded = Proof.Base64UrlEncode(original);
            var decoded = Proof.Base64UrlDecode(encoded);
            Assert.Equal(original, decoded);
        }
    }

    [Fact]
    public void Base64Url_RoundTripRandomData()
    {
        var random = new Random(42);
        for (int i = 0; i < 100; i++)
        {
            var original = new byte[32 + (i % 100)];
            random.NextBytes(original);
            var encoded = Proof.Base64UrlEncode(original);
            var decoded = Proof.Base64UrlDecode(encoded);
            Assert.Equal(original, decoded);
        }
    }

    [Fact]
    public void Base64Url_RoundTripBinaryData()
    {
        var original = new byte[] { 0x00, 0xff, 0x7f, 0x80, 0xfe, 0x01 };
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);
        Assert.Equal(original, decoded);
    }

    #endregion

    #region Stress Tests

    [Fact]
    public void Base64Url_EncodeStress1000()
    {
        var random = new Random(42);
        for (int i = 0; i < 1000; i++)
        {
            var data = new byte[32];
            random.NextBytes(data);
            var encoded = Proof.Base64UrlEncode(data);
            Assert.NotEmpty(encoded);
        }
    }

    [Fact]
    public void Base64Url_RoundTripStress500()
    {
        var random = new Random(42);
        for (int i = 0; i < 500; i++)
        {
            var original = new byte[16 + (i % 64)];
            random.NextBytes(original);
            var encoded = Proof.Base64UrlEncode(original);
            var decoded = Proof.Base64UrlDecode(encoded);
            Assert.Equal(original, decoded);
        }
    }

    [Fact]
    public void Base64Url_LargeData()
    {
        var sizes = new[] { 1000, 5000, 10000 };
        foreach (var size in sizes)
        {
            var original = new byte[size];
            new Random(42).NextBytes(original);
            var encoded = Proof.Base64UrlEncode(original);
            var decoded = Proof.Base64UrlDecode(encoded);
            Assert.Equal(original, decoded);
        }
    }

    #endregion
}
