// ASH was developed by 3maem Co. | 12/31/2025

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Tests for proof generation.
/// </summary>
public class ProofTests
{
    [Fact]
    public void Build_GeneratesDeterministicProof()
    {
        var input = new BuildProofInput
        {
            Mode = AshMode.Balanced,
            Binding = "POST /api/update",
            ContextId = "ctx_123",
            CanonicalPayload = "{\"data\":\"test\"}"
        };

        var proof1 = Proof.Build(input);
        var proof2 = Proof.Build(input);

        Assert.Equal(proof1, proof2);
    }

    [Fact]
    public void Build_DifferentInputs_DifferentProofs()
    {
        var input1 = new BuildProofInput
        {
            Mode = AshMode.Balanced,
            Binding = "POST /api/update",
            ContextId = "ctx_123",
            CanonicalPayload = "{\"data\":\"test1\"}"
        };

        var input2 = new BuildProofInput
        {
            Mode = AshMode.Balanced,
            Binding = "POST /api/update",
            ContextId = "ctx_123",
            CanonicalPayload = "{\"data\":\"test2\"}"
        };

        var proof1 = Proof.Build(input1);
        var proof2 = Proof.Build(input2);

        Assert.NotEqual(proof1, proof2);
    }

    [Fact]
    public void Build_WithNonce_IncludesNonce()
    {
        var inputWithoutNonce = new BuildProofInput
        {
            Mode = AshMode.Strict,
            Binding = "POST /api/update",
            ContextId = "ctx_123",
            CanonicalPayload = "{\"data\":\"test\"}"
        };

        var inputWithNonce = new BuildProofInput
        {
            Mode = AshMode.Strict,
            Binding = "POST /api/update",
            ContextId = "ctx_123",
            CanonicalPayload = "{\"data\":\"test\"}",
            Nonce = "nonce_abc"
        };

        var proofWithoutNonce = Proof.Build(inputWithoutNonce);
        var proofWithNonce = Proof.Build(inputWithNonce);

        Assert.NotEqual(proofWithoutNonce, proofWithNonce);
    }

    [Fact]
    public void Build_ReturnsBase64UrlEncoded()
    {
        var input = new BuildProofInput
        {
            Mode = AshMode.Balanced,
            Binding = "POST /api/update",
            ContextId = "ctx_123",
            CanonicalPayload = "{}"
        };

        var proof = Proof.Build(input);

        // Base64URL should not contain + or /
        Assert.DoesNotContain("+", proof);
        Assert.DoesNotContain("/", proof);
        Assert.DoesNotContain("=", proof);
    }

    [Fact]
    public void Base64UrlEncode_EncodesCorrectly()
    {
        var data = new byte[] { 0xfb, 0xff, 0xfe }; // Will produce + and / in standard base64
        var result = Proof.Base64UrlEncode(data);

        Assert.DoesNotContain("+", result);
        Assert.DoesNotContain("/", result);
        Assert.DoesNotContain("=", result);
    }

    [Fact]
    public void Base64UrlDecode_DecodesCorrectly()
    {
        var original = new byte[] { 0xfb, 0xff, 0xfe };
        var encoded = Proof.Base64UrlEncode(original);
        var decoded = Proof.Base64UrlDecode(encoded);

        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Base64UrlDecode_HandlesPaddedInput()
    {
        // Standard base64 with padding
        var padded = "SGVsbG8="; // "Hello" in standard base64
        var decoded = Proof.Base64UrlDecode(padded);

        Assert.Equal("Hello", System.Text.Encoding.UTF8.GetString(decoded));
    }

    [Fact]
    public void Base64UrlDecode_HandlesUnpaddedInput()
    {
        // Base64URL without padding
        var unpadded = "SGVsbG8"; // "Hello" without padding
        var decoded = Proof.Base64UrlDecode(unpadded);

        Assert.Equal("Hello", System.Text.Encoding.UTF8.GetString(decoded));
    }
}
