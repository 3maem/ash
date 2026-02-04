// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive ProofV21 tests.
/// </summary>
public class ProofV21ComprehensiveTests
{
    #region HashBody Tests

    [Fact]
    public void HashBody_ReturnsHexString()
    {
        var hash = ProofV21.HashBody("test");
        Assert.Matches("^[0-9a-f]{64}$", hash);
    }

    [Fact]
    public void HashBody_Returns64Chars()
    {
        var hash = ProofV21.HashBody("test content");
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void HashBody_IsDeterministic()
    {
        var hash1 = ProofV21.HashBody("test");
        var hash2 = ProofV21.HashBody("test");
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashBody_DifferentInputsDifferentHashes()
    {
        var hash1 = ProofV21.HashBody("test1");
        var hash2 = ProofV21.HashBody("test2");
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void HashBody_EmptyStringKnownValue()
    {
        var hash = ProofV21.HashBody("");
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    [Fact]
    public void HashBody_HelloKnownValue()
    {
        var hash = ProofV21.HashBody("hello");
        Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
    }

    [Fact]
    public void HashBody_Unicode()
    {
        var hash = ProofV21.HashBody("你好世界");
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void HashBody_LongString()
    {
        var hash = ProofV21.HashBody(new string('a', 100000));
        Assert.Equal(64, hash.Length);
    }

    [Fact]
    public void HashBody_CollisionResistance()
    {
        var hashes = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            hashes.Add(ProofV21.HashBody($"input_{i}"));
        }
        Assert.Equal(1000, hashes.Count);
    }

    #endregion

    #region DeriveClientSecret Tests

    [Fact]
    public void DeriveClientSecret_ReturnsHexString()
    {
        var secret = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx_456", "POST|/api|");
        Assert.Matches("^[0-9a-f]{64}$", secret);
    }

    [Fact]
    public void DeriveClientSecret_Returns64Chars()
    {
        var secret = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx", "binding");
        Assert.Equal(64, secret.Length);
    }

    [Fact]
    public void DeriveClientSecret_IsDeterministic()
    {
        var secret1 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx", "binding");
        var secret2 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx", "binding");
        Assert.Equal(secret1, secret2);
    }

    [Fact]
    public void DeriveClientSecret_DifferentNoncesDifferentSecrets()
    {
        var secret1 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx", "binding");
        var secret2 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1235", "ctx", "binding");
        Assert.NotEqual(secret1, secret2);
    }

    [Fact]
    public void DeriveClientSecret_DifferentContextsDifferentSecrets()
    {
        var secret1 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx1", "binding");
        var secret2 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx2", "binding");
        Assert.NotEqual(secret1, secret2);
    }

    [Fact]
    public void DeriveClientSecret_DifferentBindingsDifferentSecrets()
    {
        var secret1 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx", "POST|/api|");
        var secret2 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx", "GET|/api|");
        Assert.NotEqual(secret1, secret2);
    }

    [Fact]
    public void DeriveClientSecret_IsOneWay()
    {
        var secret = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx_456", "binding");
        Assert.DoesNotContain("abcd1234abcd1234abcd1234abcd1234", secret);
        Assert.DoesNotContain("ctx_456", secret);
    }

    [Fact]
    public void DeriveClientSecret_Uniqueness()
    {
        var secrets = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            secrets.Add(ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding"));
        }
        Assert.Equal(100, secrets.Count);
    }

    #endregion

    #region BuildProofHmac Tests

    [Fact]
    public void BuildProofHmac_ReturnsHexString()
    {
        var proof = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        Assert.Matches("^[0-9a-f]{64}$", proof);
    }

    [Fact]
    public void BuildProofHmac_Returns64Chars()
    {
        var proof = ProofV21.AshBuildProofHmac("secret", "timestamp", "binding", "bodyhash");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void BuildProofHmac_IsDeterministic()
    {
        var proof1 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        var proof2 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        Assert.Equal(proof1, proof2);
    }

    [Fact]
    public void BuildProofHmac_DifferentSecretsDifferentProofs()
    {
        var proof1 = ProofV21.AshBuildProofHmac("secret1", "1234567890", "POST|/api|", "abc123");
        var proof2 = ProofV21.AshBuildProofHmac("secret2", "1234567890", "POST|/api|", "abc123");
        Assert.NotEqual(proof1, proof2);
    }

    [Fact]
    public void BuildProofHmac_DifferentTimestampsDifferentProofs()
    {
        var proof1 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        var proof2 = ProofV21.AshBuildProofHmac("secret", "1234567891", "POST|/api|", "abc123");
        Assert.NotEqual(proof1, proof2);
    }

    [Fact]
    public void BuildProofHmac_DifferentBindingsDifferentProofs()
    {
        var proof1 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        var proof2 = ProofV21.AshBuildProofHmac("secret", "1234567890", "GET|/api|", "abc123");
        Assert.NotEqual(proof1, proof2);
    }

    [Fact]
    public void BuildProofHmac_DifferentBodyHashesDifferentProofs()
    {
        var proof1 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        var proof2 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "def456");
        Assert.NotEqual(proof1, proof2);
    }

    [Fact]
    public void BuildProofHmac_EmptySecret()
    {
        var proof = ProofV21.AshBuildProofHmac("", "1234567890", "POST|/api|", "abc123");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void BuildProofHmac_LongSecret()
    {
        var proof = ProofV21.AshBuildProofHmac(new string('a', 100000), "1234567890", "POST|/api|", "abc123");
        Assert.Equal(64, proof.Length);
    }

    [Fact]
    public void BuildProofHmac_UnicodeSecret()
    {
        var proof = ProofV21.AshBuildProofHmac("密码🔐", "1234567890", "POST|/api|", "abc123");
        Assert.Equal(64, proof.Length);
    }

    #endregion

    #region VerifyProof Tests

    [Fact]
    public void VerifyProof_ValidProofReturnsTrue()
    {
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx_123";
        var binding = "POST|/api|";
        var timestamp = "1234567890";
        var bodyHash = ProofV21.HashBody("test");

        var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

        Assert.True(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof));
    }

    [Fact]
    public void VerifyProof_InvalidProofReturnsFalse()
    {
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx_123";
        var binding = "POST|/api|";
        var timestamp = "1234567890";
        var bodyHash = ProofV21.HashBody("test");

        Assert.False(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, new string('0', 64)));
    }

    [Fact]
    public void VerifyProof_WrongTimestampReturnsFalse()
    {
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx_123";
        var binding = "POST|/api|";
        var timestamp = "1234567890";
        var bodyHash = ProofV21.HashBody("test");

        var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

        Assert.False(ProofV21.AshVerifyProof(nonce, contextId, binding, "9999999999", bodyHash, proof));
    }

    [Fact]
    public void VerifyProof_WrongBindingReturnsFalse()
    {
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx_123";
        var binding = "POST|/api|";
        var timestamp = "1234567890";
        var bodyHash = ProofV21.HashBody("test");

        var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

        Assert.False(ProofV21.AshVerifyProof(nonce, contextId, "GET|/api|", timestamp, bodyHash, proof));
    }

    [Fact]
    public void VerifyProof_WrongBodyHashReturnsFalse()
    {
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx_123";
        var binding = "POST|/api|";
        var timestamp = "1234567890";
        var bodyHash = ProofV21.HashBody("test");

        var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

        Assert.False(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, ProofV21.HashBody("tampered"), proof));
    }

    #endregion

    #region Stress Tests

    [Fact]
    public void HashBody_Stress1000()
    {
        for (int i = 0; i < 1000; i++)
        {
            var hash = ProofV21.HashBody($"body content {i}");
            Assert.Equal(64, hash.Length);
        }
    }

    [Fact]
    public void DeriveClientSecret_Stress500()
    {
        for (int i = 0; i < 500; i++)
        {
            var secret = ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding");
            Assert.Equal(64, secret.Length);
        }
    }

    [Fact]
    public void BuildProofHmac_Stress500()
    {
        for (int i = 0; i < 500; i++)
        {
            var proof = ProofV21.AshBuildProofHmac($"secret_{i}", $"{1000000000 + i}", $"POST|/api/{i}|", ProofV21.HashBody($"body_{i}"));
            Assert.Equal(64, proof.Length);
        }
    }

    [Fact]
    public void VerifyProof_Stress100()
    {
        for (int i = 0; i < 100; i++)
        {
            var nonce = $"abcd1234abcd1234abcd1234abcd1234{i:D4}";
            var contextId = $"ctx_{i}";
            var binding = $"POST|/api/{i}|";
            var timestamp = $"{1000000000 + i}";
            var bodyHash = ProofV21.HashBody($"body_{i}");

            var secret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
            var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

            Assert.True(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof));
        }
    }

    #endregion
}
