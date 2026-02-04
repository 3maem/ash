// ASH was developed by 3maem Co. | 01/2026

using Ash.Core;
using Xunit;

namespace Ash.Core.Tests;

/// <summary>
/// Comprehensive security tests.
/// </summary>
public class SecurityTests
{
    #region Timing Attack Resistance

    [Fact]
    public void TimingSafe_FirstCharDiff()
    {
        var secret = ProofV21.HashBody("actual_secret");
        var modified = "x" + secret[1..];
        Assert.False(Compare.TimingSafe(secret, modified));
    }

    [Fact]
    public void TimingSafe_LastCharDiff()
    {
        var secret = ProofV21.HashBody("actual_secret");
        var modified = secret[..^1] + "x";
        Assert.False(Compare.TimingSafe(secret, modified));
    }

    [Fact]
    public void TimingSafe_MiddleCharDiff()
    {
        var secret = ProofV21.HashBody("actual_secret");
        var modified = secret[..32] + "x" + secret[33..];
        Assert.False(Compare.TimingSafe(secret, modified));
    }

    #endregion

    #region Single Bit Change Detection

    [Fact]
    public void DetectsSingleBitChange()
    {
        var secret = "test-secret";
        var timestamp = "1234567890";
        var binding = "POST|/api|";
        var bodyHash = ProofV21.HashBody("data");

        var proof = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

        var chars = proof.ToCharArray();
        for (int i = 0; i < proof.Length; i++)
        {
            var tampered = (char[])chars.Clone();
            tampered[i] = tampered[i] == 'a' ? 'b' : 'a';
            var tamperedProof = new string(tampered);

            var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
            Assert.False(ProofV21.AshVerifyProof(nonce, "ctx", binding, timestamp, bodyHash, tamperedProof));
        }
    }

    #endregion

    #region Timestamp Tampering Detection

    [Fact]
    public void DetectsTimestampTampering()
    {
        var binding = "POST|/api|";
        var bodyHash = ProofV21.HashBody("data");
        var originalTimestamp = "1234567890";
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx123";
        var clientSecret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var proof = ProofV21.AshBuildProofHmac(clientSecret, originalTimestamp, binding, bodyHash);

        var tamperedTimestamps = new[] { "1234567891", "0000000000", "9999999999" };
        foreach (var tampered in tamperedTimestamps)
        {
            Assert.False(ProofV21.AshVerifyProof(nonce, contextId, binding, tampered, bodyHash, proof));
        }
    }

    #endregion

    #region Binding Tampering Detection

    [Fact]
    public void DetectsBindingTampering()
    {
        var timestamp = "1234567890";
        var bodyHash = ProofV21.HashBody("data");
        var originalBinding = "POST|/api/users|";
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx123";
        var clientSecret = ProofV21.DeriveClientSecret(nonce, contextId, originalBinding);
        var proof = ProofV21.AshBuildProofHmac(clientSecret, timestamp, originalBinding, bodyHash);

        var tamperedBindings = new[] { "GET|/api/users|", "POST|/api/admin|", "POST|/api/users|extra" };
        foreach (var tampered in tamperedBindings)
        {
            Assert.False(ProofV21.AshVerifyProof(nonce, contextId, tampered, timestamp, bodyHash, proof));
        }
    }

    #endregion

    #region Body Tampering Detection

    [Fact]
    public void DetectsBodyTampering()
    {
        var timestamp = "1234567890";
        var binding = "POST|/api|";
        var originalBody = "{\"name\":\"John\",\"action\":\"transfer\"}";
        var originalHash = ProofV21.HashBody(originalBody);
        var nonce = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        var contextId = "ctx123";
        var clientSecret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var proof = ProofV21.AshBuildProofHmac(clientSecret, timestamp, binding, originalHash);

        var tamperedBodies = new[] {
            "{\"name\":\"Jane\",\"action\":\"transfer\"}",
            "{\"name\":\"John\",\"action\":\"delete\"}",
            "{\"name\":\"John\",\"action\":\"transfer\",\"extra\":true}"
        };

        foreach (var tampered in tamperedBodies)
        {
            var tamperedHash = ProofV21.HashBody(tampered);
            Assert.False(ProofV21.AshVerifyProof(nonce, contextId, binding, timestamp, tamperedHash, proof));
        }
    }

    #endregion

    #region Replay Attack Prevention

    [Fact]
    public void SameInputsSameProof()
    {
        var secret = "secret";
        var timestamp = "1234567890";
        var binding = "POST|/api|";
        var bodyHash = "abc123";

        var proof1 = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);
        var proof2 = ProofV21.AshBuildProofHmac(secret, timestamp, binding, bodyHash);

        Assert.Equal(proof1, proof2);
    }

    [Fact]
    public void DifferentContextsDifferentProofs()
    {
        var timestamp = "1234567890";
        var binding = "POST|/api|";
        var bodyHash = "abc123";

        var secret1 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx1", binding);
        var secret2 = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1235", "ctx2", binding);

        var proof1 = ProofV21.AshBuildProofHmac(secret1, timestamp, binding, bodyHash);
        var proof2 = ProofV21.AshBuildProofHmac(secret2, timestamp, binding, bodyHash);

        Assert.NotEqual(proof1, proof2);
    }

    #endregion

    #region Secret Security

    [Fact]
    public void ClientSecretIsNotReversible()
    {
        var secret = ProofV21.DeriveClientSecret("abcd1234abcd1234abcd1234abcd1234", "ctx456", "binding");
        Assert.DoesNotContain("abcd1234abcd1234abcd1234abcd1234", secret);
        Assert.DoesNotContain("ctx456", secret);
    }

    [Fact]
    public void ClientSecretHasHighEntropy()
    {
        var secrets = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            secrets.Add(ProofV21.DeriveClientSecret($"abcd1234abcd1234abcd1234abcd12{i:D4}", $"ctx_{i}", "binding"));
        }
        Assert.Equal(100, secrets.Count);
    }

    #endregion

    #region Hash Security

    [Fact]
    public void HashResistsCollisions()
    {
        var hashes = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            hashes.Add(ProofV21.HashBody($"input_{i}"));
        }
        Assert.Equal(1000, hashes.Count);
    }

    [Fact]
    public void HashAvalancheEffect()
    {
        var hash1 = ProofV21.HashBody("test");
        var hash2 = ProofV21.HashBody("test1");

        var diffCount = 0;
        for (int i = 0; i < 64; i++)
        {
            if (hash1[i] != hash2[i]) diffCount++;
        }

        Assert.True(diffCount >= 20, $"Avalanche effect not sufficient: only {diffCount} chars different");
    }

    [Fact]
    public void HashPreimageResistance()
    {
        var hash = ProofV21.HashBody("secret_data");
        Assert.DoesNotContain("secret", hash);
        Assert.DoesNotContain("data", hash);
    }

    [Fact]
    public void NullByteDoesNotTruncate()
    {
        var hash1 = ProofV21.HashBody("test\0data");
        var hash2 = ProofV21.HashBody("test");
        Assert.NotEqual(hash1, hash2);
    }

    #endregion

    #region Nonce Security

    [Fact]
    public void NonceSufficientEntropy()
    {
        var nonces = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            nonces.Add(ProofV21.GenerateNonce());
        }
        Assert.Equal(1000, nonces.Count);
    }

    [Fact]
    public void NonceMinimumLength()
    {
        for (int i = 0; i < 100; i++)
        {
            var nonce = ProofV21.GenerateNonce();
            Assert.True(nonce.Length >= 32, $"Nonce too short: {nonce.Length}");
        }
    }

    #endregion

    #region Context ID Security

    [Fact]
    public void ContextIdIsUnique()
    {
        var ids = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            ids.Add(ProofV21.GenerateContextId());
        }
        Assert.Equal(1000, ids.Count);
    }

    #endregion

    #region Base64Url Security

    [Fact]
    public void Base64UrlIsUrlSafe()
    {
        var testData = new byte[][] {
            new byte[] { 0xfb, 0xff, 0xfe },
            new byte[] { 0x00, 0xff, 0x7f, 0x80 }
        };

        foreach (var data in testData)
        {
            var encoded = Proof.Base64UrlEncode(data);
            Assert.DoesNotContain("+", encoded);
            Assert.DoesNotContain("/", encoded);
            Assert.DoesNotContain("=", encoded);
        }
    }

    #endregion

    #region Proof Distribution

    [Fact]
    public void ProofHasGoodDistribution()
    {
        var charCounts = new Dictionary<char, int>();
        foreach (var c in "0123456789abcdef")
        {
            charCounts[c] = 0;
        }

        for (int i = 0; i < 100; i++)
        {
            var proof = ProofV21.AshBuildProofHmac($"secret_{i}", "1000000000", $"POST|/api/{i}|", $"body_{i}");
            foreach (var c in proof)
            {
                charCounts[c]++;
            }
        }

        foreach (var (c, count) in charCounts)
        {
            Assert.True(count >= 200, $"Character {c} appears too infrequently: {count}");
            Assert.True(count <= 600, $"Character {c} appears too frequently: {count}");
        }
    }

    #endregion

    #region HMAC Security

    [Fact]
    public void HmacProducesFixedLengthOutput()
    {
        var lengths = new[] { 1, 10, 100, 1000, 10000 };
        foreach (var len in lengths)
        {
            var proof = ProofV21.AshBuildProofHmac(new string('s', len), "1234567890", "POST|/api|", new string('a', 64));
            Assert.Equal(64, proof.Length);
        }
    }

    [Fact]
    public void SmallInputChangeDifferentOutput()
    {
        var proof1 = ProofV21.AshBuildProofHmac("secret", "1234567890", "POST|/api|", "abc123");
        var proof2 = ProofV21.AshBuildProofHmac("secret", "1234567891", "POST|/api|", "abc123");

        Assert.NotEqual(proof1, proof2);

        var diffCount = 0;
        for (int i = 0; i < proof1.Length; i++)
        {
            if (proof1[i] != proof2[i]) diffCount++;
        }

        Assert.True(diffCount >= 20, $"Avalanche effect not sufficient: {diffCount} chars different");
    }

    #endregion
}
