// ASH was developed by 3maem Co. | 12/31/2025
//
// ASH Protocol Proof Generation.
// Deterministic hash-based integrity proof.
// Same inputs MUST produce identical proof across all implementations.

using System.Security.Cryptography;
using System.Text;

namespace Ash.Core;

/// <summary>
/// ASH Protocol Proof generation functions.
/// </summary>
public static class Proof
{
    /// <summary>
    /// ASH protocol version prefix.
    /// </summary>
    public const string AshVersionPrefix = "ASHv1";

    /// <summary>
    /// Build a deterministic proof from the given inputs.
    /// </summary>
    /// <remarks>
    /// Proof structure (from ASH-Spec-v1.0):
    /// <code>
    /// proof = SHA256(
    ///   "ASHv1" + "\n" +
    ///   mode + "\n" +
    ///   binding + "\n" +
    ///   contextId + "\n" +
    ///   (nonce? + "\n" : "") +
    ///   canonicalPayload
    /// )
    /// </code>
    /// Output: Base64URL encoded (no padding)
    /// </remarks>
    /// <param name="input">Proof input parameters.</param>
    /// <returns>Base64URL encoded proof string.</returns>
    public static string Build(BuildProofInput input)
    {
        // Convert mode enum to string
        var modeString = input.Mode.ToString().ToLowerInvariant();

        // Build the proof input string
        var sb = new StringBuilder();
        sb.Append(AshVersionPrefix);
        sb.Append('\n');
        sb.Append(modeString);
        sb.Append('\n');
        sb.Append(input.Binding);
        sb.Append('\n');
        sb.Append(input.ContextId);
        sb.Append('\n');

        // Add nonce if present (server-assisted mode)
        if (!string.IsNullOrEmpty(input.Nonce))
        {
            sb.Append(input.Nonce);
            sb.Append('\n');
        }

        // Add canonical payload
        sb.Append(input.CanonicalPayload);

        // Compute SHA-256 hash
        var proofInputBytes = Encoding.UTF8.GetBytes(sb.ToString());
        var hashBytes = SHA256.HashData(proofInputBytes);

        // Encode as Base64URL (no padding)
        return Base64UrlEncode(hashBytes);
    }

    /// <summary>
    /// Encode bytes as Base64URL (no padding).
    /// RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet.
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <returns>Base64URL encoded string without padding.</returns>
    public static string Base64UrlEncode(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        // Replace + with -, / with _, and remove padding =
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Decode a Base64URL string to bytes.
    /// Handles both padded and unpadded input.
    /// </summary>
    /// <param name="input">The Base64URL string to decode.</param>
    /// <returns>The decoded bytes.</returns>
    public static byte[] Base64UrlDecode(string input)
    {
        // Replace URL-safe characters back to standard base64
        var base64 = input
            .Replace('-', '+')
            .Replace('_', '/');

        // Add padding if needed
        switch (base64.Length % 4)
        {
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
        }

        return Convert.FromBase64String(base64);
    }
}

// =========================================================================
// ASH v2.1 - Derived Client Secret & Cryptographic Proof
// =========================================================================

/// <summary>
/// ASH Protocol Proof v2.1 functions.
/// </summary>
public static partial class ProofV21
{
    /// <summary>
    /// ASH v2.1 protocol version prefix.
    /// </summary>
    public const string AshVersionPrefixV21 = "ASHv2.1";

    /// <summary>
    /// Generate a cryptographically secure random nonce.
    /// </summary>
    /// <param name="bytes">Number of bytes (default 32).</param>
    /// <returns>Hex-encoded nonce (64 chars for 32 bytes).</returns>
    public static string GenerateNonce(int bytes = 32)
    {
        var buffer = new byte[bytes];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
        return Convert.ToHexString(buffer).ToLowerInvariant();
    }

    /// <summary>
    /// Generate a unique context ID with "ash_" prefix.
    /// </summary>
    /// <returns>Context ID string.</returns>
    public static string GenerateContextId()
    {
        var buffer = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
        return "ash_" + Convert.ToHexString(buffer).ToLowerInvariant();
    }

    /// <summary>
    /// Derive client secret from server nonce (v2.1).
    /// </summary>
    /// <remarks>
    /// SECURITY PROPERTIES:
    /// - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
    /// - Context-bound: Unique per contextId + binding combination
    /// - Safe to expose: Client can use it but cannot forge other contexts
    ///
    /// Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
    /// </remarks>
    /// <param name="nonce">Server-side secret nonce (64 hex chars).</param>
    /// <param name="contextId">Context identifier.</param>
    /// <param name="binding">Request binding (e.g., "POST /login").</param>
    /// <returns>Derived client secret (64 hex chars).</returns>
    public static string DeriveClientSecret(string nonce, string contextId, string binding)
    {
        var key = Encoding.UTF8.GetBytes(nonce);
        var message = Encoding.UTF8.GetBytes(contextId + "|" + binding);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(message);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Build v2.1 cryptographic proof (client-side).
    /// </summary>
    /// <remarks>
    /// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
    /// </remarks>
    /// <param name="clientSecret">Derived client secret.</param>
    /// <param name="timestamp">Request timestamp (milliseconds as string).</param>
    /// <param name="binding">Request binding (e.g., "POST /login").</param>
    /// <param name="bodyHash">SHA-256 hash of canonical request body.</param>
    /// <returns>Proof (64 hex chars).</returns>
    public static string BuildProofV21(string clientSecret, string timestamp, string binding, string bodyHash)
    {
        var key = Encoding.UTF8.GetBytes(clientSecret);
        var message = Encoding.UTF8.GetBytes(timestamp + "|" + binding + "|" + bodyHash);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(message);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Verify v2.1 proof (server-side).
    /// </summary>
    /// <param name="nonce">Server-side secret nonce.</param>
    /// <param name="contextId">Context identifier.</param>
    /// <param name="binding">Request binding.</param>
    /// <param name="timestamp">Request timestamp.</param>
    /// <param name="bodyHash">SHA-256 hash of canonical body.</param>
    /// <param name="clientProof">Proof received from client.</param>
    /// <returns>True if proof is valid.</returns>
    public static bool VerifyProofV21(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        string bodyHash,
        string clientProof)
    {
        // Derive the same client secret server-side
        var derivedClientSecret = DeriveClientSecret(nonce, contextId, binding);

        // Compute expected proof
        var expectedProof = BuildProofV21(derivedClientSecret, timestamp, binding, bodyHash);

        // Constant-time comparison
        return Compare.TimingSafe(expectedProof, clientProof);
    }

    /// <summary>
    /// Compute SHA-256 hash of canonical body.
    /// </summary>
    /// <param name="canonicalBody">Canonicalized request body.</param>
    /// <returns>SHA-256 hash (64 hex chars).</returns>
    public static string HashBody(string canonicalBody)
    {
        var bytes = Encoding.UTF8.GetBytes(canonicalBody);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

// =========================================================================
// ASH v2.2 - Context Scoping (Selective Field Protection)
// =========================================================================

/// <summary>
/// ASH Protocol Proof v2.2 scoping functions.
/// </summary>
public static partial class ProofV22
{
    /// <summary>
    /// Scoped proof result.
    /// </summary>
    public record ScopedProofResult(string Proof, string ScopeHash);

    /// <summary>
    /// Extract scoped fields from a dictionary.
    /// Supports dot notation for nested fields.
    /// </summary>
    public static Dictionary<string, object?> ExtractScopedFields(
        Dictionary<string, object?> payload,
        string[] scope)
    {
        if (scope.Length == 0)
            return payload;

        var result = new Dictionary<string, object?>();
        foreach (var fieldPath in scope)
        {
            var value = GetNestedValue(payload, fieldPath);
            if (value != null)
            {
                SetNestedValue(result, fieldPath, value);
            }
        }
        return result;
    }

    private static object? GetNestedValue(Dictionary<string, object?> obj, string path)
    {
        var keys = path.Split('.');
        object? current = obj;

        foreach (var key in keys)
        {
            if (current is Dictionary<string, object?> dict && dict.TryGetValue(key, out var value))
            {
                current = value;
            }
            else
            {
                return null;
            }
        }

        return current;
    }

    private static void SetNestedValue(Dictionary<string, object?> obj, string path, object? value)
    {
        var keys = path.Split('.');
        var current = obj;

        for (int i = 0; i < keys.Length - 1; i++)
        {
            var key = keys[i];
            if (!current.ContainsKey(key))
            {
                current[key] = new Dictionary<string, object?>();
            }
            current = (Dictionary<string, object?>)current[key]!;
        }

        current[keys[^1]] = value;
    }

    /// <summary>
    /// Build v2.2 proof with scoped fields.
    /// </summary>
    public static ScopedProofResult BuildProofV21Scoped(
        string clientSecret,
        string timestamp,
        string binding,
        Dictionary<string, object?> payload,
        string[] scope)
    {
        var scopedPayload = ExtractScopedFields(payload, scope);
        var canonicalScoped = System.Text.Json.JsonSerializer.Serialize(scopedPayload);
        var bodyHash = ProofV21.HashBody(canonicalScoped);

        var scopeStr = string.Join(",", scope);
        var scopeHash = ProofV21.HashBody(scopeStr);

        var message = $"{timestamp}|{binding}|{bodyHash}|{scopeHash}";
        var key = Encoding.UTF8.GetBytes(clientSecret);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(messageBytes);
        var proof = Convert.ToHexString(hash).ToLowerInvariant();

        return new ScopedProofResult(proof, scopeHash);
    }

    /// <summary>
    /// Verify v2.2 proof with scoped fields.
    /// </summary>
    public static bool VerifyProofV21Scoped(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        Dictionary<string, object?> payload,
        string[] scope,
        string scopeHash,
        string clientProof)
    {
        var scopeStr = string.Join(",", scope);
        var expectedScopeHash = ProofV21.HashBody(scopeStr);
        if (!Compare.TimingSafe(expectedScopeHash, scopeHash))
            return false;

        var clientSecret = ProofV21.DeriveClientSecret(nonce, contextId, binding);
        var result = BuildProofV21Scoped(clientSecret, timestamp, binding, payload, scope);

        return Compare.TimingSafe(result.Proof, clientProof);
    }

    /// <summary>
    /// Hash scoped payload fields.
    /// </summary>
    public static string HashScopedBody(Dictionary<string, object?> payload, string[] scope)
    {
        var scopedPayload = ExtractScopedFields(payload, scope);
        var canonical = System.Text.Json.JsonSerializer.Serialize(scopedPayload);
        return ProofV21.HashBody(canonical);
    }
}
