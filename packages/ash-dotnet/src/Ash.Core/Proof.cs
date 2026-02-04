// ASH was developed by 3maem Co. | 12/31/2025
//
// ASH Protocol Proof Generation.
// Deterministic hash-based integrity proof.
// Same inputs MUST produce identical proof across all implementations.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Ash.Core.Exceptions;

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
    /// Scope field delimiter for hashing (using U+001F unit separator to avoid collision).
    /// BUG-002: Prevents collision when field names contain commas.
    /// Must match Rust ash-core SCOPE_FIELD_DELIMITER.
    /// </summary>
    public const string ScopeFieldDelimiter = "\x1F";

    // =========================================================================
    // Security Constants (Must match Rust ash-core)
    // =========================================================================

    /// <summary>
    /// Minimum hex characters for nonce in derive_client_secret.
    /// SEC-014: Ensures adequate entropy (32 hex chars = 16 bytes = 128 bits).
    /// </summary>
    public const int MinNonceHexChars = 32;

    /// <summary>
    /// Maximum nonce length.
    /// SEC-NONCE-001: Limits nonce beyond minimum entropy requirement.
    /// </summary>
    public const int MaxNonceLength = 128;

    /// <summary>
    /// Maximum context_id length.
    /// SEC-CTX-001: Limits context_id to reasonable size for headers and storage.
    /// </summary>
    public const int MaxContextIdLength = 256;

    /// <summary>
    /// Maximum binding length.
    /// SEC-AUDIT-004: Prevents DoS via extremely long bindings.
    /// </summary>
    public const int MaxBindingLength = 8192; // 8KB

    /// <summary>
    /// Pattern for valid context_id characters (alphanumeric, underscore, hyphen, dot).
    /// </summary>
    internal static readonly Regex ContextIdPattern = new(@"^[A-Za-z0-9_.\-]+$", RegexOptions.Compiled);

    /// <summary>
    /// Normalize scope fields by sorting and deduplicating.
    /// BUG-023: Ensures deterministic scope hash across all SDKs.
    /// </summary>
    /// <param name="scope">Array of field paths.</param>
    /// <returns>Sorted and deduplicated scope array.</returns>
    public static string[] AshNormalizeScopeFields(string[] scope)
    {
        if (scope.Length == 0)
            return scope;
        // Deduplicate and sort
        return scope.Distinct().OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// Normalize scope fields by sorting and deduplicating.
    /// BUG-023: Ensures deterministic scope hash across all SDKs.
    /// </summary>
    /// <param name="scope">Array of field paths.</param>
    /// <returns>Sorted and deduplicated scope array.</returns>
    [Obsolete("Use AshNormalizeScopeFields instead")]
    public static string[] NormalizeScopeFields(string[] scope) => AshNormalizeScopeFields(scope);

    /// <summary>
    /// Join scope fields with the proper delimiter after normalization.
    /// BUG-002, BUG-023: Uses unit separator and normalizes for cross-SDK compatibility.
    /// </summary>
    /// <param name="scope">Array of field paths.</param>
    /// <returns>Joined scope string.</returns>
    public static string AshJoinScopeFields(string[] scope)
    {
        var normalized = AshNormalizeScopeFields(scope);
        return string.Join(ScopeFieldDelimiter, normalized);
    }

    /// <summary>
    /// Join scope fields with the proper delimiter after normalization.
    /// BUG-002, BUG-023: Uses unit separator and normalizes for cross-SDK compatibility.
    /// </summary>
    /// <param name="scope">Array of field paths.</param>
    /// <returns>Joined scope string.</returns>
    [Obsolete("Use AshJoinScopeFields instead")]
    public static string JoinScopeFields(string[] scope) => AshJoinScopeFields(scope);

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
    public static string AshBuildProof(BuildProofInput input)
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
        return AshBase64UrlEncode(hashBytes);
    }

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
    [Obsolete("Use AshBuildProof instead")]
    public static string Build(BuildProofInput input) => AshBuildProof(input);

    /// <summary>
    /// Encode bytes as Base64URL (no padding).
    /// RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet.
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <returns>Base64URL encoded string without padding.</returns>
    public static string AshBase64UrlEncode(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        // Replace + with -, / with _, and remove padding =
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Encode bytes as Base64URL (no padding).
    /// RFC 4648 Section 5: Base 64 Encoding with URL and Filename Safe Alphabet.
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <returns>Base64URL encoded string without padding.</returns>
    [Obsolete("Use AshBase64UrlEncode instead")]
    public static string Base64UrlEncode(byte[] data) => AshBase64UrlEncode(data);

    /// <summary>
    /// Decode a Base64URL string to bytes.
    /// Handles both padded and unpadded input.
    /// </summary>
    /// <param name="input">The Base64URL string to decode.</param>
    /// <returns>The decoded bytes.</returns>
    public static byte[] AshBase64UrlDecode(string input)
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

    /// <summary>
    /// Decode a Base64URL string to bytes.
    /// Handles both padded and unpadded input.
    /// </summary>
    /// <param name="input">The Base64URL string to decode.</param>
    /// <returns>The decoded bytes.</returns>
    [Obsolete("Use AshBase64UrlDecode instead")]
    public static byte[] Base64UrlDecode(string input) => AshBase64UrlDecode(input);
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
    public static string AshGenerateNonce(int bytes = 32)
    {
        var buffer = new byte[bytes];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
        return Convert.ToHexString(buffer).ToLowerInvariant();
    }

    /// <summary>
    /// Generate a cryptographically secure random nonce.
    /// </summary>
    /// <param name="bytes">Number of bytes (default 32).</param>
    /// <returns>Hex-encoded nonce (64 chars for 32 bytes).</returns>
    [Obsolete("Use AshGenerateNonce instead")]
    public static string GenerateNonce(int bytes = 32) => AshGenerateNonce(bytes);

    /// <summary>
    /// Generate a unique context ID with "ash_" prefix.
    /// </summary>
    /// <returns>Context ID string.</returns>
    public static string AshGenerateContextId()
    {
        var buffer = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
        return "ash_" + Convert.ToHexString(buffer).ToLowerInvariant();
    }

    /// <summary>
    /// Generate a unique context ID with "ash_" prefix.
    /// </summary>
    /// <returns>Context ID string.</returns>
    [Obsolete("Use AshGenerateContextId instead")]
    public static string GenerateContextId() => AshGenerateContextId();

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
    /// <param name="nonce">Server-side secret nonce (minimum 32 hex chars for adequate entropy).</param>
    /// <param name="contextId">Context identifier (alphanumeric, underscore, hyphen, dot only).</param>
    /// <param name="binding">Request binding (e.g., "POST|/login|").</param>
    /// <returns>Derived client secret (64 hex chars).</returns>
    /// <exception cref="ValidationException">Thrown if any input fails validation.</exception>
    public static string AshDeriveClientSecret(string nonce, string contextId, string binding)
    {
        // SEC-014: Validate nonce has sufficient entropy
        if (nonce.Length < Proof.MinNonceHexChars)
        {
            throw new ValidationException(
                $"nonce must be at least {Proof.MinNonceHexChars} hex characters ({Proof.MinNonceHexChars / 2} bytes) for adequate entropy"
            );
        }

        // SEC-NONCE-001: Validate nonce doesn't exceed maximum length
        if (nonce.Length > Proof.MaxNonceLength)
        {
            throw new ValidationException(
                $"nonce exceeds maximum length of {Proof.MaxNonceLength} characters"
            );
        }

        // BUG-004: Validate nonce is valid hexadecimal
        if (!nonce.All(c => char.IsAsciiHexDigit(c)))
        {
            throw new ValidationException(
                "nonce must contain only hexadecimal characters (0-9, a-f, A-F)"
            );
        }

        // BUG-041: Validate contextId is not empty
        if (string.IsNullOrEmpty(contextId))
        {
            throw new ValidationException("context_id cannot be empty");
        }

        // SEC-CTX-001: Validate contextId doesn't exceed maximum length
        if (contextId.Length > Proof.MaxContextIdLength)
        {
            throw new ValidationException(
                $"context_id exceeds maximum length of {Proof.MaxContextIdLength} characters"
            );
        }

        // SEC-CTX-001: Validate contextId contains only allowed characters
        if (!Proof.ContextIdPattern.IsMatch(contextId))
        {
            throw new ValidationException(
                "context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot"
            );
        }

        // SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
        if (binding.Length > Proof.MaxBindingLength)
        {
            throw new ValidationException(
                $"binding exceeds maximum length of {Proof.MaxBindingLength} bytes"
            );
        }

        var key = Encoding.UTF8.GetBytes(nonce);
        var message = Encoding.UTF8.GetBytes(contextId + "|" + binding);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(message);
        return Convert.ToHexString(hash).ToLowerInvariant();
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
    [Obsolete("Use AshDeriveClientSecret instead")]
    public static string DeriveClientSecret(string nonce, string contextId, string binding) => AshDeriveClientSecret(nonce, contextId, binding);

    /// <summary>
    /// Build HMAC-based cryptographic proof (client-side).
    /// </summary>
    /// <remarks>
    /// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
    /// </remarks>
    /// <param name="clientSecret">Derived client secret.</param>
    /// <param name="timestamp">Request timestamp (milliseconds as string).</param>
    /// <param name="binding">Request binding (e.g., "POST /login").</param>
    /// <param name="bodyHash">SHA-256 hash of canonical request body.</param>
    /// <returns>Proof (64 hex chars).</returns>
    public static string AshBuildProofHmac(string clientSecret, string timestamp, string binding, string bodyHash)
    {
        var key = Encoding.UTF8.GetBytes(clientSecret);
        var message = Encoding.UTF8.GetBytes(timestamp + "|" + binding + "|" + bodyHash);
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
    [Obsolete("Use AshBuildProofHmac instead")]
    public static string BuildProofV21(string clientSecret, string timestamp, string binding, string bodyHash) => AshBuildProofHmac(clientSecret, timestamp, binding, bodyHash);

    /// <summary>
    /// Verify proof (server-side).
    /// </summary>
    /// <param name="nonce">Server-side secret nonce.</param>
    /// <param name="contextId">Context identifier.</param>
    /// <param name="binding">Request binding.</param>
    /// <param name="timestamp">Request timestamp.</param>
    /// <param name="bodyHash">SHA-256 hash of canonical body.</param>
    /// <param name="clientProof">Proof received from client.</param>
    /// <returns>True if proof is valid.</returns>
    public static bool AshVerifyProof(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        string bodyHash,
        string clientProof)
    {
        // Derive the same client secret server-side
        var derivedClientSecret = AshDeriveClientSecret(nonce, contextId, binding);

        // Compute expected proof
        var expectedProof = AshBuildProofHmac(derivedClientSecret, timestamp, binding, bodyHash);

        // Constant-time comparison
        return Compare.AshTimingSafeEqual(expectedProof, clientProof);
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
    [Obsolete("Use AshVerifyProof instead")]
    public static bool VerifyProofV21(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        string bodyHash,
        string clientProof) => AshVerifyProof(nonce, contextId, binding, timestamp, bodyHash, clientProof);

    /// <summary>
    /// Compute SHA-256 hash of canonical body.
    /// </summary>
    /// <param name="canonicalBody">Canonicalized request body.</param>
    /// <returns>SHA-256 hash (64 hex chars).</returns>
    public static string AshHashBody(string canonicalBody)
    {
        var bytes = Encoding.UTF8.GetBytes(canonicalBody);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Compute SHA-256 hash of canonical body.
    /// </summary>
    /// <param name="canonicalBody">Canonicalized request body.</param>
    /// <returns>SHA-256 hash (64 hex chars).</returns>
    [Obsolete("Use AshHashBody instead")]
    public static string HashBody(string canonicalBody) => AshHashBody(canonicalBody);
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
    public static Dictionary<string, object?> AshExtractScopedFields(
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

    /// <summary>
    /// Extract scoped fields from a dictionary.
    /// Supports dot notation for nested fields.
    /// </summary>
    [Obsolete("Use AshExtractScopedFields instead")]
    public static Dictionary<string, object?> ExtractScopedFields(
        Dictionary<string, object?> payload,
        string[] scope) => AshExtractScopedFields(payload, scope);

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
    /// Build proof with scoped fields.
    /// </summary>
    public static ScopedProofResult AshBuildProofScoped(
        string clientSecret,
        string timestamp,
        string binding,
        Dictionary<string, object?> payload,
        string[] scope)
    {
        // BUG-023: Normalize scope for deterministic ordering
        var normalizedScope = Proof.AshNormalizeScopeFields(scope);
        var scopedPayload = AshExtractScopedFields(payload, normalizedScope);
        // Use proper canonicalization (sorted keys, NFC normalization, etc.)
        var canonicalScoped = Canonicalize.AshCanonicalizeJson(scopedPayload);
        var bodyHash = ProofV21.AshHashBody(canonicalScoped);

        // BUG-002, BUG-023: Use unit separator and normalized scope
        var scopeStr = Proof.AshJoinScopeFields(scope);
        var scopeHash = ProofV21.AshHashBody(scopeStr);

        var message = $"{timestamp}|{binding}|{bodyHash}|{scopeHash}";
        var key = Encoding.UTF8.GetBytes(clientSecret);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(messageBytes);
        var proof = Convert.ToHexString(hash).ToLowerInvariant();

        return new ScopedProofResult(proof, scopeHash);
    }

    /// <summary>
    /// Build v2.2 proof with scoped fields.
    /// </summary>
    [Obsolete("Use AshBuildProofScoped instead")]
    public static ScopedProofResult BuildProofV21Scoped(
        string clientSecret,
        string timestamp,
        string binding,
        Dictionary<string, object?> payload,
        string[] scope) => AshBuildProofScoped(clientSecret, timestamp, binding, payload, scope);

    /// <summary>
    /// Verify proof with scoped fields.
    /// </summary>
    public static bool AshVerifyProofScoped(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        Dictionary<string, object?> payload,
        string[] scope,
        string scopeHash,
        string clientProof)
    {
        // BUG-002, BUG-023: Verify scope hash with unit separator and normalization
        var scopeStr = Proof.AshJoinScopeFields(scope);
        var expectedScopeHash = ProofV21.AshHashBody(scopeStr);
        if (!Compare.AshTimingSafeEqual(expectedScopeHash, scopeHash))
            return false;

        var clientSecret = ProofV21.AshDeriveClientSecret(nonce, contextId, binding);
        var result = AshBuildProofScoped(clientSecret, timestamp, binding, payload, scope);

        return Compare.AshTimingSafeEqual(result.Proof, clientProof);
    }

    /// <summary>
    /// Verify v2.2 proof with scoped fields.
    /// </summary>
    [Obsolete("Use AshVerifyProofScoped instead")]
    public static bool VerifyProofV21Scoped(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        Dictionary<string, object?> payload,
        string[] scope,
        string scopeHash,
        string clientProof) => AshVerifyProofScoped(nonce, contextId, binding, timestamp, payload, scope, scopeHash, clientProof);

    /// <summary>
    /// Hash scoped payload fields.
    /// </summary>
    public static string AshHashScopedBody(Dictionary<string, object?> payload, string[] scope)
    {
        var scopedPayload = AshExtractScopedFields(payload, scope);
        // Use proper canonicalization (sorted keys, NFC normalization, etc.)
        var canonical = Canonicalize.AshCanonicalizeJson(scopedPayload);
        return ProofV21.AshHashBody(canonical);
    }

    /// <summary>
    /// Hash scoped payload fields.
    /// </summary>
    [Obsolete("Use AshHashScopedBody instead")]
    public static string HashScopedBody(Dictionary<string, object?> payload, string[] scope) => AshHashScopedBody(payload, scope);
}


// =========================================================================
// ASH v2.3 - Unified Proof Functions (Scoping + Chaining)
// =========================================================================

/// <summary>
/// ASH Protocol Unified Proof v2.3 functions.
/// </summary>
public static partial class ProofV23
{
    /// <summary>
    /// Unified proof result.
    /// </summary>
    public record UnifiedProofResult(string Proof, string ScopeHash, string ChainHash);

    /// <summary>
    /// Hash a proof for chaining purposes.
    /// </summary>
    /// <param name="proof">Proof to hash.</param>
    /// <returns>SHA-256 hash of the proof (64 hex chars).</returns>
    public static string AshHashProof(string proof)
    {
        var bytes = Encoding.UTF8.GetBytes(proof);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Hash a proof for chaining purposes.
    /// </summary>
    /// <param name="proof">Proof to hash.</param>
    /// <returns>SHA-256 hash of the proof (64 hex chars).</returns>
    [Obsolete("Use AshHashProof instead")]
    public static string HashProof(string proof) => AshHashProof(proof);

    /// <summary>
    /// Build unified cryptographic proof with optional scoping and chaining.
    /// </summary>
    /// <remarks>
    /// Formula:
    /// <code>
    /// scopeHash  = scope.Length > 0 ? SHA256(sorted(scope).join("\x1F")) : ""
    /// bodyHash   = SHA256(canonicalize(scopedPayload))
    /// chainHash  = previousProof != null ? SHA256(previousProof) : ""
    /// proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
    /// </code>
    /// </remarks>
    /// <param name="clientSecret">Derived client secret.</param>
    /// <param name="timestamp">Request timestamp (milliseconds).</param>
    /// <param name="binding">Request binding.</param>
    /// <param name="payload">Full payload dictionary.</param>
    /// <param name="scope">Fields to protect (empty = full payload).</param>
    /// <param name="previousProof">Previous proof in chain (null = no chaining).</param>
    /// <returns>Unified proof result with proof, scopeHash, and chainHash.</returns>
    public static UnifiedProofResult AshBuildProofUnified(
        string clientSecret,
        string timestamp,
        string binding,
        Dictionary<string, object?> payload,
        string[]? scope = null,
        string? previousProof = null)
    {
        scope ??= Array.Empty<string>();

        // BUG-023: Normalize scope for deterministic ordering
        var normalizedScope = Proof.AshNormalizeScopeFields(scope);

        // Extract and hash scoped payload
        var scopedPayload = ProofV22.AshExtractScopedFields(payload, normalizedScope);
        // Use proper canonicalization (sorted keys, NFC normalization, etc.)
        var canonicalScoped = Canonicalize.AshCanonicalizeJson(scopedPayload);
        var bodyHash = ProofV21.AshHashBody(canonicalScoped);

        // BUG-002, BUG-023: Compute scope hash with unit separator and normalization
        var scopeHash = scope.Length > 0
            ? ProofV21.AshHashBody(Proof.AshJoinScopeFields(scope))
            : "";

        // Compute chain hash (empty string if no previous proof)
        var chainHash = !string.IsNullOrEmpty(previousProof)
            ? AshHashProof(previousProof)
            : "";

        // Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
        var message = $"{timestamp}|{binding}|{bodyHash}|{scopeHash}|{chainHash}";
        var key = Encoding.UTF8.GetBytes(clientSecret);
        var messageBytes = Encoding.UTF8.GetBytes(message);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(messageBytes);
        var proof = Convert.ToHexString(hash).ToLowerInvariant();

        return new UnifiedProofResult(proof, scopeHash, chainHash);
    }

    /// <summary>
    /// Build unified v2.3 cryptographic proof with optional scoping and chaining.
    /// </summary>
    /// <remarks>
    /// Formula:
    /// <code>
    /// scopeHash  = scope.Length > 0 ? SHA256(sorted(scope).join("\x1F")) : ""
    /// bodyHash   = SHA256(canonicalize(scopedPayload))
    /// chainHash  = previousProof != null ? SHA256(previousProof) : ""
    /// proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
    /// </code>
    /// </remarks>
    /// <param name="clientSecret">Derived client secret.</param>
    /// <param name="timestamp">Request timestamp (milliseconds).</param>
    /// <param name="binding">Request binding.</param>
    /// <param name="payload">Full payload dictionary.</param>
    /// <param name="scope">Fields to protect (empty = full payload).</param>
    /// <param name="previousProof">Previous proof in chain (null = no chaining).</param>
    /// <returns>Unified proof result with proof, scopeHash, and chainHash.</returns>
    [Obsolete("Use AshBuildProofUnified instead")]
    public static UnifiedProofResult BuildProofUnified(
        string clientSecret,
        string timestamp,
        string binding,
        Dictionary<string, object?> payload,
        string[]? scope = null,
        string? previousProof = null) => AshBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof);

    /// <summary>
    /// Verify unified proof with optional scoping and chaining.
    /// </summary>
    /// <param name="nonce">Server-side secret nonce.</param>
    /// <param name="contextId">Context identifier.</param>
    /// <param name="binding">Request binding.</param>
    /// <param name="timestamp">Request timestamp.</param>
    /// <param name="payload">Full payload dictionary.</param>
    /// <param name="clientProof">Proof received from client.</param>
    /// <param name="scope">Fields that were protected (empty = full payload).</param>
    /// <param name="scopeHash">Scope hash from client (empty if no scoping).</param>
    /// <param name="previousProof">Previous proof in chain (null if no chaining).</param>
    /// <param name="chainHash">Chain hash from client (empty if no chaining).</param>
    /// <returns>True if proof is valid.</returns>
    public static bool AshVerifyProofUnified(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        Dictionary<string, object?> payload,
        string clientProof,
        string[]? scope = null,
        string scopeHash = "",
        string? previousProof = null,
        string chainHash = "")
    {
        scope ??= Array.Empty<string>();

        // SEC-013: Validate consistency - scopeHash must be empty when scope is empty
        if (scope.Length == 0 && !string.IsNullOrEmpty(scopeHash))
            return false;

        // BUG-002, BUG-023: Validate scope hash with unit separator and normalization
        if (scope.Length > 0)
        {
            var expectedScopeHash = ProofV21.AshHashBody(Proof.AshJoinScopeFields(scope));
            if (!Compare.AshTimingSafeEqual(expectedScopeHash, scopeHash))
                return false;
        }

        // SEC-013: Validate consistency - chainHash must be empty when previousProof is absent
        if (string.IsNullOrEmpty(previousProof) && !string.IsNullOrEmpty(chainHash))
            return false;

        // Validate chain hash if chaining is used
        if (!string.IsNullOrEmpty(previousProof))
        {
            var expectedChainHash = AshHashProof(previousProof);
            if (!Compare.AshTimingSafeEqual(expectedChainHash, chainHash))
                return false;
        }

        // Derive client secret and compute expected proof
        var clientSecret = ProofV21.AshDeriveClientSecret(nonce, contextId, binding);
        var result = AshBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof);

        return Compare.AshTimingSafeEqual(result.Proof, clientProof);
    }

    /// <summary>
    /// Verify unified v2.3 proof with optional scoping and chaining.
    /// </summary>
    /// <param name="nonce">Server-side secret nonce.</param>
    /// <param name="contextId">Context identifier.</param>
    /// <param name="binding">Request binding.</param>
    /// <param name="timestamp">Request timestamp.</param>
    /// <param name="payload">Full payload dictionary.</param>
    /// <param name="clientProof">Proof received from client.</param>
    /// <param name="scope">Fields that were protected (empty = full payload).</param>
    /// <param name="scopeHash">Scope hash from client (empty if no scoping).</param>
    /// <param name="previousProof">Previous proof in chain (null if no chaining).</param>
    /// <param name="chainHash">Chain hash from client (empty if no chaining).</param>
    /// <returns>True if proof is valid.</returns>
    [Obsolete("Use AshVerifyProofUnified instead")]
    public static bool VerifyProofUnified(
        string nonce,
        string contextId,
        string binding,
        string timestamp,
        Dictionary<string, object?> payload,
        string clientProof,
        string[]? scope = null,
        string scopeHash = "",
        string? previousProof = null,
        string chainHash = "") => AshVerifyProofUnified(nonce, contextId, binding, timestamp, payload, clientProof, scope, scopeHash, previousProof, chainHash);
}
