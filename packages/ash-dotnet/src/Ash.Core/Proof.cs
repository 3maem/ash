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
