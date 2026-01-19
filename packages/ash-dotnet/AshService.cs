using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;

namespace Ash;

/// <summary>
/// ASH main service for request integrity protection.
/// </summary>
public class AshService
{
    /// <summary>
    /// ASH protocol version.
    /// </summary>
    public const string AshVersion = "ASHv1";

    /// <summary>
    /// Library version.
    /// </summary>
    public const string LibraryVersion = "1.0.0";

    private readonly IContextStore _store;
    private readonly AshMode _defaultMode;

    /// <summary>
    /// Create a new ASH service.
    /// </summary>
    /// <param name="store">Context store implementation</param>
    /// <param name="defaultMode">Default security mode</param>
    public AshService(IContextStore store, AshMode defaultMode = AshMode.Balanced)
    {
        _store = store;
        _defaultMode = defaultMode;
    }

    /// <summary>
    /// Issue a new context for a request.
    /// </summary>
    public async Task<AshContext> AshIssueContextAsync(
        string binding,
        long ttlMs,
        AshMode? mode = null,
        Dictionary<string, object>? metadata = null)
    {
        return await _store.CreateAsync(binding, ttlMs, mode ?? _defaultMode, metadata);
    }

    /// <summary>
    /// Verify a request against its context and proof.
    /// </summary>
    public async Task<AshVerifyResult> AshVerifyAsync(
        string contextId,
        string proof,
        string binding,
        string payload,
        string contentType)
    {
        // Get context
        var context = await _store.GetAsync(contextId);
        if (context == null)
        {
            return AshVerifyResult.Failure(AshErrorCode.InvalidContext, "Invalid or expired context");
        }

        // Check if already used
        if (context.Used)
        {
            return AshVerifyResult.Failure(AshErrorCode.ReplayDetected, "Context already used (replay detected)");
        }

        // Check binding
        if (context.Binding != binding)
        {
            return AshVerifyResult.Failure(
                AshErrorCode.EndpointMismatch,
                $"Binding mismatch: expected {context.Binding}, got {binding}");
        }

        // Canonicalize payload
        string canonicalPayload;
        try
        {
            canonicalPayload = AshCanonicalize(payload, contentType);
        }
        catch (Exception ex)
        {
            return AshVerifyResult.Failure(
                AshErrorCode.CanonicalizationFailed,
                $"Failed to canonicalize payload: {ex.Message}");
        }

        // Build expected proof
        var expectedProof = AshBuildProof(context.Mode, context.Binding, contextId, context.Nonce, canonicalPayload);

        // Verify proof
        if (!AshVerifyProof(expectedProof, proof))
        {
            return AshVerifyResult.Failure(AshErrorCode.IntegrityFailed, "Proof verification failed");
        }

        // Consume context
        if (!await _store.ConsumeAsync(contextId))
        {
            return AshVerifyResult.Failure(AshErrorCode.ReplayDetected, "Context already used (replay detected)");
        }

        return AshVerifyResult.Success(context.Metadata);
    }

    /// <summary>
    /// Canonicalize a payload based on content type.
    /// </summary>
    public string AshCanonicalize(string payload, string contentType)
    {
        if (contentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return AshCanonicalizeJson(payload);
        }

        if (contentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            return AshCanonicalizeUrlEncoded(payload);
        }

        return payload;
    }

    /// <summary>
    /// Canonicalize JSON to deterministic form.
    /// </summary>
    public static string AshCanonicalizeJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return NormalizeJson(doc.RootElement);
    }

    /// <summary>
    /// Canonicalize URL-encoded data to deterministic form.
    /// </summary>
    public static string AshCanonicalizeUrlEncoded(string data)
    {
        if (string.IsNullOrEmpty(data))
            return string.Empty;

        var parsed = HttpUtility.ParseQueryString(data);
        var pairs = new List<(string Key, string Value)>();

        foreach (string? key in parsed.AllKeys)
        {
            if (key == null) continue;
            var values = parsed.GetValues(key);
            if (values == null) continue;

            foreach (var value in values)
            {
                // NFC normalize
                var normalizedKey = key.Normalize(NormalizationForm.FormC);
                var normalizedValue = value.Normalize(NormalizationForm.FormC);
                pairs.Add((normalizedKey, normalizedValue));
            }
        }

        // Sort by key
        pairs.Sort((a, b) => string.Compare(a.Key, b.Key, StringComparison.Ordinal));

        // Encode
        var encoded = pairs.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}");
        return string.Join("&", encoded);
    }

    /// <summary>
    /// Build a cryptographic proof.
    /// </summary>
    public static string AshBuildProof(
        AshMode mode,
        string binding,
        string contextId,
        string? nonce,
        string canonicalPayload)
    {
        var sb = new StringBuilder();
        sb.Append(AshVersion).Append('\n');
        sb.Append(mode.ToModeString()).Append('\n');
        sb.Append(binding).Append('\n');
        sb.Append(contextId).Append('\n');

        if (!string.IsNullOrEmpty(nonce))
        {
            sb.Append(nonce).Append('\n');
        }

        sb.Append(canonicalPayload);

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToBase64String(hash)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    /// <summary>
    /// Verify two proofs using constant-time comparison.
    /// </summary>
    public static bool AshVerifyProof(string expected, string actual)
    {
        return AshTimingSafeEqual(expected, actual);
    }

    /// <summary>
    /// Constant-time string comparison.
    /// </summary>
    public static bool AshTimingSafeEqual(string a, string b)
    {
        if (a.Length != b.Length)
            return false;

        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);

        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    /// <summary>
    /// Normalize a binding string.
    /// </summary>
    public static string AshNormalizeBinding(string method, string path)
    {
        // Uppercase method
        method = method.ToUpperInvariant();

        // Remove query string
        var queryIndex = path.IndexOf('?');
        if (queryIndex >= 0)
            path = path[..queryIndex];

        // Ensure path starts with /
        if (!path.StartsWith('/'))
            path = "/" + path;

        // Collapse duplicate slashes
        path = Regex.Replace(path, @"/+", "/");

        // Remove trailing slash (except for root)
        if (path != "/" && path.EndsWith('/'))
            path = path.TrimEnd('/');

        return $"{method} {path}";
    }

    /// <summary>
    /// Get the context store.
    /// </summary>
    public IContextStore Store => _store;

    private static string NormalizeJson(JsonElement element)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });

        WriteNormalized(writer, element);

        writer.Flush();
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteNormalized(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                var properties = element.EnumerateObject()
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .ToList();

                foreach (var prop in properties)
                {
                    var normalizedName = prop.Name.Normalize(NormalizationForm.FormC);
                    writer.WritePropertyName(normalizedName);
                    WriteNormalized(writer, prop.Value);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteNormalized(writer, item);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                var str = element.GetString()?.Normalize(NormalizationForm.FormC) ?? "";
                writer.WriteStringValue(str);
                break;

            case JsonValueKind.Number:
                writer.WriteRawValue(element.GetRawText());
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
        }
    }
}
