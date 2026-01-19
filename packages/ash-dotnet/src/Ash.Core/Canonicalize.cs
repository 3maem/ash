// ASH was developed by 3maem Co. | 12/31/2025
//
// ASH Protocol Canonicalization Engine.
// Deterministic canonicalization for JSON and URL-encoded payloads.
// Same input MUST produce identical output across all implementations.

using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Ash.Core.Exceptions;

namespace Ash.Core;

/// <summary>
/// ASH Protocol Canonicalization functions.
/// </summary>
public static partial class Canonicalize
{
    /// <summary>
    /// Canonicalize a JSON value to a deterministic string.
    /// </summary>
    /// <remarks>
    /// Rules (from ASH-Spec-v1.0):
    /// - JSON minified (no whitespace)
    /// - Object keys sorted lexicographically (ascending)
    /// - Arrays preserve order
    /// - Unicode normalization: NFC
    /// - Numbers: no scientific notation, remove trailing zeros, -0 becomes 0
    /// - Unsupported values REJECT: NaN, Infinity, None type objects
    /// </remarks>
    /// <param name="json">The JSON element to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    public static string Json(JsonElement json)
    {
        var sb = new StringBuilder();
        BuildCanonicalJson(json, sb);
        return sb.ToString();
    }

    /// <summary>
    /// Canonicalize a JSON string to a deterministic string.
    /// </summary>
    /// <param name="jsonString">The JSON string to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    public static string Json(string jsonString)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonString);
            return Json(doc.RootElement);
        }
        catch (JsonException ex)
        {
            throw new CanonicalizationException($"Invalid JSON: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Canonicalize a dictionary to a deterministic JSON string.
    /// </summary>
    /// <param name="obj">The dictionary to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    public static string Json(IDictionary<string, object?> obj)
    {
        var jsonString = JsonSerializer.Serialize(obj);
        return Json(jsonString);
    }

    private static void BuildCanonicalJson(JsonElement element, StringBuilder sb)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Null:
                sb.Append("null");
                break;

            case JsonValueKind.True:
                sb.Append("true");
                break;

            case JsonValueKind.False:
                sb.Append("false");
                break;

            case JsonValueKind.String:
                var str = element.GetString() ?? "";
                // Apply NFC normalization
                str = str.Normalize(NormalizationForm.FormC);
                JsonEscapeString(str, sb);
                break;

            case JsonValueKind.Number:
                AppendCanonicalNumber(element, sb);
                break;

            case JsonValueKind.Array:
                sb.Append('[');
                var isFirst = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!isFirst) sb.Append(',');
                    isFirst = false;
                    BuildCanonicalJson(item, sb);
                }
                sb.Append(']');
                break;

            case JsonValueKind.Object:
                // Get all properties and sort by key
                var properties = element.EnumerateObject()
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .ToList();

                sb.Append('{');
                var isFirstProp = true;
                foreach (var prop in properties)
                {
                    // Skip null values in objects
                    if (prop.Value.ValueKind == JsonValueKind.Null)
                        continue;

                    if (!isFirstProp) sb.Append(',');
                    isFirstProp = false;

                    // Normalize key with NFC
                    var key = prop.Name.Normalize(NormalizationForm.FormC);
                    JsonEscapeString(key, sb);
                    sb.Append(':');
                    BuildCanonicalJson(prop.Value, sb);
                }
                sb.Append('}');
                break;

            default:
                throw new CanonicalizationException($"Unsupported JSON value kind: {element.ValueKind}");
        }
    }

    private static void AppendCanonicalNumber(JsonElement element, StringBuilder sb)
    {
        // Try to get as decimal for precision
        if (element.TryGetDouble(out var doubleValue))
        {
            // Check for NaN and Infinity
            if (double.IsNaN(doubleValue))
                throw new CanonicalizationException("NaN values are not allowed");

            if (double.IsInfinity(doubleValue))
                throw new CanonicalizationException("Infinity values are not allowed");

            // Convert -0 to 0
            if (doubleValue == 0)
            {
                sb.Append('0');
                return;
            }

            // Check if it's a whole number
            if (doubleValue == Math.Truncate(doubleValue) && Math.Abs(doubleValue) < 9007199254740992) // 2^53
            {
                sb.Append(((long)doubleValue).ToString(CultureInfo.InvariantCulture));
                return;
            }

            // Use the raw text if available, otherwise format without scientific notation
            var rawText = element.GetRawText();
            if (!rawText.Contains('e', StringComparison.OrdinalIgnoreCase))
            {
                sb.Append(rawText);
            }
            else
            {
                // Convert from scientific notation
                sb.Append(doubleValue.ToString("G17", CultureInfo.InvariantCulture));
            }
        }
        else
        {
            sb.Append(element.GetRawText());
        }
    }

    private static void JsonEscapeString(string s, StringBuilder sb)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append($"\\u{(int)c:x4}");
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    /// <summary>
    /// Canonicalize URL-encoded form data.
    /// </summary>
    /// <remarks>
    /// Rules (from ASH-Spec-v1.0):
    /// - Parse into key-value pairs
    /// - Percent-decode consistently
    /// - Sort keys lexicographically
    /// - For duplicate keys: preserve value order per key
    /// - Output format: k1=v1&amp;k1=v2&amp;k2=v3
    /// - Unicode NFC applies after decoding
    /// </remarks>
    /// <param name="input">URL-encoded string.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    /// <exception cref="CanonicalizationException">If input cannot be parsed.</exception>
    public static string UrlEncoded(string input)
    {
        if (string.IsNullOrEmpty(input))
            return "";

        var pairs = ParseUrlEncoded(input);
        return BuildCanonicalUrlEncoded(pairs);
    }

    /// <summary>
    /// Canonicalize URL-encoded form data from a dictionary.
    /// </summary>
    /// <param name="data">Dictionary of key-value pairs.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    public static string UrlEncoded(IDictionary<string, string> data)
    {
        var pairs = data.Select(kvp => (kvp.Key, kvp.Value)).ToList();
        return BuildCanonicalUrlEncoded(pairs);
    }

    /// <summary>
    /// Canonicalize URL-encoded form data from a dictionary with multiple values per key.
    /// </summary>
    /// <param name="data">Dictionary of key-value pairs where values can be lists.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    public static string UrlEncoded(IDictionary<string, IEnumerable<string>> data)
    {
        var pairs = new List<(string Key, string Value)>();
        foreach (var kvp in data)
        {
            foreach (var value in kvp.Value)
            {
                pairs.Add((kvp.Key, value));
            }
        }
        return BuildCanonicalUrlEncoded(pairs);
    }

    private static List<(string Key, string Value)> ParseUrlEncoded(string input)
    {
        var pairs = new List<(string Key, string Value)>();

        foreach (var part in input.Split('&'))
        {
            if (string.IsNullOrEmpty(part))
                continue;

            var eqIndex = part.IndexOf('=');
            string key, value;

            if (eqIndex == -1)
            {
                key = DecodeUrlComponent(part);
                value = "";
            }
            else
            {
                key = DecodeUrlComponent(part[..eqIndex]);
                value = DecodeUrlComponent(part[(eqIndex + 1)..]);
            }

            if (!string.IsNullOrEmpty(key))
            {
                pairs.Add((key, value));
            }
        }

        return pairs;
    }

    private static string DecodeUrlComponent(string input)
    {
        // Replace + with space (per application/x-www-form-urlencoded spec)
        input = input.Replace('+', ' ');
        return HttpUtility.UrlDecode(input);
    }

    private static string BuildCanonicalUrlEncoded(List<(string Key, string Value)> pairs)
    {
        // Normalize with NFC and sort by key
        var normalized = pairs
            .Select(p => (
                Key: p.Key.Normalize(NormalizationForm.FormC),
                Value: p.Value.Normalize(NormalizationForm.FormC)
            ))
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ToList();

        var sb = new StringBuilder();
        var isFirst = true;

        foreach (var (key, value) in normalized)
        {
            if (!isFirst) sb.Append('&');
            isFirst = false;

            sb.Append(Uri.EscapeDataString(key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(value));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Canonicalize a URL query string according to ASH specification.
    /// </summary>
    /// <remarks>
    /// 9 MUST Rules:
    /// 1. MUST parse query string after ? (or use full string if no ?)
    /// 2. MUST split on &amp; to get key=value pairs
    /// 3. MUST handle keys without values (treat as empty string)
    /// 4. MUST percent-decode all keys and values
    /// 5. MUST apply Unicode NFC normalization
    /// 6. MUST sort pairs by key lexicographically (byte order)
    /// 7. MUST preserve order of duplicate keys
    /// 8. MUST re-encode with uppercase hex (%XX)
    /// 9. MUST join with &amp; separator
    /// </remarks>
    /// <param name="query">Query string (with or without leading ?).</param>
    /// <returns>Canonical query string.</returns>
    public static string Query(string query)
    {
        // Rule 1: Remove leading ? if present
        if (query.StartsWith('?'))
        {
            query = query[1..];
        }

        if (string.IsNullOrEmpty(query))
            return "";

        // Rule 2 & 3: Parse pairs
        var pairs = ParseUrlEncoded(query);

        // Rule 4-9: Normalize, sort, and re-encode
        return BuildCanonicalUrlEncoded(pairs);
    }

    /// <summary>
    /// Normalize a binding string to canonical form (v2.3.2+ format).
    /// </summary>
    /// <remarks>
    /// Format: METHOD|PATH|CANONICAL_QUERY
    ///
    /// Rules:
    /// - Method uppercased
    /// - Path must start with /
    /// - Duplicate slashes collapsed
    /// - Trailing slash removed (except for root)
    /// - Query string canonicalized
    /// - Parts joined with | (pipe)
    /// </remarks>
    /// <param name="method">HTTP method.</param>
    /// <param name="path">Request path.</param>
    /// <param name="query">Query string (empty string if none).</param>
    /// <returns>Canonical binding string (METHOD|PATH|QUERY).</returns>
    public static string Binding(string method, string path, string query = "")
    {
        var normalizedMethod = method.ToUpperInvariant();

        // Remove fragment (#...) first
        var fragmentIndex = path.IndexOf('#');
        var normalizedPath = fragmentIndex != -1 ? path[..fragmentIndex] : path;

        // Extract path without query string (in case path contains ?)
        var queryIndex = normalizedPath.IndexOf('?');
        normalizedPath = queryIndex != -1 ? normalizedPath[..queryIndex] : normalizedPath;

        // Ensure path starts with /
        if (!normalizedPath.StartsWith('/'))
        {
            normalizedPath = "/" + normalizedPath;
        }

        // Collapse duplicate slashes
        normalizedPath = DuplicateSlashRegex().Replace(normalizedPath, "/");

        // Remove trailing slash (except for root)
        if (normalizedPath.Length > 1 && normalizedPath.EndsWith('/'))
        {
            normalizedPath = normalizedPath[..^1];
        }

        // Canonicalize query string
        var canonicalQuery = !string.IsNullOrEmpty(query) ? Query(query) : "";

        // v2.3.2 format: METHOD|PATH|CANONICAL_QUERY
        return $"{normalizedMethod}|{normalizedPath}|{canonicalQuery}";
    }

    /// <summary>
    /// Normalize a binding from a full URL path (including query string).
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="fullPath">Full URL path including query string (e.g., "/api/users?page=1").</param>
    /// <returns>Canonical binding string (METHOD|PATH|QUERY).</returns>
    public static string BindingFromUrl(string method, string fullPath)
    {
        var queryIndex = fullPath.IndexOf('?');
        string path, query;

        if (queryIndex != -1)
        {
            path = fullPath[..queryIndex];
            query = fullPath[(queryIndex + 1)..];
        }
        else
        {
            path = fullPath;
            query = "";
        }

        return Binding(method, path, query);
    }

    [GeneratedRegex(@"/+")]
    private static partial Regex DuplicateSlashRegex();
}
