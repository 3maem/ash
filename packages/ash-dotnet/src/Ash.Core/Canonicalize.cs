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
    public static string AshCanonicalizeJson(JsonElement json)
    {
        var sb = new StringBuilder();
        BuildCanonicalJson(json, sb);
        return sb.ToString();
    }

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
    [Obsolete("Use AshCanonicalizeJson instead")]
    public static string Json(JsonElement json) => AshCanonicalizeJson(json);

    /// <summary>
    /// Canonicalize a JSON string to a deterministic string.
    /// </summary>
    /// <param name="jsonString">The JSON string to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    public static string AshCanonicalizeJson(string jsonString)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonString);
            return AshCanonicalizeJson(doc.RootElement);
        }
        catch (JsonException ex)
        {
            throw new CanonicalizationException($"Invalid JSON: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Canonicalize a JSON string to a deterministic string.
    /// </summary>
    /// <param name="jsonString">The JSON string to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    [Obsolete("Use AshCanonicalizeJson instead")]
    public static string Json(string jsonString) => AshCanonicalizeJson(jsonString);

    /// <summary>
    /// Canonicalize a dictionary to a deterministic JSON string.
    /// </summary>
    /// <param name="obj">The dictionary to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    public static string AshCanonicalizeJson(IDictionary<string, object?> obj)
    {
        var jsonString = JsonSerializer.Serialize(obj);
        return AshCanonicalizeJson(jsonString);
    }

    /// <summary>
    /// Canonicalize a dictionary to a deterministic JSON string.
    /// </summary>
    /// <param name="obj">The dictionary to canonicalize.</param>
    /// <returns>Canonical JSON string.</returns>
    /// <exception cref="CanonicalizationException">If value contains unsupported types.</exception>
    [Obsolete("Use AshCanonicalizeJson instead")]
    public static string Json(IDictionary<string, object?> obj) => AshCanonicalizeJson(obj);

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

    /// <summary>
    /// Escape a string for JSON according to RFC 8785 (JCS).
    /// Minimal escaping rules:
    /// - 0x08 -> \b
    /// - 0x09 -> \t
    /// - 0x0A -> \n
    /// - 0x0C -> \f
    /// - 0x0D -> \r
    /// - 0x22 -> \"
    /// - 0x5C -> \\
    /// - 0x00-0x1F (other control chars) -> \uXXXX (lowercase hex)
    /// </summary>
    private static void JsonEscapeString(string s, StringBuilder sb)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"':   // 0x22
                    sb.Append("\\\"");
                    break;
                case '\\':  // 0x5C
                    sb.Append("\\\\");
                    break;
                case '\b':  // 0x08 - backspace
                    sb.Append("\\b");
                    break;
                case '\t':  // 0x09 - tab
                    sb.Append("\\t");
                    break;
                case '\n':  // 0x0A - newline
                    sb.Append("\\n");
                    break;
                case '\f':  // 0x0C - form feed
                    sb.Append("\\f");
                    break;
                case '\r':  // 0x0D - carriage return
                    sb.Append("\\r");
                    break;
                default:
                    if (c < 0x20)
                    {
                        // Other control characters (0x00-0x1F) -> \uXXXX with lowercase hex
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
    /// - For duplicate keys: sort by value (byte-wise)
    /// - Output format: k1=v1&amp;k1=v2&amp;k2=v3
    /// - Unicode NFC applies after decoding
    /// </remarks>
    /// <param name="input">URL-encoded string.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    /// <exception cref="CanonicalizationException">If input cannot be parsed.</exception>
    public static string AshCanonicalizeUrlEncoded(string input)
    {
        if (string.IsNullOrEmpty(input))
            return "";

        var pairs = ParseUrlEncoded(input);
        return BuildCanonicalUrlEncoded(pairs);
    }

    /// <summary>
    /// Canonicalize URL-encoded form data.
    /// </summary>
    /// <remarks>
    /// Rules (from ASH-Spec-v1.0):
    /// - Parse into key-value pairs
    /// - Percent-decode consistently
    /// - Sort keys lexicographically
    /// - For duplicate keys: sort by value (byte-wise)
    /// - Output format: k1=v1&amp;k1=v2&amp;k2=v3
    /// - Unicode NFC applies after decoding
    /// </remarks>
    /// <param name="input">URL-encoded string.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    /// <exception cref="CanonicalizationException">If input cannot be parsed.</exception>
    [Obsolete("Use AshCanonicalizeUrlEncoded instead")]
    public static string UrlEncoded(string input) => AshCanonicalizeUrlEncoded(input);

    /// <summary>
    /// Canonicalize URL-encoded form data from a dictionary.
    /// </summary>
    /// <param name="data">Dictionary of key-value pairs.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    public static string AshCanonicalizeUrlEncoded(IDictionary<string, string> data)
    {
        var pairs = data.Select(kvp => (kvp.Key, kvp.Value)).ToList();
        return BuildCanonicalUrlEncoded(pairs);
    }

    /// <summary>
    /// Canonicalize URL-encoded form data from a dictionary.
    /// </summary>
    /// <param name="data">Dictionary of key-value pairs.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    [Obsolete("Use AshCanonicalizeUrlEncoded instead")]
    public static string UrlEncoded(IDictionary<string, string> data) => AshCanonicalizeUrlEncoded(data);

    /// <summary>
    /// Canonicalize URL-encoded form data from a dictionary with multiple values per key.
    /// </summary>
    /// <param name="data">Dictionary of key-value pairs where values can be lists.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    public static string AshCanonicalizeUrlEncoded(IDictionary<string, IEnumerable<string>> data)
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

    /// <summary>
    /// Canonicalize URL-encoded form data from a dictionary with multiple values per key.
    /// </summary>
    /// <param name="data">Dictionary of key-value pairs where values can be lists.</param>
    /// <returns>Canonical URL-encoded string.</returns>
    [Obsolete("Use AshCanonicalizeUrlEncoded instead")]
    public static string UrlEncoded(IDictionary<string, IEnumerable<string>> data) => AshCanonicalizeUrlEncoded(data);

    /// <summary>
    /// Parse URL-encoded data per ASH protocol.
    /// Treats + as literal plus (not space).
    /// </summary>
    private static List<(string Key, string Value)> ParseUrlEncoded(string input)
    {
        return ParseUrlEncodedInternal(input, isFormData: false);
    }

    /// <summary>
    /// Parse query string.
    /// Treats + as literal plus (not space).
    /// </summary>
    private static List<(string Key, string Value)> ParseQueryString(string input)
    {
        return ParseUrlEncodedInternal(input, isFormData: false);
    }

    private static List<(string Key, string Value)> ParseUrlEncodedInternal(string input, bool isFormData)
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
                key = isFormData ? DecodeUrlComponentFormData(part) : DecodeUrlComponentQuery(part);
                value = "";
            }
            else
            {
                key = isFormData ? DecodeUrlComponentFormData(part[..eqIndex]) : DecodeUrlComponentQuery(part[..eqIndex]);
                value = isFormData ? DecodeUrlComponentFormData(part[(eqIndex + 1)..]) : DecodeUrlComponentQuery(part[(eqIndex + 1)..]);
            }

            if (!string.IsNullOrEmpty(key))
            {
                pairs.Add((key, value));
            }
        }

        return pairs;
    }

    /// <summary>
    /// Decode URL component for form data (application/x-www-form-urlencoded).
    /// In form data, + is treated as space.
    /// </summary>
    private static string DecodeUrlComponentFormData(string input)
    {
        // Replace + with space (per application/x-www-form-urlencoded spec)
        input = input.Replace('+', ' ');
        return HttpUtility.UrlDecode(input);
    }

    /// <summary>
    /// Decode URL component for query strings.
    /// In query strings, + is literal (not space). Space is %20.
    /// </summary>
    private static string DecodeUrlComponentQuery(string input)
    {
        // HttpUtility.UrlDecode treats + as space, but ASH protocol treats + as literal.
        // Replace + with %2B before decoding so it becomes + after decode.
        input = input.Replace("+", "%2B");
        return HttpUtility.UrlDecode(input);
    }

    /// <summary>
    /// Build canonical URL-encoded string for form data.
    /// Sorts by key first, then by value for duplicate keys (byte-wise).
    /// </summary>
    private static string BuildCanonicalUrlEncoded(List<(string Key, string Value)> pairs)
    {
        // Normalize with NFC and sort by key, then by value (byte-wise, StringComparer.Ordinal)
        var normalized = pairs
            .Select(p => (
                Key: p.Key.Normalize(NormalizationForm.FormC),
                Value: p.Value.Normalize(NormalizationForm.FormC)
            ))
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal)
            .ToList();

        return BuildEncodedString(normalized);
    }

    /// <summary>
    /// Build canonical URL-encoded string for query strings.
    /// Sorts by key then by value (byte-wise).
    /// </summary>
    private static string BuildCanonicalQueryString(List<(string Key, string Value)> pairs)
    {
        // Normalize with NFC and sort by key, then by value (byte-wise, StringComparer.Ordinal)
        var normalized = pairs
            .Select(p => (
                Key: p.Key.Normalize(NormalizationForm.FormC),
                Value: p.Value.Normalize(NormalizationForm.FormC)
            ))
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal)
            .ToList();

        return BuildEncodedString(normalized);
    }

    private static string BuildEncodedString(List<(string Key, string Value)> pairs)
    {
        var sb = new StringBuilder();
        var isFirst = true;

        foreach (var (key, value) in pairs)
        {
            if (!isFirst) sb.Append('&');
            isFirst = false;

            sb.Append(PercentEncodeUppercase(key));
            sb.Append('=');
            sb.Append(PercentEncodeUppercase(value));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Percent-encode a string with uppercase hex digits (A-F not a-f).
    /// Unreserved characters are not encoded: A-Z a-z 0-9 - _ . ~
    /// </summary>
    private static string PercentEncodeUppercase(string input)
    {
        // Uri.EscapeDataString produces uppercase hex in .NET Core/.NET 5+
        // but we'll ensure uppercase explicitly for safety
        var encoded = Uri.EscapeDataString(input);
        // Ensure percent-encoded sequences are uppercase (A-F not a-f)
        return UppercasePercentEncodingRegex().Replace(encoded, m => m.Value.ToUpperInvariant());
    }

    [GeneratedRegex(@"%[0-9a-fA-F]{2}")]
    private static partial Regex UppercasePercentEncodingRegex();

    /// <summary>
    /// Canonicalize a URL query string according to ASH v2.3.1 specification.
    /// </summary>
    /// <remarks>
    /// MUST Rules:
    /// 1. MUST remove leading ? if present
    /// 2. MUST strip fragment (#...) if present
    /// 3. MUST split on &amp; to get key=value pairs
    /// 4. MUST handle keys without values (preserve empty: a= stays as a=)
    /// 5. MUST percent-decode all keys and values
    /// 6. MUST apply Unicode NFC normalization
    /// 7. MUST sort pairs by key then by value (byte-wise, StringComparer.Ordinal)
    /// 8. MUST re-encode with uppercase hex (%XX)
    /// 9. MUST join with &amp; separator
    /// 10. + is literal plus (not space); space is %20
    /// </remarks>
    /// <param name="query">Query string (with or without leading ?).</param>
    /// <returns>Canonical query string.</returns>
    public static string AshCanonicalizeQuery(string query)
    {
        // Rule 1: Remove leading ? if present
        if (query.StartsWith('?'))
        {
            query = query[1..];
        }

        // Rule 2: Strip fragment (#...) if present
        var fragmentIndex = query.IndexOf('#');
        if (fragmentIndex != -1)
        {
            query = query[..fragmentIndex];
        }

        if (string.IsNullOrEmpty(query))
            return "";

        // Rule 3-5: Parse pairs (using query string parser - + is literal)
        var pairs = ParseQueryString(query);

        // Rule 6-9: Normalize, sort by key then value, and re-encode with uppercase hex
        return BuildCanonicalQueryString(pairs);
    }

    /// <summary>
    /// Canonicalize a URL query string according to ASH v2.3.1 specification.
    /// </summary>
    /// <remarks>
    /// MUST Rules:
    /// 1. MUST remove leading ? if present
    /// 2. MUST strip fragment (#...) if present
    /// 3. MUST split on &amp; to get key=value pairs
    /// 4. MUST handle keys without values (preserve empty: a= stays as a=)
    /// 5. MUST percent-decode all keys and values
    /// 6. MUST apply Unicode NFC normalization
    /// 7. MUST sort pairs by key then by value (byte-wise, StringComparer.Ordinal)
    /// 8. MUST re-encode with uppercase hex (%XX)
    /// 9. MUST join with &amp; separator
    /// 10. + is literal plus (not space); space is %20
    /// </remarks>
    /// <param name="query">Query string (with or without leading ?).</param>
    /// <returns>Canonical query string.</returns>
    [Obsolete("Use AshCanonicalizeQuery instead")]
    public static string Query(string query) => AshCanonicalizeQuery(query);

    /// <summary>
    /// Normalize a binding string to canonical form (v2.3.1 format).
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
    public static string AshNormalizeBinding(string method, string path, string query = "")
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
        var canonicalQuery = !string.IsNullOrEmpty(query) ? AshCanonicalizeQuery(query) : "";

        // v2.3.1 format: METHOD|PATH|CANONICAL_QUERY
        return $"{normalizedMethod}|{normalizedPath}|{canonicalQuery}";
    }

    /// <summary>
    /// Normalize a binding string to canonical form (v2.3.1 format).
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
    [Obsolete("Use AshNormalizeBinding instead")]
    public static string Binding(string method, string path, string query = "") => AshNormalizeBinding(method, path, query);

    /// <summary>
    /// Normalize a binding from a full URL path (including query string).
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="fullPath">Full URL path including query string (e.g., "/api/users?page=1").</param>
    /// <returns>Canonical binding string (METHOD|PATH|QUERY).</returns>
    public static string AshNormalizeBindingFromUrl(string method, string fullPath)
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

        return AshNormalizeBinding(method, path, query);
    }

    /// <summary>
    /// Normalize a binding from a full URL path (including query string).
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="fullPath">Full URL path including query string (e.g., "/api/users?page=1").</param>
    /// <returns>Canonical binding string (METHOD|PATH|QUERY).</returns>
    [Obsolete("Use AshNormalizeBindingFromUrl instead")]
    public static string BindingFromUrl(string method, string fullPath) => AshNormalizeBindingFromUrl(method, fullPath);

    [GeneratedRegex(@"/+")]
    private static partial Regex DuplicateSlashRegex();
}
