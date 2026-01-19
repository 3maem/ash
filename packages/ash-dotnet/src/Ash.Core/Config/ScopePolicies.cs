using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Ash.Core.Config;

/// <summary>
/// Server-side scope policy registry for ASH.
///
/// Allows servers to define which fields must be protected for each route,
/// without requiring client-side scope management.
/// </summary>
/// <example>
/// <code>
/// // Register policies at application startup
/// ScopePolicies.Register("POST|/api/transfer|", new[] { "amount", "recipient" });
/// ScopePolicies.Register("POST|/api/payment|", new[] { "amount", "card_last4" });
/// ScopePolicies.Register("PUT|/api/users/{id}|", new[] { "role", "permissions" });
///
/// // Later, get policy for a binding
/// var scope = ScopePolicies.Get("POST|/api/transfer|");
/// // Returns: ["amount", "recipient"]
/// </code>
/// </example>
public static class ScopePolicies
{
    private static readonly Dictionary<string, string[]> _policies = new();
    private static readonly object _lock = new();

    /// <summary>
    /// Register a scope policy for a binding pattern.
    /// </summary>
    /// <param name="binding">The binding pattern (supports {param} and * wildcards)</param>
    /// <param name="fields">The fields that must be protected</param>
    /// <example>
    /// <code>
    /// ScopePolicies.Register("POST|/api/transfer|", new[] { "amount", "recipient" });
    /// ScopePolicies.Register("PUT|/api/users/{id}|", new[] { "role", "permissions" });
    /// </code>
    /// </example>
    public static void Register(string binding, string[] fields)
    {
        lock (_lock)
        {
            _policies[binding] = fields;
        }
    }

    /// <summary>
    /// Register multiple scope policies at once.
    /// </summary>
    /// <param name="policies">Dictionary of binding => fields</param>
    /// <example>
    /// <code>
    /// ScopePolicies.RegisterMany(new Dictionary&lt;string, string[]&gt;
    /// {
    ///     { "POST|/api/transfer|", new[] { "amount", "recipient" } },
    ///     { "POST|/api/payment|", new[] { "amount", "card_last4" } }
    /// });
    /// </code>
    /// </example>
    public static void RegisterMany(Dictionary<string, string[]> policies)
    {
        lock (_lock)
        {
            foreach (var (binding, fields) in policies)
            {
                _policies[binding] = fields;
            }
        }
    }

    /// <summary>
    /// Get the scope policy for a binding.
    /// Returns empty array if no policy is defined (full payload protection).
    /// </summary>
    /// <param name="binding">The normalized binding string</param>
    /// <returns>The fields that must be protected</returns>
    public static string[] Get(string binding)
    {
        lock (_lock)
        {
            // Exact match first
            if (_policies.TryGetValue(binding, out var exactMatch))
            {
                return exactMatch;
            }

            // Pattern match (supports {param} and * wildcards)
            foreach (var (pattern, fields) in _policies)
            {
                if (MatchesPattern(binding, pattern))
                {
                    return fields;
                }
            }

            // Default: no scoping (full payload protection)
            return Array.Empty<string>();
        }
    }

    /// <summary>
    /// Check if a binding has a scope policy defined.
    /// </summary>
    /// <param name="binding">The normalized binding string</param>
    /// <returns>True if a policy exists</returns>
    public static bool Has(string binding)
    {
        lock (_lock)
        {
            if (_policies.ContainsKey(binding))
            {
                return true;
            }

            foreach (var pattern in _policies.Keys)
            {
                if (MatchesPattern(binding, pattern))
                {
                    return true;
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Get all registered policies.
    /// </summary>
    /// <returns>Copy of all registered scope policies</returns>
    public static Dictionary<string, string[]> GetAll()
    {
        lock (_lock)
        {
            return new Dictionary<string, string[]>(_policies);
        }
    }

    /// <summary>
    /// Clear all registered policies.
    /// Useful for testing.
    /// </summary>
    public static void Clear()
    {
        lock (_lock)
        {
            _policies.Clear();
        }
    }

    /// <summary>
    /// Check if a binding matches a pattern with wildcards.
    ///
    /// Supports:
    /// - {param} for ASP.NET-style route parameters
    /// - * for single path segment wildcard
    /// - ** for multi-segment wildcard
    /// </summary>
    private static bool MatchesPattern(string binding, string pattern)
    {
        // If no wildcards or params, must be exact match
        if (!pattern.Contains('*') && !pattern.Contains('{'))
        {
            return binding == pattern;
        }

        // Convert pattern to regex
        var regex = Regex.Escape(pattern);

        // Replace ** first (multi-segment)
        regex = regex.Replace(@"\*\*", ".*");

        // Replace * (single segment - not containing | or /)
        regex = regex.Replace(@"\*", @"[^|/]*");

        // Replace {param} (ASP.NET-style route params)
        regex = Regex.Replace(regex, @"\\{[a-zA-Z_][a-zA-Z0-9_]*\\}", @"[^|/]+");

        return Regex.IsMatch(binding, $"^{regex}$");
    }
}
