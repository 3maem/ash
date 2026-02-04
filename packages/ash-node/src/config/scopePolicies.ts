/**
 * Server-side scope policy registry for ASH.
 *
 * Allows servers to define which fields must be protected for each route,
 * without requiring client-side scope management.
 *
 * INFO-001 SECURITY NOTE: Pattern Matching Order
 * When multiple patterns could match a binding, the FIRST registered pattern wins.
 * Patterns are matched in insertion order (the order you call registerScopePolicy).
 *
 * Best Practice: Register more specific patterns BEFORE broader patterns.
 *
 * @example
 * // CORRECT: Specific pattern first
 * registerScopePolicy('POST|/api/users/admin|', ['role', 'permissions', 'adminLevel']);
 * registerScopePolicy('POST|/api/users/:id|', ['role', 'permissions']);
 *
 * // INCORRECT: Broad pattern first would match /api/users/admin too
 * registerScopePolicy('POST|/api/users/:id|', ['role', 'permissions']);  // Matches admin!
 * registerScopePolicy('POST|/api/users/admin|', ['role', 'permissions', 'adminLevel']);  // Never reached
 *
 * @example
 * // Register policies at application startup
 * registerScopePolicy('POST|/api/transfer|', ['amount', 'recipient']);
 * registerScopePolicy('POST|/api/payment|', ['amount', 'card_last4']);
 * registerScopePolicy('PUT|/api/users/:id|', ['role', 'permissions']);
 *
 * // Later, get policy for a binding
 * const scope = getScopePolicy('POST|/api/transfer|');
 * // Returns: ['amount', 'recipient']
 *
 * @module
 */

export interface ScopePolicyConfig {
  [binding: string]: string[];
}

/**
 * Internal storage for scope policies.
 */
const policies: ScopePolicyConfig = {};

/**
 * BUG-015: Cache compiled regexes for pattern matching.
 * Clears when policies change.
 * VULN-007 FIX: Limited to MAX_REGEX_CACHE_SIZE to prevent memory exhaustion.
 */
const regexCache: Map<string, RegExp> = new Map();

/**
 * VULN-007 FIX: Maximum size for regex cache to prevent memory exhaustion.
 */
const MAX_REGEX_CACHE_SIZE = 1000;

/**
 * VULN-001 FIX: Maximum pattern complexity to prevent ReDoS.
 * Limits the number of wildcards in a pattern.
 */
const MAX_PATTERN_WILDCARDS = 10;

/**
 * VULN-015 FIX: Dangerous keys that should not be allowed in scope field names.
 */
const DANGEROUS_SCOPE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Register a scope policy for a binding pattern.
 *
 * @param binding - The binding pattern (supports :param and * wildcards)
 * @param fields - The fields that must be protected
 *
 * @example
 * ashRegisterScopePolicy('POST|/api/transfer|', ['amount', 'recipient']);
 * ashRegisterScopePolicy('PUT|/api/users/:id|', ['role', 'permissions']);
 *
 * @throws Error if pattern has too many wildcards or fields contain dangerous keys
 */
export function ashRegisterScopePolicy(binding: string, fields: string[]): void {
  // VULN-001 FIX: Validate pattern complexity to prevent ReDoS
  const wildcardCount = (binding.match(/\*/g) || []).length;
  if (wildcardCount > MAX_PATTERN_WILDCARDS) {
    throw new Error(
      `Pattern has too many wildcards (${wildcardCount}). Maximum allowed: ${MAX_PATTERN_WILDCARDS}`
    );
  }

  // VULN-015 FIX: Validate field names don't contain dangerous keys
  for (const field of fields) {
    // Check the first segment of dot-notation paths
    const firstSegment = field.split('.')[0].split('[')[0];
    if (DANGEROUS_SCOPE_KEYS.has(firstSegment)) {
      throw new Error(
        `Scope field "${field}" contains dangerous key "${firstSegment}". ` +
        'This could lead to prototype pollution.'
      );
    }
  }

  policies[binding] = fields;
  // BUG-015, BUG-29 FIX: Clear entire regex cache when policies change
  // A new more specific pattern could affect matches for existing broader patterns
  regexCache.clear();
}

/**
 * Register multiple scope policies at once.
 *
 * @param config - Map of binding => fields
 *
 * @example
 * ashRegisterScopePolicies({
 *   'POST|/api/transfer|': ['amount', 'recipient'],
 *   'POST|/api/payment|': ['amount', 'card_last4'],
 * });
 *
 * @throws Error if any pattern has too many wildcards or fields contain dangerous keys
 */
export function ashRegisterScopePolicies(config: ScopePolicyConfig): void {
  // Validate all entries first before modifying state
  for (const [binding, fields] of Object.entries(config)) {
    // VULN-001 FIX: Validate pattern complexity
    const wildcardCount = (binding.match(/\*/g) || []).length;
    if (wildcardCount > MAX_PATTERN_WILDCARDS) {
      throw new Error(
        `Pattern "${binding}" has too many wildcards (${wildcardCount}). Maximum allowed: ${MAX_PATTERN_WILDCARDS}`
      );
    }

    // VULN-015 FIX: Validate field names
    for (const field of fields) {
      const firstSegment = field.split('.')[0].split('[')[0];
      if (DANGEROUS_SCOPE_KEYS.has(firstSegment)) {
        throw new Error(
          `Scope field "${field}" contains dangerous key "${firstSegment}". ` +
          'This could lead to prototype pollution.'
        );
      }
    }
  }

  // All validated, now register
  for (const [binding, fields] of Object.entries(config)) {
    policies[binding] = fields;
  }
  // BUG-29 FIX: Clear entire cache after bulk registration
  regexCache.clear();
}

/**
 * Get the scope policy for a binding.
 *
 * Returns empty array if no policy is defined (full payload protection).
 *
 * INFO-001 NOTE: If multiple patterns match, the FIRST registered pattern wins.
 * In development mode, a warning is logged if multiple patterns match.
 *
 * @param binding - The normalized binding string
 * @returns The fields that must be protected
 */
export function ashGetScopePolicy(binding: string): string[] {
  // Exact match first
  if (policies[binding]) {
    return policies[binding];
  }

  // Pattern match (supports :param and * wildcards)
  let firstMatch: { pattern: string; fields: string[] } | null = null;

  // INFO-001 FIX: In development, check for multiple matching patterns
  if (process.env.NODE_ENV !== 'production') {
    const allMatches: string[] = [];
    for (const [pattern, fields] of Object.entries(policies)) {
      if (matchesPattern(binding, pattern)) {
        if (!firstMatch) {
          firstMatch = { pattern, fields };
        }
        allMatches.push(pattern);
      }
    }

    // Warn if multiple patterns match
    if (allMatches.length > 1) {
      console.warn(
        `[ASH] Multiple scope policies match binding "${binding}": ` +
        `${allMatches.map(p => `"${p}"`).join(', ')}. ` +
        `Using first match: "${allMatches[0]}". ` +
        'Consider reordering registrations (specific patterns first).'
      );
    }

    return firstMatch ? firstMatch.fields : [];
  }

  // Production: simple first-match
  for (const [pattern, fields] of Object.entries(policies)) {
    if (matchesPattern(binding, pattern)) {
      return fields;
    }
  }

  // Default: no scoping (full payload protection)
  return [];
}

/**
 * Check if a binding has a scope policy defined.
 *
 * @param binding - The normalized binding string
 * @returns True if a policy exists
 */
export function ashHasScopePolicy(binding: string): boolean {
  if (policies[binding]) {
    return true;
  }

  for (const pattern of Object.keys(policies)) {
    if (matchesPattern(binding, pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Get all registered policies.
 *
 * @returns All registered scope policies
 */
export function ashGetAllScopePolicies(): ScopePolicyConfig {
  return { ...policies };
}

/**
 * Clear all registered policies.
 *
 * Useful for testing.
 */
export function ashClearScopePolicies(): void {
  for (const key of Object.keys(policies)) {
    delete policies[key];
  }
  // BUG-015: Clear regex cache
  regexCache.clear();
}

/**
 * Check if a binding matches a pattern with wildcards.
 * BUG-015: Uses cached regex for performance.
 * VULN-001 FIX: Uses possessive-like patterns to prevent ReDoS.
 * VULN-007 FIX: Limits cache size to prevent memory exhaustion.
 *
 * Supports:
 * - :param for Express-style route parameters
 * - * for single path segment wildcard
 * - ** for multi-segment wildcard
 *
 * @param binding - The actual binding
 * @param pattern - The pattern to match against
 * @returns True if matches
 */
function matchesPattern(binding: string, pattern: string): boolean {
  // If no wildcards or params, must be exact match
  if (!pattern.includes('*') && !pattern.includes(':')) {
    return binding === pattern;
  }

  // BUG-015: Check cache first
  let compiledRegex = regexCache.get(pattern);

  if (compiledRegex) {
    // BUG-LOGIC-056 FIX: Move to end of Map for true LRU behavior
    // Map maintains insertion order, so re-inserting moves to end
    regexCache.delete(pattern);
    regexCache.set(pattern, compiledRegex);
  } else {
    // VULN-007 FIX: Limit cache size using simple LRU-like eviction
    if (regexCache.size >= MAX_REGEX_CACHE_SIZE) {
      // Remove oldest entry (first key in Map iteration order)
      const firstKey = regexCache.keys().next().value;
      if (firstKey !== undefined) {
        regexCache.delete(firstKey);
      }
    }

    // Convert pattern to regex
    let regexStr = escapeRegex(pattern);

    // VULN-001 FIX: Use atomic groups simulation to prevent catastrophic backtracking
    // Replace ** first (multi-segment) - use lazy quantifier with anchor
    // Instead of .* which can backtrack, we use a more constrained pattern
    regexStr = regexStr.replace(/\\\*\\\*/g, '(?:[^]*?)');

    // Replace * (single segment - not containing | or /)
    // Use possessive-like pattern by being more specific
    regexStr = regexStr.replace(/\\\*/g, '(?:[^|/]*)');

    // Replace :param (Express-style route params)
    regexStr = regexStr.replace(/:[a-zA-Z_][a-zA-Z0-9_]*/g, '(?:[^|/]+)');

    compiledRegex = new RegExp(`^${regexStr}$`);
    regexCache.set(pattern, compiledRegex);
  }

  // VULN-001 FIX: Add timeout protection for regex execution
  // Use a simple length check as a heuristic - very long bindings with many segments
  // are suspicious and could trigger backtracking
  if (binding.length > 2048) {
    return false;
  }

  return compiledRegex.test(binding);
}

/**
 * Escape special regex characters.
 * PENTEST-FIX-001: Now includes * so it can be properly replaced by wildcard patterns.
 */
function escapeRegex(str: string): string {
  // Note: * is escaped here so we can selectively replace \* and \*\* patterns
  return str.replace(/[.+?^${}()|[\]\\*]/g, '\\$&');
}

// =========================================================================
// Deprecated Aliases for Backward Compatibility
// =========================================================================

/** @deprecated Use ashRegisterScopePolicy instead */
export const registerScopePolicy = ashRegisterScopePolicy;

/** @deprecated Use ashRegisterScopePolicies instead */
export const registerScopePolicies = ashRegisterScopePolicies;

/** @deprecated Use ashGetScopePolicy instead */
export const getScopePolicy = ashGetScopePolicy;

/** @deprecated Use ashHasScopePolicy instead */
export const hasScopePolicy = ashHasScopePolicy;

/** @deprecated Use ashGetAllScopePolicies instead */
export const getAllScopePolicies = ashGetAllScopePolicies;

/** @deprecated Use ashClearScopePolicies instead */
export const clearScopePolicies = ashClearScopePolicies;
