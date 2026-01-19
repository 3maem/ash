/**
 * Server-side scope policy registry for ASH.
 *
 * Allows servers to define which fields must be protected for each route,
 * without requiring client-side scope management.
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
 * Register a scope policy for a binding pattern.
 *
 * @param binding - The binding pattern (supports :param and * wildcards)
 * @param fields - The fields that must be protected
 *
 * @example
 * registerScopePolicy('POST|/api/transfer|', ['amount', 'recipient']);
 * registerScopePolicy('PUT|/api/users/:id|', ['role', 'permissions']);
 */
export function registerScopePolicy(binding: string, fields: string[]): void {
  policies[binding] = fields;
}

/**
 * Register multiple scope policies at once.
 *
 * @param config - Map of binding => fields
 *
 * @example
 * registerScopePolicies({
 *   'POST|/api/transfer|': ['amount', 'recipient'],
 *   'POST|/api/payment|': ['amount', 'card_last4'],
 * });
 */
export function registerScopePolicies(config: ScopePolicyConfig): void {
  for (const [binding, fields] of Object.entries(config)) {
    policies[binding] = fields;
  }
}

/**
 * Get the scope policy for a binding.
 *
 * Returns empty array if no policy is defined (full payload protection).
 *
 * @param binding - The normalized binding string
 * @returns The fields that must be protected
 */
export function getScopePolicy(binding: string): string[] {
  // Exact match first
  if (policies[binding]) {
    return policies[binding];
  }

  // Pattern match (supports :param and * wildcards)
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
export function hasScopePolicy(binding: string): boolean {
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
export function getAllScopePolicies(): ScopePolicyConfig {
  return { ...policies };
}

/**
 * Clear all registered policies.
 *
 * Useful for testing.
 */
export function clearScopePolicies(): void {
  for (const key of Object.keys(policies)) {
    delete policies[key];
  }
}

/**
 * Check if a binding matches a pattern with wildcards.
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

  // Convert pattern to regex
  let regex = escapeRegex(pattern);

  // Replace ** first (multi-segment)
  regex = regex.replace(/\\\*\\\*/g, '.*');

  // Replace * (single segment - not containing | or /)
  regex = regex.replace(/\\\*/g, '[^|/]*');

  // Replace :param (Express-style route params)
  regex = regex.replace(/:[a-zA-Z_][a-zA-Z0-9_]*/g, '[^|/]+');

  return new RegExp(`^${regex}$`).test(binding);
}

/**
 * Escape special regex characters except those we handle specially.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}
