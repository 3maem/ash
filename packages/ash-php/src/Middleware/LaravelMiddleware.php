<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Ash\AshErrorCode;
use Ash\Config\ScopePolicies;
use Ash\Core\Canonicalize;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * Laravel middleware for ASH verification.
 *
 * Supports ASH v2.3 unified proof features:
 * - Context scoping (selective field protection)
 * - Request chaining (workflow integrity)
 * - Server-side scope policies (ENH-003)
 *
 * Usage:
 *
 * 1. Register in app/Http/Kernel.php:
 *    protected $routeMiddleware = [
 *        'ash' => \Ash\Middleware\LaravelMiddleware::class,
 *    ];
 *
 * 2. Use in routes:
 *    Route::post('/api/update', function () { ... })->middleware('ash');
 *
 * 3. For scoped verification, client sends:
 *    - X-ASH-Scope: comma-separated field names
 *    - X-ASH-Scope-Hash: SHA256 of scope fields
 *
 * 4. For chained verification, client sends:
 *    - X-ASH-Chain-Hash: SHA256 of previous proof
 *
 * 5. Server-side scope policies (ENH-003):
 *    Register policies in your AppServiceProvider:
 *    ScopePolicies::register('POST|/api/transfer|', ['amount', 'recipient']);
 *
 *    The server will enforce these policies automatically.
 */
final class LaravelMiddleware
{
    private Ash $ash;

    /**
     * ASH header names for v2.3 unified proof.
     */
    private const HEADERS = [
        'CONTEXT_ID' => 'X-ASH-Context-ID',
        'PROOF' => 'X-ASH-Proof',
        'TIMESTAMP' => 'X-ASH-Timestamp',
        'SCOPE' => 'X-ASH-Scope',
        'SCOPE_HASH' => 'X-ASH-Scope-Hash',
        'CHAIN_HASH' => 'X-ASH-Chain-Hash',
    ];

    public function __construct(Ash $ash)
    {
        $this->ash = $ash;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @return SymfonyResponse
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        // Get required headers
        $contextId = $request->header(self::HEADERS['CONTEXT_ID']);
        $proof = $request->header(self::HEADERS['PROOF']);

        if (!$contextId) {
            return response()->json([
                'error' => 'MISSING_CONTEXT_ID',
                'message' => 'Missing X-ASH-Context-ID header',
            ], 403);
        }

        if (!$proof) {
            return response()->json([
                'error' => 'MISSING_PROOF',
                'message' => 'Missing X-ASH-Proof header',
            ], 403);
        }

        // Get optional v2.3 headers
        $scopeHeader = $request->header(self::HEADERS['SCOPE'], '');
        $scopeHash = $request->header(self::HEADERS['SCOPE_HASH'], '');
        $chainHash = $request->header(self::HEADERS['CHAIN_HASH'], '');

        // Normalize binding with query string
        $binding = Canonicalize::normalizeBinding(
            $request->method(),
            '/' . ltrim($request->path(), '/'),
            $request->getQueryString() ?? ''
        );

        // ENH-003: Check server-side scope policy
        $policyScope = ScopePolicies::get($binding);
        $hasScopePolicy = !empty($policyScope);

        // Parse client scope fields
        $clientScope = [];
        if (!empty($scopeHeader)) {
            $clientScope = array_map('trim', explode(',', $scopeHeader));
            $clientScope = array_filter($clientScope, fn($s) => $s !== '');
            $clientScope = array_values($clientScope); // Re-index
        }

        // Determine effective scope
        $scope = $clientScope;

        // ENH-003: Server-side scope policy enforcement
        if ($hasScopePolicy) {
            // If server has a policy, client MUST use it
            if (empty($clientScope)) {
                // Client didn't send scope but server requires it
                return response()->json([
                    'error' => 'SCOPE_POLICY_REQUIRED',
                    'message' => 'This endpoint requires scope headers per server policy',
                    'requiredScope' => $policyScope,
                ], 403);
            }

            // Verify client scope matches server policy
            $sortedClientScope = $clientScope;
            $sortedPolicyScope = $policyScope;
            sort($sortedClientScope);
            sort($sortedPolicyScope);

            if ($sortedClientScope !== $sortedPolicyScope) {
                return response()->json([
                    'error' => 'SCOPE_POLICY_VIOLATION',
                    'message' => 'Request scope does not match server policy',
                    'expected' => $policyScope,
                    'received' => $clientScope,
                ], 403);
            }

            $scope = $policyScope;
        }

        // Get payload
        $payload = $request->getContent();
        $contentType = $request->header('Content-Type', '');

        // Verify with v2.3 unified options
        $result = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentType,
            [
                'scope' => $scope,
                'scopeHash' => $scopeHash,
                'chainHash' => $chainHash,
            ]
        );

        if (!$result->valid) {
            $errorCode = $result->errorCode?->value ?? 'VERIFICATION_FAILED';

            // Map specific v2.3 errors
            if (!empty($scope) && !empty($scopeHash)) {
                if ($errorCode === 'INTEGRITY_FAILED') {
                    $errorCode = 'ASH_SCOPE_MISMATCH';
                }
            }
            if (!empty($chainHash)) {
                if ($errorCode === 'INTEGRITY_FAILED') {
                    $errorCode = 'ASH_CHAIN_BROKEN';
                }
            }

            return response()->json([
                'error' => $errorCode,
                'message' => $result->errorMessage ?? 'Verification failed',
            ], 403);
        }

        // Store metadata in request for downstream use
        $request->attributes->set('ash_metadata', $result->metadata);
        $request->attributes->set('ash_scope', $scope);
        $request->attributes->set('ash_scope_policy', $policyScope);
        $request->attributes->set('ash_chain_hash', $chainHash);

        return $next($request);
    }

    /**
     * Get the scope policy for a binding.
     *
     * Convenience method for controllers to check the applied policy.
     *
     * @param string $binding The normalized binding
     * @return string[] The scope policy fields
     */
    public static function getScopePolicy(string $binding): array
    {
        return ScopePolicies::get($binding);
    }
}
