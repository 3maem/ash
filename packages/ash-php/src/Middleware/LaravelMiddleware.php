<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Ash\AshErrorCode;
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

        // Parse scope fields
        $scope = [];
        if (!empty($scopeHeader)) {
            $scope = array_map('trim', explode(',', $scopeHeader));
            $scope = array_filter($scope, fn($s) => $s !== '');
        }

        // Normalize binding
        $binding = $this->ash->ashNormalizeBinding(
            $request->method(),
            $request->path()
        );

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
        $request->attributes->set('ash_chain_hash', $chainHash);

        return $next($request);
    }
}
