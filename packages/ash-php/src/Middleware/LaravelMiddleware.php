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
 * Usage:
 *
 * 1. Register in app/Http/Kernel.php:
 *    protected $routeMiddleware = [
 *        'ash' => \Ash\Middleware\LaravelMiddleware::class,
 *    ];
 *
 * 2. Use in routes:
 *    Route::post('/api/update', function () { ... })->middleware('ash');
 */
final class LaravelMiddleware
{
    private Ash $ash;

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
        // Get headers
        $contextId = $request->header('X-ASH-Context-ID');
        $proof = $request->header('X-ASH-Proof');

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

        // Normalize binding
        $binding = $this->ash->ashNormalizeBinding(
            $request->method(),
            $request->path()
        );

        // Get payload
        $payload = $request->getContent();
        $contentType = $request->header('Content-Type', '');

        // Verify
        $result = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentType
        );

        if (!$result->valid) {
            return response()->json([
                'error' => $result->errorCode?->value ?? 'VERIFICATION_FAILED',
                'message' => $result->errorMessage ?? 'Verification failed',
            ], 403);
        }

        // Store metadata in request for downstream use
        $request->attributes->set('ash_metadata', $result->metadata);

        return $next($request);
    }
}
