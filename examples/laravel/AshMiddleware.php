<?php
/**
 * ASH Integration Example: Laravel Middleware
 *
 * This example demonstrates how to integrate ASH with Laravel
 * for request integrity verification and anti-replay protection.
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Ash\Core\Ash;
use Ash\Core\Stores\RedisStore;

class AshMiddleware
{
    private $store;

    public function __construct()
    {
        // Use Redis store (configured in config/database.php)
        $this->store = new RedisStore(config('database.redis.default'));
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Get ASH headers
        $contextId = $request->header('X-ASH-Context-ID');
        $timestamp = $request->header('X-ASH-Timestamp');
        $proof = $request->header('X-ASH-Proof');

        if (!$contextId || !$timestamp || !$proof) {
            return response()->json([
                'error' => 'Missing ASH headers',
                'code' => 'ASH_HEADERS_MISSING',
            ], 403);
        }

        // Get stored context
        $stored = $this->store->get($contextId);
        if (!$stored) {
            return response()->json([
                'error' => 'Context not found',
                'code' => 'ASH_CTX_NOT_FOUND',
            ], 403);
        }

        // Check expiration
        $nowMs = (int)(microtime(true) * 1000);
        if ($nowMs > $stored['expires_at']) {
            return response()->json([
                'error' => 'Context expired',
                'code' => 'ASH_CTX_EXPIRED',
            ], 403);
        }

        // Build binding
        $binding = Ash::normalizeBinding(
            $request->method(),
            $request->path(),
            $request->getQueryString() ?? ''
        );

        // Get body hash
        $body = $request->getContent() ?: '{}';
        $bodyHash = Ash::hashBody($body);

        // Verify proof
        $isValid = Ash::verifyProofV21(
            $stored['nonce'],
            $contextId,
            $binding,
            $timestamp,
            $bodyHash,
            $proof
        );

        if (!$isValid) {
            return response()->json([
                'error' => 'Invalid proof',
                'code' => 'ASH_PROOF_MISMATCH',
            ], 403);
        }

        // Consume context (prevent replay)
        $result = $this->store->consume($contextId, $nowMs);
        if ($result !== 'consumed') {
            return response()->json([
                'error' => 'Context already used',
                'code' => 'ASH_CTX_USED',
            ], 403);
        }

        return $next($request);
    }
}
