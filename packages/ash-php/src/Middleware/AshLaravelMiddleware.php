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
 *        'ash' => \Ash\Middleware\AshLaravelMiddleware::class,
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
final class AshLaravelMiddleware
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

    /**
     * Maximum age of timestamp in seconds (default 5 minutes).
     */
    private int $maxTimestampAgeSeconds = 300;

    /**
     * Enable unified proof features (scope/chain).
     */
    private bool $enableUnified = true;

    public function __construct(Ash $ash)
    {
        $this->ash = $ash;
    }

    /**
     * Configure middleware options.
     *
     * @param array $config Configuration options:
     *                      - maxTimestampAgeSeconds: int (default 300)
     *                      - enableUnified: bool (default true)
     * @return self
     */
    public function configure(array $config): self
    {
        if (isset($config['maxTimestampAgeSeconds'])) {
            $this->maxTimestampAgeSeconds = (int) $config['maxTimestampAgeSeconds'];
        }
        if (isset($config['enableUnified'])) {
            $this->enableUnified = (bool) $config['enableUnified'];
        }
        return $this;
    }

    /**
     * Get a production-safe error message.
     *
     * @param string $detailedMessage The detailed error message for development
     * @param string $genericMessage The generic message for production
     * @return string The appropriate message based on debug mode
     */
    private function getErrorMessage(string $detailedMessage, string $genericMessage = 'Request binding does not match context'): string
    {
        if (config('app.debug') === false) {
            return $genericMessage;
        }
        return $detailedMessage;
    }

    /**
     * Validate context_id format and length.
     *
     * @param string $contextId The context ID to validate
     * @return array|null Error array if invalid, null if valid
     */
    private function validateContextId(string $contextId): ?array
    {
        // Check max length (256 chars)
        if (strlen($contextId) > 256) {
            return [
                'error' => 'ASH_INVALID_CONTEXT_ID',
                'message' => 'Context ID exceeds maximum length of 256 characters',
                'status' => 400,
            ];
        }

        // Validate format: alphanumeric + underscore/hyphen/dot only
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $contextId)) {
            return [
                'error' => 'ASH_INVALID_CONTEXT_ID',
                'message' => 'Context ID contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed',
                'status' => 400,
            ];
        }

        return null;
    }

    /**
     * Validate proof format.
     *
     * @param string $proof The proof to validate
     * @return array|null Error array if invalid, null if valid
     */
    private function validateProof(string $proof): ?array
    {
        // Must be exactly 64 hex characters (SHA-256)
        if (!preg_match('/^[a-fA-F0-9]{64}$/', $proof)) {
            return [
                'error' => 'ASH_INVALID_PROOF_FORMAT',
                'message' => 'Proof must be exactly 64 hexadecimal characters',
                'status' => 400,
            ];
        }

        return null;
    }

    /**
     * Sort strings using byte-wise comparison (like JavaScript Buffer.compare).
     *
     * @param array $strings Array of strings to sort
     * @return array Sorted array
     */
    private function byteWiseSort(array $strings): array
    {
        $sorted = $strings;
        usort($sorted, function (string $a, string $b): int {
            $lenA = strlen($a);
            $lenB = strlen($b);
            $minLen = min($lenA, $lenB);

            for ($i = 0; $i < $minLen; $i++) {
                $byteA = ord($a[$i]);
                $byteB = ord($b[$i]);
                if ($byteA !== $byteB) {
                    return $byteA <=> $byteB;
                }
            }

            return $lenA <=> $lenB;
        });

        return $sorted;
    }

    /**
     * Validate timestamp freshness.
     *
     * @param string|null $timestamp The timestamp header value
     * @return array|null Error array if invalid/expired, null if valid
     */
    private function validateTimestamp(?string $timestamp): ?array
    {
        if ($timestamp === null || $timestamp === '') {
            return [
                'error' => 'ASH_TIMESTAMP_MISSING',
                'message' => $this->getErrorMessage(
                    'Missing X-ASH-Timestamp header',
                    'Request binding does not match context'
                ),
                'status' => 460,
            ];
        }

        // Validate timestamp format (ISO 8601 or Unix timestamp)
        $timestampInt = is_numeric($timestamp) ? (int) $timestamp : strtotime($timestamp);
        if ($timestampInt === false || $timestampInt === 0) {
            return [
                'error' => 'ASH_INVALID_TIMESTAMP',
                'message' => $this->getErrorMessage(
                    'Invalid timestamp format',
                    'Request binding does not match context'
                ),
                'status' => 460,
            ];
        }

        // Convert to seconds if in milliseconds
        if ($timestampInt > 1000000000000) {
            $timestampInt = (int) ($timestampInt / 1000);
        }

        $now = time();
        $age = abs($now - $timestampInt);

        if ($age > $this->maxTimestampAgeSeconds) {
            return [
                'error' => 'ASH_TIMESTAMP_EXPIRED',
                'message' => $this->getErrorMessage(
                    "Timestamp expired (age: {$age}s, max: {$this->maxTimestampAgeSeconds}s)",
                    'Request binding does not match context'
                ),
                'status' => 460,
            ];
        }

        return null;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param string ...$guards
     * @return SymfonyResponse
     */
    public function handle(Request $request, Closure $next, string ...$guards): SymfonyResponse
    {
        // Parse guard options (e.g., 'enforce_user', 'enforce_ip', 'maxTimestampAgeSeconds:600', 'enableUnified:false')
        $enforceUser = in_array('enforce_user', $guards, true);
        $enforceIp = in_array('enforce_ip', $guards, true);

        // Parse key:value options from guards
        foreach ($guards as $guard) {
            if (strpos($guard, ':') !== false) {
                [$key, $value] = explode(':', $guard, 2);
                switch ($key) {
                    case 'maxTimestampAgeSeconds':
                        $this->maxTimestampAgeSeconds = (int) $value;
                        break;
                    case 'enableUnified':
                        $this->enableUnified = filter_var($value, FILTER_VALIDATE_BOOLEAN);
                        break;
                }
            }
        }

        // Get required headers
        $contextId = $request->header(self::HEADERS['CONTEXT_ID']);
        $proof = $request->header(self::HEADERS['PROOF']);
        $timestamp = $request->header(self::HEADERS['TIMESTAMP']);

        if (!$contextId) {
            return response()->json([
                'error' => 'ASH_CTX_NOT_FOUND',
                'message' => $this->getErrorMessage(
                    'Missing X-ASH-Context-ID header',
                    'Request binding does not match context'
                ),
            ], 450);  // v2.3.4: Context error
        }

        if (!$proof) {
            return response()->json([
                'error' => 'ASH_PROOF_MISSING',
                'message' => $this->getErrorMessage(
                    'Missing X-ASH-Proof header',
                    'Request binding does not match context'
                ),
            ], 483);  // v2.3.4: Format error
        }

        // Validate context_id format and length (input validation before store lookup)
        $contextIdError = $this->validateContextId($contextId);
        if ($contextIdError !== null) {
            return response()->json([
                'error' => $contextIdError['error'],
                'message' => $this->getErrorMessage(
                    $contextIdError['message'],
                    'Request binding does not match context'
                ),
            ], $contextIdError['status']);
        }

        // Validate proof format
        $proofError = $this->validateProof($proof);
        if ($proofError !== null) {
            return response()->json([
                'error' => $proofError['error'],
                'message' => $this->getErrorMessage(
                    $proofError['message'],
                    'Request binding does not match context'
                ),
            ], $proofError['status']);
        }

        // Validate timestamp freshness
        $timestampError = $this->validateTimestamp($timestamp);
        if ($timestampError !== null) {
            return response()->json([
                'error' => $timestampError['error'],
                'message' => $timestampError['message'],
            ], $timestampError['status']);
        }

        // Get optional v2.3 headers
        $scopeHeader = $request->header(self::HEADERS['SCOPE'], '');
        $scopeHash = $request->header(self::HEADERS['SCOPE_HASH'], '');
        $chainHash = $request->header(self::HEADERS['CHAIN_HASH'], '');

        // Check unified features are enabled
        if (!$this->enableUnified) {
            if (!empty($scopeHeader) || !empty($scopeHash) || !empty($chainHash)) {
                return response()->json([
                    'error' => 'ASH_UNIFIED_DISABLED',
                    'message' => $this->getErrorMessage(
                        'Scope/chain headers are not allowed when unified features are disabled',
                        'Request binding does not match context'
                    ),
                ], 400);
            }
        }

        // Normalize binding with query string
        $binding = Canonicalize::ashNormalizeBinding(
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
                    'error' => 'ASH_SCOPE_POLICY_REQUIRED',
                    'message' => $this->getErrorMessage(
                        'This endpoint requires scope headers per server policy',
                        'Request binding does not match context'
                    ),
                    'requiredScope' => $policyScope,
                ], 400);
            }

            // Verify client scope matches server policy using byte-wise sorting
            $sortedClientScope = $this->byteWiseSort($clientScope);
            $sortedPolicyScope = $this->byteWiseSort($policyScope);

            if ($sortedClientScope !== $sortedPolicyScope) {
                return response()->json([
                    'error' => 'ASH_SCOPE_POLICY_VIOLATION',
                    'message' => $this->getErrorMessage(
                        'Request scope does not match server policy',
                        'Request binding does not match context'
                    ),
                    'expected' => $policyScope,
                    'received' => $clientScope,
                ], 475);  // v2.3.4: Verification error
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

            // Get appropriate HTTP status code (v2.3.4: unique codes)
            $httpStatus = $result->errorCode?->httpStatus() ?? 460;

            return response()->json([
                'error' => $errorCode,
                'message' => $this->getErrorMessage(
                    $result->errorMessage ?? 'Verification failed',
                    'Request binding does not match context'
                ),
            ], $httpStatus);
        }

        // Verify IP binding if requested
        if ($enforceIp) {
            $clientIp = Ash::getClientIp();
            $contextIp = $result->metadata['ip'] ?? null;
            if ($contextIp !== null && $contextIp !== $clientIp) {
                return response()->json([
                    'error' => 'ASH_BINDING_MISMATCH',
                    'message' => $this->getErrorMessage(
                        'IP address mismatch',
                        'Request binding does not match context'
                    ),
                ], 461);  // v2.3.4: Binding mismatch
            }
        }

        // Verify user binding if requested
        if ($enforceUser) {
            $currentUserId = $request->user()?->id ?? null;
            $contextUserId = $result->metadata['user_id'] ?? null;
            if ($contextUserId !== null && $currentUserId !== (int)$contextUserId) {
                return response()->json([
                    'error' => 'ASH_BINDING_MISMATCH',
                    'message' => $this->getErrorMessage(
                        'User mismatch',
                        'Request binding does not match context'
                    ),
                ], 461);  // v2.3.4: Binding mismatch
            }
        }

        // Store metadata in request for downstream use
        $request->attributes->set('ash_metadata', $result->metadata);
        $request->attributes->set('ash_scope', $scope);
        $request->attributes->set('ash_scope_policy', $policyScope);
        $request->attributes->set('ash_chain_hash', $chainHash);
        $request->attributes->set('ash_client_ip', Ash::getClientIp());

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

/**
 * @deprecated Use AshLaravelMiddleware instead
 */
class_alias(AshLaravelMiddleware::class, 'Ash\Middleware\LaravelMiddleware');
