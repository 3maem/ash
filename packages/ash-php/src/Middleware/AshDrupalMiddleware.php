<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Ash\AshErrorCode;
use Ash\Config\ScopePolicies;
use Ash\Core\Canonicalize;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Drupal middleware for ASH verification.
 *
 * Supports ASH v2.3 unified proof features:
 * - Context scoping (selective field protection)
 * - Request chaining (workflow integrity)
 * - Server-side scope policies (ENH-003)
 * - IP binding enforcement
 * - User binding enforcement
 * - Timestamp validation
 * - Input validation
 *
 * Usage:
 *
 * 1. Create a service in your module's services.yml:
 *
 *    services:
 *      ash.middleware:
 *        class: Ash\Middleware\AshDrupalMiddleware
 *        arguments: ['@http_kernel', '@ash.service']
 *        tags:
 *          - { name: http_middleware, priority: 200 }
 *
 * 2. Configure protected routes and options in your module's configuration:
 *
 *    // In your module's configuration file (e.g., ash.settings.yml)
 *    ash.settings:
 *      protected_patterns:
 *        - '#^/api/secure/#'
 *        - '#^/api/admin/#'
 *      enforce_ip: true
 *      enforce_user: true
 *      enable_unified: true
 *      max_timestamp_age_seconds: 300
 */
final class AshDrupalMiddleware implements HttpKernelInterface
{
    private HttpKernelInterface $app;
    private Ash $ash;

    /** @var array<string> Route patterns to protect */
    private array $protectedPatterns = [];

    /** @var bool Enforce IP address binding */
    private bool $enforceIp = false;

    /** @var bool Enforce user binding */
    private bool $enforceUser = false;

    /** @var bool Enable unified proof features (scope/chain) */
    private bool $enableUnified = true;

    /** @var int Maximum age of timestamp in seconds */
    private int $maxTimestampAgeSeconds = 300;

    /** @var array<string, string> ASH header names for v2.3 unified proof */
    private const HEADERS = [
        'CONTEXT_ID' => 'X-ASH-Context-ID',
        'PROOF' => 'X-ASH-Proof',
        'TIMESTAMP' => 'X-ASH-Timestamp',
        'SCOPE' => 'X-ASH-Scope',
        'SCOPE_HASH' => 'X-ASH-Scope-Hash',
        'CHAIN_HASH' => 'X-ASH-Chain-Hash',
    ];

    public function __construct(HttpKernelInterface $app, Ash $ash)
    {
        $this->app = $app;
        $this->ash = $ash;
    }

    /**
     * Set protected route patterns.
     *
     * @param array<string> $patterns Route patterns (regex)
     */
    public function setProtectedPatterns(array $patterns): void
    {
        $this->protectedPatterns = $patterns;
    }

    /**
     * Configure middleware options.
     *
     * @param array<string, mixed> $config Configuration options:
     *                                    - enforce_ip: bool (default false)
     *                                    - enforce_user: bool (default false)
     *                                    - enable_unified: bool (default true)
     *                                    - max_timestamp_age_seconds: int (default 300)
     */
    public function configure(array $config): void
    {
        if (isset($config['enforce_ip'])) {
            $this->enforceIp = (bool) $config['enforce_ip'];
        }
        if (isset($config['enforce_user'])) {
            $this->enforceUser = (bool) $config['enforce_user'];
        }
        if (isset($config['enable_unified'])) {
            $this->enableUnified = (bool) $config['enable_unified'];
        }
        if (isset($config['max_timestamp_age_seconds'])) {
            $this->maxTimestampAgeSeconds = (int) $config['max_timestamp_age_seconds'];
        }
    }

    /**
     * Check if the application is in debug mode.
     *
     * In Drupal, checks the 'debug' parameter in the container or $_ENV.
     *
     * @return bool True if debug mode is enabled
     */
    private function isDebugMode(): bool
    {
        // Check for Drupal's debug setting via environment variable
        if (isset($_ENV['DRUPAL_DEBUG']) || isset($_SERVER['DRUPAL_DEBUG'])) {
            return filter_var($_ENV['DRUPAL_DEBUG'] ?? $_SERVER['DRUPAL_DEBUG'], FILTER_VALIDATE_BOOL);
        }

        // Check for APP_DEBUG (common Symfony convention)
        if (isset($_ENV['APP_DEBUG']) || isset($_SERVER['APP_DEBUG'])) {
            return filter_var($_ENV['APP_DEBUG'] ?? $_SERVER['APP_DEBUG'], FILTER_VALIDATE_BOOL);
        }

        // Check ASH-specific debug flag
        if (isset($_ENV['ASH_DEBUG']) || isset($_SERVER['ASH_DEBUG'])) {
            return filter_var($_ENV['ASH_DEBUG'] ?? $_SERVER['ASH_DEBUG'], FILTER_VALIDATE_BOOL);
        }

        // Default to false for production safety
        return false;
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
        if (!$this->isDebugMode()) {
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
     * Sort strings using byte-wise comparison (like JavaScript Buffer.compare).
     *
     * @param array<string> $strings Array of strings to sort
     * @return array<string> Sorted array
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
     * Get the current user ID from Drupal.
     *
     * @return int|null The user ID or null if not authenticated
     */
    private function getCurrentUserId(): ?int
    {
        // Try to get from Drupal's global user if available
        if (function_exists('Drupal::currentUser')) {
            $user = \Drupal::currentUser();
            $id = $user->id();
            return $id !== 0 ? (int) $id : null;
        }

        // Check for user in request attributes (if set by auth middleware)
        if (isset($GLOBALS['user']) && is_object($GLOBALS['user'])) {
            $user = $GLOBALS['user'];
            if (isset($user->uid)) {
                return $user->uid !== 0 ? (int) $user->uid : null;
            }
        }

        return null;
    }

    /**
     * Handle the request.
     *
     * @param Request $request
     * @param int $type
     * @param bool $catch
     * @return Response
     */
    public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): Response
    {
        // Check if route should be protected
        $path = $request->getPathInfo();
        $shouldVerify = false;

        foreach ($this->protectedPatterns as $pattern) {
            if (preg_match($pattern, $path)) {
                $shouldVerify = true;
                break;
            }
        }

        if (!$shouldVerify) {
            return $this->app->handle($request, $type, $catch);
        }

        // Get all 6 ASH headers
        $contextId = $request->headers->get(self::HEADERS['CONTEXT_ID']);
        $proof = $request->headers->get(self::HEADERS['PROOF']);
        $timestamp = $request->headers->get(self::HEADERS['TIMESTAMP']);
        $scopeHeader = $request->headers->get(self::HEADERS['SCOPE'], '');
        $scopeHash = $request->headers->get(self::HEADERS['SCOPE_HASH'], '');
        $chainHash = $request->headers->get(self::HEADERS['CHAIN_HASH'], '');

        // Validate required headers
        if (!$contextId) {
            return new JsonResponse([
                'error' => 'ASH_CTX_NOT_FOUND',
                'message' => $this->getErrorMessage(
                    'Missing X-ASH-Context-ID header',
                    'Request binding does not match context'
                ),
            ], 450);  // v2.3.4: Context error
        }

        if (!$proof) {
            return new JsonResponse([
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
            return new JsonResponse([
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
            return new JsonResponse([
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
            return new JsonResponse([
                'error' => $timestampError['error'],
                'message' => $timestampError['message'],
            ], $timestampError['status']);
        }

        // Check unified features are enabled
        if (!$this->enableUnified) {
            if (!empty($scopeHeader) || !empty($scopeHash) || !empty($chainHash)) {
                return new JsonResponse([
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
            $request->getMethod(),
            $path,
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
                return new JsonResponse([
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
                return new JsonResponse([
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
        $contentType = $request->headers->get('Content-Type', '');

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

            return new JsonResponse([
                'error' => $errorCode,
                'message' => $this->getErrorMessage(
                    $result->errorMessage ?? 'Verification failed',
                    'Request binding does not match context'
                ),
            ], $httpStatus);
        }

        // Verify IP binding if requested
        if ($this->enforceIp) {
            $clientIp = Ash::getClientIp();
            $contextIp = $result->metadata['ip'] ?? null;
            if ($contextIp !== null && $contextIp !== $clientIp) {
                return new JsonResponse([
                    'error' => 'ASH_BINDING_MISMATCH',
                    'message' => $this->getErrorMessage(
                        'IP address mismatch',
                        'Request binding does not match context'
                    ),
                ], 461);  // v2.3.4: Binding mismatch
            }
        }

        // Verify user binding if requested
        if ($this->enforceUser) {
            $currentUserId = $this->getCurrentUserId();
            $contextUserId = $result->metadata['user_id'] ?? null;
            if ($contextUserId !== null && $currentUserId !== (int) $contextUserId) {
                return new JsonResponse([
                    'error' => 'ASH_BINDING_MISMATCH',
                    'message' => $this->getErrorMessage(
                        'User mismatch',
                        'Request binding does not match context'
                    ),
                ], 461);  // v2.3.4: Binding mismatch
            }
        }

        // Store metadata in request attributes for downstream use
        $request->attributes->set('ash_metadata', $result->metadata);
        $request->attributes->set('ash_scope', $scope);
        $request->attributes->set('ash_scope_policy', $policyScope);
        $request->attributes->set('ash_chain_hash', $chainHash);
        $request->attributes->set('ash_client_ip', Ash::getClientIp());

        return $this->app->handle($request, $type, $catch);
    }

    /**
     * Get the scope policy for a binding.
     *
     * Convenience method for controllers to check the applied policy.
     *
     * @param string $binding The normalized binding
     * @return array<string> The scope policy fields
     */
    public static function getScopePolicy(string $binding): array
    {
        return ScopePolicies::get($binding);
    }
}

/**
 * @deprecated Use AshDrupalMiddleware instead
 */
class_alias(AshDrupalMiddleware::class, 'Ash\Middleware\DrupalMiddleware');
