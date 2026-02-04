<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Ash\Config\ScopePolicies;
use Ash\Core\Proof;
use Ash\Store\ContextStoreInterface;
use WP_REST_Request;
use WP_Error;

/**
 * WordPress REST API handler for ASH verification.
 *
 * Supports:
 * - Context scoping (selective field protection)
 * - IP binding with X-Forwarded-For support
 * - User binding
 * - Server-side scope policies
 * - Unified proof validation (v2.3)
 * - Timestamp freshness validation
 *
 * Configuration (via wp-config.php or .env):
 *    define('ASH_TRUST_PROXY', false);
 *    define('ASH_TRUSTED_PROXIES', '');
 *    define('ASH_TIMESTAMP_TOLERANCE', 30);
 *    define('WP_DEBUG', false);  // Controls error message detail
 *
 * Usage:
 *
 * 1. In your plugin or theme's functions.php:
 *
 *    use Ash\Middleware\WordPressHandler;
 *    use Ash\Store\MemoryStore;
 *    use Ash\Ash;
 *
 *    $store = new MemoryStore();
 *    $ash = new Ash($store);
 *    $handler = new WordPressHandler($ash);
 *    $handler->register();
 *
 * 2. Protect routes with optional binding enforcement:
 *
 *    // Basic protection
 *    $handler->protectRoutes('#^/wp-json/api/v1/protected#');
 *
 *    // With IP binding
 *    $handler->protectRoutes('#^/wp-json/api/v1/admin#', ['enforce_ip' => true]);
 *
 *    // With user binding
 *    $handler->protectRoutes('#^/wp-json/api/v1/user#', ['enforce_user' => true]);
 *
 *    // With unified proof disabled (rejects scope/chain headers)
 *    $handler->protectRoutes('#^/wp-json/api/v1/legacy#', ['enable_unified' => false]);
 */
final class WordPressHandler
{
    private Ash $ash;

    /** @var array<string, array> Routes to protect with options */
    private array $protectedRoutes = [];

    /** @var string Timestamp tolerance in seconds (default 30) */
    private int $timestampTolerance;

    public function __construct(Ash $ash)
    {
        $this->ash = $ash;
        $this->timestampTolerance = (int)(defined('ASH_TIMESTAMP_TOLERANCE') ? constant('ASH_TIMESTAMP_TOLERANCE') : 30);
    }

    /**
     * Register the handler with WordPress.
     */
    public function register(): void
    {
        add_filter('rest_pre_dispatch', [$this, 'verifyRequest'], 10, 3);
    }

    /**
     * Add routes to protect.
     *
     * @param string $pattern Regex pattern for protected route
     * @param array<string, mixed> $options Protection options:
     *   - enforce_ip: bool - Verify IP address matches context
     *   - enforce_user: bool - Verify WordPress user ID matches context
     *   - enable_unified: bool - Allow scope/chain headers (default true)
     */
    public function protectRoutes(string $pattern, array $options = []): void
    {
        // Default enable_unified to true if not specified
        if (!isset($options['enable_unified'])) {
            $options['enable_unified'] = true;
        }
        $this->protectedRoutes[$pattern] = $options;
    }

    /**
     * Get error message based on WP_DEBUG setting.
     * Returns generic messages in production, detailed in development.
     *
     * @param string $generic Generic error message for production
     * @param string|null $detailed Detailed error message for development
     * @return string The appropriate error message
     */
    private function getErrorMessage(string $generic, ?string $detailed = null): string
    {
        $isDebug = defined('WP_DEBUG') && constant('WP_DEBUG');
        if ($isDebug && $detailed !== null) {
            return $detailed;
        }
        return $generic;
    }

    /**
     * Validate context_id format and length.
     *
     * @param string $contextId The context ID to validate
     * @return array{valid: bool, error?: WP_Error}
     */
    private function validateContextId(string $contextId): array
    {
        // Validate length (max 256 chars per SEC-CTX-001)
        if (strlen($contextId) > 256) {
            return [
                'valid' => false,
                'error' => new WP_Error(
                    'ASH_CTX_INVALID',
                    $this->getErrorMessage(
                        'Invalid context identifier',
                        'Context ID exceeds maximum length of 256 characters'
                    ),
                    ['status' => 400]
                ),
            ];
        }

        // Validate format (alphanumeric + underscore/hyphen/dot only)
        if (!preg_match('/^[A-Za-z0-9_.\-]+$/', $contextId)) {
            return [
                'valid' => false,
                'error' => new WP_Error(
                    'ASH_CTX_INVALID',
                    $this->getErrorMessage(
                        'Invalid context identifier',
                        'Context ID must contain only ASCII alphanumeric characters, underscore, hyphen, or dot'
                    ),
                    ['status' => 400]
                ),
            ];
        }

        return ['valid' => true];
    }

    /**
     * Validate proof format (exactly 64 hex chars).
     *
     * @param string $proof The proof to validate
     * @return array{valid: bool, error?: WP_Error}
     */
    private function validateProof(string $proof): array
    {
        // Must be exactly 64 hex characters
        if (strlen($proof) !== 64 || !ctype_xdigit($proof)) {
            return [
                'valid' => false,
                'error' => new WP_Error(
                    'ASH_PROOF_INVALID_FORMAT',
                    $this->getErrorMessage(
                        'Invalid proof format',
                        'Proof must be exactly 64 hexadecimal characters'
                    ),
                    ['status' => 483]
                ),
            ];
        }

        return ['valid' => true];
    }

    /**
     * Validate timestamp freshness.
     *
     * @param string $timestamp The timestamp to validate (milliseconds)
     * @return array{valid: bool, error?: WP_Error}
     */
    private function validateTimestamp(string $timestamp): array
    {
        // Must be numeric
        if (!is_numeric($timestamp)) {
            return [
                'valid' => false,
                'error' => new WP_Error(
                    'ASH_TIMESTAMP_INVALID',
                    $this->getErrorMessage(
                        'Invalid timestamp',
                        'Timestamp must be numeric'
                    ),
                    ['status' => 482]
                ),
            ];
        }

        $timestampMs = (int)$timestamp;
        $nowMs = (int)(microtime(true) * 1000);
        $diffSeconds = abs($nowMs - $timestampMs) / 1000;

        if ($diffSeconds > $this->timestampTolerance) {
            return [
                'valid' => false,
                'error' => new WP_Error(
                    'ASH_TIMESTAMP_INVALID',
                    $this->getErrorMessage(
                        'Request timestamp expired',
                        sprintf('Timestamp difference %.0f seconds exceeds tolerance of %d seconds', $diffSeconds, $this->timestampTolerance)
                    ),
                    ['status' => 482]
                ),
            ];
        }

        return ['valid' => true];
    }

    /**
     * Compare two scope arrays using byte-wise sorting (deterministic).
     *
     * @param string[] $a First scope array
     * @param string[] $b Second scope array
     * @return bool True if scopes match
     */
    private function scopesMatch(array $a, array $b): bool
    {
        if (count($a) !== count($b)) {
            return false;
        }

        // Use byte-wise sorting (SORT_STRING for deterministic ordering)
        sort($a, SORT_STRING);
        sort($b, SORT_STRING);

        return $a === $b;
    }

    /**
     * Verify incoming REST API request.
     *
     * @param mixed $result Current result
     * @param \WP_REST_Server $server REST server
     * @param WP_REST_Request $request Request object
     * @return mixed|WP_Error
     */
    public function verifyRequest(mixed $result, \WP_REST_Server $server, WP_REST_Request $request): mixed
    {
        // Check if route should be protected
        $route = $request->get_route();
        $shouldVerify = false;
        $routeOptions = [];

        foreach ($this->protectedRoutes as $pattern => $options) {
            if (preg_match($pattern, $route)) {
                $shouldVerify = true;
                $routeOptions = $options;
                break;
            }
        }

        if (!$shouldVerify) {
            return $result;
        }

        // Get headers
        $contextId = $request->get_header('X-ASH-Context-ID');
        $proof = $request->get_header('X-ASH-Proof');
        $timestamp = $request->get_header('X-ASH-Timestamp');

        if (!$contextId) {
            return new WP_Error(
                'ASH_CTX_NOT_FOUND',
                $this->getErrorMessage('Missing context identifier', 'Missing X-ASH-Context-ID header'),
                ['status' => 450]
            );
        }

        if (!$proof) {
            return new WP_Error(
                'ASH_PROOF_MISSING',
                $this->getErrorMessage('Missing proof', 'Missing X-ASH-Proof header'),
                ['status' => 483]
            );
        }

        if (!$timestamp) {
            return new WP_Error(
                'ASH_TIMESTAMP_INVALID',
                $this->getErrorMessage('Missing timestamp', 'Missing X-ASH-Timestamp header'),
                ['status' => 482]
            );
        }

        // Validate context_id before store lookup
        $contextValidation = $this->validateContextId($contextId);
        if (!$contextValidation['valid']) {
            return $contextValidation['error'];
        }

        // Validate proof format before store lookup
        $proofValidation = $this->validateProof($proof);
        if (!$proofValidation['valid']) {
            return $proofValidation['error'];
        }

        // Validate timestamp freshness
        $timestampValidation = $this->validateTimestamp($timestamp);
        if (!$timestampValidation['valid']) {
            return $timestampValidation['error'];
        }

        // Normalize binding with query string
        $queryString = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
        $binding = $this->ash->ashNormalizeBinding(
            $request->get_method(),
            $route,
            $queryString
        );

        // Get payload
        $payload = $request->get_body();
        $contentType = $request->get_content_type();
        $contentTypeHeader = $contentType['value'] ?? '';

        // Get optional v2.3 headers
        $scope = $request->get_header('X-ASH-Scope');
        $scopeHash = $request->get_header('X-ASH-Scope-Hash');
        $chainHash = $request->get_header('X-ASH-Chain-Hash');

        // Check if unified features are enabled for this route
        $enableUnified = $routeOptions['enable_unified'] ?? true;

        if (!$enableUnified) {
            // Reject scope/chain headers when unified is disabled
            if (!empty($scope) || !empty($scopeHash) || !empty($chainHash)) {
                return new WP_Error(
                    'ASH_UNIFIED_DISABLED',
                    $this->getErrorMessage(
                        'Unified proof features not allowed on this endpoint',
                        'Scope/chain headers are not allowed when enable_unified is false'
                    ),
                    ['status' => 400]
                );
            }
        }

        // Parse client scope fields
        $clientScope = [];
        if (!empty($scope)) {
            $clientScope = array_map('trim', explode(',', $scope));
            $clientScope = array_filter($clientScope, fn($s) => $s !== '');
            $clientScope = array_values($clientScope); // Re-index
        }

        // ENH-003: Check server-side scope policy
        $policyScope = ScopePolicies::get($binding);
        $hasScopePolicy = !empty($policyScope);

        // Determine effective scope
        $effectiveScope = $clientScope;

        // ENH-003: Server-side scope policy enforcement
        if ($hasScopePolicy) {
            // If server has a policy, client MUST use it
            if (empty($clientScope)) {
                return new WP_Error(
                    'ASH_SCOPE_POLICY_REQUIRED',
                    $this->getErrorMessage(
                        'This endpoint requires scope headers per server policy',
                        'Missing required scope headers'
                    ),
                    [
                        'status' => 400,
                        'requiredScope' => $policyScope,
                    ]
                );
            }

            // Verify client scope matches server policy using byte-wise sorting
            if (!$this->scopesMatch($clientScope, $policyScope)) {
                return new WP_Error(
                    'ASH_SCOPE_POLICY_VIOLATION',
                    $this->getErrorMessage(
                        'Request scope does not match server policy',
                        'Client scope does not match server policy'
                    ),
                    [
                        'status' => 475,
                        'expected' => $policyScope,
                        'received' => $clientScope,
                    ]
                );
            }

            $effectiveScope = $policyScope;
        }

        // Build options
        $options = [
            'timestamp' => $timestamp,
        ];
        if (!empty($effectiveScope)) {
            $options['scope'] = $effectiveScope;
        }
        if (!empty($scopeHash)) {
            $options['scopeHash'] = $scopeHash;
        }
        if (!empty($chainHash)) {
            $options['chainHash'] = $chainHash;
        }

        // Verify
        $verifyResult = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentTypeHeader,
            $options
        );

        if (!$verifyResult->valid) {
            $errorCode = $verifyResult->errorCode?->value ?? 'ASH_PROOF_INVALID';
            $httpStatus = $verifyResult->errorCode?->httpStatus() ?? 460;
            return new WP_Error(
                $errorCode,
                $this->getErrorMessage(
                    'Verification failed',
                    $verifyResult->errorMessage ?? 'Verification failed'
                ),
                [
                    'status' => $httpStatus,
                    'code' => $errorCode,
                ]
            );
        }

        // Verify IP binding if requested
        if (!empty($routeOptions['enforce_ip'])) {
            $clientIp = Ash::getClientIp();
            $contextIp = $verifyResult->metadata['ip'] ?? null;
            if ($contextIp !== null && $contextIp !== $clientIp) {
                return new WP_Error(
                    'ASH_BINDING_MISMATCH',
                    $this->getErrorMessage('IP address mismatch'),
                    ['status' => 461]
                );
            }
        }

        // Verify user binding if requested
        if (!empty($routeOptions['enforce_user'])) {
            $currentUserId = get_current_user_id();
            $contextUserId = $verifyResult->metadata['user_id'] ?? null;
            if ($contextUserId !== null && (int)$currentUserId !== (int)$contextUserId) {
                return new WP_Error(
                    'ASH_BINDING_MISMATCH',
                    $this->getErrorMessage('User mismatch'),
                    ['status' => 461]
                );
            }
        }

        // Store metadata in request params for downstream use
        $request->set_param('_ash_metadata', $verifyResult->metadata);
        $request->set_param('_ash_client_ip', Ash::getClientIp());
        $request->set_param('_ash_scope', $effectiveScope);
        $request->set_param('_ash_scope_policy', $policyScope);
        $request->set_param('_ash_chain_hash', $chainHash);

        return $result;
    }

    /**
     * Get the ASH instance.
     *
     * @return Ash
     */
    public function getAsh(): Ash
    {
        return $this->ash;
    }
}
