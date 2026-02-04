<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Ash\AshErrorCode;
use Ash\Config\ScopePolicies;
use Ash\Core\Canonicalize;
use Ash\Core\Proof;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * CodeIgniter 4 filter for ASH verification.
 *
 * Supports ASH v2.3 unified proof features:
 * - Context scoping (selective field protection)
 * - Request chaining (workflow integrity)
 * - Server-side scope policies (ENH-003)
 * - IP binding enforcement
 * - User binding enforcement
 *
 * Usage:
 *
 * 1. Register in app/Config/Filters.php:
 *    public $aliases = [
 *        'ash' => \Ash\Middleware\CodeIgniterFilter::class,
 *    ];
 *
 * 2. Apply to routes in app/Config/Routes.php:
 *    $routes->post('api/update', 'Api::update', ['filter' => 'ash']);
 *
 * 3. With guard options:
 *    $routes->post('api/transfer', 'Api::transfer', ['filter' => 'ash:enforce_ip,enforce_user']);
 *
 * 4. For scoped verification, client sends:
 *    - X-ASH-Scope: comma-separated field names
 *    - X-ASH-Scope-Hash: SHA256 of scope fields
 *
 * 5. For chained verification, client sends:
 *    - X-ASH-Chain-Hash: SHA256 of previous proof
 *
 * 6. Server-side scope policies (ENH-003):
 *    Register policies in your Config/Boot/development.php or a service:
 *    ScopePolicies::register('POST|/api/transfer|', ['amount', 'recipient']);
 *
 *    The server will enforce these policies automatically.
 */
final class CodeIgniterFilter implements FilterInterface
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
     * Timestamp tolerance in seconds.
     */
    private int $timestampTolerance;

    public function __construct()
    {
        // In CodeIgniter, you'd typically get this from Services
        // For now, create a simple instance
        $store = new \Ash\Store\MemoryStore();
        $this->ash = new Ash($store);

        // Load timestamp tolerance from config or use default
        $this->timestampTolerance = (int) ($_ENV['ASH_TIMESTAMP_TOLERANCE'] ?? 30);
    }

    /**
     * Set the ASH instance (for dependency injection).
     *
     * @param Ash $ash
     */
    public function setAsh(Ash $ash): void
    {
        $this->ash = $ash;
    }

    /**
     * Handle incoming request.
     *
     * @param RequestInterface $request
     * @param array<mixed>|null $arguments
     * @return RequestInterface|ResponseInterface|string|void
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // Parse guard options (e.g., 'enforce_user', 'enforce_ip')
        $guards = $this->parseGuards($arguments);
        $enforceUser = $guards['enforce_user'] ?? false;
        $enforceIp = $guards['enforce_ip'] ?? false;

        // Get required headers
        $contextId = $request->getHeaderLine(self::HEADERS['CONTEXT_ID']);
        $proof = $request->getHeaderLine(self::HEADERS['PROOF']);

        // Validate context_id format before store lookup (SEC-013)
        if ($contextId !== '' && !$this->isValidContextIdFormat($contextId)) {
            return $this->errorResponse(
                AshErrorCode::CtxNotFound,
                'Invalid context_id format',
                $this->isProduction() ? [] : ['detail' => 'Context ID must start with "ash_" and contain only alphanumeric characters, underscore, hyphen, or dot']
            );
        }

        if (!$contextId) {
            return $this->errorResponse(
                AshErrorCode::CtxNotFound,
                $this->isProduction() ? 'Invalid request' : 'Missing X-ASH-Context-ID header',
                [],
                450
            );
        }

        if (!$proof) {
            return $this->errorResponse(
                AshErrorCode::ProofMissing,
                $this->isProduction() ? 'Invalid request' : 'Missing X-ASH-Proof header',
                [],
                483
            );
        }

        // Validate proof format (64 hex chars)
        if (!$this->isValidProofFormat($proof)) {
            return $this->errorResponse(
                AshErrorCode::ProofInvalid,
                $this->isProduction() ? 'Invalid request' : 'Invalid proof format',
                $this->isProduction() ? [] : ['detail' => 'Proof must be 64 hexadecimal characters']
            );
        }

        // Get optional v2.3 headers
        $timestampHeader = $request->getHeaderLine(self::HEADERS['TIMESTAMP']);
        $scopeHeader = $request->getHeaderLine(self::HEADERS['SCOPE']);
        $scopeHash = $request->getHeaderLine(self::HEADERS['SCOPE_HASH']);
        $chainHash = $request->getHeaderLine(self::HEADERS['CHAIN_HASH']);

        // Validate timestamp if provided
        if ($timestampHeader !== '' && !$this->isValidTimestamp($timestampHeader)) {
            return $this->errorResponse(
                AshErrorCode::TimestampInvalid,
                $this->isProduction() ? 'Invalid request' : 'Invalid timestamp format',
                $this->isProduction() ? [] : ['detail' => 'Timestamp must be a valid millisecond epoch']
            );
        }

        // Check timestamp freshness if provided
        if ($timestampHeader !== '' && !$this->isTimestampFresh($timestampHeader)) {
            return $this->errorResponse(
                AshErrorCode::TimestampInvalid,
                $this->isProduction() ? 'Invalid request' : 'Timestamp expired or too far in future',
                $this->isProduction() ? [] : ['tolerance_seconds' => $this->timestampTolerance]
            );
        }

        // Normalize binding with query string
        $binding = Canonicalize::ashNormalizeBinding(
            $request->getMethod(),
            $request->getUri()->getPath(),
            $request->getUri()->getQuery() ?? ''
        );

        // ENH-003: Check server-side scope policy
        $policyScope = ScopePolicies::get($binding);
        $hasScopePolicy = !empty($policyScope);

        // Parse client scope fields
        $clientScope = [];
        if ($scopeHeader !== '') {
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
                return $this->errorResponse(
                    AshErrorCode::ValidationError,
                    $this->isProduction() ? 'Invalid request' : 'This endpoint requires scope headers per server policy',
                    $this->isProduction() ? [] : ['requiredScope' => $policyScope],
                    400
                );
            }

            // Verify client scope matches server policy using byte-wise sorting
            $sortedClientScope = $clientScope;
            $sortedPolicyScope = $policyScope;
            sort($sortedClientScope, SORT_STRING);
            sort($sortedPolicyScope, SORT_STRING);

            if ($sortedClientScope !== $sortedPolicyScope) {
                return $this->errorResponse(
                    AshErrorCode::ScopeMismatch,
                    $this->isProduction() ? 'Invalid request' : 'Request scope does not match server policy',
                    $this->isProduction() ? [] : [
                        'expected' => $policyScope,
                        'received' => $clientScope,
                    ],
                    473
                );
            }

            $scope = $policyScope;
        }

        // Get payload
        $payload = $this->getRequestBody($request);
        $contentType = $request->getHeaderLine('Content-Type');

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
            $errorCode = $result->errorCode ?? AshErrorCode::ProofInvalid;
            $errorValue = $errorCode->value;

            // Map specific v2.3 errors
            if (!empty($scope) && $scopeHash !== '') {
                if ($errorValue === 'ASH_INTEGRITY_FAILED' || $errorValue === 'INTEGRITY_FAILED') {
                    $errorValue = 'ASH_SCOPE_MISMATCH';
                    $errorCode = AshErrorCode::ScopeMismatch;
                }
            }
            if ($chainHash !== '') {
                if ($errorValue === 'ASH_INTEGRITY_FAILED' || $errorValue === 'INTEGRITY_FAILED') {
                    $errorValue = 'ASH_CHAIN_BROKEN';
                    $errorCode = AshErrorCode::ChainBroken;
                }
            }

            // Get appropriate HTTP status code (v2.3.4: unique codes)
            $httpStatus = $errorCode->httpStatus();

            return $this->errorResponse(
                $errorCode,
                $this->isProduction() ? 'Invalid request' : ($result->errorMessage ?? 'Verification failed'),
                [],
                $httpStatus
            );
        }

        // Verify IP binding if requested
        if ($enforceIp) {
            $clientIp = Ash::getClientIp();
            $contextIp = $result->metadata['ip'] ?? null;
            if ($contextIp !== null && $contextIp !== $clientIp) {
                return $this->errorResponse(
                    AshErrorCode::BindingMismatch,
                    $this->isProduction() ? 'Invalid request' : 'IP address mismatch',
                    $this->isProduction() ? [] : [
                        'expected' => $contextIp,
                        'received' => $clientIp,
                    ],
                    461
                );
            }
        }

        // Verify user binding if requested
        if ($enforceUser) {
            $currentUserId = $this->getCurrentUserId($request);
            $contextUserId = $result->metadata['user_id'] ?? null;
            if ($contextUserId !== null && $currentUserId !== null && (int) $contextUserId !== (int) $currentUserId) {
                return $this->errorResponse(
                    AshErrorCode::BindingMismatch,
                    $this->isProduction() ? 'Invalid request' : 'User mismatch',
                    $this->isProduction() ? [] : [
                        'expected' => $contextUserId,
                        'received' => $currentUserId,
                    ],
                    461
                );
            }
        }

        // Store metadata for downstream use
        $request->setGlobal('ash_metadata', $result->metadata);
        $request->setGlobal('ash_scope', $scope);
        $request->setGlobal('ash_scope_policy', $policyScope);
        $request->setGlobal('ash_chain_hash', $chainHash);
        $request->setGlobal('ash_client_ip', Ash::getClientIp());

        return $request;
    }

    /**
     * After filter - not used for ASH.
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param array<mixed>|null $arguments
     * @return ResponseInterface|void
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // No post-processing needed
    }

    /**
     * Parse guard options from filter arguments.
     *
     * CodeIgniter passes arguments as an array of strings.
     * Each string can contain multiple comma-separated options.
     *
     * @param array<mixed>|null $arguments
     * @return array<string, bool>
     */
    private function parseGuards(?array $arguments): array
    {
        $guards = [];

        if ($arguments === null || empty($arguments)) {
            return $guards;
        }

        foreach ($arguments as $arg) {
            if (is_string($arg)) {
                $options = array_map('trim', explode(',', $arg));
                foreach ($options as $option) {
                    if ($option === 'enforce_user') {
                        $guards['enforce_user'] = true;
                    } elseif ($option === 'enforce_ip') {
                        $guards['enforce_ip'] = true;
                    }
                }
            }
        }

        return $guards;
    }

    /**
     * Validate context_id format.
     *
     * Context ID must start with "ash_" and contain only alphanumeric chars,
     * underscore, hyphen, or dot.
     *
     * @param string $contextId
     * @return bool
     */
    private function isValidContextIdFormat(string $contextId): bool
    {
        // Must start with ash_ prefix
        if (!str_starts_with($contextId, 'ash_')) {
            return false;
        }

        // Must contain only allowed characters
        return preg_match('/^[A-Za-z0-9_.\-]+$/', $contextId) === 1;
    }

    /**
     * Validate proof format.
     *
     * Proof must be 64 hexadecimal characters.
     *
     * @param string $proof
     * @return bool
     */
    private function isValidProofFormat(string $proof): bool
    {
        return strlen($proof) === 64 && ctype_xdigit($proof);
    }

    /**
     * Validate timestamp format.
     *
     * @param string $timestamp
     * @return bool
     */
    private function isValidTimestamp(string $timestamp): bool
    {
        return ctype_digit($timestamp) && strlen($timestamp) >= 13;
    }

    /**
     * Check if timestamp is fresh (within tolerance).
     *
     * @param string $timestamp Milliseconds since epoch
     * @return bool
     */
    private function isTimestampFresh(string $timestamp): bool
    {
        $now = (int) (microtime(true) * 1000);
        $ts = (int) $timestamp;
        $toleranceMs = $this->timestampTolerance * 1000;

        return abs($now - $ts) <= $toleranceMs;
    }

    /**
     * Get the request body as a string.
     *
     * @param RequestInterface $request
     * @return string
     */
    private function getRequestBody(RequestInterface $request): string
    {
        $body = $request->getBody();
        if (is_resource($body)) {
            $content = stream_get_contents($body);
            return $content !== false ? $content : '';
        }
        return (string) $body;
    }

    /**
     * Get the current user ID.
     *
     * This tries to extract user ID from common CodeIgniter authentication sources.
     * Override or extend this method to customize user extraction for your application.
     *
     * @param RequestInterface $request
     * @return int|null
     */
    private function getCurrentUserId(RequestInterface $request): ?int
    {
        // Try to get user ID from session (most common in CI)
        $session = session();
        if ($session !== null && $session->has('user_id')) {
            $userId = $session->get('user_id');
            return is_numeric($userId) ? (int) $userId : null;
        }

        // Try common alternative session keys
        $altKeys = ['id', 'auth_user_id', 'userId', 'uid'];
        foreach ($altKeys as $key) {
            if ($session !== null && $session->has($key)) {
                $userId = $session->get($key);
                return is_numeric($userId) ? (int) $userId : null;
            }
        }

        // Try from request attributes (for JWT/API token auth)
        $user = $request->getAttribute('user');
        if (is_array($user) && isset($user['id'])) {
            return (int) $user['id'];
        }
        if (is_object($user) && isset($user->id)) {
            return (int) $user->id;
        }

        return null;
    }

    /**
     * Check if running in production environment.
     *
     * @return bool
     */
    private function isProduction(): bool
    {
        // Check CI_ENVIRONMENT constant (CodeIgniter 4 standard)
        if (defined('CI_ENVIRONMENT')) {
            return CI_ENVIRONMENT === 'production';
        }

        // Check ENVIRONMENT constant (CodeIgniter 3 backward compatibility)
        if (defined('ENVIRONMENT')) {
            return ENVIRONMENT === 'production';
        }

        // Check APP_ENV environment variable
        $env = $_ENV['APP_ENV'] ?? $_ENV['CI_ENVIRONMENT'] ?? 'production';
        return $env === 'production';
    }

    /**
     * Create error response.
     *
     * @param AshErrorCode $code Error code
     * @param string $message Error message
     * @param array<string, mixed> $details Additional error details (only in non-production)
     * @param int|null $httpStatus Optional HTTP status code override
     * @return ResponseInterface
     */
    private function errorResponse(
        AshErrorCode $code,
        string $message,
        array $details = [],
        ?int $httpStatus = null
    ): ResponseInterface {
        $response = service('response');
        $status = $httpStatus ?? $code->httpStatus();

        $data = [
            'error' => $code->value,
            'message' => $message,
        ];

        // Only include details in non-production environments
        if (!$this->isProduction() && !empty($details)) {
            $data['details'] = $details;
        }

        return $response
            ->setStatusCode($status)
            ->setJSON($data);
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
