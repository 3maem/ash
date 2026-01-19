<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Ash\Store\ContextStoreInterface;
use WP_REST_Request;
use WP_Error;

/**
 * WordPress REST API handler for ASH verification.
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
 * 2. Protected endpoints will require ASH headers.
 */
final class WordPressHandler
{
    private Ash $ash;

    /** @var array<string> Routes to protect (regex patterns) */
    private array $protectedRoutes = [];

    public function __construct(Ash $ash)
    {
        $this->ash = $ash;
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
     * @param string ...$patterns Regex patterns for protected routes
     */
    public function protectRoutes(string ...$patterns): void
    {
        $this->protectedRoutes = array_merge($this->protectedRoutes, $patterns);
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

        foreach ($this->protectedRoutes as $pattern) {
            if (preg_match($pattern, $route)) {
                $shouldVerify = true;
                break;
            }
        }

        if (!$shouldVerify) {
            return $result;
        }

        // Get headers
        $contextId = $request->get_header('X-ASH-Context-ID');
        $proof = $request->get_header('X-ASH-Proof');

        if (!$contextId) {
            return new WP_Error(
                'ash_missing_context',
                'Missing X-ASH-Context-ID header',
                ['status' => 403]
            );
        }

        if (!$proof) {
            return new WP_Error(
                'ash_missing_proof',
                'Missing X-ASH-Proof header',
                ['status' => 403]
            );
        }

        // Normalize binding
        $binding = $this->ash->ashNormalizeBinding(
            $request->get_method(),
            $route
        );

        // Get payload
        $payload = $request->get_body();
        $contentType = $request->get_content_type();
        $contentTypeHeader = $contentType['value'] ?? '';

        // Verify
        $verifyResult = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentTypeHeader
        );

        if (!$verifyResult->valid) {
            return new WP_Error(
                'ash_verification_failed',
                $verifyResult->errorMessage ?? 'Verification failed',
                [
                    'status' => 403,
                    'code' => $verifyResult->errorCode?->value,
                ]
            );
        }

        // Store metadata in request params for downstream use
        $request->set_param('_ash_metadata', $verifyResult->metadata);

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
