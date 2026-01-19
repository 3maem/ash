<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Drupal middleware for ASH verification.
 *
 * Usage:
 *
 * 1. Create a service in your module's services.yml:
 *
 *    services:
 *      ash.middleware:
 *        class: Ash\Middleware\DrupalMiddleware
 *        arguments: ['@http_kernel', '@ash.service']
 *        tags:
 *          - { name: http_middleware, priority: 200 }
 *
 * 2. Configure protected routes in your module's configuration.
 */
final class DrupalMiddleware implements HttpKernelInterface
{
    private HttpKernelInterface $app;
    private Ash $ash;

    /** @var array<string> Route patterns to protect */
    private array $protectedPatterns = [];

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

        // Get headers
        $contextId = $request->headers->get('X-ASH-Context-ID');
        $proof = $request->headers->get('X-ASH-Proof');

        if (!$contextId) {
            return new JsonResponse([
                'error' => 'MISSING_CONTEXT_ID',
                'message' => 'Missing X-ASH-Context-ID header',
            ], 403);
        }

        if (!$proof) {
            return new JsonResponse([
                'error' => 'MISSING_PROOF',
                'message' => 'Missing X-ASH-Proof header',
            ], 403);
        }

        // Normalize binding
        $binding = $this->ash->ashNormalizeBinding(
            $request->getMethod(),
            $path
        );

        // Get payload
        $payload = $request->getContent();
        $contentType = $request->headers->get('Content-Type', '');

        // Verify
        $result = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentType
        );

        if (!$result->valid) {
            return new JsonResponse([
                'error' => $result->errorCode?->value ?? 'VERIFICATION_FAILED',
                'message' => $result->errorMessage ?? 'Verification failed',
            ], 403);
        }

        // Store metadata in request attributes
        $request->attributes->set('ash_metadata', $result->metadata);

        return $this->app->handle($request, $type, $catch);
    }
}
