<?php

declare(strict_types=1);

namespace App\Filters;

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\MemoryStore;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * ASH Filter for CodeIgniter 4
 *
 * Register in app/Config/Filters.php:
 *
 *   public $aliases = [
 *       'ash' => \App\Filters\AshFilter::class,
 *   ];
 *
 *   public $filters = [
 *       'ash' => ['before' => ['api/update', 'api/profile']],
 *   ];
 */
final class AshFilter implements FilterInterface
{
    private Ash $ash;

    public function __construct()
    {
        // In production, inject via Services
        $store = new MemoryStore();
        $this->ash = new Ash($store, AshMode::Balanced);
    }

    /**
     * Handle incoming request.
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // Get headers
        $contextId = $request->getHeaderLine('X-ASH-Context-ID');
        $proof = $request->getHeaderLine('X-ASH-Proof');

        if (!$contextId) {
            return $this->errorResponse('MISSING_CONTEXT_ID', 'Missing X-ASH-Context-ID header');
        }

        if (!$proof) {
            return $this->errorResponse('MISSING_PROOF', 'Missing X-ASH-Proof header');
        }

        // Normalize binding
        $binding = $this->ash->ashNormalizeBinding(
            $request->getMethod(),
            (string)$request->getUri()->getPath()
        );

        // Get payload
        $body = $request->getBody();
        $payload = is_string($body) ? $body : (string)$body;
        $contentType = $request->getHeaderLine('Content-Type');

        // Verify
        $result = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentType
        );

        if (!$result->valid) {
            return $this->errorResponse(
                $result->errorCode?->value ?? 'VERIFICATION_FAILED',
                $result->errorMessage ?? 'Verification failed'
            );
        }

        // Store metadata for downstream use
        $request->setGlobal('get', array_merge(
            $request->getGet(),
            ['_ash_metadata' => $result->metadata]
        ));

        return $request;
    }

    /**
     * After filter - not used.
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        return $response;
    }

    /**
     * Create error response.
     */
    private function errorResponse(string $code, string $message): ResponseInterface
    {
        return service('response')
            ->setStatusCode(403)
            ->setJSON([
                'error' => $code,
                'message' => $message,
            ]);
    }

    /**
     * Get ASH instance.
     */
    public function getAsh(): Ash
    {
        return $this->ash;
    }
}
