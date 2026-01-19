<?php

declare(strict_types=1);

namespace Ash\Middleware;

use Ash\Ash;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * CodeIgniter 4 filter for ASH verification.
 *
 * Usage:
 *
 * 1. Register in app/Config/Filters.php:
 *    public $aliases = [
 *        'ash' => \Ash\Middleware\CodeIgniterFilter::class,
 *    ];
 *
 * 2. Apply to routes in app/Config/Routes.php:
 *    $routes->post('api/update', 'ApiController::update', ['filter' => 'ash']);
 */
final class CodeIgniterFilter implements FilterInterface
{
    private Ash $ash;

    public function __construct()
    {
        // In CodeIgniter, you'd typically get this from Services
        // For now, create a simple instance
        $store = new \Ash\Store\MemoryStore();
        $this->ash = new Ash($store);
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
            $request->getUri()->getPath()
        );

        // Get payload
        $payload = $request->getBody() ?? '';
        if (is_resource($payload)) {
            $payload = stream_get_contents($payload) ?: '';
        }
        $contentType = $request->getHeaderLine('Content-Type');

        // Verify
        $result = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            (string)$payload,
            $contentType
        );

        if (!$result->valid) {
            return $this->errorResponse(
                $result->errorCode?->value ?? 'VERIFICATION_FAILED',
                $result->errorMessage ?? 'Verification failed'
            );
        }

        // Store metadata for downstream use
        $request->setGlobal('ash_metadata', $result->metadata);

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
     * Create error response.
     *
     * @param string $code Error code
     * @param string $message Error message
     * @return ResponseInterface
     */
    private function errorResponse(string $code, string $message): ResponseInterface
    {
        $response = service('response');
        return $response
            ->setStatusCode(403)
            ->setJSON([
                'error' => $code,
                'message' => $message,
            ]);
    }
}
