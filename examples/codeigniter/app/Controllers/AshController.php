<?php

declare(strict_types=1);

namespace App\Controllers;

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\MemoryStore;
use CodeIgniter\RESTful\ResourceController;

/**
 * ASH CodeIgniter 4 Example Controller
 */
class AshController extends ResourceController
{
    protected $format = 'json';
    private Ash $ash;

    public function __construct()
    {
        $store = new MemoryStore();
        $this->ash = new Ash($store, AshMode::Balanced);
    }

    /**
     * Issue a context.
     *
     * GET /api/context
     */
    public function context()
    {
        $binding = $this->request->getGet('binding') ?? 'POST /api/update';
        $mode = $this->request->getGet('mode') ?? 'balanced';

        try {
            $context = $this->ash->ashIssueContext(
                binding: $binding,
                ttlMs: 30000,
                mode: AshMode::from($mode),
                metadata: [
                    'issuedAt' => date('c'),
                ],
            );

            return $this->respond([
                'contextId' => $context->id,
                'binding' => $context->binding,
                'expiresAt' => $context->expiresAt,
                'mode' => $context->mode->value,
                'nonce' => $context->nonce,
            ]);
        } catch (\Exception $e) {
            return $this->fail('Failed to create context', 500);
        }
    }

    /**
     * Protected update endpoint.
     *
     * POST /api/update (requires 'ash' filter)
     */
    public function update()
    {
        $metadata = $this->request->getGet('_ash_metadata') ?? [];

        return $this->respond([
            'success' => true,
            'message' => 'Update processed',
            'data' => $this->request->getJSON(true),
            'metadata' => $metadata,
        ]);
    }

    /**
     * Public endpoint.
     *
     * GET /api/public
     */
    public function public()
    {
        return $this->respond([
            'message' => 'This endpoint is not protected by ASH',
            'timestamp' => date('c'),
        ]);
    }

    /**
     * Health check.
     *
     * GET /api/health
     */
    public function health()
    {
        return $this->respond([
            'status' => 'healthy',
            'ash' => [
                'version' => $this->ash->ashVersion(),
                'libraryVersion' => $this->ash->ashLibraryVersion(),
            ],
        ]);
    }
}
