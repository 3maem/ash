# ASH SDK for PHP

**Developed by 3maem Co. | شركة عمائم**

ASH SDK provides request integrity and anti-replay protection for web applications. This package offers request integrity protection, anti-replay mechanisms, and middleware for Laravel, CodeIgniter, WordPress, and Drupal.

## Installation

```bash
composer require 3maem/ash-sdk-php
```

**Requirements:**
- PHP 8.1 or later
- Extensions: `hash`, `intl`, `json`, `mbstring`

## Quick Start

### Canonicalize JSON

```php
<?php

use Ash\Canonicalize\JsonCanonicalizer;

// Canonicalize JSON to deterministic form
$canonical = JsonCanonicalizer::canonicalize('{"z":1,"a":2}');
echo $canonical; // {"a":2,"z":1}
```

### Build a Proof

```php
<?php

use Ash\AshMode;
use Ash\Proof\ProofBuilder;
use Ash\Canonicalize\JsonCanonicalizer;

// Canonicalize payload
$payload = '{"username":"test","action":"login"}';
$canonical = JsonCanonicalizer::canonicalize($payload);

// Build proof
$proof = ProofBuilder::build(
    mode: AshMode::Balanced,
    binding: 'POST /api/login',
    contextId: 'ctx_abc123',
    nonce: null,  // Optional: for server-assisted mode
    canonicalPayload: $canonical
);

echo "Proof: $proof";
```

### Verify a Proof

```php
<?php

use Ash\Ash;

$expectedProof = 'abc123...';
$receivedProof = 'abc123...';

// Use timing-safe comparison to prevent timing attacks
if (Ash::timingSafeEqual($expectedProof, $receivedProof)) {
    echo "Proof verified successfully";
} else {
    echo "Proof verification failed";
}
```

## Laravel Integration

### Register Middleware

In `app/Http/Kernel.php`:

```php
protected $routeMiddleware = [
    // ...
    'ash' => \Ash\Middleware\LaravelMiddleware::class,
];
```

### Service Provider Setup

```php
<?php

namespace App\Providers;

use Ash\Ash;
use Ash\Store\RedisStore;
use Illuminate\Support\ServiceProvider;

class AshServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Ash::class, function ($app) {
            $store = new RedisStore($app['redis']->connection());
            return new Ash($store);
        });
    }
}
```

### Use in Routes

```php
use Illuminate\Support\Facades\Route;

// Issue context endpoint
Route::post('/ash/context', function (Ash $ash) {
    $context = $ash->issueContext(
        binding: 'POST /api/update',
        ttlMs: 30000
    );

    return response()->json([
        'contextId' => $context->id,
        'expiresAt' => $context->expiresAt,
        'mode' => $context->mode->value,
    ]);
});

// Protected endpoint
Route::post('/api/update', function () {
    // Request verified by middleware
    return response()->json(['status' => 'success']);
})->middleware('ash');
```

## CodeIgniter Integration

### Register Filter

In `app/Config/Filters.php`:

```php
public $aliases = [
    'ash' => \Ash\Middleware\CodeIgniterFilter::class,
];
```

### Use in Routes

```php
$routes->post('api/update', 'ApiController::update', ['filter' => 'ash']);
```

## WordPress Integration

### Add to Plugin or Theme

```php
<?php

use Ash\Middleware\WordPressHandler;

// Initialize ASH handler
$ash_handler = new WordPressHandler();

// Hook into REST API
add_filter('rest_pre_dispatch', function ($result, $server, $request) use ($ash_handler) {
    // Check if route should be protected
    $route = $request->get_route();

    if (str_starts_with($route, '/myapi/v1/')) {
        $verification = $ash_handler->verify($request);

        if (!$verification->valid) {
            return new WP_Error(
                'ash_verification_failed',
                $verification->errorMessage,
                ['status' => 403]
            );
        }
    }

    return $result;
}, 10, 3);
```

## Drupal Integration

### Add as Middleware

```php
<?php

namespace Drupal\my_module;

use Ash\Middleware\DrupalMiddleware;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class AshMiddleware implements HttpKernelInterface
{
    protected HttpKernelInterface $app;
    protected DrupalMiddleware $ash;

    public function __construct(HttpKernelInterface $app)
    {
        $this->app = $app;
        $this->ash = new DrupalMiddleware();
    }

    public function handle(Request $request, int $type = self::MASTER_REQUEST, bool $catch = true)
    {
        if ($this->shouldVerify($request)) {
            $result = $this->ash->verify($request);
            if (!$result->valid) {
                return new JsonResponse([
                    'error' => $result->errorCode->value,
                    'message' => $result->errorMessage,
                ], 403);
            }
        }

        return $this->app->handle($request, $type, $catch);
    }
}
```

## API Reference

### JsonCanonicalizer

#### `canonicalize(string $json): string`

Canonicalizes JSON to deterministic form.

**Rules:**
- Object keys sorted lexicographically
- No whitespace
- Unicode NFC normalized

```php
use Ash\Canonicalize\JsonCanonicalizer;

$canonical = JsonCanonicalizer::canonicalize('{"z":1,"a":2}');
// Result: {"a":2,"z":1}
```

### UrlencodedCanonicalizer

#### `canonicalize(string $data): string`

Canonicalizes URL-encoded data.

```php
use Ash\Canonicalize\UrlencodedCanonicalizer;

$canonical = UrlencodedCanonicalizer::canonicalize('z=1&a=2');
// Result: a=2&z=1
```

### ProofBuilder

#### `build(AshMode $mode, string $binding, string $contextId, ?string $nonce, string $canonicalPayload): string`

Builds a cryptographic proof.

```php
use Ash\AshMode;
use Ash\Proof\ProofBuilder;

$proof = ProofBuilder::build(
    mode: AshMode::Balanced,
    binding: 'POST /api/update',
    contextId: 'ctx_abc123',
    nonce: null,
    canonicalPayload: '{"name":"John"}'
);
```

### Ash Class

Main service class for ASH operations.

```php
use Ash\Ash;
use Ash\Store\MemoryStore;

$store = new MemoryStore();
$ash = new Ash($store);

// Issue context
$context = $ash->issueContext(
    binding: 'POST /api/update',
    ttlMs: 30000,
    mode: AshMode::Balanced
);

// Verify request
$result = $ash->verify(
    contextId: $contextId,
    proof: $proof,
    binding: 'POST /api/update',
    payload: $payload,
    contentType: 'application/json'
);

if ($result->valid) {
    // Process request
}
```

## Security Modes

```php
enum AshMode: string
{
    case Minimal = 'minimal';   // Basic integrity checking
    case Balanced = 'balanced'; // Recommended for most applications
    case Strict = 'strict';     // Maximum security with nonce requirement
}
```

| Mode | Description |
|------|-------------|
| `Minimal` | Basic integrity checking |
| `Balanced` | Recommended for most applications |
| `Strict` | Maximum security with server nonce |

## Error Codes

```php
enum AshErrorCode: string
{
    case InvalidContext = 'ASH_INVALID_CONTEXT';
    case ContextExpired = 'ASH_CONTEXT_EXPIRED';
    case ReplayDetected = 'ASH_REPLAY_DETECTED';
    case IntegrityFailed = 'ASH_INTEGRITY_FAILED';
    case EndpointMismatch = 'ASH_ENDPOINT_MISMATCH';
    case CanonicalizationFailed = 'ASH_CANONICALIZATION_FAILED';
}
```

## Context Stores

### ContextStoreInterface

```php
interface ContextStoreInterface
{
    public function create(
        string $binding,
        int $ttlMs,
        AshMode $mode,
        ?array $metadata = null
    ): AshContext;

    public function get(string $id): ?AshContext;
    public function consume(string $id): bool;
    public function cleanup(): int;
}
```

### MemoryStore

In-memory store for development and testing.

```php
use Ash\Store\MemoryStore;

$store = new MemoryStore();
```

### RedisStore

Production-ready store with atomic operations.

```php
use Ash\Store\RedisStore;
use Redis;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$store = new RedisStore($redis);
```

## Complete Example

```php
<?php

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\RedisStore;
use Ash\Canonicalize\JsonCanonicalizer;
use Ash\Proof\ProofBuilder;

// Server Setup
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$store = new RedisStore($redis);
$ash = new Ash($store);

// Issue Context Endpoint
if ($_SERVER['REQUEST_URI'] === '/ash/context' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $context = $ash->issueContext(
        binding: 'POST /api/update',
        ttlMs: 30000
    );

    header('Content-Type: application/json');
    echo json_encode([
        'contextId' => $context->id,
        'expiresAt' => $context->expiresAt,
        'mode' => $context->mode->value,
    ]);
    exit;
}

// Protected Endpoint
if ($_SERVER['REQUEST_URI'] === '/api/update' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $contextId = $_SERVER['HTTP_X_ASH_CONTEXT_ID'] ?? null;
    $proof = $_SERVER['HTTP_X_ASH_PROOF'] ?? null;

    if (!$contextId || !$proof) {
        http_response_code(403);
        echo json_encode(['error' => 'Missing ASH headers']);
        exit;
    }

    $payload = file_get_contents('php://input');
    $binding = 'POST /api/update';

    $result = $ash->verify($contextId, $proof, $binding, $payload, 'application/json');

    if (!$result->valid) {
        http_response_code(403);
        echo json_encode([
            'error' => $result->errorCode->value,
            'message' => $result->errorMessage,
        ]);
        exit;
    }

    // Request verified - process safely
    header('Content-Type: application/json');
    echo json_encode(['status' => 'success']);
}
```

## Client Usage

For PHP clients making requests to ASH-protected endpoints:

```php
<?php

use Ash\AshMode;
use Ash\Proof\ProofBuilder;
use Ash\Canonicalize\JsonCanonicalizer;

// 1. Get context from server
$contextResponse = json_decode(file_get_contents('https://api.example.com/ash/context', false, stream_context_create([
    'http' => ['method' => 'POST']
])));

// 2. Prepare payload
$payload = ['name' => 'John', 'action' => 'update'];
$payloadJson = json_encode($payload);
$canonical = JsonCanonicalizer::canonicalize($payloadJson);

// 3. Build proof
$proof = ProofBuilder::build(
    mode: AshMode::from($contextResponse->mode),
    binding: 'POST /api/update',
    contextId: $contextResponse->contextId,
    nonce: $contextResponse->nonce ?? null,
    canonicalPayload: $canonical
);

// 4. Make protected request
$context = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => implode("\r\n", [
            'Content-Type: application/json',
            'X-ASH-Context-ID: ' . $contextResponse->contextId,
            'X-ASH-Proof: ' . $proof,
        ]),
        'content' => $payloadJson,
    ]
]);

$response = file_get_contents('https://api.example.com/api/update', false, $context);
```

## License

**ASH Source-Available License (ASAL-1.0)**

See the [LICENSE](https://github.com/3maem/ash/blob/main/LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
- [Packagist](https://packagist.org/packages/3maem/ash-sdk-php)
