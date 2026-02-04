# ASH SDK for PHP

[![Packagist](https://img.shields.io/packagist/v/3maem/ash-sdk-php.svg)](https://packagist.org/packages/3maem/ash-sdk-php)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.1-brightgreen)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-ASAL--1.0-blue)](../../LICENSE)
[![Version](https://img.shields.io/badge/version-2.3.4-blue)](../../CHANGELOG.md)

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package provides JCS canonicalization, proof generation, and middleware for Laravel, CodeIgniter, WordPress, and Drupal.

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

Canonicalizes JSON to deterministic form per RFC 8785 (JCS).

**Rules:**
- Object keys sorted lexicographically (UTF-16 code units)
- No whitespace
- Unicode NFC normalized
- Minimal JSON escaping (only \b, \t, \n, \f, \r, \", \\)
- Numbers normalized (no leading zeros, no trailing decimal zeros)

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

## Input Validation (v2.3.4)

All SDKs now implement consistent input validation in `Proof::ashDeriveClientSecret()`. Invalid inputs throw `ValidationException`.

### Validation Rules

| Parameter | Rule | Code |
|-----------|------|------|
| `$nonce` | Minimum 32 hex characters | SEC-014 |
| `$nonce` | Maximum 128 characters | SEC-NONCE-001 |
| `$nonce` | Hexadecimal only (0-9, a-f, A-F) | BUG-004 |
| `$contextId` | Cannot be empty | BUG-041 |
| `$contextId` | Maximum 256 characters | SEC-CTX-001 |
| `$contextId` | Alphanumeric, underscore, hyphen, dot only | SEC-CTX-001 |
| `$binding` | Maximum 8192 bytes | SEC-AUDIT-004 |

### Example

```php
use Ash\Core\Proof;
use Ash\Core\Exceptions\ValidationException;

try {
    $secret = Proof::ashDeriveClientSecret($nonce, $contextId, $binding);
} catch (ValidationException $e) {
    echo "Validation failed: " . $e->getMessage();
    echo "Error code: " . $e->getCode();  // ASH_VALIDATION_ERROR
}
```

### Validation Constants

```php
public const MIN_NONCE_HEX_CHARS = 32;    // Minimum nonce length
public const MAX_NONCE_LENGTH = 128;      // Maximum nonce length
public const MAX_CONTEXT_ID_LENGTH = 256; // Maximum context ID length
public const MAX_BINDING_LENGTH = 8192;   // Maximum binding length (8KB)
```

## Environment Configuration (v2.3.4)

The SDK supports environment-based configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `ASH_TRUST_PROXY` | `false` | Enable X-Forwarded-For handling |
| `ASH_TRUSTED_PROXIES` | (empty) | Comma-separated trusted proxy IPs |
| `ASH_RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds |
| `ASH_RATE_LIMIT_MAX` | `10` | Max contexts per window per IP |
| `ASH_TIMESTAMP_TOLERANCE` | `30` | Clock skew tolerance in seconds |

```php
// Load configuration from environment
$config = Ash::loadConfig();

// Get client IP with proxy support
$clientIp = Ash::getClientIp();
```

## IP and User Binding (v2.3.4)

All PHP middlewares support IP and user binding enforcement to prevent context theft:

### Laravel

```php
// Store client IP and user ID when creating context
$context = $ash->issueContext(
    binding: 'POST /api/transfer',
    ttlMs: 30000,
    metadata: ['ip' => $_SERVER['REMOTE_ADDR'], 'user_id' => Auth::id()]
);

// Verify in middleware
Route::post('/api/transfer', ...)->middleware('ash:enforce_ip,enforce_user');
```

### CodeIgniter

```php
// In Config/Filters.php
public $filters = [
    'before' => [
        'api/*' => ['ash' => ['enforce_ip', 'enforce_user']]
    ]
];
```

### WordPress

```php
$handler = new WordPressHandler([
    'enforce_ip' => true,
    'enforce_user' => true,
    'user_id_extractor' => function($request) {
        return get_current_user_id();
    }
]);
```

If the IP or user doesn't match, the middleware returns HTTP 461 (`ASH_BINDING_MISMATCH`).

## Error Codes (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

```php
enum AshErrorCode: string
{
    // Context errors (450-459)
    case CtxNotFound = 'ASH_CTX_NOT_FOUND';       // HTTP 450
    case CtxExpired = 'ASH_CTX_EXPIRED';          // HTTP 451
    case CtxAlreadyUsed = 'ASH_CTX_ALREADY_USED'; // HTTP 452

    // Seal/Proof errors (460-469)
    case ProofInvalid = 'ASH_PROOF_INVALID';      // HTTP 460

    // Binding/Verification errors (461, 473-479)
    case BindingMismatch = 'ASH_BINDING_MISMATCH'; // HTTP 461
    case ScopeMismatch = 'ASH_SCOPE_MISMATCH';     // HTTP 473
    case ChainBroken = 'ASH_CHAIN_BROKEN';         // HTTP 474

    // Format/Protocol errors (480-489)
    case TimestampInvalid = 'ASH_TIMESTAMP_INVALID'; // HTTP 482
    case ProofMissing = 'ASH_PROOF_MISSING';         // HTTP 483

    // Standard HTTP codes
    case CanonicalizationError = 'ASH_CANONICALIZATION_ERROR'; // HTTP 422
    case ModeViolation = 'ASH_MODE_VIOLATION';                 // HTTP 400
    case ValidationError = 'ASH_VALIDATION_ERROR';             // HTTP 400
    case UnsupportedContentType = 'ASH_UNSUPPORTED_CONTENT_TYPE'; // HTTP 415
}
```

| Code | HTTP | Description |
|------|------|-------------|
| `CtxNotFound` | 450 | Context not found |
| `CtxExpired` | 451 | Context expired |
| `CtxAlreadyUsed` | 452 | Replay detected |
| `ProofInvalid` | 460 | Proof invalid |
| `BindingMismatch` | 461 | IP/User binding mismatch |
| `ScopeMismatch` | 473 | Scope mismatch |
| `ChainBroken` | 474 | Chain broken |
| `TimestampInvalid` | 482 | Timestamp invalid |
| `ProofMissing` | 483 | Proof missing |

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
