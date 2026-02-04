# ASH SDK for Python

[![PyPI](https://img.shields.io/pypi/v/ash-sdk.svg)](https://pypi.org/project/ash-sdk/)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-brightgreen)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-ASAL--1.0-blue)](../../LICENSE)
[![Version](https://img.shields.io/badge/version-2.3.4-blue)](../../CHANGELOG.md)

**Developed by 3maem Co. | شركة عمائم**

ASH (Application Security Hash) - RFC 8785 compliant request integrity verification with server-signed seals, anti-replay protection, and zero client secrets. This package provides JCS canonicalization, proof generation, and middleware for Flask, FastAPI, and Django.

## Installation

```bash
# Basic installation
pip install ash-sdk

# With Flask support
pip install ash-sdk[flask]

# With FastAPI support
pip install ash-sdk[fastapi]

# With Redis support
pip install ash-sdk[redis]

# All features
pip install ash-sdk[all]
```

**Requirements:** Python 3.10 or later

## Quick Start

### Canonicalize JSON

```python
from ash.canonicalize import ash_canonicalize_json

# Canonicalize JSON to deterministic form
canonical = ash_canonicalize_json('{"z":1,"a":2}')
print(canonical)  # {"a":2,"z":1}
```

### Build a Proof

```python
from ash.proof import ash_build_proof
from ash.canonicalize import ash_canonicalize_json
from ash.core import AshMode

# Canonicalize payload
payload = '{"username":"test","action":"login"}'
canonical = ash_canonicalize_json(payload)

# Build proof
proof = ash_build_proof(
    mode=AshMode.BALANCED,
    binding="POST /api/login",
    context_id="ctx_abc123",
    nonce=None,  # Optional: for server-assisted mode
    canonical_payload=canonical
)

print(f"Proof: {proof}")
```

### Verify a Proof

```python
from ash.compare import ash_timing_safe_equal

expected_proof = "abc123..."
received_proof = "abc123..."

# Use timing-safe comparison to prevent timing attacks
if ash_timing_safe_equal(expected_proof, received_proof):
    print("Proof verified successfully")
else:
    print("Proof verification failed")
```

## Flask Integration

```python
from flask import Flask, jsonify, request
from ash.stores import MemoryStore
from ash.server import context
from ash.middleware.flask import ash_flask_middleware
import asyncio

app = Flask(__name__)
store = MemoryStore()

# Issue context endpoint
@app.route("/ash/context", methods=["POST"])
def get_context():
    ctx = asyncio.run(context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    ))
    return jsonify({
        "contextId": ctx.context_id,
        "expiresAt": ctx.expires_at,
        "mode": ctx.mode.value,
    })

# Protected endpoint
@app.route("/api/update", methods=["POST"])
@ash_flask_middleware(store, expected_binding="POST /api/update")
def update():
    # Request verified - safe to process
    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run()
```

## FastAPI Integration

```python
from fastapi import FastAPI, Depends
from ash.stores import MemoryStore
from ash.server import context
from ash.middleware.fastapi import AshMiddleware, ash_verify

app = FastAPI()
store = MemoryStore()

# Add ASH middleware
app.add_middleware(AshMiddleware, store=store, protected_paths=["/api/*"])

# Issue context endpoint
@app.post("/ash/context")
async def get_context():
    ctx = await context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    )
    return {
        "contextId": ctx.context_id,
        "expiresAt": ctx.expires_at,
        "mode": ctx.mode.value,
    }

# Protected endpoint
@app.post("/api/update")
async def update():
    # Request verified by middleware
    return {"status": "success"}
```

## Django Integration

```python
# settings.py
MIDDLEWARE = [
    # ...
    'ash.middleware.django.AshMiddleware',
]

ASH_SETTINGS = {
    'STORE': 'ash.stores.RedisStore',
    'REDIS_URL': 'redis://localhost:6379/0',
    'PROTECTED_PATHS': ['/api/*'],
}

# views.py
from django.http import JsonResponse
from ash.server import context

async def get_context(request):
    ctx = await context.create(
        request.ash_store,
        binding="POST /api/update",
        ttl_ms=30000,
    )
    return JsonResponse({
        "contextId": ctx.context_id,
        "expiresAt": ctx.expires_at,
        "mode": ctx.mode.value,
    })
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

```python
from ash import AshConfig, ash_get_client_ip

# Load configuration from environment
config = AshConfig()

# Get client IP with proxy support (Flask example)
client_ip = ash_get_client_ip(request)
```

## IP and User Binding (v2.3.4)

Enforce that the client IP address and/or authenticated user matches the values stored in the context metadata:

### Flask

```python
from ash.middleware.flask import ash_flask_middleware

# Store client IP and user ID when creating context
@app.route("/ash/context", methods=["POST"])
def get_context():
    ctx = asyncio.run(context.create(
        store,
        binding="POST /api/transfer",
        ttl_ms=30000,
        metadata={"ip": request.remote_addr, "user_id": current_user.id}
    ))
    return jsonify({"contextId": ctx.context_id})

# Verify IP and user binding in middleware
@app.route("/api/transfer", methods=["POST"])
@ash_flask_middleware(
    store,
    expected_binding="POST /api/transfer",
    enforce_ip=True,
    enforce_user=True
)
def transfer():
    return jsonify({"status": "success"})
```

### FastAPI

```python
from ash.middleware.fastapi import AshMiddleware

# Add ASH middleware with binding enforcement
app.add_middleware(
    AshMiddleware,
    store=store,
    protected_paths=["/api/*"],
    enforce_ip=True,
    enforce_user=True,
    user_id_extractor=lambda req: req.state.user.get("id")
)
```

If the IP or user doesn't match, the middleware returns HTTP 461 (`ASH_BINDING_MISMATCH`).

## API Reference

### Canonicalization

#### `ash_canonicalize_json(input_json: str) -> str`

Canonicalizes JSON to deterministic form per RFC 8785 (JCS).

**Rules:**
- Object keys sorted lexicographically (UTF-16 code units)
- No whitespace
- Unicode NFC normalized
- Minimal JSON escaping (only \b, \t, \n, \f, \r, \", \\)
- Numbers normalized (no leading zeros, no trailing decimal zeros)

```python
from ash.canonicalize import ash_canonicalize_json

canonical = ash_canonicalize_json('{"z":1,"a":2}')
# Result: '{"a":2,"z":1}'
```

#### `ash_canonicalize_urlencoded(input_data: str) -> str`

Canonicalizes URL-encoded data.

```python
from ash.canonicalize import ash_canonicalize_urlencoded

canonical = ash_canonicalize_urlencoded('z=1&a=2')
# Result: 'a=2&z=1'
```

### Proof Generation

#### `ash_build_proof(mode, binding, context_id, nonce, canonical_payload) -> str`

Builds a cryptographic proof.

```python
from ash.proof import ash_build_proof
from ash.core import AshMode

proof = ash_build_proof(
    mode=AshMode.BALANCED,
    binding="POST /api/update",
    context_id="ctx_abc123",
    nonce=None,  # Optional
    canonical_payload='{"name":"John"}'
)
```

#### `ash_verify_proof(expected: str, actual: str) -> bool`

Verifies two proofs match using constant-time comparison.

```python
from ash.proof import ash_verify_proof

is_valid = ash_verify_proof(expected_proof, received_proof)
```

### Binding Normalization

#### `ash_normalize_binding(method: str, path: str) -> str`

Normalizes a binding string to canonical form.

**Rules:**
- Method uppercased
- Path starts with /
- Query string excluded
- Duplicate slashes collapsed
- Trailing slash removed (except for root)

```python
from ash.binding import ash_normalize_binding

binding = ash_normalize_binding("post", "/api//test/")
# Result: 'POST /api/test'
```

### Secure Comparison

#### `ash_timing_safe_equal(a: str | bytes, b: str | bytes) -> bool`

Performs constant-time comparison to prevent timing attacks.

```python
from ash.compare import ash_timing_safe_equal

is_equal = ash_timing_safe_equal("secret1", "secret2")
```

## Security Modes

```python
from ash.core import AshMode

class AshMode(Enum):
    MINIMAL = "minimal"    # Basic integrity checking
    BALANCED = "balanced"  # Recommended for most applications
    STRICT = "strict"      # Maximum security with nonce requirement
```

| Mode | Description |
|------|-------------|
| `MINIMAL` | Basic integrity checking |
| `BALANCED` | Recommended for most applications |
| `STRICT` | Maximum security with server nonce |

## Context Stores

### MemoryStore

In-memory store for development and testing.

```python
from ash.stores import MemoryStore

store = MemoryStore()
```

### RedisStore

Production-ready store with atomic operations.

```python
import redis
from ash.stores import RedisStore

redis_client = redis.Redis(host='localhost', port=6379, db=0)
store = RedisStore(redis_client)
```

## Client Usage

For Python clients making requests to ASH-protected endpoints:

```python
import requests
from ash.canonicalize import ash_canonicalize_json
from ash.proof import ash_build_proof
from ash.core import AshMode
import json

# 1. Get context from server
ctx_response = requests.post("https://api.example.com/ash/context").json()

# 2. Prepare payload
payload = {"name": "John", "action": "update"}
payload_json = json.dumps(payload)
canonical = ash_canonicalize_json(payload_json)

# 3. Build proof
proof = ash_build_proof(
    mode=AshMode(ctx_response["mode"]),
    binding="POST /api/update",
    context_id=ctx_response["contextId"],
    nonce=ctx_response.get("nonce"),
    canonical_payload=canonical
)

# 4. Make protected request
response = requests.post(
    "https://api.example.com/api/update",
    json=payload,
    headers={
        "X-ASH-Context-ID": ctx_response["contextId"],
        "X-ASH-Proof": proof,
    }
)
```

### Using the Client Helper

```python
from ash.client import AshClient
import requests

client = AshClient()

# Get context from server
ctx_response = requests.post("https://api.example.com/ash/context").json()

# Build proof headers automatically
headers = client.build_headers(
    context_id=ctx_response["contextId"],
    mode=ctx_response["mode"],
    binding="POST /api/update",
    payload={"name": "John"},
    nonce=ctx_response.get("nonce"),
)

# Make protected request
response = requests.post(
    "https://api.example.com/api/update",
    json={"name": "John"},
    headers=headers,
)
```

## Complete Server Example

```python
from flask import Flask, jsonify, request
from ash.stores import RedisStore
from ash.server import context, verify
from ash.canonicalize import ash_canonicalize_json
from ash.proof import ash_build_proof
from ash.core import AshMode
import redis
import asyncio

app = Flask(__name__)

# Production Redis store
redis_client = redis.Redis(host='localhost', port=6379, db=0)
store = RedisStore(redis_client)

@app.route("/ash/context", methods=["POST"])
def issue_context():
    """Issue a new ASH context."""
    binding = request.json.get("binding", "POST /api/update")

    ctx = asyncio.run(context.create(
        store,
        binding=binding,
        ttl_ms=30000,
        mode=AshMode.BALANCED,
    ))

    return jsonify({
        "contextId": ctx.context_id,
        "expiresAt": ctx.expires_at,
        "mode": ctx.mode.value,
    })

@app.route("/api/update", methods=["POST"])
def update():
    """Protected endpoint with manual verification."""
    context_id = request.headers.get("X-ASH-Context-ID")
    proof = request.headers.get("X-ASH-Proof")

    if not context_id or not proof:
        return jsonify({"error": "Missing ASH headers"}), 403

    # Verify the request
    result = asyncio.run(verify.verify_request(
        store=store,
        context_id=context_id,
        proof=proof,
        binding="POST /api/update",
        payload=request.get_data(as_text=True),
        content_type=request.content_type,
    ))

    if not result.valid:
        return jsonify({
            "error": result.error_code.value,
            "message": result.error_message,
        }), 403

    # Request verified - safe to process
    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run(debug=True)
```

## Input Validation (v2.3.4)

All SDKs now implement consistent input validation in `ash_derive_client_secret`. Invalid inputs raise `ValidationError`.

### Validation Rules

| Parameter | Rule | Code |
|-----------|------|------|
| `nonce` | Minimum 32 hex characters | SEC-014 |
| `nonce` | Maximum 128 characters | SEC-NONCE-001 |
| `nonce` | Hexadecimal only (0-9, a-f, A-F) | BUG-004 |
| `context_id` | Cannot be empty | BUG-041 |
| `context_id` | Maximum 256 characters | SEC-CTX-001 |
| `context_id` | Alphanumeric, underscore, hyphen, dot only | SEC-CTX-001 |
| `binding` | Maximum 8192 bytes | SEC-AUDIT-004 |

### Example

```python
from ash.core.proof import ash_derive_client_secret
from ash.core.errors import ValidationError

try:
    secret = ash_derive_client_secret(nonce, context_id, binding)
except ValidationError as e:
    print(f"Validation failed: {e.message}")
    print(f"Error code: {e.code}")  # ASH_VALIDATION_ERROR
```

### Validation Constants

```python
MIN_NONCE_HEX_CHARS = 32    # Minimum nonce length
MAX_NONCE_LENGTH = 128      # Maximum nonce length
MAX_CONTEXT_ID_LENGTH = 256 # Maximum context ID length
MAX_BINDING_LENGTH = 8192   # Maximum binding length (8KB)
```

## Error Handling (v2.3.4 - Unique HTTP Status Codes)

ASH uses unique HTTP status codes in the 450-499 range for precise error identification.

```python
# Error classes with unique HTTP status codes
from ash.core.errors import (
    InvalidContextError,      # HTTP 450 - Context not found
    ContextExpiredError,      # HTTP 451 - Context expired
    ReplayDetectedError,      # HTTP 452 - Replay detected
    IntegrityFailedError,     # HTTP 460 - Proof invalid
    BindingMismatchError,     # HTTP 461 - IP/User binding mismatch
    ScopeMismatchError,       # HTTP 473 - Scope mismatch
    ChainBrokenError,         # HTTP 474 - Chain broken
    TimestampInvalidError,    # HTTP 482 - Timestamp invalid
    ProofMissingError,        # HTTP 483 - Proof missing
    CanonicalizationError,    # HTTP 422 - Canonicalization failed
    ValidationError,          # HTTP 400 - Validation failed
    UnsupportedContentTypeError,  # HTTP 415 - Content type not supported
)
```

| Exception | HTTP | Description |
|-----------|------|-------------|
| `InvalidContextError` | 450 | Context not found |
| `ContextExpiredError` | 451 | Context expired |
| `ReplayDetectedError` | 452 | Replay detected |
| `IntegrityFailedError` | 460 | Proof invalid |
| `BindingMismatchError` | 461 | IP/User binding mismatch |
| `ScopeMismatchError` | 473 | Scope mismatch |
| `ChainBrokenError` | 474 | Chain broken |
| `TimestampInvalidError` | 482 | Timestamp invalid |
| `ProofMissingError` | 483 | Proof missing |
| `CanonicalizationError` | 422 | Canonicalization failed |
| `ValidationError` | 400 | Validation failed |

## Type Hints

The SDK is fully typed for IDE support:

```python
from ash.core import AshMode, AshContext, AshVerifyResult

def process_context(ctx: AshContext) -> None:
    print(f"Context ID: {ctx.context_id}")
    print(f"Expires at: {ctx.expires_at}")
    print(f"Mode: {ctx.mode}")
```

## License

**ASH Source-Available License (ASAL-1.0)**

See the [LICENSE](https://github.com/3maem/ash/blob/main/LICENSE) for full terms.

## Links

- [Main Repository](https://github.com/3maem/ash)
- [PyPI Package](https://pypi.org/project/ash-sdk/)
