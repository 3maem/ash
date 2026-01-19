# ASH SDK for Python

**Developed by 3maem Co. | شركة عمائم**

ASH SDK provides request integrity and anti-replay protection for web applications. This SDK provides request integrity protection, anti-replay mechanisms, and middleware for Flask, FastAPI, and Django.

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

## API Reference

### Canonicalization

#### `ash_canonicalize_json(input_json: str) -> str`

Canonicalizes JSON to deterministic form.

**Rules:**
- Object keys sorted lexicographically
- No whitespace
- Unicode NFC normalized

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

## Error Handling

```python
from ash.core import AshErrorCode

class AshErrorCode(Enum):
    INVALID_CONTEXT = "ASH_INVALID_CONTEXT"
    CONTEXT_EXPIRED = "ASH_CONTEXT_EXPIRED"
    REPLAY_DETECTED = "ASH_REPLAY_DETECTED"
    INTEGRITY_FAILED = "ASH_INTEGRITY_FAILED"
    ENDPOINT_MISMATCH = "ASH_ENDPOINT_MISMATCH"
    CANONICALIZATION_FAILED = "ASH_CANONICALIZATION_FAILED"
```

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

Proprietary - All Rights Reserved

## Links

- [Main Repository](https://github.com/3maem/ash)
- [PyPI Package](https://pypi.org/project/ash-sdk/)
