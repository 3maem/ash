# ASH Protocol for Python

**Authenticity & Stateless Hardening Protocol** - Tamper-proof, replay-resistant API requests.

```
pip install ash-protocol[flask]
```

## Quick Start

```python
from flask import Flask, jsonify
import ash
import asyncio

app = Flask(__name__)
store = ash.stores.Memory()

# Issue context endpoint
@app.route("/ash/context", methods=["POST"])
def get_context():
    ctx = asyncio.run(ash.context.create(
        store,
        binding="POST /api/update",
        ttl_ms=30000,
    ))
    return jsonify({
        "contextId": ctx.context_id,
        "expiresAt": ctx.expires_at,
        "mode": ctx.mode,
    })

# Protected endpoint
@app.route("/api/update", methods=["POST"])
@ash.middleware.flask(store, expected_binding="POST /api/update")
def update():
    # Request verified - safe to process
    return jsonify({"status": "ok"})
```

## Features

- **Tamper Detection** - Cryptographic proof ensures payload integrity
- **Replay Prevention** - One-time contexts prevent request replay
- **Flask Integration** - Simple decorator-based middleware
- **Redis Support** - Production-ready with atomic operations

## Installation

```bash
# Basic
pip install ash-protocol

# With Flask support
pip install ash-protocol[flask]

# With Redis support
pip install ash-protocol[redis]

# All features
pip install ash-protocol[all]
```

## Production Setup with Redis

```python
import redis
import ash

redis_client = redis.Redis(host='localhost', port=6379, db=0)
store = ash.stores.Redis(redis_client)
```

## Client Usage

Generate ASH proofs from Python applications:

```python
from ash.client import AshClient
import requests

client = AshClient()

# Get context from server
ctx_response = requests.post("http://api.example.com/ash/context").json()

# Build proof headers
headers = client.build_headers(
    context_id=ctx_response["contextId"],
    mode=ctx_response["mode"],
    binding="POST /api/update",
    payload={"name": "John"},
)

# Make protected request
response = requests.post(
    "http://api.example.com/api/update",
    json={"name": "John"},
    headers=headers,
)
```

## ASH Protocol Availability

| Language | Package | Status |
|----------|---------|--------|
| JavaScript/TypeScript | `@3maem/ash-server`, `@3maem/ash-client-web` | ✅ Available |
| Python | `ash-protocol` | ✅ Available |
| Go | `github.com/3maem/ash-go` | 🔜 Coming soon |
| PHP | `3maem/ash-php` | 🔜 Coming soon |
| Java/Kotlin | `com.3maem:ash-java` | 🔜 Planned |
| C#/.NET | `3maem.Ash` | 🔜 Planned |
| Rust | `ash-protocol` | 🔜 Planned |

## License

Proprietary - 3maem
