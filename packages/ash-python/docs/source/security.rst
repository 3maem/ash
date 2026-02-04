Security Best Practices
=======================

This guide covers security best practices when using the ASH SDK.

Secure Memory Handling
----------------------

For high-security environments, use secure memory utilities to prevent
secrets from lingering in memory:

.. code-block:: python

   from ash.core import SecureString, SecureBytes, secure_derive_client_secret

   # Using context manager (recommended)
   with secure_derive_client_secret(nonce, context_id, binding) as secret:
       proof = build_proof_v21(secret.get(), timestamp, binding, body_hash)
   # Memory automatically zeroed

   # Manual management
   secret = SecureString("sensitive_value")
   try:
       # Use secret.get() to access the value
       result = some_function(secret.get())
   finally:
       secret.clear()  # Explicitly clear memory

Context TTL Configuration
-------------------------

Use short TTLs to minimize the replay window:

.. code-block:: python

   # Recommended: 30 seconds or less
   ctx = store.create(
       binding=binding,
       ttl_ms=30000,  # 30 seconds
       mode='balanced'
   )

   # For high-value transactions: even shorter
   ctx = store.create(
       binding=binding,
       ttl_ms=10000,  # 10 seconds
       mode='strict'
   )

   # Never exceed 5 minutes
   # ttl_ms=300000 is the absolute maximum

Store Security
--------------

Memory Store (Development Only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from ash.stores.memory import MemoryStore

   # Only for development/testing
   store = MemoryStore()

   # WARNING: No persistence, no shared state across processes

Redis Store (Production)
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from ash.stores.redis import RedisStore
   import redis

   # Use TLS for production
   client = redis.Redis(
       host='redis.example.com',
       port=6379,
       ssl=True,
       ssl_cert_reqs='required',
       ssl_ca_certs='/path/to/ca.crt',
       password='your_password',
   )

   store = RedisStore(client)

Binding Validation
------------------

Always validate bindings match the expected endpoint:

.. code-block:: python

   from ash.core import normalize_binding

   # Server-side validation
   expected_binding = normalize_binding("POST", "/api/transfer", "")
   if context.binding != expected_binding:
       raise ValueError("Binding mismatch - possible cross-endpoint attack")

Timing Attack Prevention
------------------------

Always use constant-time comparison for security-sensitive values:

.. code-block:: python

   from ash.core import timing_safe_equal

   # CORRECT: Constant-time comparison
   if timing_safe_equal(expected_proof, client_proof):
       # Valid
       pass

   # WRONG: Variable-time comparison
   # if expected_proof == client_proof:  # DON'T DO THIS
   #     pass

Error Handling
--------------

Never expose internal error details to clients:

.. code-block:: python

   from ash.errors import (
       AshError,
       ASH_CTX_NOT_FOUND,
       ASH_CTX_EXPIRED,
       ASH_PROOF_INVALID,
   )

   try:
       verify_request(request)
   except AshError as e:
       # Log detailed error server-side
       logger.error(f"ASH verification failed: {e.code} - {e.message}")

       # Return generic error to client
       return jsonify({'error': 'Request verification failed'}), 403

Clock Drift
-----------

Allow some tolerance for clock drift between client and server:

.. code-block:: python

   import time

   MAX_CLOCK_DRIFT_MS = 5000  # 5 seconds

   client_timestamp = int(request.headers.get('X-ASH-Timestamp'))
   server_timestamp = int(time.time() * 1000)

   if abs(server_timestamp - client_timestamp) > MAX_CLOCK_DRIFT_MS:
       raise ValueError("Timestamp outside acceptable range")

Security Boundaries
-------------------

Remember what ASH does and does not protect:

**ASH Protects:**

* Request integrity (payload not modified)
* Replay prevention (request used only once)
* Context binding (request for intended endpoint)

**ASH Does NOT Protect:**

* User authentication (who is making the request)
* Authorization (whether user has permission)
* Transport security (use HTTPS)
* Input validation (sanitize all inputs)

Always use ASH alongside other security controls in a defense-in-depth architecture.
