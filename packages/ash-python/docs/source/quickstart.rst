Quick Start Guide
=================

This guide covers the basic usage of the ASH SDK for Python.

Installation
------------

Install from PyPI:

.. code-block:: bash

   pip install ash-sdk

   # With Flask support
   pip install ash-sdk[flask]

   # With Redis support
   pip install ash-sdk[redis]

   # All optional dependencies
   pip install ash-sdk[all]

Basic Usage
-----------

JSON Canonicalization
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from ash.core import canonicalize_json

   # Sort keys and remove whitespace
   canonical = canonicalize_json('{"z": 1, "a": 2}')
   assert canonical == '{"a":2,"z":1}'

   # Handles nested objects
   canonical = canonicalize_json('{"b": {"z": 1, "a": 2}, "a": 1}')
   assert canonical == '{"a":1,"b":{"a":2,"z":1}}'

Proof Generation (v2.1)
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from ash.core import (
       derive_client_secret,
       build_proof_v21,
       hash_body,
       normalize_binding,
   )

   # Server provides these values
   nonce = "server_nonce_value"
   context_id = "ash_abc123"

   # Normalize the binding
   binding = normalize_binding("POST", "/api/transfer", "")
   # => "POST|/api/transfer|"

   # Derive client secret
   client_secret = derive_client_secret(nonce, context_id, binding)

   # Hash the request body
   body_hash = hash_body('{"amount":100}')

   # Build the proof
   timestamp = str(int(time.time() * 1000))
   proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

Proof Verification (v2.1)
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from ash.core import verify_proof_v21

   is_valid = verify_proof_v21(
       nonce=nonce,
       context_id=context_id,
       binding=binding,
       timestamp=timestamp,
       body_hash=body_hash,
       client_proof=client_proof,
   )

   if not is_valid:
       raise ValueError("Invalid proof")

Secure Memory Handling
~~~~~~~~~~~~~~~~~~~~~~

For high-security environments:

.. code-block:: python

   from ash.core import SecureString, secure_derive_client_secret

   # Context manager ensures cleanup
   with secure_derive_client_secret(nonce, context_id, binding) as secret:
       proof = build_proof_v21(secret.get(), timestamp, binding, body_hash)
   # Memory automatically cleared here

Flask Integration
-----------------

Server Setup
~~~~~~~~~~~~

.. code-block:: python

   from flask import Flask, request, jsonify
   from ash.middleware.flask import ash_middleware
   from ash.stores.memory import MemoryStore

   app = Flask(__name__)
   store = MemoryStore()

   # Context issuance endpoint
   @app.route('/ash/context', methods=['POST'])
   def create_context():
       data = request.get_json()
       ctx = store.create(
           binding=data['binding'],
           ttl_ms=30000,
           mode='balanced'
       )
       return jsonify({
           'contextId': ctx.id,
           'clientSecret': ctx.client_secret,
       })

   # Protected endpoint
   @app.route('/api/transfer', methods=['POST'])
   @ash_middleware(store=store, expected_binding='POST|/api/transfer|')
   def transfer():
       # Request verified - safe to process
       data = request.get_json()
       return jsonify({'success': True})

Client Usage
~~~~~~~~~~~~

.. code-block:: python

   import requests
   from ash.core import (
       canonicalize_json,
       build_proof_v21,
       hash_body,
   )
   import time
   import json

   # 1. Get context
   ctx_response = requests.post('http://localhost:5000/ash/context', json={
       'binding': 'POST|/api/transfer|'
   })
   ctx = ctx_response.json()

   # 2. Prepare request
   payload = {'amount': 100, 'to': 'account123'}
   canonical = canonicalize_json(json.dumps(payload))
   body_hash = hash_body(canonical)
   timestamp = str(int(time.time() * 1000))

   # 3. Build proof
   proof = build_proof_v21(
       ctx['clientSecret'],
       timestamp,
       'POST|/api/transfer|',
       body_hash
   )

   # 4. Send protected request
   response = requests.post(
       'http://localhost:5000/api/transfer',
       headers={
           'Content-Type': 'application/json',
           'X-ASH-Context-ID': ctx['contextId'],
           'X-ASH-Proof': proof,
           'X-ASH-Timestamp': timestamp,
       },
       json=payload
   )

Next Steps
----------

* See :doc:`api/index` for complete API reference
* See :doc:`security` for security best practices
