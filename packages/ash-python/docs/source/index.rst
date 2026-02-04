ASH SDK for Python
==================

**ASH (Application Security Hash)** - RFC 8785 compliant request integrity
verification with server-signed seals, anti-replay protection, and zero client secrets.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   api/index
   security

Installation
------------

.. code-block:: bash

   pip install ash-sdk

Quick Example
-------------

.. code-block:: python

   from ash.core import (
       canonicalize_json,
       derive_client_secret,
       build_proof_v21,
       hash_body,
   )

   # Canonicalize payload
   canonical = canonicalize_json('{"z": 1, "a": 2}')
   # => '{"a":2,"z":1}'

   # Build proof (v2.1)
   client_secret = derive_client_secret(nonce, context_id, binding)
   body_hash = hash_body(canonical)
   proof = build_proof_v21(client_secret, timestamp, binding, body_hash)

Features
--------

* **RFC 8785 Compliant**: JSON Canonicalization Scheme (JCS)
* **HMAC-SHA256 Proofs**: Cryptographic request integrity
* **Anti-Replay Protection**: Single-use contexts with TTL
* **Secure Memory Utilities**: Auto-clearing sensitive data
* **Flask Integration**: Middleware for Flask applications
* **Redis Store**: Production-ready context storage

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
