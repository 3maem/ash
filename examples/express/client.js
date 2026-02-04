/**
 * ASH Integration Example: Express.js Client
 *
 * This example demonstrates how to make ASH-protected requests
 * from a client application.
 */

const {
  ashCanonicalizeJson,
  ashBuildProofV21,
  ashDeriveClientSecret,
  ashHashBody,
  ashNormalizeBinding,
} = require('@3maem/ash-node');

const API_BASE = process.env.API_BASE || 'http://localhost:3000';

/**
 * Make an ASH-protected API request
 */
async function makeProtectedRequest(endpoint, payload) {
  // Step 1: Request a context from the server
  const contextResponse = await fetch(`${API_BASE}/api/context`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ endpoint, ttlMs: 30000 }),
  });

  if (!contextResponse.ok) {
    throw new Error('Failed to get ASH context');
  }

  const context = await contextResponse.json();
  console.log('Got context:', context.contextId);

  // Step 2: Prepare the request
  const binding = ashNormalizeBinding('POST', endpoint, '');
  const canonicalPayload = ashCanonicalizeJson(payload);
  const bodyHash = ashHashBody(canonicalPayload);
  const timestamp = Date.now().toString();

  // Step 3: Build the proof
  // Note: In server-assisted mode, the server provides the nonce
  // and client derives the secret. For this example, we simulate it.
  const clientSecret = context.clientSecret; // From server response
  const proof = ashBuildProofV21(clientSecret, timestamp, binding, bodyHash);

  // Step 4: Make the protected request
  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ASH-Context-ID': context.contextId,
      'X-ASH-Timestamp': timestamp,
      'X-ASH-Proof': proof,
    },
    body: JSON.stringify(payload),
  });

  return response.json();
}

// Example: Make a transfer
async function exampleTransfer() {
  try {
    const result = await makeProtectedRequest('/api/transfer', {
      fromAccount: 'ACC_001',
      toAccount: 'ACC_002',
      amount: 100.00,
      currency: 'USD',
    });

    console.log('Transfer result:', result);
  } catch (error) {
    console.error('Transfer failed:', error.message);
  }
}

// Example: Make a payment
async function examplePayment() {
  try {
    const result = await makeProtectedRequest('/api/payment', {
      merchantId: 'MERCHANT_123',
      amount: 49.99,
      currency: 'USD',
    });

    console.log('Payment result:', result);
  } catch (error) {
    console.error('Payment failed:', error.message);
  }
}

// Run examples
console.log('ASH Client Example');
console.log('==================');
exampleTransfer();
