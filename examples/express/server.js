/**
 * ASH Integration Example: Express.js Server
 *
 * This example demonstrates how to integrate ASH with Express.js
 * for request integrity verification and anti-replay protection.
 */

const express = require('express');
const {
  ashCreateContext,
  ashVerifyRequest,
  AshMemoryStore,
  AshExpressMiddleware
} = require('@3maem/ash-node');

const app = express();
app.use(express.json());

// Initialize ASH store (use Redis in production)
const ashStore = new AshMemoryStore();

// Configure ASH middleware for protected routes
const ashMiddleware = new AshExpressMiddleware({
  store: ashStore,
  protectedPaths: ['/api/transfer', '/api/payment'],
  mode: 'balanced',
  timestampToleranceMs: 30000, // 30 seconds
});

// Apply ASH middleware
app.use('/api', ashMiddleware.handler());

// Public endpoint: Issue ASH context
app.post('/api/context', async (req, res) => {
  try {
    const { endpoint, ttlMs = 30000 } = req.body;

    const context = await ashCreateContext(ashStore, {
      binding: `POST|${endpoint}|`,
      ttlMs,
      mode: 'balanced',
    });

    res.json({
      contextId: context.contextId,
      expiresAt: context.expiresAt,
      // Note: clientSecret is derived server-side in v2.1+
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Protected endpoint: Money transfer
app.post('/api/transfer', async (req, res) => {
  // If we reach here, ASH verification passed
  const { fromAccount, toAccount, amount } = req.body;

  // Process the transfer
  console.log(`Transfer: ${amount} from ${fromAccount} to ${toAccount}`);

  res.json({
    success: true,
    message: 'Transfer completed',
    transactionId: `TXN_${Date.now()}`,
  });
});

// Protected endpoint: Payment
app.post('/api/payment', async (req, res) => {
  const { merchantId, amount, currency } = req.body;

  console.log(`Payment: ${amount} ${currency} to merchant ${merchantId}`);

  res.json({
    success: true,
    paymentId: `PAY_${Date.now()}`,
  });
});

// Health check (unprotected)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);

  if (err.code?.startsWith('ASH_')) {
    return res.status(403).json({
      error: 'Request verification failed',
      code: err.code,
    });
  }

  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ASH Express example running on port ${PORT}`);
  console.log('Protected endpoints: /api/transfer, /api/payment');
});

module.exports = app;
