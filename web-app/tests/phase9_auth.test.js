/**
 * Phase 9.1 - Alert Management Authentication & Authorization Test Suite
 * Validates that unauthenticated, invalid, expired, and insufficient-role requests
 * are strictly rejected with 401/403, and authorized requests succeed.
 */

const test = require('node:test');
const assert = require('node:assert');
const app = require('../src/server');
const db = require('../src/services/database');
const {
  ADMIN_API_KEY,
  OPERATOR_API_KEY,
  VIEWER_API_KEY,
  generateHmacToken
} = require('../src/middleware/auth.middleware');

let server;
let baseUrl;
let testAlertId;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });

  // Create a dedicated test alert for authorization tests
  try {
    const inserted = await db.insertSecurityAlert({
      timestamp: new Date().toISOString(),
      sourceIp: '127.0.0.1',
      method: 'GET',
      targetUrl: '/phase9-auth-test',
      alertType: 'AUTH_TEST',
      severity: 'MEDIUM',
      riskScore: 50.0,
      description: 'Phase 9 Auth Verification Alert',
      status: 'new'
    });
    testAlertId = inserted.id || 1;
  } catch {
    testAlertId = 1;
  }
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Phase 9.1 - Auth 1: Unauthenticated mutation request is rejected with 401 Unauthorized', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH'
  });

  assert.strictEqual(res.status, 401);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  assert.strictEqual(data.error, 'Unauthorized');
  assert.ok(data.message.includes('Authentication required'));
});

test('Phase 9.1 - Auth 2: Request with invalid API key is rejected with 401 Unauthorized', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH',
    headers: {
      'Authorization': 'Bearer wrong_invalid_secret_key_12345'
    }
  });

  assert.strictEqual(res.status, 401);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  assert.strictEqual(data.error, 'Unauthorized');
  assert.ok(data.message.includes('Invalid authentication credentials'));
});

test('Phase 9.1 - Auth 3: Request with expired HMAC token is rejected with 401 Unauthorized', async () => {
  // Generate a token that expired 10 seconds ago (-10000 ms)
  const expiredToken = generateHmacToken('operator', -10000);

  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${expiredToken}`
    }
  });

  assert.strictEqual(res.status, 401);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  assert.ok(data.message.includes('expired'));
});

test('Phase 9.1 - Auth 4: Viewer role has insufficient permissions and is rejected with 403 Forbidden', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH',
    headers: {
      'X-API-Key': VIEWER_API_KEY
    }
  });

  assert.strictEqual(res.status, 403);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  assert.strictEqual(data.error, 'Forbidden');
  assert.ok(data.message.includes('Insufficient permissions'));
});

test('Phase 9.1 - Auth 5: Operator role can successfully acknowledge an alert', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/acknowledge`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${OPERATOR_API_KEY}`
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'ok');
  assert.strictEqual(data.alert.status, 'acknowledged');
});

test('Phase 9.1 - Auth 6: Admin role can successfully resolve an alert', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/resolve`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${ADMIN_API_KEY}`
    }
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'ok');
  assert.strictEqual(data.alert.status, 'resolved');
});

test('Phase 9.1 - Auth 7: Valid HMAC session token can successfully update alert status (Reopen)', async () => {
  const validHmacToken = generateHmacToken('operator', 3600000); // 1 hour TTL

  const res = await fetch(`${baseUrl}/api/alerts/${testAlertId}/status`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${validHmacToken}`
    },
    body: JSON.stringify({ status: 'new' })
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.strictEqual(data.status, 'ok');
  assert.strictEqual(data.alert.status, 'new');
});

test('Phase 9.1 - Auth 8: Non-numeric / malformed alert ID is rejected with 400 Bad Request', async () => {
  const res = await fetch(`${baseUrl}/api/alerts/invalid-id-xyz/acknowledge`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${ADMIN_API_KEY}`
    }
  });

  assert.strictEqual(res.status, 400);
  const data = await res.json();
  assert.strictEqual(data.status, 'error');
  assert.ok(data.message.includes('Invalid alert ID parameter'));
});
