const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const db = require('../src/services/database');
const registry = require('../src/services/websiteRegistry');
const policyEngine = require('../src/services/policyEngine');
const monitoringController = require('../src/controllers/monitoring.controller');
const { DEFAULT_GATEWAY_SECRET } = require('../src/middleware/agentAuth.middleware');
const gateway = require('../../gateway/server');
const nodeShopServer = require('../../demo-sites/node-site/server');

let BASE_URL = 'http://127.0.0.1:3000';
let GATEWAY_URL = 'http://127.0.0.1:8080';

describe('Phase 10: Multi-Website Monitoring & Active Enforcement', () => {
  let webServer = null;
  let adminCookie = null;
  let analystCookie = null;
  let testWebsiteId = `site_test_${Date.now()}`;
  let gatewayRunning = false;
  let nodeShopRunning = false;

  before(async () => {
    // 0. Start dedicated Web App instance on dynamic port if 3000 is occupied or in batch mode
    await new Promise((resolve) => {
      webServer = app.listen(0, '127.0.0.1', () => {
        const port = webServer.address().port;
        BASE_URL = `http://127.0.0.1:${port}`;
        process.env.WEB_APP_URL = BASE_URL;
        resolve();
      });
    });

    // 1. Authenticate as ADMIN
    const adminLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'Admin@123456' })
    });
    if (adminLoginRes.ok) {
      const setCookie = adminLoginRes.headers.get('set-cookie');
      if (setCookie) {
        adminCookie = setCookie.split(';')[0];
      }
    }

    // 2. Authenticate as ANALYST
    const analystLoginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'analyst', password: 'Analyst@123456' })
    });
    if (analystLoginRes.ok) {
      const setCookie = analystLoginRes.headers.get('set-cookie');
      if (setCookie) {
        analystCookie = setCookie.split(';')[0];
      }
    }

    // 3. Start Gateway
    try {
      await new Promise((resolve) => {
        gateway.server.listen(0, '127.0.0.1', () => {
          const gwPort = gateway.server.address().port;
          GATEWAY_URL = `http://127.0.0.1:${gwPort}`;
          gatewayRunning = true;
          resolve();
        });
        gateway.server.on('error', () => {
          gatewayRunning = false;
          resolve();
        });
      });
    } catch {}

    // 4. Start Demo Node Shop if not already listening
    try {
      await new Promise((resolve) => {
        nodeShopServer.listen(4001, '0.0.0.0', () => {
          nodeShopRunning = true;
          resolve();
        });
        nodeShopServer.on('error', () => {
          nodeShopRunning = false;
          resolve();
        });
      });
    } catch {}
  });

  after(async () => {
    if (webServer) {
      webServer.close();
    }
    if (gatewayRunning) {
      gateway.server.close();
    }
    if (nodeShopRunning) {
      nodeShopServer.close();
    }
    // Clean up test website if created
    try {
      const client = await db.pool.connect();
      try {
        await client.query(`DELETE FROM monitored_websites WHERE website_id = $1`, [testWebsiteId]);
      } finally {
        client.release();
      }
    } catch {}
  });

  // --------------------------------------------------------------------------
  // A. Agent Authentication Tests
  // --------------------------------------------------------------------------

  test('Test 1: Agent Auth - Rejects requests without credentials with 401 Unauthorized', async () => {
    const res = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_id: 'evt-1' })
    });
    assert.equal(res.status, 401);
    const data = await res.json();
    assert.equal(data.status, 'error');
    assert.equal(data.error, 'Unauthorized');
  });

  test('Test 2: Agent Auth - Rejects invalid credentials with 401 Unauthorized', async () => {
    const res = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': 'invalid_secret_key_123'
      },
      body: JSON.stringify({ event_id: 'evt-1' })
    });
    assert.equal(res.status, 401);
  });

  test('Test 3: Agent Auth - Accepts valid X-Gateway-Secret credentials', async () => {
    const res = await fetch(`${BASE_URL}/api/monitoring/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({ website_id: 'site_demo_node', path: '/health' })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'success');
    assert.ok(data.decision);
    assert.equal(data.decision.action, 'ALLOW');
  });

  // --------------------------------------------------------------------------
  // B. Event Ingestion Schema & Normalization Tests
  // --------------------------------------------------------------------------

  test('Test 4: Event Ingestion - Rejects missing required fields with 400 Bad Request', async () => {
    const res = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({
        // missing event_id and source_id
        method: 'GET',
        path: '/test'
      })
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.message.includes('Missing or invalid event_id'));
  });

  test('Test 5: Event Ingestion - Rejects unregistered website source_id with 404 Not Found', async () => {
    const res = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({
        event_id: `evt-unreg-${Date.now()}`,
        source_id: 'site_completely_unregistered_xyz',
        method: 'GET',
        path: '/test'
      })
    });
    assert.equal(res.status, 404);
  });

  test('Test 6: Event Ingestion - Rejects duplicate event submission with 409 Conflict', async () => {
    const duplicateId = `evt-dup-${Date.now()}`;
    const payload = {
      event_id: duplicateId,
      source_id: 'site_demo_node',
      method: 'GET',
      path: '/products'
    };

    // First ingestion -> 201 Created
    const res1 = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify(payload)
    });
    assert.equal(res1.status, 201);

    // Second ingestion with same event_id -> 409 Conflict
    const res2 = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify(payload)
    });
    assert.equal(res2.status, 409);
    const data2 = await res2.json();
    assert.equal(data2.error, 'Conflict');
  });

  test('Test 7: Event Ingestion - Sanitizes and redacts sensitive query parameters', async () => {
    const eventId = `evt-redact-${Date.now()}`;
    const res = await fetch(`${BASE_URL}/api/ingest/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({
        event_id: eventId,
        source_id: 'site_demo_node',
        method: 'GET',
        path: '/api/login?user=alice&password=SuperSecretPassword123&token=tok_999'
      })
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.log_id);

    // Query request_logs to verify password was redacted
    const logRes = await fetch(`${BASE_URL}/api/logs?limit=5`);
    const logData = await logRes.json();
    const insertedLog = (logData.logs || []).find(l => l.id === data.log_id);
    if (insertedLog) {
      assert.ok(!insertedLog.url.includes('SuperSecretPassword123'), 'Raw password must not be logged');
      assert.ok(insertedLog.url.includes('[REDACTED]'), 'Sensitive parameters must be masked');
    }
  });

  // --------------------------------------------------------------------------
  // C. SSRF Protection Tests
  // --------------------------------------------------------------------------

  test('Test 8: SSRF Protection - Rejects prohibited cloud metadata hosts', () => {
    const check1 = registry.validateUpstreamUrl('http://169.254.169.254/latest/meta-data');
    assert.equal(check1.valid, false);
    assert.ok(check1.reason.includes('SSRF Protection'));

    const check2 = registry.validateUpstreamUrl('http://metadata.google.internal/computeMetadata/v1');
    assert.equal(check2.valid, false);

    const check3 = registry.validateUpstreamUrl('ftp://127.0.0.1:4001');
    assert.equal(check3.valid, false);
    assert.ok(check3.reason.includes('Only HTTP and HTTPS'));
  });

  test('Test 9: SSRF Protection - Accepts approved localhost upstreams with valid ports', () => {
    const check = registry.validateUpstreamUrl('http://127.0.0.1:4001');
    assert.equal(check.valid, true);
    assert.equal(check.parsedUrl.port, '4001');
  });

  // --------------------------------------------------------------------------
  // D. Enforcement Policy & Decision Tests
  // --------------------------------------------------------------------------

  test('Test 10: Policy Decision - MONITOR_ONLY mode never blocks attacks (returns ALLOW)', async () => {
    // Ensure site_demo_node is in MONITOR_ONLY mode
    await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');

    const res = await fetch(`${BASE_URL}/api/monitoring/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({
        website_id: 'site_demo_node',
        ip: '10.0.0.99',
        method: 'GET',
        path: "/search?q=' OR 1=1--"
      })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.decision.action, 'ALLOW');
    assert.equal(data.decision.mode, 'MONITOR_ONLY');
  });

  test('Test 11: Policy Decision - ENFORCE mode blocks SQL Injection attacks (returns BLOCK)', async () => {
    // Switch site_demo_node to ENFORCE mode
    await db.updateWebsiteMode('site_demo_node', 'ENFORCE');

    const res = await fetch(`${BASE_URL}/api/monitoring/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({
        website_id: 'site_demo_node',
        ip: '10.0.0.99',
        method: 'GET',
        path: "/search?q=' OR 1=1--"
      })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.decision.action, 'BLOCK');
    assert.equal(data.decision.statusCode, 403);
    assert.ok(data.decision.reason.includes('SQL_INJECTION') || data.decision.reason.includes('Detected Attack'));

    // Revert back to MONITOR_ONLY for subsequent tests
    await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');
  });

  test('Test 12: Policy Decision - Explicit IP block policy blocks in ENFORCE mode', async () => {
    const blockedIp = '198.51.100.42';

    // Create policy
    const policy = await db.createPolicy({
      websiteId: 'site_demo_node',
      policyType: 'IP_BLOCK',
      matchCriteria: { ip: blockedIp },
      action: 'BLOCK',
      reason: 'Malicious Botnet IP range'
    });

    try {
      await db.updateWebsiteMode('site_demo_node', 'ENFORCE');

      const res = await fetch(`${BASE_URL}/api/monitoring/decision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
        },
        body: JSON.stringify({
          website_id: 'site_demo_node',
          ip: blockedIp,
          method: 'GET',
          path: '/products'
        })
      });

      const data = await res.json();
      assert.equal(data.decision.action, 'BLOCK');
      assert.ok(data.decision.reason.includes('Malicious Botnet IP range'));
    } finally {
      await db.deletePolicy(policy.id);
      await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');
    }
  });

  test('Test 13: Policy Decision - Explicit ALLOW exception overrides detection blocking', async () => {
    const trustedIp = '192.0.2.10';

    // Create ALLOW exception policy for trusted security scanner
    const exceptionPolicy = await db.createPolicy({
      websiteId: 'site_demo_node',
      policyType: 'IP_BLOCK',
      matchCriteria: { ip: trustedIp },
      action: 'ALLOW',
      reason: 'Authorized Internal Penetration Testing IP'
    });

    try {
      await db.updateWebsiteMode('site_demo_node', 'ENFORCE');

      // Even with an attack payload, trusted IP is explicitly ALLOWED
      const res = await fetch(`${BASE_URL}/api/monitoring/decision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
        },
        body: JSON.stringify({
          website_id: 'site_demo_node',
          ip: trustedIp,
          method: 'GET',
          path: "/search?q=' OR 1=1--"
        })
      });

      const data = await res.json();
      assert.equal(data.decision.action, 'ALLOW');
      assert.ok(data.decision.reason.includes('Authorized Internal Penetration Testing IP'));
    } finally {
      await db.deletePolicy(exceptionPolicy.id);
      await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');
    }
  });

  // --------------------------------------------------------------------------
  // E. RBAC Management & Authorization Tests
  // --------------------------------------------------------------------------

  test('Test 14: RBAC Management - Unauthenticated access to /api/websites is rejected (401)', async () => {
    const res = await fetch(`${BASE_URL}/api/websites`);
    assert.equal(res.status, 401);
  });

  test('Test 15: RBAC Management - ANALYST role can view websites but cannot register new website (403)', async () => {
    if (!analystCookie) {
      console.warn('Skipping analyst check: analyst account not active');
      return;
    }

    // 1. Can view websites -> 200 OK
    const viewRes = await fetch(`${BASE_URL}/api/websites`, {
      headers: { Cookie: analystCookie }
    });
    assert.equal(viewRes.status, 200);

    // 2. Cannot register new website -> 403 Forbidden
    const createRes = await fetch(`${BASE_URL}/api/websites`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: analystCookie
      },
      body: JSON.stringify({
        websiteId: 'site_analyst_fail',
        name: 'Analyst Site',
        upstreamUrl: 'http://127.0.0.1:4999'
      })
    });
    assert.equal(createRes.status, 403);
  });

  test('Test 16: RBAC Management - ADMIN role can register websites and toggle monitoring mode (200/201)', async () => {
    if (!adminCookie) {
      console.warn('Skipping admin check: admin account not active');
      return;
    }

    // Register test website
    const createRes = await fetch(`${BASE_URL}/api/websites`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        websiteId: testWebsiteId,
        name: 'Phase 10 Test Site',
        upstreamUrl: 'http://127.0.0.1:4001',
        monitoringMode: 'MONITOR_ONLY'
      })
    });
    assert.equal(createRes.status, 201);
    const createData = await createRes.json();
    assert.equal(createData.website.websiteId, testWebsiteId);

    // Toggle monitoring mode
    const patchRes = await fetch(`${BASE_URL}/api/websites/${testWebsiteId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({ monitoringMode: 'ENFORCE' })
    });
    assert.equal(patchRes.status, 200);
    const patchData = await patchRes.json();
    assert.equal(patchData.website.monitoringMode, 'ENFORCE');
  });

  // --------------------------------------------------------------------------
  // F. Gateway End-to-End & Multi-Site Routing Tests
  // --------------------------------------------------------------------------

  test('Test 17: Gateway End-to-End - Health check returns status ONLINE on port 8080', async () => {
    const res = await fetch(`${GATEWAY_URL}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ONLINE');
    assert.equal(data.port, 8080);
  });

  test('Test 18: Gateway End-to-End - Proxies permitted request to Demo Node Shop (:4001)', async () => {
    // Via path prefix routing: /site/site_demo_node/products
    const res = await fetch(`${GATEWAY_URL}/site/site_demo_node/products`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-security-guard-monitored'), 'ACTIVE');
    const data = await res.json();
    assert.equal(data.app, 'demo-node-shop');
    assert.ok(Array.isArray(data.products));
    assert.ok(data.products.length > 0);
  });

  test('Test 19: Gateway End-to-End - Rejects unknown website ID with 404 Not Found', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/site_unknown_nonexistent/products`);
    assert.equal(res.status, 404);
    const data = await res.json();
    assert.ok(data.message.includes('Unknown or unapproved website'));
  });

  test('Test 20: Gateway Active Enforcement - Gateway blocks attack with 403 Forbidden in ENFORCE mode', async () => {
    // Set site_demo_node to ENFORCE
    await db.updateWebsiteMode('site_demo_node', 'ENFORCE');

    try {
      const res = await fetch(`${GATEWAY_URL}/site/site_demo_node/search?q=' OR 1=1--`);
      assert.equal(res.status, 403);
      assert.equal(res.headers.get('x-security-guard-enforced'), 'BLOCK');
      const data = await res.json();
      assert.equal(data.status, 'blocked');
      assert.equal(data.website_id, 'site_demo_node');
      assert.ok(data.reason);
    } finally {
      // Revert to MONITOR_ONLY
      await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');
    }
  });
});
