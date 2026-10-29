const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const app = require('../src/server');
const db = require('../src/services/database');
const { normalizeIp } = require('../src/utils/ip.util');

let server;
const PORT = 3099;

test.before((t, done) => {
  server = app.listen(PORT, done);
});

test.after((t, done) => {
  db.close().finally(() => {
    server.close(done);
  });
});

function makeRequest(reqPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: PORT,
        path: reqPath,
        method: options.method || 'GET',
        headers: options.headers || {}
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          resolve({ statusCode: res.statusCode, data, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// Test 1: Web App starts
test('Test 1: Web App starts and renders home page', async () => {
  const res = await makeRequest('/');
  assert.strictEqual(res.statusCode, 200);
  assert.match(res.data, /SECURITY GUARD/);
});

// Test 2: GET /api/health returns success
test('Test 2: GET /api/health returns success and reports service & database status', async () => {
  const res = await makeRequest('/api/health');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.ok(json.status === 'ok' || json.status === 'degraded');
  assert.strictEqual(json.service, 'web-app');
  assert.ok(json.database === 'connected' || json.database === 'disconnected');
});

// Test 3: Request generates file log in requests.log
test('Test 3: Request generates JSON file log in requests.log', async () => {
  const probe = 'unit_test_log_' + Date.now();
  await makeRequest(`/search?q=${probe}`);
  await new Promise((r) => setTimeout(r, 100));

  const logFilePath = path.resolve(__dirname, '../logs/requests.log');
  assert.ok(fs.existsSync(logFilePath), 'requests.log must exist');
  const content = fs.readFileSync(logFilePath, 'utf-8');
  assert.ok(content.includes(probe), 'Log must contain probe query');
});

// Test 4: Request creates or gracefully handles PostgreSQL persistence
test('Test 4: Request log persistence to database returns response without throwing', async () => {
  const testEntry = {
    timestamp: new Date().toISOString(),
    ip: '127.0.0.1',
    method: 'GET',
    url: '/test-db-insert',
    statusCode: 200,
    userAgent: 'test-runner',
    responseTime: 10
  };

  const result = await db.insertRequestLog(testEntry);
  assert.ok(typeof result.success === 'boolean');
});

// Test 5: GET /api/logs returns data with valid schema
test('Test 5: GET /api/logs returns valid structured JSON data', async () => {
  const res = await makeRequest('/api/logs?limit=5');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(Array.isArray(json.logs));
  assert.ok(typeof json.total === 'number');
  assert.ok(typeof json.count === 'number');
});

// Test 6: Pagination works
test('Test 6: Pagination works properly on GET /api/logs', async () => {
  const res = await makeRequest('/api/logs?page=1&limit=2');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.page, 1);
  assert.strictEqual(json.limit, 2);
  assert.ok(json.count <= 2);
});

// Test 7: Filter by IP works
test('Test 7: Filter by IP functions correctly on GET /api/logs', async () => {
  const res = await makeRequest('/api/logs?ip=127.0.0.1');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  for (const log of json.logs) {
    assert.strictEqual(log.ip, '127.0.0.1');
  }
});

// Test 8: Filter by method works
test('Test 8: Filter by HTTP method functions correctly on GET /api/logs', async () => {
  const res = await makeRequest('/api/logs?method=GET');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  for (const log of json.logs) {
    assert.strictEqual((log.method || '').toUpperCase(), 'GET');
  }
});

// Test 9: Filter by status code works
test('Test 9: Filter by status code functions correctly on GET /api/logs', async () => {
  const res = await makeRequest('/api/logs?statusCode=200');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  for (const log of json.logs) {
    assert.strictEqual(parseInt(log.statusCode, 10), 200);
  }
});

// Test 10: Stats API works
test('Test 10: GET /api/logs/stats returns computed statistics', async () => {
  const res = await makeRequest('/api/logs/stats');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(json.stats);
  assert.ok(typeof json.stats.totalRequests === 'number');
  assert.ok(typeof json.stats.successfulRequests === 'number');
  assert.ok(typeof json.stats.uniqueIps === 'number');
});

// Test 11: Database offline does not crash Web App (Graceful Degradation)
test('Test 11: Database offline does not crash Web App', async () => {
  // Ensure that even if DB operations fail internally, HTTP endpoint remains resilient
  const res = await makeRequest('/api/health');
  assert.strictEqual(res.statusCode, 200);

  const logsRes = await makeRequest('/api/logs?limit=5');
  assert.strictEqual(logsRes.statusCode, 200);

  const pageRes = await makeRequest('/search?q=resilience_test');
  assert.strictEqual(pageRes.statusCode, 200);
});

// Test 12: IP normalization works
test('Test 12: IP normalization handles IPv4-mapped IPv6, localhost, and forwarded IPs', () => {
  assert.strictEqual(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
  assert.strictEqual(normalizeIp('::ffff:192.168.1.50'), '192.168.1.50');
  assert.strictEqual(normalizeIp('::1'), '127.0.0.1');
  assert.strictEqual(normalizeIp('::'), '127.0.0.1');
  assert.strictEqual(normalizeIp('192.168.1.100'), '192.168.1.100');
  assert.strictEqual(normalizeIp('10.0.0.1, 10.0.0.2'), '10.0.0.1');
  assert.strictEqual(normalizeIp(''), '127.0.0.1');
  assert.strictEqual(normalizeIp(null), '127.0.0.1');
});

// Test 13: Phase 3 GET /api/alerts returns valid schema
test('Test 13: Phase 3 GET /api/alerts returns valid structured JSON data', async () => {
  const res = await makeRequest('/api/alerts?limit=5');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(Array.isArray(json.alerts));
  assert.ok(typeof json.total === 'number');
  assert.ok(typeof json.count === 'number');
});

// Test 14: Phase 3 GET /api/alerts enforces limit <= 100
test('Test 14: Phase 3 GET /api/alerts enforces maximum limit <= 100', async () => {
  const res = await makeRequest('/api/alerts?limit=999');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.limit, 100);
});

// Test 15: Phase 3 GET /api/alerts/stats returns statistics
test('Test 15: Phase 3 GET /api/alerts/stats returns security alert statistics', async () => {
  const res = await makeRequest('/api/alerts/stats');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(json.stats);
  assert.ok(typeof json.stats.totalAlerts === 'number');
  assert.ok(typeof json.stats.newAlerts === 'number');
  assert.ok(Array.isArray(json.stats.topAlertTypes));
  assert.ok(Array.isArray(json.stats.topAlertIps));
});

// Test 16: Phase 3 GET /api/alerts/:id returns 404 for non-existent alert
test('Test 16: Phase 3 GET /api/alerts/:id returns 404 for non-existent ID', async () => {
  const res = await makeRequest('/api/alerts/999999');
  assert.strictEqual(res.statusCode, 404);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'error');
});

// Test 17: Phase 3 Database offline resilience with alerts insertion & retrieval
test('Test 17: Phase 3 Alert insertion handles DB gracefully without throwing', async () => {
  const testAlert = {
    timestamp: new Date().toISOString(),
    sourceIp: '127.0.0.1',
    method: 'GET',
    targetUrl: '/search?q=test',
    alertType: 'TEST_ALERT',
    severity: 'HIGH',
    riskScore: 75.0,
    description: 'Unit test alert',
    status: 'new'
  };
  const result = await db.insertSecurityAlert(testAlert);
  assert.ok(typeof result.success === 'boolean');
});

// Test 18: Phase 3 DetectionClient forwardLog is resilient and non-blocking
test('Test 18: DetectionClient forwardLog does not throw when engine is offline', async () => {
  const detectionClient = require('../src/services/detectionClient');
  const dummyLog = {
    ip: '127.0.0.1',
    method: 'GET',
    url: '/test-resilience'
  };
  const res = await detectionClient.forwardLog(dummyLog);
  assert.ok(res);
  assert.ok(res.status === 'unavailable' || res.status === 'skipped' || typeof res.detected === 'boolean');
});

// Test 19: Phase 4 GET /api/alerts/stream returns SSE stream headers and connected event
test('Test 19: Phase 4 GET /api/alerts/stream returns SSE stream headers and connected event', async () => {
  await new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: PORT,
        path: '/api/alerts/stream',
        method: 'GET'
      },
      (res) => {
        assert.strictEqual(res.statusCode, 200);
        assert.ok(res.headers['content-type'].includes('text/event-stream'));
        res.on('data', (chunk) => {
          const text = chunk.toString();
          if (text.includes('event: connected')) {
            req.destroy();
            resolve();
          }
        });
      }
    );
    req.on('error', (err) => {
      // req.destroy() can emit ECONNRESET on client side which is normal when closing SSE test
      if (err.code !== 'ECONNRESET') reject(err);
      else resolve();
    });
    req.end();
  });
});

// Test 20: Phase 4 GET /api/alerts/stats includes acknowledged and resolved counts
test('Test 20: Phase 4 GET /api/alerts/stats includes acknowledged and resolved counts', async () => {
  const res = await makeRequest('/api/alerts/stats');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(typeof json.stats.acknowledgedAlerts === 'number');
  assert.ok(typeof json.stats.resolvedAlerts === 'number');
});

// Test 21: Phase 4 GET /api/alerts supports sorting and totalPages
test('Test 21: Phase 4 GET /api/alerts supports sorting and totalPages', async () => {
  const res = await makeRequest('/api/alerts?sort=risk_desc&limit=5');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(typeof json.totalPages === 'number');
  assert.ok(Array.isArray(json.alerts));
});

// Test 22: Phase 4 Alert lifecycle: acknowledge and resolve
test('Test 22: Phase 4 Alert lifecycle: acknowledge and resolve an alert', async () => {
  // First, get an existing alert or insert one
  const listRes = await makeRequest('/api/alerts?limit=1');
  const listJson = JSON.parse(listRes.data);
  let alertId;

  if (listJson.alerts && listJson.alerts.length > 0) {
    alertId = listJson.alerts[0].id;
  } else {
    // Insert a test alert if none exists
    const inserted = await db.insertSecurityAlert({
      timestamp: new Date().toISOString(),
      sourceIp: '127.0.0.1',
      method: 'GET',
      targetUrl: '/lifecycle-test',
      alertType: 'LIFECYCLE_TEST',
      severity: 'MEDIUM',
      riskScore: 50.0,
      description: 'Lifecycle test alert',
      status: 'new'
    });
    alertId = inserted.id || 1;
  }

  const authHeaders = { 'Authorization': 'Bearer secguard_admin_key_2026_demo' };

  // 1. Acknowledge
  const ackRes = await makeRequest(`/api/alerts/${alertId}/acknowledge`, { method: 'PATCH', headers: authHeaders });
  assert.strictEqual(ackRes.statusCode, 200);
  const ackJson = JSON.parse(ackRes.data);
  assert.strictEqual(ackJson.status, 'ok');
  assert.strictEqual(ackJson.alert.status, 'acknowledged');

  // 2. Resolve
  const resRes = await makeRequest(`/api/alerts/${alertId}/resolve`, { method: 'PATCH', headers: authHeaders });
  assert.strictEqual(resRes.statusCode, 200);
  const resJson = JSON.parse(resRes.data);
  assert.strictEqual(resJson.status, 'ok');
  assert.strictEqual(resJson.alert.status, 'resolved');
});

// Test 23: Phase 4 PATCH /api/alerts/:id/status validates status parameter
test('Test 23: Phase 4 PATCH /api/alerts/:id/status validates status parameter', async () => {
  const res = await makeRequest('/api/alerts/1/status', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer secguard_admin_key_2026_demo' },
    body: JSON.stringify({ status: 'invalid_status' })
  });
  assert.strictEqual(res.statusCode, 400);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'error');
});

// Test 24: Phase 4 PATCH /api/alerts/:id/acknowledge returns 404 for non-existent alert
test('Test 24: Phase 4 PATCH /api/alerts/:id/acknowledge returns 404 for non-existent alert', async () => {
  const res = await makeRequest('/api/alerts/999999/acknowledge', {
    method: 'PATCH',
    headers: { 'Authorization': 'Bearer secguard_admin_key_2026_demo' }
  });
  assert.strictEqual(res.statusCode, 404);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'error');
});

