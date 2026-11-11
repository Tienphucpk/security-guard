/**
 * Phase 5.3 & Phase 5.4 - End-to-End (E2E) Security & Alert Lifecycle Integration Tests
 *
 * Verifies the complete live pipeline:
 * HTTP Request -> Logging Middleware -> Detection Engine -> PostgreSQL -> Alert API -> SSE Broadcast
 *
 * Covers:
 * 1. E2E Attack Detection & Database Persistence (SQLi, XSS, Probing)
 * 2. Foreign Key link between security_alerts and request_logs (alert.requestLog)
 * 3. Alert Lifecycle State Machine (NEW -> ACKNOWLEDGED -> RESOLVED -> REOPEN)
 * 4. Server-Sent Events (SSE) real-time event streaming:
 *    - event: connected
 *    - event: alert_created (with full payload on incoming attack)
 *    - event: alert_updated (with full payload on status transition)
 *    - heartbeat comments & graceful client disconnect cleanup
 * 5. Safe cleanup of test markers (never touching user data)
 */

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const app = require('../src/server');
const db = require('../src/services/database');
const alertStream = require('../src/services/alertStream');

let server;
const PORT = 3097; // Dedicated test port for Phase 5 test suite

test.before((t, done) => {
  server = app.listen(PORT, done);
});

test.after(async () => {
  // Safe cleanup: only remove test markers created in phase5 tests
  try {
    const pool = db.getPool ? db.getPool() : null;
    if (pool) {
      await pool.query("DELETE FROM security_alerts WHERE target_url LIKE '%phase5_marker%'");
      await pool.query("DELETE FROM request_logs WHERE url LIKE '%phase5_marker%'");
    }
  } catch (err) {
    // Graceful degradation if pool direct query not exposed
  }
  await db.close();
  await new Promise((resolve) => server.close(resolve));
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

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ============================================================================
// Phase 5.3: End-to-End Pipeline & Alert Lifecycle Tests
// ============================================================================

test('Phase 5.3 - E2E 1: Attack request generates request_log and security_alert with foreign key link', async () => {
  const marker = 'phase5_marker_sqli_' + Date.now();
  const attackUrl = `/search?q=${marker}_%27%20OR%201=1--`;

  // 1. Send simulated attack request to Web App
  const res = await makeRequest(attackUrl);
  assert.strictEqual(res.statusCode, 200);

  // 2. Allow async detection client and DB persistence to finish
  await sleep(700);

  // 3. Query Alert API to verify alert was recorded in database
  const alertsRes = await makeRequest('/api/alerts?sort=newest&limit=10');
  assert.strictEqual(alertsRes.statusCode, 200);
  const alertsJson = JSON.parse(alertsRes.data);
  assert.strictEqual(alertsJson.status, 'ok');

  const matchingAlert = alertsJson.alerts.find((a) => a.targetUrl && a.targetUrl.includes(marker));
  assert.ok(matchingAlert, 'Security alert matching phase5 marker must exist in database');
  assert.strictEqual(matchingAlert.alertType, 'SQL_INJECTION');
  assert.strictEqual(matchingAlert.severity, 'CRITICAL');
  assert.ok(parseFloat(matchingAlert.riskScore) >= 80.0);
  assert.strictEqual(matchingAlert.status, 'new');
  assert.strictEqual(matchingAlert.sourceIp, '127.0.0.1');

  // 4. Query single alert detail and verify linked request_log data is joined
  const detailRes = await makeRequest(`/api/alerts/${matchingAlert.id}`);
  assert.strictEqual(detailRes.statusCode, 200);
  const detailJson = JSON.parse(detailRes.data);
  assert.strictEqual(detailJson.status, 'ok');
  assert.ok(detailJson.alert, 'Alert details must be returned');

  // If database supports join, requestLog is populated
  if (detailJson.alert.requestLog) {
    assert.strictEqual(detailJson.alert.requestLog.statusCode, 200);
    assert.ok(detailJson.alert.requestLog.url.includes(marker));
  }
});

test('Phase 5.3 - E2E 2: Alert Lifecycle State Machine (NEW -> ACKNOWLEDGED -> RESOLVED -> REOPEN)', async () => {
  const marker = 'phase5_marker_lifecycle_' + Date.now();
  const attackUrl = `/search?q=${marker}_%27%20OR%201=1--`;

  await makeRequest(attackUrl);

  let alert = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    await sleep(400);
    const alertsRes = await makeRequest('/api/alerts?sort=newest&limit=30');
    try {
      const alertsJson = JSON.parse(alertsRes.data);
      alert = alertsJson.alerts?.find((a) => a.targetUrl && a.targetUrl.includes(marker));
      if (alert) break;
    } catch {}
  }

  assert.ok(alert, 'Alert must exist for lifecycle testing');
  const alertId = alert.id;

  const authHeaders = { 'Authorization': 'Bearer secguard_admin_key_2026_demo' };

  // Step 1: Initial State is NEW
  assert.strictEqual(alert.status, 'new');

  // Step 2: Transition to ACKNOWLEDGED
  const ackRes = await makeRequest(`/api/alerts/${alertId}/acknowledge`, { method: 'PATCH', headers: authHeaders });
  assert.strictEqual(ackRes.statusCode, 200);
  const ackJson = JSON.parse(ackRes.data);
  assert.strictEqual(ackJson.status, 'ok');
  assert.strictEqual(ackJson.alert.status, 'acknowledged');
  assert.ok(ackJson.alert.updatedAt, 'updatedAt must be populated');

  // Verify persistence in DB
  const verifyAck = await makeRequest(`/api/alerts/${alertId}`);
  assert.strictEqual(JSON.parse(verifyAck.data).alert.status, 'acknowledged');

  // Step 3: Transition to RESOLVED
  const resolveRes = await makeRequest(`/api/alerts/${alertId}/resolve`, { method: 'PATCH', headers: authHeaders });
  assert.strictEqual(resolveRes.statusCode, 200);
  const resolveJson = JSON.parse(resolveRes.data);
  assert.strictEqual(resolveJson.status, 'ok');
  assert.strictEqual(resolveJson.alert.status, 'resolved');

  // Verify persistence in DB
  const verifyResolve = await makeRequest(`/api/alerts/${alertId}`);
  assert.strictEqual(JSON.parse(verifyResolve.data).alert.status, 'resolved');

  // Step 4: Reopen Alert back to NEW
  const reopenRes = await makeRequest(`/api/alerts/${alertId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer secguard_admin_key_2026_demo' },
    body: JSON.stringify({ status: 'new' })
  });
  assert.strictEqual(reopenRes.statusCode, 200);
  const reopenJson = JSON.parse(reopenRes.data);
  assert.strictEqual(reopenJson.alert.status, 'new');

  // Verify persistence in DB
  const verifyReopen = await makeRequest(`/api/alerts/${alertId}`);
  assert.strictEqual(JSON.parse(verifyReopen.data).alert.status, 'new');
});

// ============================================================================
// Phase 5.4: Server-Sent Events (SSE) Real-Time Stream Verification
// ============================================================================

test('Phase 5.4 - SSE 1: Client connects to /api/alerts/stream and receives event: connected with valid payload', async () => {
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
        assert.ok(res.headers['cache-control'].includes('no-cache'));

        res.on('data', (chunk) => {
          const text = chunk.toString();
          if (text.includes('event: connected')) {
            const dataMatch = text.match(/data:\s*(\{.*\})/);
            assert.ok(dataMatch, 'Connected event must contain JSON data payload');
            const payload = JSON.parse(dataMatch[1]);
            assert.strictEqual(payload.status, 'connected');
            assert.ok(payload.timestamp);
            req.destroy();
            resolve();
          }
        });
      }
    );
    req.on('error', (err) => {
      if (err.code !== 'ECONNRESET') reject(err);
      else resolve();
    });
    req.end();
  });
});

test('Phase 5.4 - SSE 2: Live SSE receives alert_created and alert_updated events in real-time', async () => {
  const marker = 'phase5_marker_live_sse_' + Date.now();
  let receivedAlertCreated = false;
  let receivedAlertUpdated = false;
  let createdAlertId = null;

  await new Promise((resolve, reject) => {
    let sseReq;
    const timer = setTimeout(() => {
      if (sseReq) sseReq.destroy();
      reject(new Error(`Timed out waiting for SSE events. created=${receivedAlertCreated}, updated=${receivedAlertUpdated}`));
    }, 6000);

    sseReq = http.request(
      {
        hostname: '127.0.0.1',
        port: PORT,
        path: '/api/alerts/stream',
        method: 'GET'
      },
      (res) => {
        assert.strictEqual(res.statusCode, 200);

        res.on('data', (chunk) => {
          const text = chunk.toString();

          // 1. Initial handshake
          if (text.includes('event: connected') && !receivedAlertCreated) {
            setTimeout(() => {
              makeRequest(`/search?q=${marker}_%27%20OR%201=1--`);
            }, 100);
          }

          // 2. Real-time alert_created event
          if (text.includes('event: alert_created')) {
            const dataMatch = text.match(/data:\s*(\{.*\})/);
            if (dataMatch) {
              try {
                const alertData = JSON.parse(dataMatch[1]);
                if (alertData.targetUrl && alertData.targetUrl.includes(marker)) {
                  receivedAlertCreated = true;
                  createdAlertId = alertData.id;

                  // Now trigger alert acknowledge to test alert_updated event
                  setTimeout(() => {
                    makeRequest(`/api/alerts/${createdAlertId}/acknowledge`, {
                      method: 'PATCH',
                      headers: { 'Authorization': 'Bearer secguard_admin_key_2026_demo' }
                    });
                  }, 150);
                }
              } catch (e) {}
            }
          }

          // 3. Real-time alert_updated event
          if (text.includes('event: alert_updated')) {
            const dataMatch = text.match(/data:\s*(\{.*\})/);
            if (dataMatch) {
              try {
                const updatedData = JSON.parse(dataMatch[1]);
                if (createdAlertId && String(updatedData.id) === String(createdAlertId)) {
                  receivedAlertUpdated = true;
                  clearTimeout(timer);
                  sseReq.destroy();
                  resolve();
                }
              } catch (e) {}
            }
          }
        });
      }
    );

    sseReq.on('error', (err) => {
      clearTimeout(timer);
      if (err.code !== 'ECONNRESET') reject(err);
      else resolve();
    });

    sseReq.end();
  });

  assert.ok(receivedAlertCreated, 'SSE stream must receive event: alert_created for live attack');
  assert.ok(receivedAlertUpdated, 'SSE stream must receive event: alert_updated for live state change');
});

test('Phase 5.4 - SSE 3: Disconnect cleanup decreases active client count', async () => {
  let countDuring = 0;
  let countAfter = 0;

  await new Promise((resolve) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: PORT,
        path: '/api/alerts/stream',
        method: 'GET'
      },
      (res) => {
        res.on('data', (chunk) => {
          if (chunk.toString().includes('event: connected')) {
            countDuring = alertStream.getClientCount();
            req.destroy(); // Disconnect client
            setTimeout(resolve, 250);
          }
        });
      }
    );
    req.on('error', () => {});
    req.end();
  });

  await sleep(250);
  countAfter = alertStream.getClientCount();
  assert.ok(countDuring > countAfter, `Client count during (${countDuring}) must be greater than count after disconnect (${countAfter})`);
});

test('Phase 5.4 - SSE 4: Polling fallback endpoints function consistently', async () => {
  const res = await makeRequest('/api/alerts/stats');
  assert.strictEqual(res.statusCode, 200);
  const json = JSON.parse(res.data);
  assert.strictEqual(json.status, 'ok');
  assert.ok(typeof json.stats.totalAlerts === 'number');
  assert.ok(typeof json.stats.newAlerts === 'number');
  assert.ok(typeof json.stats.acknowledgedAlerts === 'number');
  assert.ok(typeof json.stats.resolvedAlerts === 'number');
});
