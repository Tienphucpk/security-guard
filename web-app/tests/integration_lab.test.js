const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/server');
const db = require('../src/services/database');
const gateway = require('../../gateway/server');
const labServer = require('../../integration-lab/server');

let BASE_URL = 'http://127.0.0.1:3000';
let GATEWAY_URL = 'http://127.0.0.1:8080';
let LAB_URL = 'http://127.0.0.1:4005';

describe('Real-World Integration Lab Validation: Standalone External Site Protection', () => {
  let webServer = null;
  let adminCookie = null;
  const testWebsiteId = `site_lab_${Date.now()}`;
  let gatewayRunning = false;
  let labRunning = false;

  before(async () => {
    process.env.ALLOW_PRIVATE_UPSTREAMS = 'true';

    // 1. Start dynamic Web App
    await new Promise((resolve) => {
      webServer = app.listen(0, '127.0.0.1', () => {
        const port = webServer.address().port;
        BASE_URL = `http://127.0.0.1:${port}`;
        process.env.WEB_APP_URL = BASE_URL;
        resolve();
      });
    });

    // 2. Start Integration Lab App on dynamic port
    await new Promise((resolve) => {
      labServer.listen(0, '127.0.0.1', () => {
        const port = labServer.address().port;
        LAB_URL = `http://127.0.0.1:${port}`;
        labRunning = true;
        resolve();
      });
    });

    // 3. Start Gateway on dynamic port
    await new Promise((resolve) => {
      gateway.server.listen(0, '127.0.0.1', () => {
        const port = gateway.server.address().port;
        GATEWAY_URL = `http://127.0.0.1:${port}`;
        gatewayRunning = true;
        resolve();
      });
    });

    // 4. Authenticate as ADMIN
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'Admin@123456' })
    });
    if (loginRes.ok) {
      const cookie = loginRes.headers.get('set-cookie');
      if (cookie) adminCookie = cookie.split(';')[0];
    }
  });

  after(async () => {
    delete process.env.ALLOW_PRIVATE_UPSTREAMS;
    if (webServer) await new Promise(r => webServer.close(r));
    if (gatewayRunning) await new Promise(r => gateway.server.close(r));
    if (labRunning) await new Promise(r => labServer.close(r));
    try {
      await db.deleteWebsite(testWebsiteId);
    } catch {}
  });

  // --------------------------------------------------------------------------
  // 1. External Registration & Health Verification
  // --------------------------------------------------------------------------
  test('Step 1: Admin registers standalone Integration Lab site via API', async () => {
    const regRes = await fetch(`${BASE_URL}/api/websites/external`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        websiteId: testWebsiteId,
        name: 'Enterprise Integration Lab Portal',
        domain: `lab-portal-${Date.now()}.local`,
        integrationMethod: 'REVERSE_PROXY',
        upstreamUrl: LAB_URL,
        monitoringMode: 'MONITOR_ONLY'
      })
    });

    assert.equal(regRes.status, 201);
    const data = await regRes.json();
    assert.equal(data.status, 'success');
    assert.equal(data.website.websiteId, testWebsiteId);
    assert.equal(data.website.monitoringMode, 'MONITOR_ONLY');
  });

  test('Step 2: Admin verifies upstream connectivity and health check', async () => {
    const verifyRes = await fetch(`${BASE_URL}/api/websites/${testWebsiteId}/verify`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });

    assert.equal(verifyRes.status, 200);
    const data = await verifyRes.json();
    assert.equal(data.status, 'success');
    assert.equal(data.healthStatus, 'HEALTHY');
  });

  // --------------------------------------------------------------------------
  // 2. Gateway Traffic Routing in MONITOR_ONLY Mode
  // --------------------------------------------------------------------------
  test('Step 3: Gateway forwards benign search query to upstream in MONITOR_ONLY mode', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/${testWebsiteId}/api/articles?q=security`, {
      headers: { 'User-Agent': 'Mozilla/5.0 BenignClient' }
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'success');
    assert.ok(Array.isArray(data.articles));
    assert.ok(data.count >= 1);
    assert.equal(res.headers.get('x-security-guard-monitored'), 'ACTIVE');
  });

  test('Step 4: Gateway permits attack traffic in MONITOR_ONLY mode while raising security alert', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/${testWebsiteId}/api/articles?q=%2527%20OR%201%3D1--`, {
      headers: { 'User-Agent': 'Mozilla/5.0 Attacker' }
    });

    // In MONITOR_ONLY mode, upstream receives request
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-security-guard-monitored'), 'ACTIVE');
  });

  // --------------------------------------------------------------------------
  // 3. Active Enforcement in ENFORCE Mode
  // --------------------------------------------------------------------------
  test('Step 5: Admin switches website mode to ENFORCE', async () => {
    const patchRes = await fetch(`${BASE_URL}/api/websites/${testWebsiteId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({ monitoringMode: 'ENFORCE' })
    });

    assert.equal(patchRes.status, 200);
    const data = await patchRes.json();
    assert.equal(data.website.monitoringMode, 'ENFORCE');
  });

  test('Step 6: Gateway in ENFORCE mode continues allowing benign traffic', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/${testWebsiteId}/api/articles?q=zero+trust`, {
      headers: { 'User-Agent': 'Mozilla/5.0 BenignClient' }
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'success');
    assert.ok(data.count >= 1);
  });

  test('Step 7: Gateway in ENFORCE mode actively BLOCKS SQL Injection attack with 403 Forbidden', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/${testWebsiteId}/api/articles?q=%27%20OR%201%3D1--`, {
      headers: { 'User-Agent': 'Mozilla/5.0 SqlAttacker' }
    });

    assert.equal(res.status, 403);
    assert.equal(res.headers.get('x-security-guard-enforced'), 'BLOCK');
    const data = await res.json();
    assert.equal(data.status, 'blocked');
    assert.equal(data.website_id, testWebsiteId);
    assert.ok(data.reason.includes('SQL_INJECTION') || data.reason.includes('Detected Attack'));
  });

  test('Step 8: Gateway in ENFORCE mode actively BLOCKS XSS payload with 403 Forbidden', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/${testWebsiteId}/api/articles?q=%3Cscript%3Ealert(1)%3C/script%3E`, {
      headers: { 'User-Agent': 'Mozilla/5.0 XssAttacker' }
    });

    assert.equal(res.status, 403);
    assert.equal(res.headers.get('x-security-guard-enforced'), 'BLOCK');
    const data = await res.json();
    assert.equal(data.status, 'blocked');
    assert.ok(data.reason.includes('XSS') || data.reason.includes('Detected Attack'));
  });

  // --------------------------------------------------------------------------
  // 4. Evidence Trail & Audit Verification
  // --------------------------------------------------------------------------
  test('Step 9: Admin retrieves comprehensive detection evidence for the integrated site', async () => {
    const evRes = await fetch(`${BASE_URL}/api/monitoring/evidence?websiteId=${testWebsiteId}&limit=10`, {
      headers: { Cookie: adminCookie }
    });

    assert.equal(evRes.status, 200);
    const data = await evRes.json();
    assert.equal(data.status, 'success');
    assert.ok(Array.isArray(data.evidence));
    assert.ok(data.count >= 1);

    const blockedEntry = data.evidence.find(e => e.decision === 'BLOCK');
    assert.ok(blockedEntry, 'Expected at least one BLOCKED decision evidence record');
    assert.ok(blockedEntry.riskScore >= 70.0);
  });
});
