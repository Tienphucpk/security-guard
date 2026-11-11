/**
 * SECURITY GUARD - Real Docker Web Security Labs Integration Tests
 * Validates real traffic routing, telemetry, detection, active enforcement,
 * and per-website dashboard statistics across 4 live Docker targets:
 *  - OWASP Juice Shop (:4101)
 *  - DVWA (:4102)
 *  - OWASP WebGoat (:4103/WebGoat)
 *  - OWASP WebWolf (:9091/WebWolf)
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const db = require('../src/services/database');
const gateway = require('../../gateway/server');

let BASE_URL = 'http://127.0.0.1:3000';
let GATEWAY_URL = 'http://127.0.0.1:8080';

describe('Real Docker Web Security Labs Integration Tests', () => {
  let webServer = null;
  let adminCookie = null;
  let gatewayRunning = false;

  before(async () => {
    // 1. Start dedicated Web App instance on dynamic port
    await new Promise((resolve) => {
      webServer = app.listen(0, '127.0.0.1', () => {
        const port = webServer.address().port;
        BASE_URL = `http://127.0.0.1:${port}`;
        process.env.WEB_APP_URL = BASE_URL;
        resolve();
      });
    });

    // 2. Authenticate as ADMIN
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

    // 3. Start Gateway on dynamic port
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
  });

  after(async () => {
    if (webServer) {
      await new Promise((resolve) => webServer.close(resolve));
    }
    if (gatewayRunning && gateway.server) {
      await new Promise((resolve) => gateway.server.close(resolve));
    }
    // Reset dvwa to MONITOR_ONLY to preserve normal state
    try {
      await db.updateWebsiteMode('dvwa', 'MONITOR_ONLY');
    } catch {}
  });

  // ============================================================================
  // Test 1: Connectivity & Active Health Check Probing
  // ============================================================================
  test('Active health check probes confirm all 4 Docker containers are ONLINE and HEALTHY', async () => {
    const labSites = ['owasp_juice_shop', 'dvwa', 'owasp_webgoat', 'owasp_webwolf'];

    for (const siteId of labSites) {
      const verifyRes = await fetch(`${BASE_URL}/api/websites/${siteId}/verify`, {
        method: 'POST',
        headers: { Cookie: adminCookie }
      });

      assert.equal(verifyRes.status, 200, `Health check for ${siteId} returned ${verifyRes.status}`);
      const data = await verifyRes.json();
      assert.equal(data.status, 'success');
      assert.equal(data.healthStatus, 'HEALTHY', `Site ${siteId} should be HEALTHY`);
      assert.match(data.diagnostic, /Reachable: HTTP (200|302|405)/, `Expected reachability diagnostic for ${siteId}`);
    }
  });

  // ============================================================================
  // Test 2: Reverse Proxy Routing & Redirect Rewriting for All 4 Labs
  // ============================================================================
  test('Gateway correctly routes requests and rewrites redirects for Juice Shop (:4101)', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/owasp_juice_shop/`, {
      redirect: 'manual'
    });

    assert.ok(res.status === 200 || res.status === 304, `Juice Shop returned status ${res.status}`);
    const setCookie = res.headers.get('set-cookie');
    assert.ok(setCookie && setCookie.includes('secguard_site=owasp_juice_shop'), 'Gateway should set secguard_site cookie');
  });

  test('Gateway correctly routes and rewrites 302 Location redirect for DVWA (:4102)', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/dvwa/`, {
      redirect: 'manual'
    });

    assert.equal(res.status, 302, 'DVWA initial request should redirect to login.php');
    const location = res.headers.get('location');
    assert.ok(location, 'DVWA should return Location header');
    assert.ok(location.includes('/site/dvwa/'), `Location header should be rewritten to keep Gateway prefix: ${location}`);
  });

  test('Gateway handles subpath upstreams correctly for OWASP WebGoat (:4103/WebGoat)', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/owasp_webgoat/`, {
      redirect: 'manual'
    });

    assert.equal(res.status, 302, 'WebGoat root should redirect to login');
    const location = res.headers.get('location');
    assert.ok(location, 'WebGoat should return Location header');
    assert.ok(location.includes('/site/owasp_webgoat/'), `Location header should maintain prefix: ${location}`);
  });

  test('Gateway handles subpath upstreams correctly for OWASP WebWolf (:9091/WebWolf)', async () => {
    const res = await fetch(`${GATEWAY_URL}/site/owasp_webwolf/`, {
      redirect: 'manual'
    });

    assert.equal(res.status, 302, 'WebWolf root should redirect to login');
    const location = res.headers.get('location');
    assert.ok(location, 'WebWolf should return Location header');
    assert.ok(location.includes('/site/owasp_webwolf/'), `Location header should maintain prefix: ${location}`);
  });

  // ============================================================================
  // Test 3: SQL Injection Detection & Alert Attribution on DVWA
  // ============================================================================
  test('SQL Injection attack on DVWA triggers security alert attributed to dvwa website', async () => {
    // DVWA in MONITOR_ONLY mode
    await db.updateWebsiteMode('dvwa', 'MONITOR_ONLY');

    const sqliPayload = '/site/dvwa/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271&Submit=Submit';
    const res = await fetch(`${GATEWAY_URL}${sqliPayload}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    });

    // In MONITOR_ONLY, request passes through to upstream DVWA
    assert.ok(res.status < 500, `Expected successful proxying under MONITOR_ONLY, got ${res.status}`);

    // Wait 600ms for async detection & DB ingestion to complete
    await new Promise((r) => setTimeout(r, 600));

    // Check security_alerts for dvwa
    const alertsRes = await fetch(`${BASE_URL}/api/alerts?websiteId=dvwa&limit=10`);
    assert.equal(alertsRes.status, 200);
    const alertData = await alertsRes.json();
    assert.ok(alertData.alerts.length > 0, 'Security alerts should be generated for dvwa');
    const sqliAlert = alertData.alerts.find(a => a.alert_type === 'SQL_INJECTION' || a.alertType === 'SQL_INJECTION');
    assert.ok(sqliAlert, 'Should contain SQL_INJECTION alert');
    assert.equal(sqliAlert.website_id || sqliAlert.websiteId, 'dvwa');
  });

  // ============================================================================
  // Test 4: Reflected XSS Detection & Alert Attribution
  // ============================================================================
  test('Cross-Site Scripting (XSS) on DVWA triggers XSS security alert', async () => {
    const xssPayload = '/site/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(%27SECURITY_GUARD_XSS%27)%3C/script%3E';
    const res = await fetch(`${GATEWAY_URL}${xssPayload}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    });

    assert.ok(res.status < 500);
    await new Promise((r) => setTimeout(r, 400));

    const alertsRes = await fetch(`${BASE_URL}/api/alerts?websiteId=dvwa&limit=10`);
    const alertData = await alertsRes.json();
    const xssAlert = alertData.alerts.find(a => a.alert_type === 'XSS' || a.alertType === 'XSS');
    assert.ok(xssAlert, 'Should contain XSS alert for dvwa');
  });

  // ============================================================================
  // Test 5: Path Traversal Attack Detection
  // ============================================================================
  test('Path Traversal attack on Docker lab triggers PATH_TRAVERSAL alert', async () => {
    const traversalPayload = '/site/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd';
    const res = await fetch(`${GATEWAY_URL}${traversalPayload}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
    });

    assert.ok(res.status < 500);
    await new Promise((r) => setTimeout(r, 400));

    const alertsRes = await fetch(`${BASE_URL}/api/alerts?websiteId=dvwa&limit=10`);
    const alertData = await alertsRes.json();
    const traversalAlert = alertData.alerts.find(a => a.alert_type === 'PATH_TRAVERSAL' || a.alertType === 'PATH_TRAVERSAL');
    assert.ok(traversalAlert, 'Should contain PATH_TRAVERSAL alert');
  });

  // ============================================================================
  // Test 6: Active Enforcement Mode Blocks Attacks with 403 Forbidden
  // ============================================================================
  test('Switching DVWA to ENFORCE mode actively drops attacks at Gateway with 403 Forbidden', async () => {
    // 1. Switch mode to ENFORCE
    await db.updateWebsiteMode('dvwa', 'ENFORCE');

    // 2. Normal request to DVWA still succeeds
    const cleanRes = await fetch(`${GATEWAY_URL}/site/dvwa/`, { redirect: 'manual' });
    assert.equal(cleanRes.status, 302, 'Clean request should pass through in ENFORCE mode');

    // 3. Attack request is blocked at Gateway
    const attackPayload = "/site/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,version()--&Submit=Submit";
    const blockRes = await fetch(`${GATEWAY_URL}${attackPayload}`);

    assert.equal(blockRes.status, 403, 'Attack must be blocked with 403 Forbidden');
    assert.equal(blockRes.headers.get('x-security-guard-enforced'), 'BLOCK');

    const blockBody = await blockRes.json();
    assert.equal(blockBody.status, 'blocked');
    assert.equal(blockBody.website_id, 'dvwa');
    assert.ok(blockBody.reason, 'Block response should contain security reason');

    // 4. Restore DVWA to MONITOR_ONLY
    await db.updateWebsiteMode('dvwa', 'MONITOR_ONLY');
  });

  // ============================================================================
  // Test 7: Enriched Website Metrics & Stats Filtering Isolation
  // ============================================================================
  test('getAllWebsites() and stats APIs accurately aggregate metrics per Docker lab', async () => {
    const websitesRes = await fetch(`${BASE_URL}/api/websites`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(websitesRes.status, 200);
    const data = await websitesRes.json();
    const dvwaSite = data.websites.find(w => w.websiteId === 'dvwa');

    assert.ok(dvwaSite, 'DVWA site should exist in registry');
    assert.ok(dvwaSite.totalRequests > 0, 'DVWA should have recorded requests');
    assert.ok(dvwaSite.suspiciousRequests > 0, 'DVWA should have suspicious requests');
    assert.ok(dvwaSite.totalAlerts > 0, 'DVWA should have total alerts recorded');

    // Test log stats filtered by websiteId
    const statsRes = await fetch(`${BASE_URL}/api/logs/stats?website_id=dvwa`);
    assert.equal(statsRes.status, 200);
    const statsData = await statsRes.json();
    assert.ok(statsData.stats.totalRequests > 0, 'Stats for dvwa should reflect dvwa-only count');

    // Test alert stats filtered by websiteId
    const alertStatsRes = await fetch(`${BASE_URL}/api/alerts/stats?website_id=dvwa`);
    assert.equal(alertStatsRes.status, 200);
    const alertStatsData = await alertStatsRes.json();
    assert.ok(alertStatsData.stats.totalAlerts > 0, 'Alert stats should count alerts for dvwa');
  });
});
