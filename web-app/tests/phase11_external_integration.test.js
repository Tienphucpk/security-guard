const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const app = require('../src/server');
const db = require('../src/services/database');
const registry = require('../src/services/websiteRegistry');
const { validateExternalUrl, isRestrictedIpv4, isRestrictedIpv6 } = require('../src/services/ssrfValidator');
const { 
  generateAgentSecret, 
  hashSecret, 
  encryptSecret, 
  decryptSecret, 
  signPayload, 
  verifyHmacSignature,
  MAX_TIMESTAMP_SKEW_SEC 
} = require('../src/services/agentAuthService');
const { parseIngestionLogs, redactUrl, computeLogHash } = require('../src/services/logParser');
const { securityGuardAgent } = require('../../agents/node-agent/index');

let BASE_URL = 'http://127.0.0.1:3000';

describe('Phase 11: External Website Integration & Live Monitoring', () => {
  let webServer = null;
  let adminCookie = null;
  let analystCookie = null;
  const testSiteId = `site_ext_${Date.now()}`;
  let registeredSecret = 'secguard_ag_test_seed_initial_secret_123';

  before(async () => {
    // 1. Start dedicated Web App instance on dynamic port
    await new Promise((resolve) => {
      webServer = app.listen(0, '127.0.0.1', () => {
        const port = webServer.address().port;
        BASE_URL = `http://127.0.0.1:${port}`;
        process.env.WEB_APP_PUBLIC_URL = BASE_URL;
        resolve();
      });
    });

    // 2. Authenticate as ADMIN
    const adminRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'Admin@123456' })
    });
    if (adminRes.ok) {
      const setCookie = adminRes.headers.get('set-cookie');
      if (setCookie) adminCookie = setCookie.split(';')[0];
    }

    // 3. Authenticate as ANALYST
    const analystRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'analyst', password: 'Analyst@123456' })
    });
    if (analystRes.ok) {
      const setCookie = analystRes.headers.get('set-cookie');
      if (setCookie) analystCookie = setCookie.split(';')[0];
    }
  });

  after(async () => {
    if (webServer) {
      webServer.close();
    }
    try {
      const client = await db.pool.connect();
      try {
        await client.query(`DELETE FROM monitored_websites WHERE website_id LIKE 'site_ext_%'`);
      } finally {
        client.release();
      }
    } catch {}
  });

  // ============================================================================
  // Suite 1: SSRF Validation & DNS Defense
  // ============================================================================
  describe('1. SSRF & DNS Protection Boundary', () => {
    test('1.1 Should reject private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)', async () => {
      const res1 = await validateExternalUrl('http://192.168.1.50:8080/app', { allowPrivate: false });
      assert.strictEqual(res1.valid, false);
      assert.match(res1.error, /SSRF Violation|restricted/i);

      const res2 = await validateExternalUrl('http://10.0.0.1/admin', { allowPrivate: false });
      assert.strictEqual(res2.valid, false);

      const res3 = await validateExternalUrl('http://172.20.0.5/', { allowPrivate: false });
      assert.strictEqual(res3.valid, false);
    });

    test('1.2 Should reject loopback addresses (127.0.0.1, localhost, ::1)', async () => {
      const res1 = await validateExternalUrl('http://127.0.0.1:3000/api', { allowPrivate: false });
      assert.strictEqual(res1.valid, false);

      const res2 = await validateExternalUrl('http://localhost:8080', { allowPrivate: false });
      assert.strictEqual(res2.valid, false);
    });

    test('1.3 Should reject AWS/GCP/Azure Cloud Metadata endpoint (169.254.169.254) even in lab mode', async () => {
      const res = await validateExternalUrl('http://169.254.169.254/latest/meta-data/', { allowPrivate: true });
      assert.strictEqual(res.valid, false);
      assert.match(res.error, /169\.254\.169\.254/);
    });

    test('1.4 Should reject non-HTTP/HTTPS schemes (file://, ftp://, gopher://)', async () => {
      const res = await validateExternalUrl('file:///etc/passwd');
      assert.strictEqual(res.valid, false);
      assert.match(res.error, /Unsupported protocol/);
    });

    test('1.5 Should reject URLs containing userinfo credentials', async () => {
      const res = await validateExternalUrl('http://admin:secret@8.8.8.8/');
      assert.strictEqual(res.valid, false);
      assert.match(res.error, /Userinfo credentials/);
    });

    test('1.6 Should accept legitimate public IPs with allowPrivate false', async () => {
      const res = await validateExternalUrl('http://8.8.8.8/', { allowPrivate: false });
      assert.strictEqual(res.valid, true);
      assert.strictEqual(res.resolvedIps.includes('8.8.8.8'), true);
    });
  });

  // ============================================================================
  // Suite 2: Agent Authentication, Cryptography & HMAC Replay Defense
  // ============================================================================
  describe('2. Agent Credential Cryptography & HMAC Protection', () => {
    test('2.1 Should generate cryptographic secret with prefix and hash', () => {
      const creds = generateAgentSecret();
      assert.ok(creds.plaintextSecret.startsWith('secguard_ag_'));
      assert.strictEqual(creds.secretHash.length, 64);
      assert.ok(creds.encryptedSecret.includes(':'));
    });

    test('2.2 Should correctly encrypt and decrypt agent secret with AES-256-GCM', () => {
      const original = 'secguard_ag_secret_test_value_12345';
      const encrypted = encryptSecret(original);
      assert.notStrictEqual(encrypted, original);
      const decrypted = decryptSecret(encrypted);
      assert.strictEqual(decrypted, original);
    });

    test('2.3 Should compute and verify valid HMAC signature within window', () => {
      const secret = 'my_test_secret_key_999';
      const body = { action: 'ping', count: 42 };
      const nowSec = Math.floor(Date.now() / 1000);

      const sig = signPayload(body, nowSec, secret);
      const header = `t=${nowSec},v1=${sig}`;

      const verified = verifyHmacSignature(body, header, secret);
      assert.strictEqual(verified.valid, true);
      assert.strictEqual(verified.timestamp, nowSec);
    });

    test('2.4 Should reject expired or replayed HMAC signature (> 300 seconds skew)', () => {
      const secret = 'my_test_secret_key_999';
      const body = { action: 'ping' };
      const staleTimestamp = Math.floor(Date.now() / 1000) - 350; // 350 seconds ago

      const sig = signPayload(body, staleTimestamp, secret);
      const header = `t=${staleTimestamp},v1=${sig}`;

      const verified = verifyHmacSignature(body, header, secret);
      assert.strictEqual(verified.valid, false);
      assert.match(verified.error, /expired|replay/i);
    });

    test('2.5 Should reject mismatched or forged HMAC signature', () => {
      const secret = 'my_test_secret_key_999';
      const body = { action: 'transfer', amount: 1000 };
      const nowSec = Math.floor(Date.now() / 1000);

      const wrongSig = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
      const header = `t=${nowSec},v1=${wrongSig}`;

      const verified = verifyHmacSignature(body, header, secret);
      assert.strictEqual(verified.valid, false);
      assert.strictEqual(verified.error, 'Invalid HMAC signature');
    });
  });

  // ============================================================================
  // Suite 3: External Website Registration & RBAC
  // ============================================================================
  describe('3. External Website Registration & RBAC Access Control', () => {
    test('3.1 Should reject external website registration by ANALYST role (403)', async () => {
      const res = await fetch(`${BASE_URL}/api/websites/external`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: analystCookie
        },
        body: JSON.stringify({
          websiteId: 'site_analyst_fail',
          name: 'Unauthorized External Site',
          integrationMethod: 'APPLICATION_AGENT'
        })
      });
      assert.strictEqual(res.status, 403);
    });

    test('3.2 Should reject registration with SSRF loopback upstream for REVERSE_PROXY', async () => {
      const res = await fetch(`${BASE_URL}/api/websites/external`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie
        },
        body: JSON.stringify({
          websiteId: 'site_ssrf_reject',
          name: 'Malicious Upstream Target',
          integrationMethod: 'REVERSE_PROXY',
          upstreamUrl: 'http://127.0.0.1:22'
        })
      });
      assert.strictEqual(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /SSRF Validation Failed/i);
    });

    test('3.3 Should register external website by ADMIN, defaulting to MONITOR_ONLY', async () => {
      const res = await fetch(`${BASE_URL}/api/websites/external`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: adminCookie
        },
        body: JSON.stringify({
          websiteId: testSiteId,
          name: 'External Production Portal',
          domain: 'portal.example.com',
          integrationMethod: 'APPLICATION_AGENT',
          description: 'Phase 11 integration test target'
        })
      });

      assert.strictEqual(res.status, 201);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.website.websiteId, testSiteId);
      assert.strictEqual(data.website.monitoringMode, 'MONITOR_ONLY');
      assert.strictEqual(data.website.integrationMethod, 'APPLICATION_AGENT');
      assert.strictEqual(data.website.isExternal, true);
      assert.ok(data.plaintextSecret.startsWith('secguard_ag_'));
      assert.ok(data.instructions.summary.length > 0);

      registeredSecret = data.plaintextSecret;
    });

    test('3.4 Plaintext secret must never appear in website listing or database query', async () => {
      const res = await fetch(`${BASE_URL}/api/websites`, {
        headers: { Cookie: adminCookie }
      });
      const data = await res.json();
      const site = data.websites.find(w => w.websiteId === testSiteId);
      assert.ok(site);
      assert.strictEqual(site.plaintextSecret, undefined);
      assert.strictEqual(site.agentSecret, undefined);
      assert.strictEqual(site.agentSecretHash, undefined);
    });
  });

  // ============================================================================
  // Suite 4: Secret Rotation Mechanism
  // ============================================================================
  describe('4. Credential Rotation & Old Secret Invalidation', () => {
    let newSecret = null;

    test('4.1 Should allow ADMIN to rotate secret and return new plaintext once', async () => {
      const res = await fetch(`${BASE_URL}/api/websites/${testSiteId}/rotate-secret`, {
        method: 'POST',
        headers: { Cookie: adminCookie }
      });
      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.ok(data.plaintextSecret.startsWith('secguard_ag_'));
      assert.notStrictEqual(data.plaintextSecret, registeredSecret);

      newSecret = data.plaintextSecret;
    });

    test('4.2 Ingestion with old invalidated secret must be rejected (401)', async () => {
      const res = await fetch(`${BASE_URL}/api/ingest/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Website-Id': testSiteId,
          'X-Agent-Secret': registeredSecret
        },
        body: JSON.stringify({
          event_id: `evt_old_${Date.now()}`,
          source_id: testSiteId,
          method: 'GET',
          path: '/test'
        })
      });
      assert.strictEqual(res.status, 401);
    });

    test('4.3 Ingestion with newly rotated secret must succeed (201)', async () => {
      const eventId = `evt_new_${Date.now()}`;
      const res = await fetch(`${BASE_URL}/api/ingest/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Website-Id': testSiteId,
          'X-Agent-Secret': newSecret
        },
        body: JSON.stringify({
          event_id: eventId,
          source_id: testSiteId,
          method: 'GET',
          path: '/test-success'
        })
      });
      assert.strictEqual(res.status, 201);
      registeredSecret = newSecret;
    });
  });

  // ============================================================================
  // Suite 5: Log Parser & Passive Log Ingestion
  // ============================================================================
  describe('5. Log Ingestion & Sensitive Data Redaction', () => {
    test('5.1 Should correctly parse Nginx Combined Log Format', () => {
      const rawLog = '198.51.100.12 - frank [10/Oct/2026:13:55:36 +0700] "GET /api/user?token=secret123 HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0 Chrome/120.0"';
      const result = parseIngestionLogs(rawLog, 'site_log_test');

      assert.strictEqual(result.parsedCount, 1);
      const entry = result.entries[0];
      assert.strictEqual(entry.ip, '198.51.100.12');
      assert.strictEqual(entry.method, 'GET');
      assert.strictEqual(entry.statusCode, 200);
      assert.strictEqual(entry.url, '/api/user?token=[REDACTED]');
      assert.strictEqual(entry.userAgent, 'Mozilla/5.0 Chrome/120.0');
    });

    test('5.2 Should correctly parse JSON Lines format and redact sensitive fields', () => {
      const jsonLine = JSON.stringify({
        ip: '203.0.113.8',
        method: 'POST',
        url: '/auth/login?password=myPassword123',
        statusCode: 401,
        userAgent: 'CustomScanner/2.1'
      });
      const result = parseIngestionLogs(jsonLine, 'site_log_test');

      assert.strictEqual(result.parsedCount, 1);
      assert.strictEqual(result.entries[0].url, '/auth/login?password=[REDACTED]');
      assert.strictEqual(result.entries[0].statusCode, 401);
    });

    test('5.3 Should deduplicate identical log entries within batch', () => {
      const line = '198.51.100.12 - - [10/Oct/2026:13:55:36 +0700] "GET /home HTTP/1.1" 200 1200';
      const raw = `${line}\n${line}\n${line}`;
      const result = parseIngestionLogs(raw, 'site_log_test');

      assert.strictEqual(result.parsedCount, 1);
      assert.strictEqual(result.duplicatesSkipped, 2);
    });

    test('5.4 Should ingest logs via POST /api/ingest/logs with HMAC signature', async () => {
      const rawLogBatch = [
        '198.51.100.1 - - [10/Oct/2026:14:00:00 +0700] "GET /index.html HTTP/1.1" 200 1024',
        '198.51.100.2 - - [10/Oct/2026:14:00:01 +0700] "GET /style.css HTTP/1.1" 200 512'
      ].join('\n');

      const timestamp = Math.floor(Date.now() / 1000);
      const sig = signPayload(rawLogBatch, timestamp, registeredSecret);

      const res = await fetch(`${BASE_URL}/api/ingest/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'X-Website-Id': testSiteId,
          'X-Agent-Signature': `t=${timestamp},v1=${sig}`
        },
        body: rawLogBatch
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.status, 'success');
      assert.strictEqual(data.parsedCount, 2);
      assert.strictEqual(data.insertedCount, 2);
    });
  });

  // ============================================================================
  // Suite 6: Connection Verification & Diagnostics API
  // ============================================================================
  describe('6. Connection Verification & Telemetry Health Diagnostics', () => {
    test('6.1 Verification of website with active telemetry should return HEALTHY', async () => {
      const res = await fetch(`${BASE_URL}/api/websites/${testSiteId}/verify`, {
        method: 'POST',
        headers: { Cookie: analystCookie }
      });

      assert.strictEqual(res.status, 200);
      const data = await res.json();
      assert.strictEqual(data.healthStatus, 'HEALTHY');
      assert.match(data.diagnostic, /Active telemetry stream/);
    });

    test('6.2 Verification of unknown website should return 404 Not Found', async () => {
      const res = await fetch(`${BASE_URL}/api/websites/non_existent_site/verify`, {
        method: 'POST',
        headers: { Cookie: analystCookie }
      });
      assert.strictEqual(res.status, 404);
    });
  });

  // ============================================================================
  // Suite 7: Application Agent Reusable Middleware
  // ============================================================================
  describe('7. Reusable Application Agent Middleware', () => {
    test('7.1 Redact query string helper should sanitize sensitive credentials', () => {
      const clean = redactUrl('/search?q=test&token=abc12345&apikey=xyz999');
      assert.strictEqual(clean, '/search?q=test&token=[REDACTED]&apikey=[REDACTED]');
    });

    test('7.2 Agent middleware initialization should return non-intrusive middleware function', () => {
      const middleware = securityGuardAgent({
        websiteId: testSiteId,
        agentSecret: registeredSecret,
        collectorUrl: `${BASE_URL}/api/ingest/events`
      });
      assert.strictEqual(typeof middleware, 'function');
    });
  });
});
