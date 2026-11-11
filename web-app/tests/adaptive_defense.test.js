const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/server');
const db = require('../src/services/database');
const requestNormalizer = require('../src/services/requestNormalizer');
const adaptiveScorer = require('../src/services/adaptiveScorer');
const { DEFAULT_GATEWAY_SECRET } = require('../src/middleware/agentAuth.middleware');

let BASE_URL = 'http://127.0.0.1:3000';

describe('Advanced Defense: Adaptive Hybrid Defense & Multi-Encoding Normalization', () => {
  let webServer = null;
  let adminCookie = null;
  let analystCookie = null;

  before(async () => {
    // Start dynamic test server
    await new Promise((resolve) => {
      webServer = app.listen(0, '127.0.0.1', () => {
        const port = webServer.address().port;
        BASE_URL = `http://127.0.0.1:${port}`;
        resolve();
      });
    });

    // Login ADMIN
    const adminRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'Admin@123456' })
    });
    if (adminRes.ok) {
      const cookie = adminRes.headers.get('set-cookie');
      if (cookie) adminCookie = cookie.split(';')[0];
    }

    // Login ANALYST
    const analystRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'analyst', password: 'Analyst@123456' })
    });
    if (analystRes.ok) {
      const cookie = analystRes.headers.get('set-cookie');
      if (cookie) analystCookie = cookie.split(';')[0];
    }
  });

  after(async () => {
    if (webServer) {
      await new Promise((res) => webServer.close(res));
    }
  });

  // ============================================================================
  // 1. Normalization & De-obfuscation Unit Tests
  // ============================================================================
  test('Normalizer: Unmasks double URL encoding (%2527 -> \')', () => {
    const raw = '%2527%20OR%201%3D1';
    const decoded = requestNormalizer.recursiveUrlDecode(raw);
    assert.equal(decoded, "' OR 1=1");
  });

  test('Normalizer: Unmasks HTML entity encoded script tags', () => {
    const raw = '&lt;script&gt;alert(1)&lt;/script&gt;';
    const decoded = requestNormalizer.decodeHtmlEntities(raw);
    assert.equal(decoded, '<script>alert(1)</script>');
  });

  test('Normalizer: Strips inline SQL comment obfuscation', () => {
    const raw = 'UN/**/ION/**/SELECT/**/1,2,3';
    const normalized = requestNormalizer.normalizeSqlSyntax(raw);
    assert.equal(normalized, 'UNION SELECT 1,2,3');
  });

  test('Normalizer: Full normalization pipeline handles multi-layered obfuscations', () => {
    const raw = '%253Cscript%253Ealert(%2526quot%253BXSS%2526quot%253B)%253C%252Fscript%253E';
    const clean = requestNormalizer.normalizeText(raw);
    assert.ok(clean.includes('<script>alert('));
    assert.ok(clean.includes('XSS'));
  });

  test('Normalizer: Sanitizes sensitive credentials from headers', () => {
    const headers = {
      'user-agent': 'Mozilla/5.0',
      'authorization': 'Bearer super_secret_token_123',
      'cookie': 'connect.sid=s%3Axyz; secret=top_secret',
      'x-custom-header': 'normal_value'
    };
    const sanitized = requestNormalizer.sanitizeHeaders(headers);
    assert.equal(sanitized['authorization'], '[REDACTED]');
    assert.equal(sanitized['cookie'], '[REDACTED]');
    assert.equal(sanitized['user-agent'], 'Mozilla/5.0');
    assert.equal(sanitized['x-custom-header'], 'normal_value');
  });

  // ============================================================================
  // 2. Adaptive Risk Scoring Engine Unit Tests
  // ============================================================================
  test('Adaptive Scorer: Standalone ML anomaly score is strictly bounded under 70', () => {
    const result = adaptiveScorer.evaluateAdaptiveRisk({
      ruleDetections: [],
      mlResult: {
        is_anomaly: true,
        anomaly_score: 95.0,
        raw_score: -0.12,
        threshold: -0.026,
        mode: 'enforce'
      },
      monitoringMode: 'ENFORCE'
    });

    assert.ok(result.riskScore <= 48.0, `Expected riskScore <= 48, got ${result.riskScore}`);
    assert.notEqual(result.decision, 'BLOCK', 'Standalone ML anomaly must never trigger active BLOCK');
    assert.equal(result.decision, 'MONITOR');
  });

  test('Adaptive Scorer: Critical Rule hit triggers BLOCK in ENFORCE mode', () => {
    const result = adaptiveScorer.evaluateAdaptiveRisk({
      ruleDetections: [{
        rule_id: 'RULE_SQLI_1',
        type: 'SQL_INJECTION',
        severity: 'CRITICAL',
        score: 90.0,
        reason: 'SQL Union pattern detected'
      }],
      mlResult: null,
      monitoringMode: 'ENFORCE'
    });

    assert.equal(result.decision, 'BLOCK');
    assert.equal(result.statusCode, 403);
    assert.ok(result.riskScore >= 90.0);
    assert.equal(result.ruleSeverity, 'CRITICAL');
  });

  test('Adaptive Scorer: Synergistic corroboration boosts score when Rule + ML both detect threat', () => {
    const ruleOnly = adaptiveScorer.evaluateAdaptiveRisk({
      ruleDetections: [{
        rule_id: 'RULE_XSS_1',
        type: 'XSS_ATTACK',
        severity: 'HIGH',
        score: 75.0,
        reason: 'Script tag in payload'
      }],
      mlResult: null,
      monitoringMode: 'ENFORCE'
    });

    const ruleAndMl = adaptiveScorer.evaluateAdaptiveRisk({
      ruleDetections: [{
        rule_id: 'RULE_XSS_1',
        type: 'XSS_ATTACK',
        severity: 'HIGH',
        score: 75.0,
        reason: 'Script tag in payload'
      }],
      mlResult: {
        is_anomaly: true,
        anomaly_score: 80.0,
        raw_score: -0.08,
        threshold: -0.026,
        mode: 'enforce'
      },
      monitoringMode: 'ENFORCE'
    });

    assert.ok(ruleAndMl.riskScore > ruleOnly.riskScore, 'Synergistic Rule + ML score must exceed rule-only score');
    assert.ok(ruleAndMl.evidence.scoring.finalRiskScore >= 85.0);
  });

  test('Adaptive Scorer: Benign traffic yields low risk score and ALLOW decision', () => {
    const result = adaptiveScorer.evaluateAdaptiveRisk({
      ruleDetections: [],
      mlResult: {
        is_anomaly: false,
        anomaly_score: 12.0,
        raw_score: 0.15,
        threshold: -0.026,
        mode: 'enforce'
      },
      monitoringMode: 'ENFORCE'
    });

    assert.equal(result.decision, 'ALLOW');
    assert.equal(result.statusCode, 200);
    assert.ok(result.riskScore < 35.0);
  });

  // ============================================================================
  // 3. API & End-to-End Decision Integration Tests
  // ============================================================================
  test('API: Decision endpoint detects double-URL encoded SQL injection through normalizer', async () => {
    // Ensure demo node site is in MONITOR_ONLY mode for this test
    await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');

    const res = await fetch(`${BASE_URL}/api/monitoring/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': DEFAULT_GATEWAY_SECRET
      },
      body: JSON.stringify({
        websiteId: 'site_demo_node',
        requestId: `test_req_${Date.now()}`,
        ip: '198.51.100.77',
        method: 'GET',
        path: '/api/products',
        query: {
          search: '%2527%20OR%201%3D1--' // Double URL-encoded SQLi
        }
      })
    });

    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'success');
    assert.ok(data.decision);
    assert.ok(data.decision.riskScore >= 75.0, `Expected riskScore >= 75, got ${data.decision.riskScore}`);
    assert.ok(data.decision.ruleMatches.includes('SQL_INJECTION') || data.decision.reason.includes('SQL_INJECTION'));
    assert.ok(data.decision.evidence);
  });

  test('API: GET /api/monitoring/evidence requires ADMIN or ANALYST role', async () => {
    // Unauthenticated request should be 401
    const unauthRes = await fetch(`${BASE_URL}/api/monitoring/evidence`);
    assert.equal(unauthRes.status, 401);

    // Authenticated request with ADMIN cookie should succeed
    const adminRes = await fetch(`${BASE_URL}/api/monitoring/evidence?limit=10`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(adminRes.status, 200);
    const data = await adminRes.json();
    assert.equal(data.status, 'success');
    assert.ok(Array.isArray(data.evidence));
    assert.ok(data.count >= 1);

    // Verify evidence record schema
    const latest = data.evidence[0];
    assert.ok(latest.requestId);
    assert.ok(typeof latest.riskScore === 'number');
    assert.ok(latest.decision);
    assert.ok(latest.evidence);
  });
});
