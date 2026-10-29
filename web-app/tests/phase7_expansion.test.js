/**
 * Phase 7 - Expanded Detection Rules (Path Traversal & Command Injection) Integration Tests
 *
 * Verifies:
 * 1. Path Traversal attack detection & alert persistence (RULE-TRAV-001)
 * 2. Command Injection attack detection & alert persistence (RULE-CMDI-001)
 * 3. Severity precedence & correlation when multiple rules trigger
 * 4. Safe test cleanup of markers
 */

const test = require('node:test');
const assert = require('node:assert');
const detectionClient = require('../src/services/detectionClient');
const db = require('../src/services/database');

const TEST_MARKER = `phase7_marker_${Date.now()}`;

test.after(async () => {
  // Safe cleanup of test markers
  try {
    const pool = db.getPool ? db.getPool() : null;
    if (pool) {
      await pool.query("DELETE FROM security_alerts WHERE target_url LIKE '%phase7_marker%'");
      await pool.query("DELETE FROM request_logs WHERE url LIKE '%phase7_marker%'");
    }
  } catch (err) {
    // Graceful degradation
  }
});

test('Phase 7.1 - Path Traversal (RULE-TRAV-001): Detects and saves alert', async () => {
  const logEntry = {
    ip: '10.88.1.1',
    method: 'GET',
    url: `/download?marker=${TEST_MARKER}_trav&file=../../../../etc/passwd`,
    statusCode: 200,
    responseTime: 30,
    userAgent: 'Mozilla/5.0'
  };

  const detectionResult = {
    detected: true,
    risk_score: 75.0,
    severity: 'HIGH',
    detections: [
      {
        type: 'PATH_TRAVERSAL',
        severity: 'HIGH',
        score: 75.0,
        reason: 'Matched Path Traversal pattern: ../',
        rule_id: 'RULE-TRAV-001'
      }
    ]
  };

  await detectionClient.handleDetectionAlert(logEntry, detectionResult);

  const alertsRes = await db.getAlerts({ limit: 10 });
  const travAlert = alertsRes.alerts.find(a => (a.targetUrl || '').includes(`${TEST_MARKER}_trav`));

  assert.ok(travAlert, 'Path Traversal alert must be saved in database');
  assert.strictEqual(travAlert.alertType, 'PATH_TRAVERSAL');
  assert.strictEqual(travAlert.severity, 'HIGH');
  assert.strictEqual(parseFloat(travAlert.riskScore), 75.0);
});

test('Phase 7.2 - Command Injection (RULE-CMDI-001): Detects and saves CRITICAL alert', async () => {
  const logEntry = {
    ip: '10.88.1.2',
    method: 'GET',
    url: `/api/ping?marker=${TEST_MARKER}_cmdi&host=127.0.0.1; whoami`,
    statusCode: 200,
    responseTime: 85,
    userAgent: 'Mozilla/5.0'
  };

  const detectionResult = {
    detected: true,
    risk_score: 85.0,
    severity: 'CRITICAL',
    detections: [
      {
        type: 'COMMAND_INJECTION',
        severity: 'CRITICAL',
        score: 85.0,
        reason: 'Matched Command Injection pattern: ; whoami',
        rule_id: 'RULE-CMDI-001'
      }
    ]
  };

  await detectionClient.handleDetectionAlert(logEntry, detectionResult);

  const alertsRes = await db.getAlerts({ limit: 10 });
  const cmdiAlert = alertsRes.alerts.find(a => (a.targetUrl || '').includes(`${TEST_MARKER}_cmdi`));

  assert.ok(cmdiAlert, 'Command Injection alert must be saved in database');
  assert.strictEqual(cmdiAlert.alertType, 'COMMAND_INJECTION');
  assert.strictEqual(cmdiAlert.severity, 'CRITICAL');
  assert.strictEqual(parseFloat(cmdiAlert.riskScore), 85.0);
});

test('Phase 7.3 - Multi-threat correlation: Command Injection (score 85) takes precedence over Path Traversal (score 75)', async () => {
  const logEntry = {
    ip: '10.88.1.3',
    method: 'GET',
    url: `/api/tool?marker=${TEST_MARKER}_multi&file=../../etc/passwd&run=; whoami`,
    statusCode: 200,
    responseTime: 95
  };

  const multiDetectionResult = {
    detected: true,
    risk_score: 95.0,
    severity: 'CRITICAL',
    detections: [
      {
        type: 'PATH_TRAVERSAL',
        severity: 'HIGH',
        score: 75.0,
        reason: 'Matched Path Traversal pattern: ../',
        rule_id: 'RULE-TRAV-001'
      },
      {
        type: 'COMMAND_INJECTION',
        severity: 'CRITICAL',
        score: 85.0,
        reason: 'Matched Command Injection pattern: ; whoami',
        rule_id: 'RULE-CMDI-001'
      }
    ]
  };

  await detectionClient.handleDetectionAlert(logEntry, multiDetectionResult);

  const alertsRes = await db.getAlerts({ limit: 10 });
  const multiAlert = alertsRes.alerts.find(a => (a.targetUrl || '').includes(`${TEST_MARKER}_multi`));

  assert.ok(multiAlert, 'Correlated multi-threat alert must be persisted');
  assert.strictEqual(multiAlert.alertType, 'COMMAND_INJECTION', 'Higher score rule must be primary alertType');
  assert.strictEqual(multiAlert.severity, 'CRITICAL');
  assert.strictEqual(multiAlert.details.detections.length, 2, 'All sub-detections must be preserved in details');
});
