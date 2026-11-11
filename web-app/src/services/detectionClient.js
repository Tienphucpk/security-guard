/**
 * Client communicating with the Python Detection Engine service.
 * Forwards HTTP request logs asynchronously, analyzes responses, and triggers alerts.
 */

const fs = require('fs');
const path = require('path');
const db = require('./database');
const alertStream = require('./alertStream');

const alertLogDir = path.resolve(__dirname, '../../logs');
const alertLogFile = path.join(alertLogDir, 'alerts.log');

if (!fs.existsSync(alertLogDir)) {
  fs.mkdirSync(alertLogDir, { recursive: true });
}

class DetectionClient {
  constructor() {
    const rawUrl = process.env.DETECTION_ENGINE_URL || 'http://127.0.0.1:5000';
    this.engineUrl = rawUrl.replace('://localhost', '://127.0.0.1');
    // Enabled by default in Phase 3 unless explicitly set to 'false'
    this.isEnabled = process.env.DETECTION_FORWARD_ENABLED !== 'false';
    this.timeoutMs = parseInt(process.env.DETECTION_TIMEOUT_MS || '1500', 10);
    // Phase 6: Deduplication cache for ML anomaly alerts: Map<"ip:url", timestamp>
    this.mlDedupCache = new Map();
    this.mlDedupWindowMs = parseInt(process.env.ML_DEDUP_WINDOW_MS || '60000', 10);
  }

  /**
   * Embedded fallback rules for when Python engine is offline
   */
  evaluateFallbackRules(logEntry = {}) {
    let decodedUrl = logEntry.url || '';
    try {
      decodedUrl = decodeURIComponent(decodedUrl);
    } catch {}
    const text = `${logEntry.url || ''} ${decodedUrl} ${logEntry.body || ''}`.replace(/\+/g, ' ').toLowerCase();
    const userAgent = logEntry.userAgent || logEntry.user_agent || '';
    const detections = [];

    // 1. SQL Injection
    if (/union(\s+all)?\s+select|information_schema|waitfor\s+delay|sleep\s*\(|benchmark\s*\(|'\s*or\s*'?1'?\s*=\s*'?1|--|#|\/\*|version\s*\(|select\s+.*from/i.test(text)) {
      detections.push({
        type: 'SQL_INJECTION',
        severity: 'CRITICAL',
        score: 85,
        reason: "Matched SQL injection signature in request: ' OR 1=1 or UNION SELECT",
        rule_id: 'RULE-SQLI-001'
      });
    }

    // 2. Cross-Site Scripting (XSS)
    if (/<script|<\/script>|javascript:|onerror\s*=|onload\s*=|onclick\s*=|document\.cookie|<iframe|<svg/i.test(text)) {
      detections.push({
        type: 'XSS',
        severity: 'HIGH',
        score: 80,
        reason: 'Cross-Site Scripting HTML/JS execution tags detected in request parameters',
        rule_id: 'RULE-XSS-001'
      });
    }

    // 3. Path Traversal
    if (/\.\.[\/\\]|%2e%2e[\/\\]|etc\/(passwd|shadow|hosts)|windows[\/\\]win\.ini|boot\.ini/i.test(text)) {
      detections.push({
        type: 'PATH_TRAVERSAL',
        severity: 'HIGH',
        score: 80,
        reason: 'Directory traversal pattern detected: attempts to climb directory hierarchy',
        rule_id: 'RULE-TRAV-001'
      });
    }

    // 4. Command Injection
    if (/(?:;|\||`|\$\()\s*(?:cat|ls|whoami|id|uname|nc|bash|sh|cmd|powershell)\b/i.test(text)) {
      detections.push({
        type: 'COMMAND_INJECTION',
        severity: 'HIGH',
        score: 85,
        reason: 'OS command execution delimiter and system executable identified',
        rule_id: 'RULE-CMD-001'
      });
    }

    // 5. Abnormal User-Agent / Scanner
    if (/(?:sqlmap|nikto|nmap|acunetix|nessus|masscan)/i.test(userAgent)) {
      detections.push({
        type: 'SUSPICIOUS_SCANNER',
        severity: 'MEDIUM',
        score: 70,
        reason: 'Automated vulnerability scanner identified via User-Agent',
        rule_id: 'RULE-SCAN-001'
      });
    }

    if (detections.length > 0) {
      const maxScore = Math.max(...detections.map(d => d.score));
      return {
        detected: true,
        risk_score: maxScore,
        severity: maxScore >= 80 ? 'CRITICAL' : (maxScore >= 60 ? 'HIGH' : 'MEDIUM'),
        detections,
        status: 'analyzed',
        is_anomaly: false,
        ml_result: { model_available: false, is_anomaly: false, anomaly_score: 0 }
      };
    }

    return {
      detected: false,
      risk_score: 0,
      severity: 'LOW',
      detections: [],
      status: 'analyzed',
      is_anomaly: false,
      ml_result: { model_available: false, is_anomaly: false, anomaly_score: 0 }
    };
  }

  /**
   * Forward log entry to Detection Engine, analyze result, and generate security alert if detected
   * @param {Object} logEntry 
   * @returns {Promise<Object>}
   */
  async forwardLog(logEntry) {
    if (!this.isEnabled) {
      return { status: 'skipped', reason: 'forwarding_disabled' };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const res = await fetch(`${this.engineUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(logEntry),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        return { status: 'error', statusCode: res.status };
      }

      const result = await res.json();

      // If anomaly detected, process and record security alert
      if (result && result.detected === true) {
        await this.handleDetectionAlert(logEntry, result);
      } else if (result && result.ml_result && result.ml_result.is_anomaly && result.ml_result.mode === 'shadow') {
        // Shadow mode telemetry logging: log ML observation without generating user-facing alert
        console.log(`[ML SHADOW] Anomaly observed for ${logEntry.ip || 'unknown'} on ${logEntry.url || '/'} (Score: ${result.ml_result.anomaly_score}, Version: ${result.ml_result.model_version})`);
      }

      return result;
    } catch (err) {
      // Graceful degradation: analyze with fallback rules if Python engine is offline
      const fallback = this.evaluateFallbackRules(logEntry);
      if (fallback && fallback.detected) {
        await this.handleDetectionAlert(logEntry, fallback);
        return fallback;
      }
      return { status: 'unavailable', detected: false, error: err.message };
    }
  }

  /**
   * Records a security alert into Database and alerts.log fallback
   * @param {Object} logEntry 
   * @param {Object} detectionResult 
   */
  async handleDetectionAlert(logEntry, detectionResult) {
    // Sort detections: rule-based specific detectors take precedence over generic ML_ANOMALY when both fire
    const allDetections = [...(detectionResult.detections || [])];
    const ruleDetections = allDetections.filter(d => d.type !== 'ML_ANOMALY');
    const mlDetections = allDetections.filter(d => d.type === 'ML_ANOMALY');

    let primaryDetection;
    if (ruleDetections.length > 0) {
      ruleDetections.sort((a, b) => (b.score || 0) - (a.score || 0));
      primaryDetection = ruleDetections[0];
    } else if (mlDetections.length > 0) {
      primaryDetection = mlDetections[0];
    } else {
      primaryDetection = {};
    }

    const alertType = primaryDetection.type || 'ANOMALY_DETECTED';

    // ML alert deduplication: if alertType is ML_ANOMALY, check deduplication window
    if (alertType === 'ML_ANOMALY') {
      const sourceIp = logEntry.ip || '127.0.0.1';
      const targetUrl = logEntry.url || '/';
      const dedupKey = `${sourceIp}:${targetUrl}`;
      const now = Date.now();
      const lastSeen = this.mlDedupCache.get(dedupKey);

      if (lastSeen && (now - lastSeen) < this.mlDedupWindowMs) {
        console.log(`[ML DEDUP] Suppressed duplicate ML_ANOMALY alert for ${dedupKey} (seen ${Math.round((now - lastSeen) / 1000)}s ago)`);
        return null;
      }
      this.mlDedupCache.set(dedupKey, now);

      if (this.mlDedupCache.size > 1000) {
        for (const [key, ts] of this.mlDedupCache.entries()) {
          if ((now - ts) > this.mlDedupWindowMs * 2) {
            this.mlDedupCache.delete(key);
          }
        }
      }
    }

    const description = allDetections.map(d => d.reason).join(' | ') || 'Suspicious request pattern';

    const alertData = {
      timestamp: logEntry.timestamp || new Date().toISOString(),
      sourceIp: logEntry.ip || '127.0.0.1',
      method: (logEntry.method || 'GET').toUpperCase(),
      targetUrl: logEntry.url || '/',
      alertType: alertType,
      severity: detectionResult.severity || 'MEDIUM',
      riskScore: parseFloat(detectionResult.risk_score) || 0.0,
      description: description,
      details: {
        detections: allDetections,
        ml_result: detectionResult.ml_result || null,
        statusCode: logEntry.statusCode,
        userAgent: logEntry.userAgent
      },
      status: 'new',
      requestLogId: logEntry.id || null,
      websiteId: logEntry.websiteId || logEntry.website_id || 'default_web_app'
    };

    // 1. Console alert logs
    console.warn(`[DETECTION] ${alertType} detected from ${alertData.sourceIp} (Score: ${alertData.riskScore}, Severity: ${alertData.severity})`);
    console.warn(`[ALERT] Creating security alert for ${alertData.sourceIp} - Target: ${alertData.targetUrl}`);

    // 2. Persist to alerts.log file (fallback & persistence)
    try {
      const line = JSON.stringify(alertData);
      fs.appendFile(alertLogFile, line + '\n', (err) => {
        if (err) console.error('[ALERT LOGGER ERROR]', err.message);
      });
    } catch (e) {
      console.error('[ALERT FILE ERROR]', e.message);
    }

    // 3. Persist to PostgreSQL security_alerts
    let savedAlert = { ...alertData };
    try {
      const inserted = await db.insertSecurityAlert(alertData);
      if (inserted && inserted.id) {
        savedAlert.id = inserted.id;
      }
    } catch (dbErr) {
      // Graceful degradation: already written to alerts.log
      console.warn('[DB ALERT WARN] PostgreSQL alert save skipped/fallback:', dbErr.message);
    }

    // 4. Broadcast real-time SSE notification
    try {
      alertStream.broadcast('alert_created', savedAlert);
    } catch (sseErr) {
      console.error('[SSE BROADCAST ERROR]', sseErr.message);
    }
  }
}

module.exports = new DetectionClient();
