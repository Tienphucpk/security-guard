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
      // Graceful degradation: never crash or hang if Detection Engine is offline or timed out
      if (err.name === 'AbortError') {
        console.warn(`[DETECTION CLIENT] Request timed out after ${this.timeoutMs}ms`);
      } else {
        // Engine unreachable or network error
        // Keep warning quiet to avoid cluttering normal console
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
      requestLogId: logEntry.id || null
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
