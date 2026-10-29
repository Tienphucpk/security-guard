const db = require('./database');
const registry = require('./websiteRegistry');
const alertStream = require('./alertStream');

class PolicyEngineService {
  constructor() {
    const rawUrl = process.env.DETECTION_ENGINE_URL || 'http://127.0.0.1:5000';
    this.engineUrl = rawUrl.replace('://localhost', '://127.0.0.1');
    this.timeoutMs = parseInt(process.env.DECISION_TIMEOUT_MS || '600', 10);
  }

  /**
   * Matches an IP or IP prefix against criteria
   */
  matchesIp(clientIp, targetIp) {
    if (!clientIp || !targetIp) return false;
    return clientIp.trim() === targetIp.trim() || targetIp.trim() === '*';
  }

  /**
   * Matches a request path against criteria
   */
  matchesPath(reqPath, prefix) {
    if (!reqPath || !prefix) return false;
    return reqPath.toLowerCase().startsWith(prefix.toLowerCase());
  }

  /**
   * Evaluates the request against active policies and deterministic detectors
   * @param {Object} reqData 
   * @returns {Promise<Object>} Decision result
   */
  async evaluateDecision(reqData) {
    const {
      websiteId,
      requestId,
      ip = '127.0.0.1',
      method = 'GET',
      path = '/',
      headers = {},
      query = {},
      body = null
    } = reqData;

    // 1. Verify that website is registered and active
    const website = await db.getWebsiteById(websiteId);
    if (!website) {
      return {
        action: 'BLOCK',
        statusCode: 404,
        reason: `Unknown or unregistered website identifier '${websiteId}'`,
        mode: 'ENFORCE',
        degraded: false
      };
    }

    if (!website.isActive) {
      return {
        action: 'BLOCK',
        statusCode: 503,
        reason: `Website '${website.name}' (${websiteId}) is currently deactivated by administrator`,
        mode: website.monitoringMode,
        degraded: false
      };
    }

    const currentMode = (website.monitoringMode || 'MONITOR_ONLY').toUpperCase();
    const fullUrl = path + (Object.keys(query).length > 0 ? '?' + new URLSearchParams(query).toString() : '');

    // 2. Priority 1: Administrator-approved explicit security policies
    const policies = await db.getActivePoliciesForWebsite(websiteId);

    // 2a. Check explicit ALLOW policies first (whitelists / exceptions)
    for (const policy of policies) {
      if (policy.action === 'ALLOW') {
        let criteria = policy.matchCriteria;
        if (typeof criteria === 'string') {
          try { criteria = JSON.parse(criteria); } catch {}
        }
        if (criteria?.ip && this.matchesIp(ip, criteria.ip)) {
          return {
            action: 'ALLOW',
            statusCode: 200,
            reason: `Allowed by explicit exception policy #${policy.id}: ${policy.reason}`,
            mode: currentMode,
            degraded: false
          };
        }
        if (criteria?.path_prefix && this.matchesPath(path, criteria.path_prefix)) {
          return {
            action: 'ALLOW',
            statusCode: 200,
            reason: `Allowed by explicit path exception #${policy.id}: ${policy.reason}`,
            mode: currentMode,
            degraded: false
          };
        }
      }
    }

    // 2b. Check explicit BLOCK policies
    for (const policy of policies) {
      if (policy.action === 'BLOCK') {
        let criteria = policy.matchCriteria;
        if (typeof criteria === 'string') {
          try { criteria = JSON.parse(criteria); } catch {}
        }
        let matched = false;
        if (criteria?.ip && this.matchesIp(ip, criteria.ip)) {
          matched = true;
        } else if (criteria?.path_prefix && this.matchesPath(path, criteria.path_prefix)) {
          matched = true;
        }

        if (matched) {
          const reasonText = `Administrative Policy #${policy.id} (${policy.policyType}): ${policy.reason}`;

          // If mode is ENFORCE, block immediately
          if (currentMode === 'ENFORCE') {
            await this.recordAudit({
              websiteId,
              requestId,
              action: 'BLOCKED',
              policyId: policy.id,
              reason: reasonText,
              clientIp: ip,
              targetPath: path,
              matchedRule: policy.policyType
            });

            return {
              action: 'BLOCK',
              statusCode: 403,
              reason: reasonText,
              mode: currentMode,
              policyId: policy.id,
              degraded: false
            };
          } else {
            // MONITOR_ONLY mode: record and permit
            await this.recordAudit({
              websiteId,
              requestId,
              action: 'ALLOWED_MONITOR',
              policyId: policy.id,
              reason: `[MONITOR ONLY] ${reasonText}`,
              clientIp: ip,
              targetPath: path,
              matchedRule: policy.policyType
            });
          }
        }
      }
    }

    // 3. Priority 2: Deterministic Rule-Based Detections (Existing 8 detectors)
    let detectionResult = null;
    let degraded = false;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const detectionPayload = {
        timestamp: new Date().toISOString(),
        ip: ip,
        method: method,
        url: fullUrl,
        statusCode: 200,
        userAgent: headers['user-agent'] || 'unknown',
        responseTime: 1
      };

      const res = await fetch(`${this.engineUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(detectionPayload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        detectionResult = await res.json();
      }
    } catch (err) {
      // Fail-open for demo: detection engine unreachable or timed out
      degraded = true;
    }

    // Evaluate detection outcome
    if (detectionResult && detectionResult.detected === true) {
      const allDetections = detectionResult.detections || [];
      const ruleDetections = allDetections.filter(d => d.type !== 'ML_ANOMALY');

      if (ruleDetections.length > 0) {
        // Deterministic rule matched
        const topRule = ruleDetections[0];
        const ruleReason = `Detected Attack [${topRule.type}]: ${topRule.reason || 'Malicious pattern'}`;

        if (currentMode === 'ENFORCE') {
          await this.recordAudit({
            websiteId,
            requestId,
            action: 'BLOCKED',
            reason: ruleReason,
            clientIp: ip,
            targetPath: path,
            matchedRule: topRule.type
          });

          return {
            action: 'BLOCK',
            statusCode: 403,
            reason: ruleReason,
            mode: currentMode,
            matchedRule: topRule.type,
            degraded: false
          };
        } else {
          // In MONITOR_ONLY, log audit and allow
          await this.recordAudit({
            websiteId,
            requestId,
            action: 'ALLOWED_MONITOR',
            reason: `[MONITOR ONLY] ${ruleReason}`,
            clientIp: ip,
            targetPath: path,
            matchedRule: topRule.type
          });
        }
      }
    }

    // 4. Default: Allow request through
    return {
      action: 'ALLOW',
      statusCode: 200,
      reason: 'No blocking policy or rule matched',
      mode: currentMode,
      degraded: degraded
    };
  }

  /**
   * Helper to insert audit record and emit SSE update
   */
  async recordAudit(auditData) {
    try {
      const inserted = await db.insertEnforcementAudit(auditData);
      const auditPayload = { ...auditData, id: inserted?.id, createdAt: inserted?.createdAt || new Date().toISOString() };
      alertStream.broadcast('enforcement_audit', auditPayload);
    } catch (err) {
      console.warn('[AUDIT LOG WARN]', err.message);
    }
  }
}

module.exports = new PolicyEngineService();
