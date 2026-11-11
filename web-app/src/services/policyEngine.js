const db = require('./database');
const registry = require('./websiteRegistry');
const alertStream = require('./alertStream');
const requestNormalizer = require('./requestNormalizer');
const adaptiveScorer = require('./adaptiveScorer');

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
   * Embedded fallback signature analyzer ensuring uninterrupted protection
   * even if external Python microservice is temporarily offline.
   */
  evaluateFallbackRules(url, reqData = {}) {
    const bodyStr = typeof reqData.body === 'string' ? reqData.body : JSON.stringify(reqData.body || '');
    const userAgent = reqData.headers?.['user-agent'] || reqData.userAgent || '';
    let decodedUrl = url || '';
    try {
      decodedUrl = decodeURIComponent(decodedUrl);
    } catch {}
    const text = `${url} ${decodedUrl} ${bodyStr}`.replace(/\+/g, ' ').toLowerCase();
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
   * Evaluates the request against active policies, multi-encoding normalization,
   * deterministic detectors and Isolation Forest anomaly analysis.
   * 
   * @param {Object} reqData 
   * @returns {Promise<Object>} Decision result with adaptive evidence
   */
  async evaluateDecision(reqData) {
    const startTime = Date.now();
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

    // 2. Normalization & De-obfuscation Layer
    // Unmasks recursive double-URL encoding, HTML entities, and SQL comment insertions
    const normalizedPath = requestNormalizer.normalizeText(path);
    const normalizedQuery = {};
    for (const [k, v] of Object.entries(query || {})) {
      normalizedQuery[k] = typeof v === 'string' ? requestNormalizer.normalizeText(v) : v;
    }
    let queryPart = '';
    if (Object.keys(normalizedQuery).length > 0) {
      const decodedQuery = decodeURIComponent(new URLSearchParams(normalizedQuery).toString().replace(/\+/g, '%20'));
      queryPart = (normalizedPath.includes('?') ? '&' : '?') + decodedQuery;
    }
    const fullNormalizedUrl = normalizedPath + queryPart;
    const fullRawUrl = path + (Object.keys(query || {}).length > 0 ? '?' + new URLSearchParams(query).toString() : '');

    // 3. Priority 1: Administrator-approved explicit security policies
    const policies = await db.getActivePoliciesForWebsite(websiteId);

    // 3a. Check explicit ALLOW policies first (whitelists / exceptions)
    for (const policy of policies) {
      if (policy.action === 'ALLOW') {
        let criteria = policy.matchCriteria;
        if (typeof criteria === 'string') {
          try { criteria = JSON.parse(criteria); } catch {}
        }
        if (criteria?.ip && this.matchesIp(ip, criteria.ip)) {
          const adaptiveRes = adaptiveScorer.evaluateAdaptiveRisk({
            monitoringMode: currentMode,
            policyMatch: policy,
            processingTimeMs: Date.now() - startTime
          });
          await this.recordEvidence({ ...adaptiveRes, requestId, websiteId });

          return {
            action: 'ALLOW',
            statusCode: 200,
            reason: `Allowed by explicit exception policy #${policy.id}: ${policy.reason}`,
            mode: currentMode,
            degraded: false,
            riskScore: 0.0,
            evidence: adaptiveRes.evidence
          };
        }
        if (criteria?.path_prefix && this.matchesPath(path, criteria.path_prefix)) {
          const adaptiveRes = adaptiveScorer.evaluateAdaptiveRisk({
            monitoringMode: currentMode,
            policyMatch: policy,
            processingTimeMs: Date.now() - startTime
          });
          await this.recordEvidence({ ...adaptiveRes, requestId, websiteId });

          return {
            action: 'ALLOW',
            statusCode: 200,
            reason: `Allowed by explicit path exception #${policy.id}: ${policy.reason}`,
            mode: currentMode,
            degraded: false,
            riskScore: 0.0,
            evidence: adaptiveRes.evidence
          };
        }
      }
    }

    // 3b. Check explicit BLOCK policies
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
          const adaptiveRes = adaptiveScorer.evaluateAdaptiveRisk({
            monitoringMode: currentMode,
            policyMatch: policy,
            processingTimeMs: Date.now() - startTime
          });
          await this.recordEvidence({ ...adaptiveRes, requestId, websiteId });

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
              degraded: false,
              riskScore: 100.0,
              evidence: adaptiveRes.evidence
            };
          } else {
            // MONITOR_ONLY mode: record audit and permit
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

            return {
              action: 'ALLOW',
              statusCode: 200,
              reason: `[MONITOR ONLY] ${reasonText}`,
              mode: currentMode,
              policyId: policy.id,
              degraded: false,
              riskScore: 100.0,
              evidence: adaptiveRes.evidence
            };
          }
        }
      }
    }

    // 4. Priority 2: Deterministic Rule-Based Detections & ML Isolation Forest
    let detectionResult = null;
    let degraded = false;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      // Send both raw and normalized URL features; primary inspection on normalized URL
      const detectionPayload = {
        timestamp: new Date().toISOString(),
        ip: ip,
        method: method,
        url: fullNormalizedUrl,
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
      // Graceful fallback: perform deterministic pattern detection if Python engine is offline
      degraded = true;
      detectionResult = this.evaluateFallbackRules(fullNormalizedUrl, reqData);
    }

    // 5. Adaptive Risk Synthesis via Evidence Aggregator
    const processingTimeMs = Date.now() - startTime;
    const allDetections = detectionResult?.detections || [];
    const ruleDetections = allDetections.filter(d => d.type !== 'ML_ANOMALY');
    const mlResult = detectionResult?.ml_result || null;

    const adaptive = adaptiveScorer.evaluateAdaptiveRisk({
      ruleDetections,
      mlResult,
      monitoringMode: currentMode,
      processingTimeMs
    });

    // Persist detection evidence for auditability
    await this.recordEvidence({ ...adaptive, requestId, websiteId });

    // 6. Action Resolution
    if (adaptive.decision === 'BLOCK' && currentMode === 'ENFORCE') {
      const topRule = ruleDetections[0] || { type: 'ANOMALY', reason: 'High Risk Anomaly' };
      const ruleReason = `Detected Attack [${topRule.type}]: ${topRule.reason || 'Malicious pattern'}`;

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
        degraded: false,
        riskScore: adaptive.riskScore,
        ruleMatches: adaptive.ruleMatches,
        mlAnomalyScore: adaptive.mlAnomalyScore,
        evidence: adaptive.evidence,
        decisionReason: adaptive.decisionReason
      };
    }

    if (ruleDetections.length > 0) {
      // Attack detected but in MONITOR_ONLY mode: record audit and permit traffic
      const topRule = ruleDetections[0];
      const ruleReason = `Detected Attack [${topRule.type}]: ${topRule.reason || 'Malicious pattern'}`;

      await this.recordAudit({
        websiteId,
        requestId,
        action: 'ALLOWED_MONITOR',
        reason: `[MONITOR ONLY] ${ruleReason}`,
        clientIp: ip,
        targetPath: path,
        matchedRule: topRule.type
      });

      return {
        action: 'ALLOW',
        statusCode: 200,
        reason: `[MONITOR ONLY] ${ruleReason}`,
        mode: currentMode,
        matchedRule: topRule.type,
        degraded: false,
        riskScore: adaptive.riskScore,
        ruleMatches: adaptive.ruleMatches,
        mlAnomalyScore: adaptive.mlAnomalyScore,
        evidence: adaptive.evidence,
        decisionReason: adaptive.decisionReason
      };
    }

    // Default Allow
    return {
      action: 'ALLOW',
      statusCode: 200,
      reason: adaptive.decisionReason || 'No blocking policy or rule matched',
      mode: currentMode,
      degraded: degraded,
      riskScore: adaptive.riskScore,
      ruleMatches: adaptive.ruleMatches,
      mlAnomalyScore: adaptive.mlAnomalyScore,
      evidence: adaptive.evidence,
      decisionReason: adaptive.decisionReason
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

  /**
   * Helper to persist detection evidence asynchronously
   */
  async recordEvidence(evidenceData) {
    try {
      await db.insertDetectionEvidence(evidenceData);
    } catch (err) {
      console.warn('[EVIDENCE AUDIT WARN]', err.message);
    }
  }
}

module.exports = new PolicyEngineService();
