const { v4: uuidv4 } = require('crypto');
const db = require('../services/database');
const registry = require('../services/websiteRegistry');
const policyEngine = require('../services/policyEngine');
const detectionClient = require('../services/detectionClient');
const alertStream = require('../services/alertStream');

const SENSITIVE_KEYS = new Set([
  'password', 'pass', 'pwd', 'token', 'access_token', 'refresh_token',
  'secret', 'api_key', 'apikey', 'authorization', 'cookie', 'credit_card',
  'card_number', 'cvv', 'cvc', 'ssn'
]);

/**
 * Redacts sensitive fields from objects or query strings
 */
function redactObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const cleaned = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(k.toLowerCase())) {
      cleaned[k] = '[REDACTED]';
    } else if (typeof v === 'object' && v !== null) {
      cleaned[k] = redactObject(v);
    } else {
      cleaned[k] = v;
    }
  }
  return cleaned;
}

/**
 * Redacts sensitive query parameters from a URL path
 */
function redactUrlQuery(urlPath) {
  if (!urlPath || typeof urlPath !== 'string') return '/';
  try {
    const parts = urlPath.split('?');
    if (parts.length < 2) return urlPath;
    const [pathPart, queryPart] = parts;
    const params = new URLSearchParams(queryPart);
    for (const key of params.keys()) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        params.set(key, '[REDACTED]');
      }
    }
    return `${pathPart}?${decodeURIComponent(params.toString())}`;
  } catch {
    return urlPath;
  }
}

// In-memory deduplication cache for event IDs to prevent duplicate processing
const eventDedupCache = new Map();
const EVENT_DEDUP_WINDOW_MS = 60000;

class MonitoringController {
  /**
   * Evaluates an enforcement decision for a pending request
   * POST /api/monitoring/decision
   */
  async makeDecision(req, res) {
    const { website_id, websiteId, request_id, requestId, ip, method, path, headers, query, body } = req.body || {};
    const targetWebsiteId = websiteId || website_id;

    if (!targetWebsiteId) {
      return res.status(400).json({
        status: 'error',
        error: 'Bad Request',
        message: 'Missing required field: website_id'
      });
    }

    try {
      const decision = await policyEngine.evaluateDecision({
        websiteId: targetWebsiteId,
        requestId: requestId || request_id,
        ip: ip || req.ip || '127.0.0.1',
        method: (method || 'GET').toUpperCase(),
        path: path || '/',
        headers: redactObject(headers || {}),
        query: query || {},
        body: redactObject(body)
      });

      return res.status(200).json({
        status: 'success',
        decision: decision
      });
    } catch (err) {
      console.error('[DECISION ERROR]', err.message);
      // Fail-open for demo if decision crashes
      return res.status(200).json({
        status: 'success',
        decision: {
          action: 'ALLOW',
          statusCode: 200,
          reason: 'Emergency fail-open on decision error: ' + err.message,
          mode: 'MONITOR_ONLY',
          degraded: true
        }
      });
    }
  }

  /**
   * Ingests telemetry event from Monitoring Gateway or authorized agents
   * POST /api/ingest/events
   */
  async ingestEvents(req, res) {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({
        status: 'error',
        error: 'Bad Request',
        message: 'Payload must be a valid JSON object'
      });
    }

    // Required fields validation
    const eventId = body.event_id || body.eventId;
    const sourceId = body.source_id || body.sourceId || body.website_id || body.websiteId;
    const method = body.method;
    const path = body.path || body.url;

    if (!eventId || typeof eventId !== 'string') {
      return res.status(400).json({ status: 'error', error: 'Bad Request', message: 'Missing or invalid event_id' });
    }
    if (!sourceId || typeof sourceId !== 'string') {
      return res.status(400).json({ status: 'error', error: 'Bad Request', message: 'Missing or invalid source_id' });
    }
    if (!method || typeof method !== 'string') {
      return res.status(400).json({ status: 'error', error: 'Bad Request', message: 'Missing or invalid method' });
    }
    if (!path || typeof path !== 'string') {
      return res.status(400).json({ status: 'error', error: 'Bad Request', message: 'Missing or invalid path' });
    }

    // Deduplication check
    const now = Date.now();
    if (eventDedupCache.has(eventId)) {
      return res.status(409).json({
        status: 'error',
        error: 'Conflict',
        message: `Duplicate event submission rejected: ${eventId}`
      });
    }
    eventDedupCache.set(eventId, now);

    // Clean old dedup entries periodically
    if (eventDedupCache.size > 2000) {
      for (const [k, v] of eventDedupCache.entries()) {
        if (now - v > EVENT_DEDUP_WINDOW_MS) eventDedupCache.delete(k);
      }
    }

    // Verify website is registered
    const website = await registry.getWebsite(sourceId);
    if (!website) {
      return res.status(404).json({
        status: 'error',
        error: 'Not Found',
        message: `Unregistered website source_id: '${sourceId}'`
      });
    }

    const safeUrl = redactUrlQuery(path);
    const sourceIp = body.source_ip || body.ip || '127.0.0.1';
    const statusCode = parseInt(body.status_code || body.statusCode || 200, 10);
    const responseTime = parseFloat(body.response_time_ms || body.responseTime || 0);
    const userAgent = String(body.user_agent || body.userAgent || 'unknown').slice(0, 500);
    const isBlocked = Boolean(body.blocked || statusCode === 403);
    const blockReason = body.block_reason || body.reason || null;

    // 1. Insert into PostgreSQL request_logs with website attribution
    const logEntry = {
      timestamp: body.timestamp || new Date().toISOString(),
      ip: sourceIp,
      method: method.toUpperCase(),
      url: safeUrl,
      statusCode: statusCode,
      userAgent: userAgent,
      responseTime: responseTime,
      websiteId: website.websiteId,
      blocked: isBlocked,
      blockReason: blockReason
    };

    let logId = null;
    try {
      const dbResult = await db.insertRequestLog(logEntry);
      if (dbResult && dbResult.id) logId = dbResult.id;
    } catch (err) {
      console.warn('[INGEST DB WARN]', err.message);
    }

    // 2. Forward to Detection Pipeline if request was forwarded (not blocked)
    if (!isBlocked) {
      detectionClient.forwardLog({
        ...logEntry,
        id: logId,
        websiteId: website.websiteId
      }).catch(() => {});
    }

    // 3. Broadcast real-time SSE event for dashboard
    alertStream.broadcast('website_event', {
      eventId,
      requestId: body.request_id || body.requestId,
      websiteId: website.websiteId,
      websiteName: website.name,
      method: logEntry.method,
      url: safeUrl,
      statusCode: statusCode,
      sourceIp: sourceIp,
      blocked: isBlocked,
      blockReason: blockReason,
      timestamp: logEntry.timestamp
    });

    return res.status(201).json({
      status: 'success',
      message: 'Event ingested successfully',
      event_id: eventId,
      log_id: logId
    });
  }

  /**
   * Lists registered websites (ANALYST / ADMIN)
   * GET /api/websites
   */
  async listWebsites(req, res) {
    try {
      const websites = await registry.getWebsites(true);
      return res.status(200).json({ status: 'success', websites });
    } catch (err) {
      return res.status(500).json({ status: 'error', error: err.message });
    }
  }

  /**
   * Registers a new website (ADMIN only)
   * POST /api/websites
   */
  async registerWebsite(req, res) {
    const { websiteId, name, upstreamUrl, monitoringMode, description } = req.body || {};
    try {
      const created = await registry.registerWebsite({
        websiteId,
        name,
        upstreamUrl,
        monitoringMode,
        description
      });
      return res.status(201).json({ status: 'success', website: created });
    } catch (err) {
      return res.status(400).json({ status: 'error', error: err.message });
    }
  }

  /**
   * Updates website mode or upstream (ADMIN only)
   * PATCH /api/websites/:id
   */
  async updateWebsite(req, res) {
    const { id } = req.params;
    const { monitoringMode, upstreamUrl, isActive } = req.body || {};
    try {
      let updated = null;
      if (monitoringMode) {
        updated = await registry.setMonitoringMode(id, monitoringMode);
      }
      if (upstreamUrl) {
        updated = await registry.setUpstreamUrl(id, upstreamUrl);
      }
      if (isActive !== undefined) {
        updated = await db.updateWebsiteStatus(id, isActive);
      }

      if (!updated) {
        return res.status(404).json({ status: 'error', error: `Website '${id}' not found` });
      }

      alertStream.broadcast('website_updated', updated);
      return res.status(200).json({ status: 'success', website: updated });
    } catch (err) {
      return res.status(400).json({ status: 'error', error: err.message });
    }
  }

  /**
   * Lists policies for a website
   * GET /api/websites/:id/policies
   */
  async listPolicies(req, res) {
    const { id } = req.params;
    try {
      const policies = await db.getPoliciesByWebsite(id);
      return res.status(200).json({ status: 'success', websiteId: id, policies });
    } catch (err) {
      return res.status(500).json({ status: 'error', error: err.message });
    }
  }

  /**
   * Creates an enforcement policy (ADMIN only)
   * POST /api/websites/:id/policies
   */
  async createPolicy(req, res) {
    const { id } = req.params;
    const { policyType, matchCriteria, action, reason, expiresAt } = req.body || {};

    if (!policyType || !matchCriteria || !reason) {
      return res.status(400).json({
        status: 'error',
        error: 'Missing required policy fields: policyType, matchCriteria, reason'
      });
    }

    try {
      const policy = await db.createPolicy({
        websiteId: id,
        policyType,
        matchCriteria,
        action: action || 'BLOCK',
        reason,
        expiresAt
      });
      alertStream.broadcast('policy_created', policy);
      return res.status(201).json({ status: 'success', policy });
    } catch (err) {
      return res.status(400).json({ status: 'error', error: err.message });
    }
  }

  /**
   * Deletes an enforcement policy (ADMIN only)
   * DELETE /api/websites/:id/policies/:policyId
   */
  async deletePolicy(req, res) {
    const { policyId } = req.params;
    try {
      const deleted = await db.deletePolicy(policyId);
      if (!deleted) {
        return res.status(404).json({ status: 'error', error: 'Policy not found' });
      }
      alertStream.broadcast('policy_deleted', { policyId });
      return res.status(200).json({ status: 'success', message: `Policy #${policyId} deleted` });
    } catch (err) {
      return res.status(500).json({ status: 'error', error: err.message });
    }
  }

  /**
   * Lists enforcement audit logs (ANALYST / ADMIN)
   * GET /api/websites/audit
   */
  async listAudit(req, res) {
    const { websiteId, limit } = req.query;
    try {
      const audits = await db.getRecentEnforcementAudits({
        limit: parseInt(limit, 10) || 50,
        websiteId: websiteId || null
      });
      return res.status(200).json({ status: 'success', count: audits.length, audits });
    } catch (err) {
      return res.status(500).json({ status: 'error', error: err.message });
    }
  }
}

module.exports = new MonitoringController();
