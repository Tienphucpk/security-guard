const crypto = require('crypto');
const http = require('http');
const https = require('https');

const SENSITIVE_PARAM_REGEX = /([?&])(password|passwd|token|access_token|secret|api_key|auth|session|apikey)=([^&#]*)/gi;

/**
 * Redacts sensitive credentials from query string
 */
function redactUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return '/';
  return urlStr.replace(SENSITIVE_PARAM_REGEX, '$1$2=[REDACTED]');
}

/**
 * Creates a reusable Security Guard Application Agent middleware for Express applications
 * 
 * @param {Object} config
 * @param {string} config.websiteId - Registered website identifier
 * @param {string} config.agentSecret - Plaintext agent secret
 * @param {string} [config.collectorUrl] - Full URL to /api/ingest/events
 * @param {boolean} [config.enabled=true] - Toggle middleware active state
 * @param {number} [config.maxQueueSize=500] - Bounded in-memory event buffer limit
 * @param {number} [config.timeoutMs=3000] - HTTP dispatch timeout
 * @param {number} [config.maxRetries=2] - Dispatch retry attempts
 * @returns {Function} Express middleware (req, res, next)
 */
function securityGuardAgent(config = {}) {
  const websiteId = config.websiteId || process.env.SECURITY_GUARD_WEBSITE_ID;
  const agentSecret = config.agentSecret || process.env.SECURITY_GUARD_SECRET;
  const collectorUrl = config.collectorUrl || process.env.SECURITY_GUARD_COLLECTOR_URL || 'http://localhost:3000/api/ingest/events';
  const enabled = config.enabled !== false;
  const maxQueueSize = config.maxQueueSize || 500;
  const timeoutMs = config.timeoutMs || 3000;
  const maxRetries = config.maxRetries || 2;

  if (!enabled || !websiteId || !agentSecret) {
    // Return pass-through if disabled or credentials absent
    return (req, res, next) => next();
  }

  // Bounded event queue to prevent memory leak
  const queue = [];
  let isFlushing = false;

  function sendEventWithRetry(eventPayload, attempt = 1) {
    const timestamp = Math.floor(Date.now() / 1000);
    const bodyStr = JSON.stringify(eventPayload);
    const payloadToSign = `${timestamp}.${bodyStr}`;
    const signature = crypto.createHmac('sha256', agentSecret).update(payloadToSign).digest('hex');

    let parsedUrl;
    try {
      parsedUrl = new URL(collectorUrl);
    } catch (e) {
      return;
    }

    const client = parsedUrl.protocol === 'https:' ? https : http;
    const req = client.request(parsedUrl, {
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        'X-Website-Id': websiteId,
        'X-Agent-Signature': `t=${timestamp},v1=${signature}`,
        'User-Agent': 'SecurityGuard-NodeAgent/1.0'
      }
    }, (res) => {
      res.resume(); // consume response body
      if (res.statusCode >= 400 && attempt <= maxRetries) {
        setTimeout(() => sendEventWithRetry(eventPayload, attempt + 1), 500 * attempt);
      }
    });

    req.on('timeout', () => {
      req.destroy();
      if (attempt <= maxRetries) {
        setTimeout(() => sendEventWithRetry(eventPayload, attempt + 1), 500 * attempt);
      }
    });

    req.on('error', () => {
      if (attempt <= maxRetries) {
        setTimeout(() => sendEventWithRetry(eventPayload, attempt + 1), 500 * attempt);
      }
    });

    req.write(bodyStr);
    req.end();
  }

  function flushQueue() {
    if (isFlushing || queue.length === 0) return;
    isFlushing = true;

    while (queue.length > 0) {
      const item = queue.shift();
      sendEventWithRetry(item);
    }

    isFlushing = false;
  }

  // Periodic flush interval
  const flushTimer = setInterval(flushQueue, 1000);
  if (flushTimer.unref) flushTimer.unref();

  return function agentMiddleware(req, res, next) {
    const startTime = Date.now();

    // Hook into response finish
    res.on('finish', () => {
      try {
        const responseTime = Date.now() - startTime;
        const rawUrl = req.originalUrl || req.url || '/';
        const cleanPath = redactUrl(rawUrl);

        const clientIp = req.ip ||
          (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null) ||
          req.socket?.remoteAddress ||
          '127.0.0.1';

        const event = {
          event_id: `evt_${crypto.randomUUID()}`,
          request_id: `req_${crypto.randomUUID()}`,
          source_id: websiteId,
          website_id: websiteId,
          method: req.method,
          path: cleanPath,
          status_code: res.statusCode,
          source_ip: clientIp,
          response_time_ms: responseTime,
          user_agent: req.headers['user-agent'] || 'unknown',
          timestamp: new Date().toISOString()
        };

        // Bounded buffer enforcement: drop oldest if exceeding limit
        if (queue.length >= maxQueueSize) {
          queue.shift();
        }
        queue.push(event);

        // Immediate flush if queue has events
        setImmediate(flushQueue);
      } catch (err) {
        // Never fail the host application
      }
    });

    next();
  };
}

module.exports = {
  securityGuardAgent,
  redactUrl
};
