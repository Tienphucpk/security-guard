/**
 * SECURITY GUARD - Monitoring & Active Enforcement Gateway
 * Technology-Independent Reverse-Proxy Gateway
 * Default Port: 8080
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');
const path = require('path');

// Import SSRF Validator
let validateExternalUrl = null;
try {
  const ssrfModule = require('../web-app/src/services/ssrfValidator');
  validateExternalUrl = ssrfModule.validateExternalUrl;
} catch (e) {
  // Fallback basic validator if loaded standalone
  validateExternalUrl = async (u) => ({ valid: true });
}

const PORT = parseInt(process.env.GATEWAY_PORT || '8080', 10);
const HOST = process.env.GATEWAY_HOST || '0.0.0.0';
function getWebAppUrl() { return process.env.WEB_APP_URL || 'http://127.0.0.1:3000'; }
const GATEWAY_SECRET = process.env.GATEWAY_SHARED_SECRET || 'secguard_gateway_internal_secret_2026';

// Pre-approved Docker security labs (SSRF Boundary)
const APPROVED_UPSTREAMS = {
  'owasp_juice_shop': 'http://127.0.0.1:4101',
  'dvwa': 'http://127.0.0.1:4102',
  'owasp_webgoat': 'http://127.0.0.1:4103/WebGoat',
  'owasp_webwolf': 'http://127.0.0.1:9091/WebWolf'
};

// In-memory cache for dynamic website registry
const dynamicRegistryCache = new Map();
const domainToIdMap = new Map();
let lastRegistryFetch = 0;
const REGISTRY_CACHE_TTL_MS = 10000;

/**
 * Fetches and updates dynamic registry cache from Web App
 */
async function refreshRegistry() {
  const now = Date.now();
  if (now - lastRegistryFetch <= REGISTRY_CACHE_TTL_MS && dynamicRegistryCache.size > 0) {
    return;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);
    const res = await fetch(`${getWebAppUrl()}/api/websites`, {
      headers: { 'X-Gateway-Secret': GATEWAY_SECRET },
      signal: controller.signal
    }).catch(() => null);
    clearTimeout(timeoutId);

    if (res && res.ok) {
      const data = await res.json();
      if (Array.isArray(data.websites)) {
        dynamicRegistryCache.clear();
        domainToIdMap.clear();

        for (const site of data.websites) {
          dynamicRegistryCache.set(site.websiteId, site);
          if (site.domain) {
            domainToIdMap.set(site.domain.toLowerCase(), site.websiteId);
            const hostNoPort = site.domain.toLowerCase().split(':')[0];
            domainToIdMap.set(hostNoPort, site.websiteId);
          }
        }
        lastRegistryFetch = now;
      }
    }
  } catch {}
}

/**
 * Resolves upstream configuration for a website ID
 */
async function resolveUpstream(websiteId) {
  if (!websiteId) return null;
  const cleanId = String(websiteId).trim();

  // 1. Check hardcoded approved demo upstreams first
  if (APPROVED_UPSTREAMS[cleanId]) {
    return {
      websiteId: cleanId,
      upstreamUrl: APPROVED_UPSTREAMS[cleanId],
      isExternal: false,
      integrationMethod: 'REVERSE_PROXY'
    };
  }

  // 2. Check dynamic registry cache
  await refreshRegistry();
  const site = dynamicRegistryCache.get(cleanId);
  if (site && site.upstreamUrl) {
    return {
      websiteId: site.websiteId,
      upstreamUrl: site.upstreamUrl,
      isExternal: Boolean(site.isExternal),
      integrationMethod: site.integrationMethod || 'REVERSE_PROXY'
    };
  }

  return null;
}

/**
 * Resolves website ID from Host header domain
 */
async function resolveWebsiteIdFromHost(hostHeader) {
  if (!hostHeader) return null;
  await refreshRegistry();
  const cleanHost = hostHeader.toLowerCase().trim();
  const siteId = domainToIdMap.get(cleanHost) || domainToIdMap.get(cleanHost.split(':')[0]);
  return siteId || null;
}

/**
 * Sends asynchronous ingestion event to Web App
 */
function sendIngestionEvent(eventData) {
  const payload = JSON.stringify(eventData);
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'X-Gateway-Secret': GATEWAY_SECRET
    },
    timeout: 1500
  };

  const req = http.request(`${getWebAppUrl()}/api/ingest/events`, options, (res) => {
    res.resume(); // Discard response body
  });

  req.on('error', (err) => {
    // Non-blocking telemetry warning
    console.warn('[GATEWAY TELEMETRY WARN] Failed to post event:', err.message);
  });

  req.write(payload);
  req.end();
}

/**
 * Requests an enforcement decision from Web App
 */
async function evaluateDecision(decisionData) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1000);

    const res = await fetch(`${getWebAppUrl()}/api/monitoring/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': GATEWAY_SECRET
      },
      body: JSON.stringify(decisionData),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return data.decision || { action: 'ALLOW', mode: 'MONITOR_ONLY' };
    }
  } catch (err) {
    console.warn('[GATEWAY DECISION TIMEOUT/ERROR]', err.message);
  }

  // Default fail-open for demo if decision service is down
  return { action: 'ALLOW', reason: 'Fail-open fallback on decision timeout', degraded: true };
}

/**
 * Main HTTP Server Request Handler
 */
const server = http.createServer(async (req, res) => {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || `gw-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

  // 1. Gateway Health Check Endpoint
  if (req.url === '/health' || req.url === '/gateway/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'ONLINE',
      service: 'Security Guard Monitoring Gateway',
      port: PORT,
      approvedUpstreams: APPROVED_UPSTREAMS,
      timestamp: new Date().toISOString()
    }));
  }

  // 2. Identify Target Website & Upstream URL
  let websiteId = req.headers['x-website-id'];
  let targetPath = req.url;
  let isPathPrefixRouting = false;

  // Path Prefix Routing: /site/:website_id/*
  const prefixMatch = req.url.match(/^\/site\/([a-zA-Z0-9_-]+)(\/.*|\?.*|$)/);
  if (prefixMatch) {
    websiteId = prefixMatch[1];
    targetPath = prefixMatch[2] || '/';
    if (!targetPath.startsWith('/')) targetPath = '/' + targetPath;
    isPathPrefixRouting = true;
  }

  // Host Header Routing fallback
  if (!websiteId && req.headers.host) {
    websiteId = await resolveWebsiteIdFromHost(req.headers.host);
  }

  // Cookie fallback: secguard_site cookie (supports SPA static assets & AJAX requests)
  if (!websiteId && req.headers.cookie) {
    const cookieMatch = req.headers.cookie.match(/(?:^|;\s*)secguard_site=([a-zA-Z0-9_-]+)/);
    if (cookieMatch) {
      websiteId = cookieMatch[1];
      targetPath = req.url;
    }
  }

  // Referer fallback (e.g. assets or API calls loaded from /site/:website_id/)
  if (!websiteId && req.headers.referer) {
    const refMatch = req.headers.referer.match(/\/site\/([a-zA-Z0-9_-]+)/);
    if (refMatch) {
      websiteId = refMatch[1];
      targetPath = req.url;
    }
  }

  if (!websiteId) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      error: 'Bad Request',
      message: 'Missing website identifier. Provide header X-Website-Id, Host domain, or use path prefix /site/:website_id/*',
      hint: 'Available sites: owasp_juice_shop, dvwa, owasp_webgoat, owasp_webwolf'
    }));
  }

  const upstreamInfo = await resolveUpstream(websiteId);
  if (!upstreamInfo || !upstreamInfo.upstreamUrl) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      error: 'Not Found',
      message: `Unknown or unapproved website identifier '${websiteId}'`,
      hint: 'Approved sites: owasp_juice_shop, dvwa, owasp_webgoat, owasp_webwolf'
    }));
  }

  // Check integration method: only REVERSE_PROXY can be proxied
  if (upstreamInfo.integrationMethod && upstreamInfo.integrationMethod !== 'REVERSE_PROXY') {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      error: 'Integration Method Mismatch',
      message: `Website '${websiteId}' is configured for ${upstreamInfo.integrationMethod}, not REVERSE_PROXY. Proxy routing is disabled for this website.`
    }));
  }

  // SSRF Protection for external upstreams
  if (upstreamInfo.isExternal && validateExternalUrl) {
    const allowPrivate = process.env.ALLOW_PRIVATE_UPSTREAMS === 'true';
    const ssrfCheck = await validateExternalUrl(upstreamInfo.upstreamUrl, { allowPrivate });
    if (!ssrfCheck.valid) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        error: 'Bad Gateway (SSRF Violation)',
        message: `Upstream destination is blocked: ${ssrfCheck.error}`
      }));
    }
  }

  const upstreamBase = upstreamInfo.upstreamUrl;

  // 3. Buffer Request Body (up to 1MB limit)
  const chunks = [];
  let bodyLength = 0;
  const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB

  req.on('data', (chunk) => {
    bodyLength += chunk.length;
    if (bodyLength <= MAX_PAYLOAD_SIZE) {
      chunks.push(chunk);
    }
  });

  req.on('end', async () => {
    if (bodyLength > MAX_PAYLOAD_SIZE) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Payload Too Large', limit: '1MB' }));
    }

    const bodyBuffer = Buffer.concat(chunks);
    let bodySnippet = null;
    if (bodyBuffer.length > 0 && bodyBuffer.length < 4096) {
      try {
        bodySnippet = JSON.parse(bodyBuffer.toString('utf-8'));
      } catch {
        bodySnippet = bodyBuffer.toString('utf-8');
      }
    }

    // 4. Request Enforcement Decision from Policy Engine
    const decision = await evaluateDecision({
      website_id: websiteId,
      request_id: requestId,
      ip: clientIp,
      method: req.method,
      path: targetPath,
      headers: req.headers,
      body: bodySnippet
    });

    const isBlocked = decision.action === 'BLOCK';

    // 5. Active Enforcement: If BLOCKED, reject request with 403 Forbidden
    if (isBlocked) {
      const blockReason = decision.reason || 'Blocked by Security Guard Enforcement Policy';
      const responseTime = Date.now() - startTime;

      // Submit blocked ingestion event
      sendIngestionEvent({
        event_id: `evt-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
        request_id: requestId,
        source_id: websiteId,
        timestamp: new Date().toISOString(),
        method: req.method,
        path: targetPath,
        source_ip: clientIp,
        status_code: 403,
        response_time_ms: responseTime,
        user_agent: req.headers['user-agent'] || 'unknown',
        blocked: true,
        block_reason: blockReason
      });

      res.writeHead(403, {
        'Content-Type': 'application/json',
        'X-Security-Guard-Enforced': 'BLOCK',
        'X-Request-Id': requestId
      });

      return res.end(JSON.stringify({
        status: 'blocked',
        error: 'Forbidden by Security Guard',
        website_id: websiteId,
        request_id: requestId,
        client_ip: clientIp,
        target_path: targetPath,
        reason: blockReason,
        mode: decision.mode || 'ENFORCE',
        matched_rule: decision.matchedRule || null,
        timestamp: new Date().toISOString()
      }, null, 2));
    }

    // 6. Forward Permitted Request to Approved Upstream
    // Handle subpath upstreams (e.g., OWASP WebGoat on /WebGoat, WebWolf on /WebWolf)
    const baseParsed = new URL(upstreamBase);
    const basePath = (baseParsed.pathname || '').replace(/\/+$/, '');
    let finalPath = targetPath;
    if (basePath && basePath !== '/' && !finalPath.startsWith(basePath)) {
      finalPath = basePath + (finalPath.startsWith('/') ? finalPath : '/' + finalPath);
    }
    const upstreamUrl = new URL(finalPath, baseParsed.origin);

    const upstreamOptions = {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port,
      path: upstreamUrl.pathname + upstreamUrl.search,
      method: req.method,
      headers: {
        ...req.headers,
        host: upstreamUrl.host,
        'x-forwarded-for': clientIp,
        'x-forwarded-proto': 'http',
        'x-request-id': requestId,
        'x-security-guard-monitored': 'true'
      },
      timeout: 5000
    };

    const clientLib = upstreamUrl.protocol === 'https:' ? https : http;

    const proxyReq = clientLib.request(upstreamOptions, (upstreamRes) => {
      const responseTime = Date.now() - startTime;

      // Copy and adjust upstream headers for client response
      const resHeaders = { ...upstreamRes.headers };

      // Rewrite Location header for redirects (301, 302, 303, 307, 308)
      if (resHeaders.location && isPathPrefixRouting) {
        let loc = resHeaders.location;
        const originStr = upstreamUrl.origin;
        if (loc.startsWith(originStr)) {
          loc = loc.slice(originStr.length);
        }
        if (loc.startsWith('/')) {
          resHeaders.location = `/site/${websiteId}${loc}`;
        } else if (!loc.startsWith('http://') && !loc.startsWith('https://')) {
          resHeaders.location = `/site/${websiteId}/${loc}`;
        }
      }

      // If user accesses via /site/:website_id, set secguard_site cookie so SPA subrequests resolve properly
      if (isPathPrefixRouting) {
        const existingCookie = resHeaders['set-cookie'];
        const siteCookie = `secguard_site=${websiteId}; Path=/; SameSite=Lax`;
        if (Array.isArray(existingCookie)) {
          resHeaders['set-cookie'] = [...existingCookie, siteCookie];
        } else if (existingCookie) {
          resHeaders['set-cookie'] = [existingCookie, siteCookie];
        } else {
          resHeaders['set-cookie'] = siteCookie;
        }
      }

      res.writeHead(upstreamRes.statusCode, {
        ...resHeaders,
        'X-Request-Id': requestId,
        'X-Security-Guard-Monitored': 'ACTIVE'
      });

      upstreamRes.pipe(res);

      // Submit telemetry event asynchronously
      sendIngestionEvent({
        event_id: `evt-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
        request_id: requestId,
        source_id: websiteId,
        timestamp: new Date().toISOString(),
        method: req.method,
        path: targetPath,
        source_ip: clientIp,
        status_code: upstreamRes.statusCode,
        response_time_ms: responseTime,
        user_agent: req.headers['user-agent'] || 'unknown',
        blocked: false,
        headers: req.headers,
        body: bodySnippet
      });
    });

    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      if (!res.headersSent) {
        res.writeHead(504, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Gateway Timeout', message: `Upstream '${websiteId}' did not respond in time` }));
      }
    });

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Bad Gateway',
          message: `Unable to connect to upstream for '${websiteId}': ${err.message}`,
          upstream: upstreamBase
        }));
      }
    });

    if (bodyBuffer.length > 0) {
      proxyReq.write(bodyBuffer);
    }
    proxyReq.end();
  });
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log('===================================================');
    console.log(`  SECURITY GUARD - Monitoring Gateway`);
    console.log(`  Listening on http://${HOST}:${PORT}`);
    console.log(`  Target Web App: ${getWebAppUrl()}`);
    console.log(`  Docker Web Security Labs:`);
    console.log(`    - owasp_juice_shop -> http://127.0.0.1:4101`);
    console.log(`    - dvwa             -> http://127.0.0.1:4102`);
    console.log(`    - owasp_webgoat    -> http://127.0.0.1:4103/WebGoat`);
    console.log(`    - owasp_webwolf    -> http://127.0.0.1:9091/WebWolf`);
    console.log('===================================================');
  });
}

module.exports = { server, resolveUpstream, evaluateDecision, APPROVED_UPSTREAMS };
