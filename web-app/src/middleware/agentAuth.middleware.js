const crypto = require('crypto');
const db = require('../services/database');

const DEFAULT_GATEWAY_SECRET = process.env.GATEWAY_SHARED_SECRET || 'secguard_gateway_internal_secret_2026';

/**
 * Timing-safe string comparison
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Middleware: Validates that the request comes from an authorized Monitoring Gateway / Agent
 * Checks X-Gateway-Secret, X-Agent-Secret, or Authorization: Bearer <secret>
 */
async function requireAgentAuth(req, res, next) {
  const secretHeader = req.headers['x-gateway-secret'] ||
                       req.headers['x-agent-secret'] ||
                       (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7).trim() : null);

  if (!secretHeader) {
    return res.status(401).json({
      status: 'error',
      error: 'Unauthorized',
      message: 'Missing Gateway / Agent authentication credentials'
    });
  }

  // 1. Verify against default configured system gateway secret
  if (safeCompare(secretHeader, DEFAULT_GATEWAY_SECRET)) {
    req.agent = { type: 'GATEWAY_CORE', id: 'system_gateway' };
    return next();
  }

  // 2. Check if this is a per-website custom agent secret
  const websiteId = req.headers['x-website-id'] || req.body?.source_id || req.body?.website_id;
  if (websiteId) {
    try {
      const site = await db.getWebsiteById(websiteId);
      if (site && site.agentSecretHash) {
        // Calculate hash of provided secret
        const hash = crypto.createHash('sha256').update(secretHeader).digest('hex');
        if (safeCompare(hash, site.agentSecretHash)) {
          req.agent = { type: 'WEBSITE_AGENT', websiteId: site.websiteId };
          return next();
        }
      }
    } catch {}
  }

  return res.status(401).json({
    status: 'error',
    error: 'Unauthorized',
    message: 'Invalid Gateway / Agent authentication credentials'
  });
}

module.exports = {
  requireAgentAuth,
  DEFAULT_GATEWAY_SECRET
};
