const crypto = require('crypto');
const db = require('../services/database');
const { 
  safeCompare, 
  hashSecret, 
  decryptSecret, 
  verifyHmacSignature,
  MAX_TIMESTAMP_SKEW_SEC 
} = require('../services/agentAuthService');

const DEFAULT_GATEWAY_SECRET = process.env.GATEWAY_SHARED_SECRET || 'secguard_gateway_internal_secret_2026';

/**
 * Middleware: Validates that the request comes from an authorized Monitoring Gateway or Application Agent
 * Supports:
 *  1. System Gateway secret (X-Gateway-Secret or Bearer)
 *  2. HMAC signature (X-Agent-Signature: t=<timestamp>,v1=<signature>)
 *  3. Per-website custom agent secret (X-Agent-Secret or Bearer) with optional replay timestamp
 */
async function requireAgentAuth(req, res, next) {
  const gatewaySecret = req.headers['x-gateway-secret'];
  const agentSecret = req.headers['x-agent-secret'];
  const agentSignature = req.headers['x-agent-signature'];
  const bearerSecret = req.headers['authorization']?.startsWith('Bearer ') 
    ? req.headers['authorization'].slice(7).trim() 
    : null;

  const candidateSecret = gatewaySecret || agentSecret || bearerSecret;

  // 1. Check system default Gateway Secret
  if (candidateSecret && safeCompare(candidateSecret, DEFAULT_GATEWAY_SECRET)) {
    req.agent = { type: 'GATEWAY_CORE', id: 'system_gateway' };
    return next();
  }

  const websiteId = req.headers['x-website-id'] || req.body?.source_id || req.body?.website_id || req.body?.websiteId;

  // 2. Check HMAC signature if provided
  if (agentSignature) {
    if (!websiteId) {
      return res.status(401).json({
        status: 'error',
        error: 'Unauthorized',
        message: 'X-Website-Id header or website_id body field is required when using HMAC signature'
      });
    }

    try {
      const site = await db.getWebsiteById(websiteId);
      if (!site) {
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: `Unknown or unregistered website ID: ${websiteId}`
        });
      }

      if (!site.isActive) {
        return res.status(403).json({
          status: 'error',
          error: 'Forbidden',
          message: `Website ${websiteId} is currently deactivated`
        });
      }

      const plaintextSecret = decryptSecret(site.encryptedAgentSecret);
      if (!plaintextSecret) {
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: 'Website has no valid agent secret configured'
        });
      }

      const result = verifyHmacSignature(req.body, agentSignature, plaintextSecret);
      if (!result.valid) {
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: result.error || 'Invalid HMAC signature'
        });
      }

      req.agent = { type: 'WEBSITE_AGENT', websiteId: site.websiteId, authMethod: 'HMAC_SIGNATURE' };
      return next();
    } catch (err) {
      return res.status(500).json({ status: 'error', message: err.message });
    }
  }

  // 3. Check Per-website custom agent secret (direct header)
  if (candidateSecret) {
    if (websiteId) {
      try {
        const site = await db.getWebsiteById(websiteId);
        if (!site) {
          return res.status(401).json({
            status: 'error',
            error: 'Unauthorized',
            message: `Unknown or unregistered website ID: ${websiteId}`
          });
        }

        if (!site.isActive) {
          return res.status(403).json({
            status: 'error',
            error: 'Forbidden',
            message: `Website ${websiteId} is currently deactivated`
          });
        }

        // Check timestamp replay if X-Agent-Timestamp is provided
        const timestampHeader = req.headers['x-agent-timestamp'];
        if (timestampHeader) {
          const ts = parseInt(timestampHeader, 10);
          const now = Math.floor(Date.now() / 1000);
          if (isNaN(ts) || Math.abs(now - ts) > MAX_TIMESTAMP_SKEW_SEC) {
            return res.status(401).json({
              status: 'error',
              error: 'Unauthorized',
              message: 'Request timestamp expired or replay detected (> 300s skew)'
            });
          }
        }

        if (site.agentSecretHash) {
          const hash = hashSecret(candidateSecret);
          if (safeCompare(hash, site.agentSecretHash)) {
            req.agent = { type: 'WEBSITE_AGENT', websiteId: site.websiteId, authMethod: 'AGENT_SECRET' };
            return next();
          }
        }
      } catch (err) {
        return res.status(500).json({ status: 'error', message: err.message });
      }
    }
  }

  return res.status(401).json({
    status: 'error',
    error: 'Unauthorized',
    message: 'Missing or invalid Gateway / Agent authentication credentials'
  });
}

module.exports = {
  requireAgentAuth,
  DEFAULT_GATEWAY_SECRET
};
