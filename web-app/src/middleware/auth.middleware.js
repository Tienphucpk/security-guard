const crypto = require('crypto');
const db = require('../services/database');

// Static API keys for lab demonstrations and CLI tools
const ADMIN_API_KEY = process.env.ALERT_ADMIN_KEY || 'secguard_admin_key_2026_demo';
const OPERATOR_API_KEY = process.env.ALERT_OPERATOR_KEY || 'secguard_operator_key_2026_demo';
const VIEWER_API_KEY = process.env.ALERT_VIEWER_KEY || 'secguard_viewer_key_2026_demo';
const AUTH_SECRET_KEY = process.env.AUTH_SECRET_KEY || 'secguard_auth_signing_secret_2026';

/**
 * Creates a cryptographic HMAC-SHA256 signature
 */
function createSignature(payload, secret = AUTH_SECRET_KEY) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

/**
 * Generates an HMAC session token for demonstration and test cases
 * Format: role.timestamp.signature
 */
function generateHmacToken(role = 'operator', ttlMs = 86400000, secret = AUTH_SECRET_KEY) {
  const expiresAt = Date.now() + ttlMs;
  const payload = `${role}.${expiresAt}`;
  const sig = createSignature(payload, secret);
  return `${payload}.${sig}`;
}

/**
 * Verifies static API keys and HMAC tokens
 * @param {string} token
 * @returns {{valid: boolean, role?: string, reason?: string}}
 */
function verifyCredentials(token) {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'missing' };
  }

  const cleanToken = token.trim();

  // 1. Check static configured API Keys
  if (cleanToken === ADMIN_API_KEY) {
    return { valid: true, role: 'admin' };
  }
  if (cleanToken === OPERATOR_API_KEY) {
    return { valid: true, role: 'operator' };
  }
  if (cleanToken === VIEWER_API_KEY) {
    return { valid: true, role: 'viewer' };
  }

  // 2. Check signed HMAC session tokens: role.expiresAt.signature
  const parts = cleanToken.split('.');
  if (parts.length === 3) {
    const [role, expiresAtStr, receivedSig] = parts;
    const expiresAt = parseInt(expiresAtStr, 10);

    if (isNaN(expiresAt)) {
      return { valid: false, reason: 'malformed' };
    }

    if (Date.now() > expiresAt) {
      return { valid: false, reason: 'expired' };
    }

    const payload = `${role}.${expiresAtStr}`;
    const expectedSig = createSignature(payload, AUTH_SECRET_KEY);

    // Timing-safe comparison to prevent side-channel timing attacks
    const sigA = Buffer.from(receivedSig, 'hex');
    const sigB = Buffer.from(expectedSig, 'hex');

    if (sigA.length === sigB.length && crypto.timingSafeEqual(sigA, sigB)) {
      return { valid: true, role };
    }
    return { valid: false, reason: 'invalid_signature' };
  }

  return { valid: false, reason: 'invalid_key' };
}

/**
 * Extracts session ID or bearer token from Request cookies or headers
 * @param {import('express').Request} req 
 * @returns {string|null}
 */
function extractToken(req) {
  // 1. Check HttpOnly cookie
  if (req.cookies && req.cookies.secguard_session) {
    return req.cookies.secguard_session;
  }

  // 2. Check Authorization header: Bearer <token>
  const authHeader = req.headers['authorization'];
  if (authHeader && typeof authHeader === 'string') {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match) {
      return match[1].trim();
    }
    return authHeader.trim();
  }

  // 3. Check custom API Key headers
  if (req.headers['x-api-key']) {
    return String(req.headers['x-api-key']).trim();
  }
  if (req.headers['x-admin-key']) {
    return String(req.headers['x-admin-key']).trim();
  }

  return null;
}

/**
 * Authenticates request via PostgreSQL session or API credentials
 * Attaches req.user = { id, username, email, role, isActive } on success
 */
async function authenticateRequest(req) {
  const token = extractToken(req);
  if (!token) {
    return { authenticated: false, reason: 'missing' };
  }

  // 1. Try PostgreSQL server-side session first
  try {
    const sessionRecord = await db.validateSession(token);
    if (sessionRecord && sessionRecord.user) {
      return {
        authenticated: true,
        user: sessionRecord.user,
        sessionId: token
      };
    }
  } catch (err) {
    // If DB check fails, continue to fallback credentials check
  }

  // 2. Check static API keys and cryptographic HMAC tokens (for lab/testing)
  const credCheck = verifyCredentials(token);
  if (credCheck.valid) {
    const roleNormalized = (credCheck.role || 'viewer').toUpperCase();
    return {
      authenticated: true,
      user: {
        id: roleNormalized === 'ADMIN' ? 1 : 999,
        username: credCheck.role,
        email: `${credCheck.role}@securityguard.local`,
        role: roleNormalized,
        isActive: true
      },
      sessionId: null
    };
  }

  return {
    authenticated: false,
    reason: credCheck.reason || 'invalid'
  };
}

/**
 * Middleware: Enforces that user is authenticated (session or valid token)
 */
function requireAuth(req, res, next) {
  authenticateRequest(req)
    .then((authResult) => {
      if (!authResult.authenticated) {
        const isExpired = authResult.reason === 'expired';
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: isExpired
            ? 'Session or token has expired. Please log in again.'
            : 'Authentication required. Please log in.'
        });
      }

      req.user = authResult.user;
      req.sessionId = authResult.sessionId;
      next();
    })
    .catch((err) => {
      return res.status(500).json({
        status: 'error',
        error: 'Internal Server Error',
        message: 'Authentication check failed: ' + err.message
      });
    });
}

/**
 * Middleware: Enforces Role-Based Access Control (RBAC)
 * @param {string[]} allowedRoles e.g. ['ADMIN']
 */
function requireRole(allowedRoles = ['ADMIN']) {
  const normalizedAllowed = allowedRoles.map(r => String(r).toUpperCase());

  return (req, res, next) => {
    // First ensure user is authenticated
    if (!req.user || !req.user.role) {
      return requireAuth(req, res, () => {
        checkRole(req, res, next, normalizedAllowed);
      });
    }

    checkRole(req, res, next, normalizedAllowed);
  };
}

function checkRole(req, res, next, normalizedAllowed) {
  const userRole = String(req.user.role).toUpperCase();
  if (!normalizedAllowed.includes(userRole)) {
    return res.status(403).json({
      status: 'error',
      error: 'Forbidden',
      message: `Insufficient permissions: role '${req.user.role}' is not authorized. Required roles: ${normalizedAllowed.join(', ')}`
    });
  }
  next();
}

/**
 * Middleware: Protects Alert Mutation Endpoints
 * Supports both Phase 9.1 keys ('admin', 'operator') and Phase 9 RBAC ('ADMIN')
 * Rejects 'ANALYST' and 'VIEWER' with 403 Forbidden
 * Rejects unauthenticated requests with 401 Unauthorized
 */
function requireAlertAuth(allowedRoles = ['admin', 'operator', 'ADMIN']) {
  const normalizedAllowed = allowedRoles.map(r => String(r).toUpperCase());

  return async (req, res, next) => {
    const authResult = await authenticateRequest(req);
    if (!authResult.authenticated) {
      let msg = 'Invalid authentication credentials';
      if (authResult.reason === 'missing') {
        msg = 'Authentication required to mutate security alerts';
      } else if (authResult.reason === 'expired') {
        msg = 'Authentication credentials have expired';
      }
      return res.status(401).json({
        status: 'error',
        error: 'Unauthorized',
        message: msg
      });
    }

    const roleUpper = String(authResult.user.role).toUpperCase();
    if (!normalizedAllowed.includes(roleUpper)) {
      return res.status(403).json({
        status: 'error',
        error: 'Forbidden',
        message: `Insufficient permissions: role '${authResult.user.role}' cannot mutate alerts. Required roles: admin, operator`
      });
    }

    req.user = authResult.user;
    req.sessionId = authResult.sessionId;
    next();
  };
}

/**
 * Middleware: Validates that :id route parameter is a positive integer
 */
function validateAlertIdParam(req, res, next) {
  const idStr = req.params.id;
  const parsedId = parseInt(idStr, 10);

  if (isNaN(parsedId) || parsedId <= 0 || String(parsedId) !== String(idStr).trim()) {
    return res.status(400).json({
      status: 'error',
      error: 'Bad Request',
      message: 'Invalid alert ID parameter. Must be a positive integer.'
    });
  }

  req.validatedAlertId = parsedId;
  next();
}

module.exports = {
  requireAuth,
  requireRole,
  requireAlertAuth,
  validateAlertIdParam,
  verifyCredentials,
  generateHmacToken,
  authenticateRequest,
  ADMIN_API_KEY,
  OPERATOR_API_KEY,
  VIEWER_API_KEY
};
