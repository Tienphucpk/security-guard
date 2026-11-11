const express = require('express');
const router = express.Router();
const apiController = require('../controllers/api.controller');
const authController = require('../controllers/auth.controller');
const userController = require('../controllers/user.controller');
const monitoringController = require('../controllers/monitoring.controller');
const {
  requireAuth,
  requireRole,
  requireAlertAuth,
  validateAlertIdParam
} = require('../middleware/auth.middleware');
const { requireAgentAuth } = require('../middleware/agentAuth.middleware');

// Health and monitoring
router.get('/health', apiController.health);

// Request Logs APIs
router.get('/logs/stats', apiController.getStats);
router.get('/logs', apiController.getRecentLogs);

// Security Alerts APIs (Phase 3 & Phase 4)
router.get('/alerts/stats', apiController.getAlertStats);
router.get('/alerts/stream', apiController.streamAlerts);

// Protected Alert Mutation Routes (Phase 9 Authentication & RBAC)
// Allowed: ADMIN role (session) or admin/operator API keys; Denied: ANALYST role (403), unauthenticated (401)
router.patch('/alerts/:id/acknowledge', validateAlertIdParam, requireAlertAuth(['admin', 'operator', 'ADMIN']), apiController.acknowledgeAlert);
router.patch('/alerts/:id/resolve', validateAlertIdParam, requireAlertAuth(['admin', 'operator', 'ADMIN']), apiController.resolveAlert);
router.patch('/alerts/:id/status', validateAlertIdParam, requireAlertAuth(['admin', 'operator', 'ADMIN']), apiController.updateAlertStatus);

router.get('/alerts/:id', apiController.getAlertById);
router.get('/alerts', apiController.getAlerts);

// ==============================================================================
// Phase 9: Authentication & Session APIs
// ==============================================================================
router.post('/auth/login', authController.apiLogin);
router.post('/auth/logout', authController.apiLogout);
router.get('/auth/me', requireAuth, authController.apiMe);

// ==============================================================================
// Phase 9: User Management APIs (Strictly Restricted to ADMIN)
// ==============================================================================
router.get('/users', requireAuth, requireRole(['ADMIN']), userController.listUsers);
router.post('/users', requireAuth, requireRole(['ADMIN']), userController.createUser);
router.patch('/users/:id/status', requireAuth, requireRole(['ADMIN']), userController.updateUserStatus);
router.patch('/users/:id/role', requireAuth, requireRole(['ADMIN']), userController.updateUserRole);

// ==============================================================================
// Phase 10: Multi-Website Monitoring & Active Enforcement APIs
// ==============================================================================

// Gateway Agent-authenticated APIs
router.post('/monitoring/decision', requireAgentAuth, monitoringController.makeDecision);
router.post('/ingest/events', requireAgentAuth, monitoringController.ingestEvents);
router.post('/ingest/logs', requireAgentAuth, monitoringController.ingestLogs);

// Flexible auth: allows either ADMIN/ANALYST session cookie OR Gateway core secret
const requireUserOrGatewayAuth = (req, res, next) => {
  const gwSecret = req.headers['x-gateway-secret'];
  const defaultSecret = process.env.GATEWAY_SHARED_SECRET || 'secguard_gateway_internal_secret_2026';
  if (gwSecret && gwSecret === defaultSecret) {
    return next();
  }
  return requireAuth(req, res, () => {
    requireRole(['ADMIN', 'ANALYST'])(req, res, next);
  });
};

// Website Registry & Management APIs (RBAC: ADMIN full, ANALYST read-only)
router.get('/websites', requireUserOrGatewayAuth, monitoringController.listWebsites);
router.post('/websites', requireAuth, requireRole(['ADMIN']), monitoringController.registerWebsite);
router.post('/websites/external', requireAuth, requireRole(['ADMIN']), monitoringController.registerExternalWebsite);
router.post('/websites/:id/rotate-secret', requireAuth, requireRole(['ADMIN']), monitoringController.rotateSecret);
router.post('/websites/:id/verify', requireAuth, requireRole(['ADMIN', 'ANALYST']), monitoringController.verifyWebsiteHealth);
router.patch('/websites/:id', requireAuth, requireRole(['ADMIN']), monitoringController.updateWebsite);
router.get('/websites/audit', requireAuth, requireRole(['ADMIN', 'ANALYST']), monitoringController.listAudit);
router.get('/monitoring/evidence', requireAuth, requireRole(['ADMIN', 'ANALYST']), monitoringController.listEvidence);
router.get('/websites/:id/policies', requireAuth, requireRole(['ADMIN', 'ANALYST']), monitoringController.listPolicies);
router.post('/websites/:id/policies', requireAuth, requireRole(['ADMIN']), monitoringController.createPolicy);
router.delete('/websites/:id/policies/:policyId', requireAuth, requireRole(['ADMIN']), monitoringController.deletePolicy);

module.exports = router;
