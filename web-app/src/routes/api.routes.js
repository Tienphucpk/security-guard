const express = require('express');
const router = express.Router();
const apiController = require('../controllers/api.controller');
const authController = require('../controllers/auth.controller');
const userController = require('../controllers/user.controller');
const {
  requireAuth,
  requireRole,
  requireAlertAuth,
  validateAlertIdParam
} = require('../middleware/auth.middleware');

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

module.exports = router;
