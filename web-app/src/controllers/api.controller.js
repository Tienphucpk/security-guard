const db = require('../services/database');
const alertStream = require('../services/alertStream');
const {
  getLogsFromFileFallback,
  getLogStatsFromFileFallback,
  getAlertsFromFileFallback,
  getAlertByIdFromFileFallback,
  getAlertStatsFromFileFallback,
  updateAlertStatusInFileFallback
} = require('../utils/logger');

const VALID_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);

/**
 * Controller handling JSON API endpoints for SECURITY GUARD Web Application
 */
const apiController = {
  /**
   * Health check endpoint reporting service & database connection state
   */
  health: async (req, res) => {
    try {
      const dbHealth = await db.checkHealth();
      const isConnected = dbHealth.connected;

      res.status(200).json({
        status: isConnected ? 'ok' : 'degraded',
        service: 'web-app',
        database: isConnected ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    } catch {
      res.status(200).json({
        status: 'degraded',
        service: 'web-app',
        database: 'disconnected',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    }
  },

  /**
   * Retrieves request logs with pagination and filters
   * Falls back gracefully to requests.log if PostgreSQL is offline
   */
  getRecentLogs: async (req, res) => {
    try {
      // Input sanitization & validation
      let page = parseInt(req.query.page, 10);
      if (isNaN(page) || page < 1) page = 1;

      let limit = parseInt(req.query.limit, 10);
      if (isNaN(limit) || limit < 1) limit = 50;
      if (limit > 100) limit = 100; // Enforce maximum 100 items per request

      const { ip, from, to } = req.query;

      let method = req.query.method ? String(req.query.method).toUpperCase().trim() : undefined;
      if (method && !VALID_METHODS.has(method)) {
        return res.status(400).json({
          status: 'error',
          message: `Invalid HTTP method: ${method}. Allowed methods: ${Array.from(VALID_METHODS).join(', ')}`
        });
      }

      let statusCode = req.query.statusCode !== undefined ? parseInt(req.query.statusCode, 10) : undefined;
      if (statusCode !== undefined && (isNaN(statusCode) || statusCode < 100 || statusCode > 599)) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid statusCode. Must be an integer between 100 and 599.'
        });
      }

      // 1. Try querying PostgreSQL
      try {
        const result = await db.getLogs({ page, limit, ip, method, statusCode, from, to });
        return res.status(200).json({
          status: 'ok',
          source: 'database',
          page: result.page,
          limit: result.limit,
          count: result.count,
          total: result.total,
          logs: result.logs
        });
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database query failed, using requests.log fallback:', dbErr.message);
      }

      // 2. Graceful degradation: Fallback to requests.log
      const fileResult = getLogsFromFileFallback({ page, limit, ip, method, statusCode });
      return res.status(200).json({
        status: 'ok',
        source: 'file_fallback',
        page: fileResult.page,
        limit: fileResult.limit,
        count: fileResult.count,
        total: fileResult.total,
        logs: fileResult.logs
      });
    } catch (err) {
      console.error('[API ERROR] Failed to fetch logs:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while retrieving request logs'
      });
    }
  },

  /**
   * Log statistics summary endpoint
   * Computes totals, status distributions, unique IPs, and top routes
   */
  getStats: async (req, res) => {
    try {
      // 1. Try querying PostgreSQL
      try {
        const stats = await db.getLogStats();
        return res.status(200).json({
          status: 'ok',
          source: 'database',
          stats
        });
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database stats failed, using requests.log fallback:', dbErr.message);
      }

      // 2. Graceful degradation: Compute from requests.log
      const fileStats = getLogStatsFromFileFallback();
      return res.status(200).json({
        status: 'ok',
        source: 'file_fallback',
        stats: fileStats
      });
    } catch (err) {
      console.error('[API ERROR] Failed to compute stats:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while calculating log statistics'
      });
    }
  },

  /**
   * Retrieves security alerts with pagination and filters
   * Falls back gracefully to alerts.log if PostgreSQL is offline
   */
  /**
   * Retrieves security alerts with pagination, filters, and sorting
   * Falls back gracefully to alerts.log if PostgreSQL is offline
   */
  getAlerts: async (req, res) => {
    try {
      let page = parseInt(req.query.page, 10);
      if (isNaN(page) || page < 1) page = 1;

      let limit = parseInt(req.query.limit, 10);
      if (isNaN(limit) || limit < 1) limit = 50;
      if (limit > 100) limit = 100; // Enforce maximum 100 items

      const { severity, type, status, ip, from, to } = req.query;

      let sort = req.query.sort ? String(req.query.sort).toLowerCase().trim() : 'newest';
      const validSorts = new Set(['newest', 'oldest', 'risk_desc', 'risk_asc']);
      if (!validSorts.has(sort)) {
        sort = 'newest';
      }

      // 1. Try querying PostgreSQL
      try {
        const result = await db.getAlerts({ page, limit, severity, type, status, ip, from, to, sort });
        return res.status(200).json({
          status: 'ok',
          source: 'database',
          page: result.page,
          limit: result.limit,
          count: result.count,
          total: result.total,
          totalPages: result.totalPages || (result.total > 0 ? Math.ceil(result.total / limit) : 0),
          alerts: result.alerts
        });
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database alerts query failed, using alerts.log fallback:', dbErr.message);
      }

      // 2. Graceful degradation: Fallback to alerts.log
      const fileResult = getAlertsFromFileFallback({ page, limit, severity, type, status, ip, sort });
      return res.status(200).json({
        status: 'ok',
        source: 'file_fallback',
        page: fileResult.page,
        limit: fileResult.limit,
        count: fileResult.count,
        total: fileResult.total,
        totalPages: fileResult.totalPages || (fileResult.total > 0 ? Math.ceil(fileResult.total / limit) : 0),
        alerts: fileResult.alerts
      });
    } catch (err) {
      console.error('[API ERROR] Failed to fetch alerts:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while retrieving security alerts'
      });
    }
  },

  /**
   * Retrieves a single security alert by ID (including linked request_log if available)
   */
  getAlertById: async (req, res) => {
    try {
      const alertId = req.params.id;

      // 1. Try querying PostgreSQL
      try {
        const alert = await db.getAlertById(alertId);
        if (alert) {
          return res.status(200).json({
            status: 'ok',
            source: 'database',
            alert
          });
        }
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database alert by id failed, using alerts.log fallback:', dbErr.message);
      }

      // 2. Graceful degradation: Fallback to alerts.log
      const fileAlert = getAlertByIdFromFileFallback(alertId);
      if (fileAlert) {
        return res.status(200).json({
          status: 'ok',
          source: 'file_fallback',
          alert: fileAlert
        });
      }

      return res.status(404).json({
        status: 'error',
        message: `Security alert with ID ${alertId} not found`
      });
    } catch (err) {
      console.error('[API ERROR] Failed to fetch alert by ID:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while retrieving alert'
      });
    }
  },

  /**
   * Alert statistics summary endpoint
   */
  getAlertStats: async (req, res) => {
    try {
      // 1. Try querying PostgreSQL
      try {
        const stats = await db.getAlertStats();
        return res.status(200).json({
          status: 'ok',
          source: 'database',
          stats
        });
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database alert stats failed, using alerts.log fallback:', dbErr.message);
      }

      // 2. Graceful degradation: Compute from alerts.log
      const fileStats = getAlertStatsFromFileFallback();
      return res.status(200).json({
        status: 'ok',
        source: 'file_fallback',
        stats: fileStats
      });
    } catch (err) {
      console.error('[API ERROR] Failed to compute alert stats:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while calculating alert statistics'
      });
    }
  },

  /**
   * Real-time Server-Sent Events stream for Security Alerts
   */
  streamAlerts: (req, res) => {
    alertStream.addClient(req, res);
  },

  /**
   * Acknowledges a security alert (status -> acknowledged)
   */
  acknowledgeAlert: async (req, res) => {
    try {
      const alertId = req.params.id;
      if (!alertId) {
        return res.status(400).json({ status: 'error', message: 'Alert ID is required' });
      }

      let updated = null;
      try {
        updated = await db.updateAlertStatus(alertId, 'acknowledged');
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database update alert failed, using file fallback:', dbErr.message);
      }

      if (!updated) {
        updated = updateAlertStatusInFileFallback(alertId, 'acknowledged');
      }

      if (!updated) {
        return res.status(404).json({
          status: 'error',
          message: `Security alert with ID ${alertId} not found`
        });
      }

      // Broadcast real-time update to all active SSE subscribers
      try {
        alertStream.broadcast('alert_updated', updated);
      } catch (sseErr) {
        console.error('[SSE BROADCAST ERROR]', sseErr.message);
      }

      return res.status(200).json({
        status: 'ok',
        message: 'Alert acknowledged successfully',
        alert: updated
      });
    } catch (err) {
      console.error('[API ERROR] Failed to acknowledge alert:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while acknowledging alert'
      });
    }
  },

  /**
   * Resolves a security alert (status -> resolved)
   */
  resolveAlert: async (req, res) => {
    try {
      const alertId = req.params.id;
      if (!alertId) {
        return res.status(400).json({ status: 'error', message: 'Alert ID is required' });
      }

      let updated = null;
      try {
        updated = await db.updateAlertStatus(alertId, 'resolved');
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database update alert failed, using file fallback:', dbErr.message);
      }

      if (!updated) {
        updated = updateAlertStatusInFileFallback(alertId, 'resolved');
      }

      if (!updated) {
        return res.status(404).json({
          status: 'error',
          message: `Security alert with ID ${alertId} not found`
        });
      }

      // Broadcast real-time update to all active SSE subscribers
      try {
        alertStream.broadcast('alert_updated', updated);
      } catch (sseErr) {
        console.error('[SSE BROADCAST ERROR]', sseErr.message);
      }

      return res.status(200).json({
        status: 'ok',
        message: 'Alert resolved successfully',
        alert: updated
      });
    } catch (err) {
      console.error('[API ERROR] Failed to resolve alert:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while resolving alert'
      });
    }
  },

  /**
   * Generic status transition for a security alert (e.g. reopen or custom)
   */
  updateAlertStatus: async (req, res) => {
    try {
      const alertId = req.params.id;
      const { status } = req.body || {};
      const validStatuses = ['new', 'acknowledged', 'resolved'];
      if (!status || !validStatuses.includes(String(status).toLowerCase())) {
        return res.status(400).json({
          status: 'error',
          message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
        });
      }

      const normalizedStatus = String(status).toLowerCase();
      let updated = null;
      try {
        updated = await db.updateAlertStatus(alertId, normalizedStatus);
      } catch (dbErr) {
        console.warn('[DB FALLBACK] Database update alert failed, using file fallback:', dbErr.message);
      }

      if (!updated) {
        updated = updateAlertStatusInFileFallback(alertId, normalizedStatus);
      }

      if (!updated) {
        return res.status(404).json({
          status: 'error',
          message: `Security alert with ID ${alertId} not found`
        });
      }

      try {
        alertStream.broadcast('alert_updated', updated);
      } catch (sseErr) {
        console.error('[SSE BROADCAST ERROR]', sseErr.message);
      }

      return res.status(200).json({
        status: 'ok',
        message: `Alert status updated to ${normalizedStatus}`,
        alert: updated
      });
    } catch (err) {
      console.error('[API ERROR] Failed to update alert status:', err.message);
      return res.status(500).json({
        status: 'error',
        message: 'Internal server error while updating alert status'
      });
    }
  }
};

module.exports = apiController;
