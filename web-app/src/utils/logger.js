const fs = require('fs');
const path = require('path');
const db = require('../services/database');
const detectionClient = require('../services/detectionClient');

const logDir = path.resolve(__dirname, '../../logs');
const logFile = path.join(logDir, 'requests.log');
const alertLogFile = path.join(logDir, 'alerts.log');

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

/**
 * Write log entry to console, file, and PostgreSQL
 * Operates with graceful degradation (never crashes on IO or DB error)
 * @param {Object} logData
 */
function logRequest(logData) {
  const logLine = JSON.stringify(logData);

  // 1. Standard console output
  console.log(`[HTTP LOG] ${logLine}`);

  // 2. Append to log file (asynchronous)
  try {
    fs.appendFile(logFile, logLine + '\n', (err) => {
      if (err) {
        console.error('[LOGGER ERROR] Failed to write to log file:', err.message);
      }
    });
  } catch (err) {
    console.error('[LOGGER ERROR] File system write exception:', err.message);
  }

  // 3. Persist to PostgreSQL (non-blocking) and forward to Detection Engine
  db.insertRequestLog(logData)
    .then((res) => {
      const entryToForward = { ...logData, id: res && res.id ? res.id : undefined };
      detectionClient.forwardLog(entryToForward).catch(() => {});
    })
    .catch((err) => {
      console.warn('[DB ERROR] Unhandled insert error:', err.message);
      // Even if DB fails, forward to Detection Engine for analysis
      detectionClient.forwardLog(logData).catch(() => {});
    });
}

/**
 * Read and parse logs from requests.log as fallback when database is offline
 * @param {Object} options
 * @returns {{logs: Array, total: number, page: number, limit: number, count: number}}
 */
function getLogsFromFileFallback({ page = 1, limit = 50, ip, method, statusCode } = {}) {
  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));

  if (!fs.existsSync(logFile)) {
    return { logs: [], total: 0, page: safePage, limit: safeLimit, count: 0 };
  }

  try {
    const raw = fs.readFileSync(logFile, 'utf-8');
    const lines = raw.trim().split('\n').filter(Boolean);
    let parsed = [];

    for (let i = 0; i < lines.length; i++) {
      try {
        const item = JSON.parse(lines[i]);
        item.id = i + 1;
        parsed.push(item);
      } catch {
        // Skip corrupted line
      }
    }

    // Filter by criteria
    if (ip) {
      const searchIp = String(ip).trim().toLowerCase();
      parsed = parsed.filter(l => (l.ip || '').toLowerCase() === searchIp);
    }

    if (method) {
      const searchMethod = String(method).trim().toUpperCase();
      parsed = parsed.filter(l => (l.method || '').toUpperCase() === searchMethod);
    }

    if (statusCode !== undefined && statusCode !== null && statusCode !== '') {
      const searchCode = parseInt(statusCode, 10);
      if (!isNaN(searchCode)) {
        parsed = parsed.filter(l => parseInt(l.statusCode, 10) === searchCode);
      }
    }

    const total = parsed.length;
    // Sort descending by timestamp (newest first)
    parsed.reverse();

    const offset = (safePage - 1) * safeLimit;
    const paginated = parsed.slice(offset, offset + safeLimit);

    return {
      logs: paginated,
      total,
      page: safePage,
      limit: safeLimit,
      count: paginated.length
    };
  } catch (err) {
    console.error('[LOGGER ERROR] Failed reading file fallback:', err.message);
    return { logs: [], total: 0, page: safePage, limit: safeLimit, count: 0 };
  }
}

/**
 * Compute statistics from requests.log as fallback when database is offline
 * @returns {Object}
 */
function getLogStatsFromFileFallback() {
  if (!fs.existsSync(logFile)) {
    return {
      totalRequests: 0,
      successfulRequests: 0,
      clientErrors: 0,
      serverErrors: 0,
      uniqueIps: 0,
      topIps: [],
      topPaths: [],
      httpMethods: {}
    };
  }

  try {
    const raw = fs.readFileSync(logFile, 'utf-8');
    const lines = raw.trim().split('\n').filter(Boolean);

    let totalRequests = 0;
    let successfulRequests = 0;
    let clientErrors = 0;
    let serverErrors = 0;
    const ipCounts = {};
    const pathCounts = {};
    const methodCounts = {};

    for (const line of lines) {
      try {
        const l = JSON.parse(line);
        totalRequests++;

        const code = parseInt(l.statusCode, 10) || 200;
        if (code >= 200 && code < 300) successfulRequests++;
        else if (code >= 400 && code < 500) clientErrors++;
        else if (code >= 500 && code < 600) serverErrors++;

        const ip = l.ip || 'unknown';
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;

        const pathUrl = (l.url || '/').split('?')[0];
        pathCounts[pathUrl] = (pathCounts[pathUrl] || 0) + 1;

        const m = (l.method || 'GET').toUpperCase();
        methodCounts[m] = (methodCounts[m] || 0) + 1;
      } catch {
        // Skip bad line
      }
    }

    const topIps = Object.entries(ipCounts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const topPaths = Object.entries(pathCounts)
      .map(([url, count]) => ({ url, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalRequests,
      successfulRequests,
      clientErrors,
      serverErrors,
      uniqueIps: Object.keys(ipCounts).length,
      topIps,
      topPaths,
      httpMethods: methodCounts
    };
  } catch (err) {
    console.error('[LOGGER ERROR] Failed computing file fallback stats:', err.message);
    return {
      totalRequests: 0,
      successfulRequests: 0,
      clientErrors: 0,
      serverErrors: 0,
      uniqueIps: 0,
      topIps: [],
      topPaths: [],
      httpMethods: {}
    };
  }
}

/**
 * Read and parse alerts from alerts.log as fallback when database is offline
 * @param {Object} options
 * @returns {{alerts: Array, total: number, page: number, limit: number, count: number}}
 */
function getAlertsFromFileFallback({ page = 1, limit = 50, severity, type, status, ip } = {}) {
  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));

  if (!fs.existsSync(alertLogFile)) {
    return { alerts: [], total: 0, page: safePage, limit: safeLimit, count: 0 };
  }

  try {
    const raw = fs.readFileSync(alertLogFile, 'utf-8');
    const lines = raw.trim().split('\n').filter(Boolean);
    let parsed = [];

    for (let i = 0; i < lines.length; i++) {
      try {
        const item = JSON.parse(lines[i]);
        item.id = i + 1;
        parsed.push(item);
      } catch {
        // Skip corrupted line
      }
    }

    if (ip) {
      const searchIp = String(ip).trim().toLowerCase();
      parsed = parsed.filter(a => (a.sourceIp || a.ip || '').toLowerCase() === searchIp);
    }

    if (severity) {
      const searchSev = String(severity).trim().toUpperCase();
      parsed = parsed.filter(a => (a.severity || '').toUpperCase() === searchSev);
    }

    if (type) {
      const searchType = String(type).trim().toUpperCase();
      parsed = parsed.filter(a => (a.alertType || '').toUpperCase() === searchType);
    }

    if (status) {
      const searchStat = String(status).trim().toLowerCase();
      parsed = parsed.filter(a => (a.status || 'new').toLowerCase() === searchStat);
    }

    const total = parsed.length;
    const totalPages = Math.ceil(total / safeLimit) || 1;

    // Sorting
    if (sort === 'oldest') {
      parsed.sort((a, b) => new Date(a.createdAt || a.timestamp) - new Date(b.createdAt || b.timestamp));
    } else if (sort === 'risk_desc') {
      parsed.sort((a, b) => (parseFloat(b.riskScore || b.risk_score) || 0) - (parseFloat(a.riskScore || a.risk_score) || 0));
    } else if (sort === 'risk_asc') {
      parsed.sort((a, b) => (parseFloat(a.riskScore || a.risk_score) || 0) - (parseFloat(b.riskScore || b.risk_score) || 0));
    } else {
      // Default: newest first
      parsed.sort((a, b) => new Date(b.createdAt || b.timestamp) - new Date(a.createdAt || a.timestamp));
    }

    const offset = (safePage - 1) * safeLimit;
    const paginated = parsed.slice(offset, offset + safeLimit).map(a => ({
      ...a,
      updatedAt: a.updatedAt || a.updated_at || a.createdAt || a.timestamp
    }));

    return {
      alerts: paginated,
      total,
      totalPages,
      page: safePage,
      limit: safeLimit,
      count: paginated.length
    };
  } catch (err) {
    console.error('[LOGGER ERROR] Failed reading alert fallback:', err.message);
    return { alerts: [], total: 0, totalPages: 1, page: safePage, limit: safeLimit, count: 0 };
  }
}

/**
 * Retrieve single alert from file fallback by ID
 * @param {number|string} id 
 * @returns {Object|null}
 */
function getAlertByIdFromFileFallback(id) {
  const alertId = parseInt(id, 10);
  if (isNaN(alertId) || !fs.existsSync(alertLogFile)) return null;

  try {
    const raw = fs.readFileSync(alertLogFile, 'utf-8');
    const lines = raw.trim().split('\n').filter(Boolean);
    for (let i = 0; i < lines.length; i++) {
      if (i + 1 === alertId) {
        const item = JSON.parse(lines[i]);
        item.id = alertId;
        item.updatedAt = item.updatedAt || item.updated_at || item.createdAt || item.timestamp;
        return item;
      }
    }
  } catch {}
  return null;
}

/**
 * Update alert status in file fallback
 * @param {number|string} id 
 * @param {string} newStatus 
 * @returns {Object|null}
 */
function updateAlertStatusInFileFallback(id, newStatus) {
  const alertId = parseInt(id, 10);
  if (isNaN(alertId) || !fs.existsSync(alertLogFile)) return null;

  try {
    const raw = fs.readFileSync(alertLogFile, 'utf-8');
    const lines = raw.trim().split('\n').filter(Boolean);
    let updatedItem = null;

    for (let i = 0; i < lines.length; i++) {
      if (i + 1 === alertId) {
        const item = JSON.parse(lines[i]);
        item.id = alertId;
        item.status = String(newStatus).toLowerCase();
        item.updatedAt = new Date().toISOString();
        lines[i] = JSON.stringify(item);
        updatedItem = item;
        break;
      }
    }

    if (updatedItem) {
      fs.writeFileSync(alertLogFile, lines.join('\n') + '\n', 'utf-8');
      return updatedItem;
    }
  } catch (err) {
    console.error('[LOGGER ERROR] Failed updating alert status in fallback:', err.message);
  }
  return null;
}

/**
 * Compute alert statistics from alerts.log fallback
 * @returns {Object}
 */
function getAlertStatsFromFileFallback() {
  if (!fs.existsSync(alertLogFile)) {
    return {
      totalAlerts: 0,
      newAlerts: 0,
      acknowledgedAlerts: 0,
      resolvedAlerts: 0,
      criticalAlerts: 0,
      highAlerts: 0,
      mediumAlerts: 0,
      lowAlerts: 0,
      criticalSeverity: 0,
      highSeverity: 0,
      mediumSeverity: 0,
      lowSeverity: 0,
      mlAlerts: 0,
      alertsLast24Hours: 0,
      topAlertTypes: [],
      topAlertIps: []
    };
  }

  try {
    const raw = fs.readFileSync(alertLogFile, 'utf-8');
    const lines = raw.trim().split('\n').filter(Boolean);

    let totalAlerts = 0;
    let newAlerts = 0;
    let acknowledgedAlerts = 0;
    let resolvedAlerts = 0;
    let criticalSeverity = 0;
    let highSeverity = 0;
    let mediumSeverity = 0;
    let lowSeverity = 0;
    const typeCounts = {};
    const ipCounts = {};

    for (const line of lines) {
      try {
        const a = JSON.parse(line);
        totalAlerts++;
        const st = (a.status || 'new').toLowerCase();
        if (st === 'new') newAlerts++;
        else if (st === 'acknowledged') acknowledgedAlerts++;
        else if (st === 'resolved') resolvedAlerts++;

        const sev = (a.severity || 'MEDIUM').toUpperCase();
        if (sev === 'CRITICAL') criticalSeverity++;
        else if (sev === 'HIGH') highSeverity++;
        else if (sev === 'MEDIUM') mediumSeverity++;
        else if (sev === 'LOW') lowSeverity++;

        const t = a.alertType || 'UNKNOWN';
        typeCounts[t] = (typeCounts[t] || 0) + 1;

        const ip = a.sourceIp || a.ip || 'unknown';
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      } catch {}
    }

    const topAlertTypes = Object.entries(typeCounts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const topAlertIps = Object.entries(ipCounts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    return {
      totalAlerts,
      newAlerts,
      acknowledgedAlerts,
      resolvedAlerts,
      criticalAlerts: criticalSeverity,
      highAlerts: highSeverity,
      mediumAlerts: mediumSeverity,
      lowAlerts: lowSeverity,
      criticalSeverity,
      highSeverity,
      mediumSeverity,
      lowSeverity,
      mlAlerts: (typeCounts['ML_ANOMALY'] || 0),
      alertsLast24Hours: totalAlerts,
      topAlertTypes,
      topAlertIps
    };
  } catch (err) {
    console.error('[LOGGER ERROR] Failed computing alert stats fallback:', err.message);
    return {
      totalAlerts: 0,
      newAlerts: 0,
      acknowledgedAlerts: 0,
      resolvedAlerts: 0,
      criticalAlerts: 0,
      highAlerts: 0,
      mediumAlerts: 0,
      lowAlerts: 0,
      criticalSeverity: 0,
      highSeverity: 0,
      mediumSeverity: 0,
      lowSeverity: 0,
      mlAlerts: 0,
      alertsLast24Hours: 0,
      topAlertTypes: [],
      topAlertIps: []
    };
  }
}

module.exports = {
  logRequest,
  getLogsFromFileFallback,
  getLogStatsFromFileFallback,
  getAlertsFromFileFallback,
  getAlertByIdFromFileFallback,
  updateAlertStatusInFileFallback,
  getAlertStatsFromFileFallback,
  logFile,
  alertLogFile,
  logDir
};
