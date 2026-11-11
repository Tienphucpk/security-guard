const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// Auto-load .env configuration in Node.js 20+
try {
  const envPath = path.resolve(__dirname, '../../.env');
  const rootEnvPath = path.resolve(__dirname, '../../../.env');
  if (process.loadEnvFile) {
    if (fs.existsSync(envPath)) process.loadEnvFile(envPath);
    else if (fs.existsSync(rootEnvPath)) process.loadEnvFile(rootEnvPath);
  }
} catch {}

class DatabaseService {
  constructor() {
    this.config = {
      host: process.env.DB_HOST || process.env.DATABASE_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || process.env.DATABASE_PORT || '5432', 10),
      database: process.env.DB_NAME || process.env.DATABASE_NAME || 'security_guard',
      user: process.env.DB_USER || process.env.DATABASE_USER || 'security_guard',
      password: process.env.DB_PASSWORD || process.env.DATABASE_PASSWORD || 'change_me',
      // Quick connection timeout so server never hangs if DB is down
      connectionTimeoutMillis: 2000,
      idleTimeoutMillis: 10000,
      max: 20
    };

    this.pool = new Pool(this.config);
    this.isConnected = false;
    this.lastError = null;

    // Prevent uncaught errors from crashing Node process
    this.pool.on('error', (err) => {
      this.isConnected = false;
      this.lastError = err.message;
      console.warn('[DB POOL ERROR]', err.message);
    });
  }

  /**
   * Health check verifying if PostgreSQL is reachable
   * @returns {Promise<{connected: boolean, error: string|null}>}
   */
  async checkHealth() {
    try {
      const client = await this.pool.connect();
      try {
        await client.query('SELECT 1');
        this.isConnected = true;
        this.lastError = null;
        return { connected: true, error: null };
      } finally {
        client.release();
      }
    } catch (err) {
      this.isConnected = false;
      this.lastError = err.message;
      return { connected: false, error: err.message };
    }
  }

  /**
   * Inserts an HTTP request log entry into the request_logs table
   * @param {Object} logEntry 
   * @returns {Promise<{success: boolean, id?: number, error?: string}>}
   */
  async insertRequestLog(logEntry) {
    const query = `
      INSERT INTO request_logs (
        timestamp,
        ip,
        method,
        url,
        status_code,
        user_agent,
        response_time_ms,
        website_id,
        blocked,
        block_reason,
        request_id,
        risk_score,
        decision,
        decision_reason,
        rule_matches,
        ml_anomaly_score,
        evidence
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
      RETURNING id
    `;

    const values = [
      logEntry.timestamp ? new Date(logEntry.timestamp) : new Date(),
      logEntry.ip || '127.0.0.1',
      (logEntry.method || 'GET').toUpperCase(),
      logEntry.url || '/',
      parseInt(logEntry.statusCode, 10) || 200,
      logEntry.userAgent || 'unknown',
      parseFloat(logEntry.responseTime) || 0.0,
      logEntry.websiteId || logEntry.website_id || 'default_web_app',
      Boolean(logEntry.blocked),
      logEntry.blockReason || logEntry.block_reason || null,
      logEntry.requestId || logEntry.request_id || null,
      parseFloat(logEntry.riskScore || logEntry.risk_score || 0.0),
      logEntry.decision || (logEntry.blocked ? 'BLOCK' : 'ALLOW'),
      logEntry.decisionReason || logEntry.decision_reason || null,
      JSON.stringify(logEntry.ruleMatches || logEntry.rule_matches || []),
      typeof logEntry.mlAnomalyScore === 'number' ? logEntry.mlAnomalyScore : (logEntry.ml_anomaly_score || null),
      JSON.stringify(logEntry.evidence || {})
    ];

    try {
      const res = await this.pool.query(query, values);
      this.isConnected = true;
      return { success: true, id: res.rows[0]?.id };
    } catch (err) {
      this.isConnected = false;
      this.lastError = err.message;
      console.warn('[DB ERROR] Failed to save request log to PostgreSQL:', err.message);
      return { success: false, error: err.message };
    }
  }

  /**
   * Inserts comprehensive detection evidence audit record
   * @param {Object} evidenceData
   * @returns {Promise<{success: boolean, id?: number, error?: string}>}
   */
  async insertDetectionEvidence(evidenceData) {
    const query = `
      INSERT INTO detection_evidence (
        request_id,
        website_id,
        request_log_id,
        timestamp,
        rule_matches,
        rule_severity,
        ml_anomaly_score,
        ml_threshold,
        ml_mode,
        matched_features,
        evidence,
        risk_score,
        decision,
        decision_reason,
        processing_time_ms
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING id
    `;
    const values = [
      evidenceData.requestId || evidenceData.request_id || `req_${Date.now()}`,
      evidenceData.websiteId || evidenceData.website_id || 'default_web_app',
      evidenceData.requestLogId || evidenceData.request_log_id || null,
      evidenceData.timestamp ? new Date(evidenceData.timestamp) : new Date(),
      JSON.stringify(evidenceData.ruleMatches || evidenceData.rule_matches || []),
      evidenceData.ruleSeverity || evidenceData.rule_severity || 'NONE',
      typeof evidenceData.mlAnomalyScore === 'number' ? evidenceData.mlAnomalyScore : (evidenceData.ml_anomaly_score || 0.0),
      typeof evidenceData.mlThreshold === 'number' ? evidenceData.mlThreshold : (evidenceData.ml_threshold || 0.0),
      evidenceData.mlMode || evidenceData.ml_mode || 'shadow',
      JSON.stringify(evidenceData.matchedFeatures || evidenceData.matched_features || []),
      JSON.stringify(evidenceData.evidence || {}),
      parseFloat(evidenceData.riskScore || evidenceData.risk_score || 0.0),
      evidenceData.decision || 'ALLOW',
      evidenceData.decisionReason || evidenceData.decision_reason || 'Normal traffic',
      parseFloat(evidenceData.processingTimeMs || evidenceData.processing_time_ms || 0.0)
    ];

    try {
      const res = await this.pool.query(query, values);
      this.isConnected = true;
      return { success: true, id: res.rows[0]?.id };
    } catch (err) {
      console.warn('[DB ERROR] Failed to save detection evidence:', err.message);
      return { success: false, error: err.message };
    }
  }

  /**
   * Retrieves recent detection evidence records with optional filters
   * @param {Object} params
   * @returns {Promise<Array>}
   */
  async getRecentDetectionEvidence({ limit = 50, websiteId = null, decision = null } = {}) {
    const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
    const whereClauses = [];
    const values = [];
    let paramIndex = 1;

    if (websiteId) {
      whereClauses.push(`website_id = $${paramIndex++}`);
      values.push(websiteId.trim());
    }
    if (decision) {
      whereClauses.push(`decision = $${paramIndex++}`);
      values.push(decision.trim().toUpperCase());
    }

    const whereSQL = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const query = `
      SELECT 
        id,
        request_id AS "requestId",
        website_id AS "websiteId",
        request_log_id AS "requestLogId",
        timestamp,
        rule_matches AS "ruleMatches",
        rule_severity AS "ruleSeverity",
        ml_anomaly_score AS "mlAnomalyScore",
        ml_threshold AS "mlThreshold",
        ml_mode AS "mlMode",
        matched_features AS "matchedFeatures",
        evidence,
        risk_score AS "riskScore",
        decision,
        decision_reason AS "decisionReason",
        processing_time_ms AS "processingTimeMs"
      FROM detection_evidence
      ${whereSQL}
      ORDER BY id DESC
      LIMIT $${paramIndex};
    `;
    values.push(safeLimit);

    try {
      const res = await this.pool.query(query, values);
      this.isConnected = true;
      return res.rows;
    } catch (err) {
      console.warn('[DB ERROR] Failed to fetch detection evidence:', err.message);
      return [];
    }
  }

  /**
   * Retrieves request logs with pagination and filters using parameterized queries
   * @param {Object} params
   * @returns {Promise<{logs: Array, total: number, page: number, limit: number, count: number}>}
   */
  async getLogs({ page = 1, limit = 50, ip, method, statusCode, from, to, websiteId } = {}) {
    const safePage = Math.max(1, parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
    const offset = (safePage - 1) * safeLimit;

    const whereClauses = [];
    const values = [];
    let paramIndex = 1;

    if (websiteId && typeof websiteId === 'string') {
      whereClauses.push(`website_id = $${paramIndex++}`);
      values.push(websiteId.trim());
    }

    if (ip && typeof ip === 'string') {
      whereClauses.push(`ip = $${paramIndex++}`);
      values.push(ip.trim());
    }

    if (method && typeof method === 'string') {
      whereClauses.push(`method = $${paramIndex++}`);
      values.push(method.trim().toUpperCase());
    }

    if (statusCode !== undefined && statusCode !== null && statusCode !== '') {
      const code = parseInt(statusCode, 10);
      if (!isNaN(code)) {
        whereClauses.push(`status_code = $${paramIndex++}`);
        values.push(code);
      }
    }

    if (from) {
      const fromDate = new Date(from);
      if (!isNaN(fromDate.getTime())) {
        whereClauses.push(`timestamp >= $${paramIndex++}`);
        values.push(fromDate);
      }
    }

    if (to) {
      const toDate = new Date(to);
      if (!isNaN(toDate.getTime())) {
        whereClauses.push(`timestamp <= $${paramIndex++}`);
        values.push(toDate);
      }
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    // Total count query
    const countQuery = `SELECT COUNT(*) AS total FROM request_logs ${whereSql}`;
    const countRes = await this.pool.query(countQuery, values);
    const total = parseInt(countRes.rows[0]?.total || 0, 10);

    // Data query
    const dataValues = [...values, safeLimit, offset];
    const dataQuery = `
      SELECT 
        id,
        timestamp,
        ip,
        method,
        url,
        status_code AS "statusCode",
        user_agent AS "userAgent",
        response_time_ms AS "responseTime",
        website_id AS "websiteId",
        blocked,
        block_reason AS "blockReason"
      FROM request_logs
      ${whereSql}
      ORDER BY timestamp DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    const dataRes = await this.pool.query(dataQuery, dataValues);
    this.isConnected = true;

    return {
      logs: dataRes.rows,
      total,
      page: safePage,
      limit: safeLimit,
      count: dataRes.rows.length
    };
  }

  /**
   * Computes summary metrics and aggregates from request_logs
   * @param {string|null} websiteId
   * @returns {Promise<Object>}
   */
  async getLogStats(websiteId = null) {
    let whereClause = '';
    const params = [];
    if (websiteId && websiteId !== 'all') {
      whereClause = ' WHERE website_id = $1';
      params.push(websiteId);
    }

    const summaryQuery = `
      SELECT
        COUNT(*) AS "totalRequests",
        COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) AS "successfulRequests",
        COUNT(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 END) AS "clientErrors",
        COUNT(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 END) AS "serverErrors",
        COUNT(DISTINCT ip) AS "uniqueIps"
      FROM request_logs${whereClause}
    `;

    const topIpsQuery = `
      SELECT ip, COUNT(*) AS count
      FROM request_logs${whereClause}
      GROUP BY ip
      ORDER BY count DESC
      LIMIT 5
    `;

    const topPathsQuery = `
      SELECT url, COUNT(*) AS count
      FROM request_logs${whereClause}
      GROUP BY url
      ORDER BY count DESC
      LIMIT 5
    `;

    const methodsQuery = `
      SELECT method, COUNT(*) AS count
      FROM request_logs${whereClause}
      GROUP BY method
      ORDER BY count DESC
    `;

    const [summaryRes, topIpsRes, topPathsRes, methodsRes] = await Promise.all([
      this.pool.query(summaryQuery, params),
      this.pool.query(topIpsQuery, params),
      this.pool.query(topPathsQuery, params),
      this.pool.query(methodsQuery, params)
    ]);

    this.isConnected = true;

    const row = summaryRes.rows[0] || {};
    const httpMethods = {};
    for (const m of methodsRes.rows) {
      httpMethods[m.method] = parseInt(m.count, 10);
    }

    return {
      totalRequests: parseInt(row.totalRequests || 0, 10),
      successfulRequests: parseInt(row.successfulRequests || 0, 10),
      clientErrors: parseInt(row.clientErrors || 0, 10),
      serverErrors: parseInt(row.serverErrors || 0, 10),
      uniqueIps: parseInt(row.uniqueIps || 0, 10),
      topIps: topIpsRes.rows.map(r => ({ ip: r.ip, count: parseInt(r.count, 10) })),
      topPaths: topPathsRes.rows.map(r => ({ url: r.url, count: parseInt(r.count, 10) })),
      httpMethods
    };
  }

  /**
   * Inserts a security alert entry into the security_alerts table
   * @param {Object} alertData
   * @returns {Promise<{success: boolean, id?: number, error?: string}>}
   */
  async insertSecurityAlert(alertData) {
    const query = `
      INSERT INTO security_alerts (
        rule_id,
        request_log_id,
        alert_type,
        severity,
        risk_score,
        source_ip,
        method,
        target_url,
        description,
        details,
        status,
        created_at,
        updated_at,
        website_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING id
    `;

    const now = alertData.timestamp ? new Date(alertData.timestamp) : new Date();
    const values = [
      alertData.ruleId || null,
      alertData.requestLogId || null,
      alertData.alertType || 'ANOMALY_DETECTED',
      (alertData.severity || 'MEDIUM').toUpperCase(),
      parseFloat(alertData.riskScore) || 0.0,
      alertData.sourceIp || '127.0.0.1',
      (alertData.method || 'GET').toUpperCase(),
      alertData.targetUrl || '/',
      alertData.description || 'Security anomaly detected',
      JSON.stringify(alertData.details || {}),
      alertData.status || 'new',
      now,
      now,
      alertData.websiteId || alertData.website_id || 'default_web_app'
    ];

    try {
      const res = await this.pool.query(query, values);
      this.isConnected = true;
      return { success: true, id: res.rows[0]?.id };
    } catch (err) {
      this.isConnected = false;
      this.lastError = err.message;
      console.warn('[DB ERROR] Failed to save security alert to PostgreSQL:', err.message);
      return { success: false, error: err.message };
    }
  }

  /**
   * Retrieves security alerts with pagination, filters, and sorting using parameterized SQL
   * @param {Object} params
   * @returns {Promise<{alerts: Array, total: number, totalPages: number, page: number, limit: number, count: number}>}
   */
  async getAlerts({ page = 1, limit = 50, severity, type, status, ip, from, to, sort = 'newest', websiteId } = {}) {
    const safePage = Math.max(1, parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
    const offset = (safePage - 1) * safeLimit;

    const whereClauses = [];
    const values = [];
    let paramIndex = 1;

    if (websiteId && typeof websiteId === 'string') {
      whereClauses.push(`website_id = $${paramIndex++}`);
      values.push(websiteId.trim());
    }

    if (ip && typeof ip === 'string') {
      whereClauses.push(`source_ip = $${paramIndex++}`);
      values.push(ip.trim());
    }

    if (severity && typeof severity === 'string') {
      whereClauses.push(`UPPER(severity) = $${paramIndex++}`);
      values.push(severity.trim().toUpperCase());
    }

    if (type && typeof type === 'string') {
      whereClauses.push(`alert_type = $${paramIndex++}`);
      values.push(type.trim().toUpperCase());
    }

    if (status && typeof status === 'string') {
      whereClauses.push(`status = $${paramIndex++}`);
      values.push(status.trim().toLowerCase());
    }

    if (from) {
      const fromDate = new Date(from);
      if (!isNaN(fromDate.getTime())) {
        whereClauses.push(`created_at >= $${paramIndex++}`);
        values.push(fromDate);
      }
    }

    if (to) {
      const toDate = new Date(to);
      if (!isNaN(toDate.getTime())) {
        whereClauses.push(`created_at <= $${paramIndex++}`);
        values.push(toDate);
      }
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const countQuery = `SELECT COUNT(*) AS total FROM security_alerts ${whereSql}`;
    const countRes = await this.pool.query(countQuery, values);
    const total = parseInt(countRes.rows[0]?.total || 0, 10);
    const totalPages = Math.ceil(total / safeLimit) || 1;

    // Validate and build ORDER BY clause
    let orderBySql = 'ORDER BY created_at DESC';
    if (sort === 'oldest') {
      orderBySql = 'ORDER BY created_at ASC';
    } else if (sort === 'risk_desc') {
      orderBySql = 'ORDER BY risk_score DESC, created_at DESC';
    } else if (sort === 'risk_asc') {
      orderBySql = 'ORDER BY risk_score ASC, created_at DESC';
    }

    const dataValues = [...values, safeLimit, offset];
    const dataQuery = `
      SELECT
        id,
        rule_id AS "ruleId",
        request_log_id AS "requestLogId",
        alert_type AS "alertType",
        severity,
        risk_score AS "riskScore",
        source_ip AS "sourceIp",
        method,
        target_url AS "targetUrl",
        description,
        details,
        status,
        created_at AS "createdAt",
        COALESCE(updated_at, created_at) AS "updatedAt",
        website_id AS "websiteId"
      FROM security_alerts
      ${whereSql}
      ${orderBySql}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;

    const dataRes = await this.pool.query(dataQuery, dataValues);
    this.isConnected = true;

    return {
      alerts: dataRes.rows,
      total,
      totalPages,
      page: safePage,
      limit: safeLimit,
      count: dataRes.rows.length
    };
  }

  /**
   * Retrieves single security alert by ID with associated request log if available
   * @param {number|string} id 
   * @returns {Promise<Object|null>}
   */
  async getAlertById(id) {
    const alertId = parseInt(id, 10);
    if (isNaN(alertId)) return null;

    const query = `
      SELECT
        id,
        rule_id AS "ruleId",
        request_log_id AS "requestLogId",
        alert_type AS "alertType",
        severity,
        risk_score AS "riskScore",
        source_ip AS "sourceIp",
        method,
        target_url AS "targetUrl",
        description,
        details,
        status,
        created_at AS "createdAt",
        COALESCE(updated_at, created_at) AS "updatedAt",
        website_id AS "websiteId"
      FROM security_alerts
      WHERE id = $1
    `;

    const res = await this.pool.query(query, [alertId]);
    if (!res.rows[0]) return null;

    const alert = res.rows[0];

    // If linked to request_logs, fetch request details
    if (alert.requestLogId) {
      try {
        const logRes = await this.pool.query(
          `SELECT id, timestamp, ip, method, url, status_code AS "statusCode", user_agent AS "userAgent", response_time_ms AS "responseTime"
           FROM request_logs WHERE id = $1`,
          [alert.requestLogId]
        );
        alert.requestLog = logRes.rows[0] || null;
      } catch {
        alert.requestLog = null;
      }
    } else {
      alert.requestLog = null;
    }

    return alert;
  }

  /**
   * Updates an alert status (e.g. acknowledge, resolve) and records updated_at timestamp
   * @param {number|string} id 
   * @param {string} newStatus 
   * @returns {Promise<Object|null>}
   */
  async updateAlertStatus(id, newStatus) {
    const alertId = parseInt(id, 10);
    if (isNaN(alertId)) return null;

    const validStatus = String(newStatus).trim().toLowerCase();
    const query = `
      UPDATE security_alerts
      SET status = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING
        id,
        rule_id AS "ruleId",
        request_log_id AS "requestLogId",
        alert_type AS "alertType",
        severity,
        risk_score AS "riskScore",
        source_ip AS "sourceIp",
        method,
        target_url AS "targetUrl",
        description,
        details,
        status,
        created_at AS "createdAt",
        updated_at AS "updatedAt"
    `;

    const res = await this.pool.query(query, [validStatus, alertId]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Computes security alert statistics with breakdown by status and severity
   * @param {string|null} websiteId
   * @returns {Promise<Object>}
   */
  async getAlertStats(websiteId = null) {
    let whereClause = '';
    const params = [];
    if (websiteId && websiteId !== 'all') {
      whereClause = ' WHERE website_id = $1';
      params.push(websiteId);
    }

    const summaryQuery = `
      SELECT
        COUNT(*) AS "totalAlerts",
        COUNT(CASE WHEN status = 'new' THEN 1 END) AS "newAlerts",
        COUNT(CASE WHEN status = 'acknowledged' THEN 1 END) AS "acknowledgedAlerts",
        COUNT(CASE WHEN status = 'resolved' THEN 1 END) AS "resolvedAlerts",
        COUNT(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 END) AS "criticalAlerts",
        COUNT(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 END) AS "highAlerts",
        COUNT(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 END) AS "mediumAlerts",
        COUNT(CASE WHEN UPPER(severity) = 'LOW' THEN 1 END) AS "lowAlerts",
        COUNT(CASE WHEN alert_type = 'ML_ANOMALY' THEN 1 END) AS "mlAlerts",
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '24 hours' THEN 1 END) AS "alertsLast24Hours"
      FROM security_alerts${whereClause}
    `;

    const topTypesQuery = `
      SELECT alert_type AS type, COUNT(*) AS count
      FROM security_alerts${whereClause}
      GROUP BY alert_type
      ORDER BY count DESC
      LIMIT 5
    `;

    const topIpsQuery = `
      SELECT source_ip AS ip, COUNT(*) AS count
      FROM security_alerts${whereClause}
      GROUP BY source_ip
      ORDER BY count DESC
      LIMIT 5
    `;

    const [sumRes, typesRes, ipsRes] = await Promise.all([
      this.pool.query(summaryQuery, params),
      this.pool.query(topTypesQuery, params),
      this.pool.query(topIpsQuery, params)
    ]);

    const row = sumRes.rows[0] || {};
    const critical = parseInt(row.criticalAlerts || 0, 10);
    const high = parseInt(row.highAlerts || 0, 10);
    const medium = parseInt(row.mediumAlerts || 0, 10);
    const low = parseInt(row.lowAlerts || 0, 10);

    return {
      totalAlerts: parseInt(row.totalAlerts || 0, 10),
      newAlerts: parseInt(row.newAlerts || 0, 10),
      acknowledgedAlerts: parseInt(row.acknowledgedAlerts || 0, 10),
      resolvedAlerts: parseInt(row.resolvedAlerts || 0, 10),
      criticalAlerts: critical,
      highAlerts: high,
      mediumAlerts: medium,
      lowAlerts: low,
      mlAlerts: parseInt(row.mlAlerts || 0, 10),
      // Backward compatibility aliases for Phase 3
      criticalSeverity: critical,
      highSeverity: high,
      mediumSeverity: medium,
      lowSeverity: low,
      alertsLast24Hours: parseInt(row.alertsLast24Hours || 0, 10),
      topAlertTypes: typesRes.rows.map(r => ({ type: r.type, count: parseInt(r.count, 10) })),
      topAlertIps: ipsRes.rows.map(r => ({ ip: r.ip, count: parseInt(r.count, 10) }))
    };
  }

  // ============================================================================
  // Phase 9: User Management & Session Storage
  // ============================================================================

  /**
   * Finds a user by username or email (case-insensitive)
   * @param {string} identifier 
   * @returns {Promise<Object|null>}
   */
  async findUserByUsernameOrEmail(identifier) {
    if (!identifier || typeof identifier !== 'string') return null;
    const query = `
      SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
      FROM users
      WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)
      LIMIT 1;
    `;
    const res = await this.pool.query(query, [identifier.trim()]);
    return res.rows[0] || null;
  }

  /**
   * Finds a user by ID
   * @param {number} id 
   * @returns {Promise<Object|null>}
   */
  async findUserById(id) {
    const query = `
      SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
      FROM users
      WHERE id = $1;
    `;
    const res = await this.pool.query(query, [parseInt(id, 10)]);
    return res.rows[0] || null;
  }

  /**
   * Creates a new server-side session in PostgreSQL
   * @param {number} userId 
   * @param {string} ip 
   * @param {string} userAgent 
   * @param {number} durationHours 
   * @returns {Promise<{sessionId: string, expiresAt: Date}>}
   */
  async createSession(userId, ip, userAgent, durationHours = 24) {
    const crypto = require('crypto');
    const sessionId = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000);
    const query = `
      INSERT INTO user_sessions (session_id, user_id, expires_at, ip, user_agent)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING session_id, expires_at;
    `;
    const res = await this.pool.query(query, [sessionId, userId, expiresAt, ip || '127.0.0.1', userAgent || '']);
    return {
      sessionId: res.rows[0].session_id,
      expiresAt: res.rows[0].expires_at
    };
  }

  /**
   * Validates a session ID and returns the associated active user
   * @param {string} sessionId 
   * @returns {Promise<{sessionId: string, expiresAt: Date, user: Object}|null>}
   */
  async validateSession(sessionId) {
    if (!sessionId || typeof sessionId !== 'string') return null;
    const query = `
      SELECT 
        s.session_id, s.expires_at,
        u.id AS user_id, u.username, u.email, u.role, u.is_active
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.session_id = $1 AND s.expires_at > CURRENT_TIMESTAMP;
    `;
    const res = await this.pool.query(query, [sessionId]);
    if (!res.rows[0]) return null;
    const row = res.rows[0];
    // Reject immediately if user account has been disabled
    if (!row.is_active) return null;
    return {
      sessionId: row.session_id,
      expiresAt: row.expires_at,
      user: {
        id: row.user_id,
        username: row.username,
        email: row.email,
        role: (row.role || 'ANALYST').toUpperCase(),
        isActive: row.is_active
      }
    };
  }

  /**
   * Deletes a specific session on logout
   * @param {string} sessionId 
   * @returns {Promise<boolean>}
   */
  async deleteSession(sessionId) {
    if (!sessionId) return false;
    const query = `DELETE FROM user_sessions WHERE session_id = $1;`;
    const res = await this.pool.query(query, [sessionId]);
    return res.rowCount > 0;
  }

  /**
   * Deletes all sessions of a user (e.g. on password change or deactivation)
   * @param {number} userId 
   * @returns {Promise<boolean>}
   */
  async deleteUserSessions(userId) {
    if (!userId) return false;
    const query = `DELETE FROM user_sessions WHERE user_id = $1;`;
    await this.pool.query(query, [userId]);
    return true;
  }

  /**
   * Retrieves all users (without password hash)
   * @returns {Promise<Array>}
   */
  async getAllUsers() {
    const query = `
      SELECT id, username, email, role, is_active AS "isActive", created_at AS "createdAt", updated_at AS "updatedAt"
      FROM users
      ORDER BY id ASC;
    `;
    const res = await this.pool.query(query);
    return res.rows.map(u => ({ ...u, role: (u.role || 'ANALYST').toUpperCase() }));
  }

  /**
   * Creates a new user
   * @param {Object} userData 
   * @returns {Promise<Object>}
   */
  async createUser({ username, email, passwordHash, role = 'ANALYST' }) {
    const query = `
      INSERT INTO users (username, email, password_hash, role, is_active)
      VALUES ($1, $2, $3, $4, true)
      RETURNING id, username, email, role, is_active AS "isActive", created_at AS "createdAt";
    `;
    const res = await this.pool.query(query, [
      username.trim(),
      email.trim().toLowerCase(),
      passwordHash,
      role.toUpperCase()
    ]);
    return { ...res.rows[0], role: res.rows[0].role.toUpperCase() };
  }

  /**
   * Updates user status (active/inactive)
   * @param {number} id 
   * @param {boolean} isActive 
   * @returns {Promise<Object|null>}
   */
  async updateUserStatus(id, isActive) {
    const query = `
      UPDATE users
      SET is_active = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING id, username, email, role, is_active AS "isActive", updated_at AS "updatedAt";
    `;
    const res = await this.pool.query(query, [Boolean(isActive), parseInt(id, 10)]);
    return res.rows[0] ? { ...res.rows[0], role: res.rows[0].role.toUpperCase() } : null;
  }

  /**
   * Updates user role (ADMIN or ANALYST)
   * @param {number} id 
   * @param {string} role 
   * @returns {Promise<Object|null>}
   */
  async updateUserRole(id, role) {
    const query = `
      UPDATE users
      SET role = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING id, username, email, role, is_active AS "isActive", updated_at AS "updatedAt";
    `;
    const res = await this.pool.query(query, [role.toUpperCase(), parseInt(id, 10)]);
    return res.rows[0] ? { ...res.rows[0], role: res.rows[0].role.toUpperCase() } : null;
  }

  /**
   * Counts total active ADMIN accounts in the database
   * @returns {Promise<number>}
   */
  async countActiveAdmins() {
    const query = `
      SELECT COUNT(*) AS total
      FROM users
      WHERE role = 'ADMIN' AND is_active = true;
    `;
    const res = await this.pool.query(query);
    return parseInt(res.rows[0]?.total || 0, 10);
  }

  // ============================================================================
  // Phase 10: Multi-Website Registry, Policy & Enforcement Database Methods
  // ============================================================================

  /**
   * Retrieves all registered monitored websites with enriched traffic & alert metrics
   * @returns {Promise<Array>}
   */
  async getAllWebsites() {
    const query = `
      SELECT 
        w.id,
        w.website_id AS "websiteId",
        w.name,
        w.domain,
        w.integration_method AS "integrationMethod",
        w.upstream_url AS "upstreamUrl",
        w.monitoring_mode AS "monitoringMode",
        w.is_active AS "isActive",
        w.is_external AS "isExternal",
        w.health_status AS "healthStatus",
        w.last_health_check AS "lastHealthCheck",
        w.health_diagnostic AS "healthDiagnostic",
        w.last_event_at AS "lastEventAt",
        w.description,
        w.created_at AS "createdAt",
        w.updated_at AS "updatedAt",
        COALESCE(req_stats.total_requests, 0)::int AS "totalRequests",
        COALESCE(req_stats.normal_requests, 0)::int AS "normalRequests",
        COALESCE(req_stats.suspicious_requests, 0)::int AS "suspiciousRequests",
        COALESCE(alert_stats.total_alerts, 0)::int AS "totalAlerts",
        GREATEST(w.last_event_at, req_stats.last_request_time) AS "lastActivity"
      FROM monitored_websites w
      LEFT JOIN (
        SELECT 
          website_id,
          COUNT(*) AS total_requests,
          COUNT(CASE WHEN blocked = FALSE AND (decision IS NULL OR decision = 'ALLOW') THEN 1 END) AS normal_requests,
          COUNT(CASE WHEN blocked = TRUE OR (decision IS NOT NULL AND decision != 'ALLOW') THEN 1 END) AS suspicious_requests,
          MAX(created_at) AS last_request_time
        FROM request_logs
        GROUP BY website_id
      ) req_stats ON req_stats.website_id = w.website_id
      LEFT JOIN (
        SELECT 
          website_id,
          COUNT(*) AS total_alerts
        FROM security_alerts
        GROUP BY website_id
      ) alert_stats ON alert_stats.website_id = w.website_id
      ORDER BY w.id ASC;
    `;
    const res = await this.pool.query(query);
    this.isConnected = true;
    return res.rows;
  }

  /**
   * Retrieves a specific monitored website by its stable website_id
   * @param {string} websiteId
   * @returns {Promise<Object|null>}
   */
  async getWebsiteById(websiteId) {
    const query = `
      SELECT 
        id,
        website_id AS "websiteId",
        name,
        domain,
        integration_method AS "integrationMethod",
        upstream_url AS "upstreamUrl",
        monitoring_mode AS "monitoringMode",
        is_active AS "isActive",
        is_external AS "isExternal",
        health_status AS "healthStatus",
        last_health_check AS "lastHealthCheck",
        health_diagnostic AS "healthDiagnostic",
        last_event_at AS "lastEventAt",
        agent_secret_hash AS "agentSecretHash",
        encrypted_agent_secret AS "encryptedAgentSecret",
        description,
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM monitored_websites
      WHERE website_id = $1;
    `;
    const res = await this.pool.query(query, [String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Retrieves a specific monitored website by its domain/hostname
   * @param {string} domain
   * @returns {Promise<Object|null>}
   */
  async getWebsiteByDomain(domain) {
    if (!domain) return null;
    const query = `
      SELECT 
        id,
        website_id AS "websiteId",
        name,
        domain,
        integration_method AS "integrationMethod",
        upstream_url AS "upstreamUrl",
        monitoring_mode AS "monitoringMode",
        is_active AS "isActive",
        is_external AS "isExternal",
        health_status AS "healthStatus",
        last_health_check AS "lastHealthCheck",
        health_diagnostic AS "healthDiagnostic",
        last_event_at AS "lastEventAt",
        agent_secret_hash AS "agentSecretHash",
        encrypted_agent_secret AS "encryptedAgentSecret",
        description,
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM monitored_websites
      WHERE domain = $1 OR domain = $2
      LIMIT 1;
    `;
    const cleanDomain = String(domain).trim().toLowerCase();
    const domainWithoutPort = cleanDomain.split(':')[0];
    const res = await this.pool.query(query, [cleanDomain, domainWithoutPort]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Registers a new monitored website
   */
  async createWebsite({ 
    websiteId, 
    name, 
    domain = null, 
    integrationMethod = 'REVERSE_PROXY', 
    upstreamUrl = null, 
    monitoringMode = 'MONITOR_ONLY', 
    description = '', 
    agentSecretHash = null,
    encryptedAgentSecret = null,
    isExternal = false
  }) {
    const query = `
      INSERT INTO monitored_websites (
        website_id,
        name,
        domain,
        integration_method,
        upstream_url,
        monitoring_mode,
        is_active,
        is_external,
        agent_secret_hash,
        encrypted_agent_secret,
        health_status,
        description
      )
      VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8, $9, 'UNKNOWN', $10)
      RETURNING id, website_id AS "websiteId", name, domain, integration_method AS "integrationMethod",
                upstream_url AS "upstreamUrl", monitoring_mode AS "monitoringMode", is_active AS "isActive", 
                is_external AS "isExternal", health_status AS "healthStatus", description, created_at AS "createdAt";
    `;
    const res = await this.pool.query(query, [
      String(websiteId).trim(),
      String(name).trim(),
      domain ? String(domain).trim().toLowerCase() : null,
      ['REVERSE_PROXY', 'APPLICATION_AGENT', 'LOG_INGESTION'].includes(String(integrationMethod).toUpperCase()) 
        ? String(integrationMethod).toUpperCase() 
        : 'REVERSE_PROXY',
      upstreamUrl ? String(upstreamUrl).trim() : null,
      monitoringMode && String(monitoringMode).toUpperCase() === 'ENFORCE' ? 'ENFORCE' : 'MONITOR_ONLY',
      Boolean(isExternal),
      agentSecretHash,
      encryptedAgentSecret,
      description
    ]);
    this.isConnected = true;
    return res.rows[0];
  }

  /**
   * Updates health status and diagnostic message
   */
  async updateWebsiteHealth(websiteId, healthStatus, diagnostic = null) {
    const query = `
      UPDATE monitored_websites
      SET health_status = $1, health_diagnostic = $2, last_health_check = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE website_id = $3
      RETURNING id, website_id AS "websiteId", health_status AS "healthStatus", health_diagnostic AS "healthDiagnostic", last_health_check AS "lastHealthCheck";
    `;
    const res = await this.pool.query(query, [
      String(healthStatus).toUpperCase(),
      diagnostic ? String(diagnostic) : null,
      String(websiteId).trim()
    ]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Updates last event timestamp for a website when telemetry/log arrives
   */
  async updateWebsiteLastEvent(websiteId) {
    const query = `
      UPDATE monitored_websites
      SET last_event_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE website_id = $1;
    `;
    await this.pool.query(query, [String(websiteId).trim()]).catch(() => {});
  }

  /**
   * Rotates agent credentials for a website
   */
  async rotateWebsiteSecret(websiteId, agentSecretHash, encryptedAgentSecret) {
    const query = `
      UPDATE monitored_websites
      SET agent_secret_hash = $1, encrypted_agent_secret = $2, updated_at = CURRENT_TIMESTAMP
      WHERE website_id = $3
      RETURNING id, website_id AS "websiteId", updated_at AS "updatedAt";
    `;
    const res = await this.pool.query(query, [agentSecretHash, encryptedAgentSecret, String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Updates monitoring mode ('MONITOR_ONLY' or 'ENFORCE')
   */
  async updateWebsiteMode(websiteId, mode) {
    const validMode = String(mode).toUpperCase() === 'ENFORCE' ? 'ENFORCE' : 'MONITOR_ONLY';
    const query = `
      UPDATE monitored_websites
      SET monitoring_mode = $1, updated_at = CURRENT_TIMESTAMP
      WHERE website_id = $2
      RETURNING id, website_id AS "websiteId", name, upstream_url AS "upstreamUrl",
                monitoring_mode AS "monitoringMode", is_active AS "isActive", updated_at AS "updatedAt";
    `;
    const res = await this.pool.query(query, [validMode, String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Updates upstream URL
   */
  async updateWebsiteUpstream(websiteId, upstreamUrl) {
    const query = `
      UPDATE monitored_websites
      SET upstream_url = $1, updated_at = CURRENT_TIMESTAMP
      WHERE website_id = $2
      RETURNING id, website_id AS "websiteId", name, upstream_url AS "upstreamUrl",
                monitoring_mode AS "monitoringMode", is_active AS "isActive", updated_at AS "updatedAt";
    `;
    const res = await this.pool.query(query, [String(upstreamUrl).trim(), String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Updates active state of website
   */
  async updateWebsiteStatus(websiteId, isActive) {
    const query = `
      UPDATE monitored_websites
      SET is_active = $1, updated_at = CURRENT_TIMESTAMP
      WHERE website_id = $2
      RETURNING id, website_id AS "websiteId", name, is_active AS "isActive", updated_at AS "updatedAt";
    `;
    const res = await this.pool.query(query, [Boolean(isActive), String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows[0] || null;
  }

  /**
   * Retrieves all policies for a given website
   */
  async getPoliciesByWebsite(websiteId) {
    const query = `
      SELECT 
        id,
        website_id AS "websiteId",
        policy_type AS "policyType",
        match_criteria AS "matchCriteria",
        action,
        reason,
        is_active AS "isActive",
        expires_at AS "expiresAt",
        created_at AS "createdAt"
      FROM enforcement_policies
      WHERE website_id = $1
      ORDER BY id DESC;
    `;
    const res = await this.pool.query(query, [String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows;
  }

  /**
   * Retrieves active, non-expired policies for policy evaluation
   */
  async getActivePoliciesForWebsite(websiteId) {
    const query = `
      SELECT 
        id,
        website_id AS "websiteId",
        policy_type AS "policyType",
        match_criteria AS "matchCriteria",
        action,
        reason,
        is_active AS "isActive",
        expires_at AS "expiresAt"
      FROM enforcement_policies
      WHERE website_id = $1
        AND is_active = TRUE
        AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
      ORDER BY id ASC;
    `;
    const res = await this.pool.query(query, [String(websiteId).trim()]);
    this.isConnected = true;
    return res.rows;
  }

  /**
   * Creates a new enforcement policy
   */
  async createPolicy({ websiteId, policyType, matchCriteria, action = 'BLOCK', reason, expiresAt = null }) {
    const query = `
      INSERT INTO enforcement_policies (
        website_id,
        policy_type,
        match_criteria,
        action,
        reason,
        is_active,
        expires_at
      )
      VALUES ($1, $2, $3, $4, $5, TRUE, $6)
      RETURNING id, website_id AS "websiteId", policy_type AS "policyType",
                match_criteria AS "matchCriteria", action, reason, is_active AS "isActive",
                expires_at AS "expiresAt", created_at AS "createdAt";
    `;
    const res = await this.pool.query(query, [
      String(websiteId).trim(),
      String(policyType).toUpperCase().trim(),
      typeof matchCriteria === 'string' ? matchCriteria : JSON.stringify(matchCriteria || {}),
      action.toUpperCase() === 'ALLOW' ? 'ALLOW' : 'BLOCK',
      String(reason || 'Administrative Security Policy').trim(),
      expiresAt ? new Date(expiresAt) : null
    ]);
    this.isConnected = true;
    return res.rows[0];
  }

  /**
   * Deletes an enforcement policy by ID
   */
  async deletePolicy(policyId) {
    const query = `DELETE FROM enforcement_policies WHERE id = $1 RETURNING id;`;
    const res = await this.pool.query(query, [parseInt(policyId, 10)]);
    this.isConnected = true;
    return res.rows.length > 0;
  }

  /**
   * Inserts an enforcement audit log entry
   */
  async insertEnforcementAudit({ websiteId, requestId, action, policyId = null, reason, clientIp, targetPath, matchedRule = null }) {
    const query = `
      INSERT INTO enforcement_audit_logs (
        website_id,
        request_id,
        action,
        policy_id,
        reason,
        client_ip,
        target_path,
        matched_rule
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id, created_at AS "createdAt";
    `;
    const res = await this.pool.query(query, [
      String(websiteId).trim(),
      requestId ? String(requestId).trim() : null,
      String(action).toUpperCase().trim(),
      policyId ? parseInt(policyId, 10) : null,
      String(reason || 'Enforcement evaluation').trim(),
      String(clientIp || '127.0.0.1').trim(),
      String(targetPath || '/').trim(),
      matchedRule ? String(matchedRule).trim() : null
    ]);
    this.isConnected = true;
    return res.rows[0];
  }

  /**
   * Retrieves recent enforcement audit records
   */
  async getRecentEnforcementAudits({ limit = 50, websiteId } = {}) {
    const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
    const whereClauses = [];
    const values = [];
    let paramIndex = 1;

    if (websiteId && typeof websiteId === 'string') {
      whereClauses.push(`website_id = $${paramIndex++}`);
      values.push(websiteId.trim());
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const query = `
      SELECT 
        id,
        website_id AS "websiteId",
        request_id AS "requestId",
        action,
        policy_id AS "policyId",
        reason,
        client_ip AS "clientIp",
        target_path AS "targetPath",
        matched_rule AS "matchedRule",
        created_at AS "createdAt"
      FROM enforcement_audit_logs
      ${whereSql}
      ORDER BY created_at DESC
      LIMIT $${paramIndex++};
    `;
    values.push(safeLimit);

    const res = await this.pool.query(query, values);
    this.isConnected = true;
    return res.rows;
  }

  /**
   * Closes connection pool cleanly (used in tests or shutdown)
   */
  async close() {
    try {
      await this.pool.end();
    } catch {
      // Ignore closing error
    }
  }
}

module.exports = new DatabaseService();
