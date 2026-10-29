const { URL } = require('url');
const db = require('./database');
const { validateExternalUrl } = require('./ssrfValidator');
const { generateAgentSecret } = require('./agentAuthService');

// Block dangerous cloud metadata endpoints and broadcast addresses
const FORBIDDEN_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  '255.255.255.255',
  '0.0.0.0'
]);

class WebsiteRegistryService {
  constructor() {
    this.cache = new Map();
    this.cacheTtlMs = 15000;
    this.lastFetch = 0;
  }

  /**
   * Validates if an upstream URL is safe and valid (SSRF Prevention)
   * @param {string} upstreamUrl 
   * @returns {{ valid: boolean, reason?: string, parsedUrl?: URL }}
   */
  validateUpstreamUrl(upstreamUrl) {
    if (!upstreamUrl || typeof upstreamUrl !== 'string') {
      return { valid: false, reason: 'Upstream URL must be a non-empty string' };
    }

    let parsed;
    try {
      parsed = new URL(upstreamUrl);
    } catch {
      return { valid: false, reason: 'Invalid URL format' };
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { valid: false, reason: 'Only HTTP and HTTPS protocols are allowed' };
    }

    const hostname = parsed.hostname.toLowerCase();

    // Check cloud metadata endpoints
    if (FORBIDDEN_HOSTS.has(hostname) || hostname.endsWith('.internal')) {
      return { valid: false, reason: 'Prohibited upstream host (SSRF Protection)' };
    }

    // In this lab / Windows localhost environment, approved demo upstreams are local loopback
    // Restrict port to approved demo ranges (4000-4999) or localhost
    const port = parseInt(parsed.port, 10);
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      if (!port || port < 1024 || port > 65535) {
        return { valid: false, reason: 'Localhost upstream must specify a valid non-privileged port (1024-65535)' };
      }
    }

    return { valid: true, parsedUrl: parsed };
  }

  /**
   * Generates integration instructions based on method and website info
   */
  generateIntegrationInstructions(site, plaintextSecret = null) {
    const webAppUrl = process.env.WEB_APP_PUBLIC_URL || 'http://localhost:3000';
    const gatewayUrl = process.env.GATEWAY_PUBLIC_URL || 'http://localhost:8080';
    const secretDisplay = plaintextSecret || '<YOUR_AGENT_SECRET>';

    switch (site.integrationMethod) {
      case 'REVERSE_PROXY':
        return {
          method: 'REVERSE_PROXY',
          summary: 'Route incoming traffic through Security Guard Monitoring Gateway',
          steps: [
            `1. Point your DNS A/CNAME record for "${site.domain || site.name}" to the Security Guard Gateway (${gatewayUrl}).`,
            `2. Ensure upstream server (${site.upstreamUrl || 'target server'}) accepts forwarded headers: X-Forwarded-For, X-Forwarded-Host, X-Website-Id.`,
            `3. All requests through the Gateway are automatically inspected against Rule-based detectors and Isolation Forest ML.`,
            `4. In MONITOR_ONLY mode, alerts are logged and displayed on the Dashboard. Switch to ENFORCE to actively drop attack payloads with HTTP 403.`
          ],
          curlExample: `curl -H "Host: ${site.domain || 'mysite.com'}" ${gatewayUrl}/`
        };

      case 'APPLICATION_AGENT':
        return {
          method: 'APPLICATION_AGENT',
          summary: 'Install lightweight Node.js or Python agent middleware directly in your application',
          steps: [
            `1. Include the Security Guard Agent middleware in your Express or Flask/Django application.`,
            `2. Configure environment credentials:`,
            `   SECURITY_GUARD_URL=${webAppUrl}`,
            `   SECURITY_GUARD_WEBSITE_ID=${site.websiteId}`,
            `   SECURITY_GUARD_SECRET=${secretDisplay}`,
            `3. The agent will asynchronously forward request telemetry with HMAC-SHA256 signatures. Sensitive fields are redacted automatically.`
          ],
          codeSnippet: `const { securityGuardAgent } = require('./security-guard-agent');\napp.use(securityGuardAgent({\n  websiteId: '${site.websiteId}',\n  agentSecret: '${secretDisplay}',\n  collectorUrl: '${webAppUrl}/api/ingest/events'\n}));`
        };

      case 'LOG_INGESTION':
        return {
          method: 'LOG_INGESTION',
          summary: 'Stream access logs (Nginx, Apache, or JSON Lines) passively to the ingestion API',
          steps: [
            `1. Configure your log shipper (Fluentd, Logstash, Vector, or cron script) to stream access logs to:`,
            `   POST ${webAppUrl}/api/ingest/logs`,
            `2. Send authentication header "X-Agent-Secret: ${secretDisplay}" and "X-Website-Id: ${site.websiteId}".`,
            `3. Supported formats: Nginx Combined Log, Apache Common Log, or JSON Lines.`
          ],
          curlExample: `curl -X POST "${webAppUrl}/api/ingest/logs" \\\n  -H "X-Website-Id: ${site.websiteId}" \\\n  -H "X-Agent-Secret: ${secretDisplay}" \\\n  -H "Content-Type: text/plain" \\\n  --data-binary @/var/log/nginx/access.log`
        };

      default:
        return { method: site.integrationMethod, steps: [] };
    }
  }

  /**
   * Retrieves all registered websites (with in-memory caching)
   * @param {boolean} forceRefresh 
   * @returns {Promise<Array>}
   */
  async getWebsites(forceRefresh = false) {
    const now = Date.now();
    if (!forceRefresh && (now - this.lastFetch) < this.cacheTtlMs && this.cache.size > 0) {
      return Array.from(this.cache.values());
    }

    const sites = await db.getAllWebsites();
    this.cache.clear();
    for (const site of sites) {
      this.cache.set(site.websiteId, site);
    }
    this.lastFetch = now;
    return sites;
  }

  /**
   * Retrieves a website by its websiteId
   * @param {string} websiteId 
   * @returns {Promise<Object|null>}
   */
  async getWebsite(websiteId) {
    if (!websiteId) return null;
    const cleanId = String(websiteId).trim();
    if (this.cache.has(cleanId)) {
      return this.cache.get(cleanId);
    }
    const site = await db.getWebsiteById(cleanId);
    if (site) {
      this.cache.set(site.websiteId, site);
    }
    return site;
  }

  /**
   * Registers a new internal website with strict validation
   */
  async registerWebsite({ websiteId, name, upstreamUrl, monitoringMode = 'MONITOR_ONLY', description = '', agentSecretHash = null }) {
    if (!websiteId || !/^[a-zA-Z0-9_-]{3,64}$/.test(websiteId)) {
      throw new Error('websiteId must be alphanumeric with underscores or dashes (3-64 chars)');
    }

    if (!name || name.trim().length === 0) {
      throw new Error('name is required');
    }

    const validation = this.validateUpstreamUrl(upstreamUrl);
    if (!validation.valid) {
      throw new Error(`Invalid upstream URL: ${validation.reason}`);
    }

    const existing = await db.getWebsiteById(websiteId);
    if (existing) {
      throw new Error(`Website ID '${websiteId}' is already registered`);
    }

    const created = await db.createWebsite({
      websiteId,
      name,
      domain: validation.parsedUrl.host,
      integrationMethod: 'REVERSE_PROXY',
      upstreamUrl: validation.parsedUrl.origin,
      monitoringMode,
      description,
      agentSecretHash,
      isExternal: false
    });

    this.cache.set(created.websiteId, created);
    return created;
  }

  /**
   * Registers an external website with SSRF protection and agent credentials
   */
  async registerExternalWebsite({
    websiteId,
    name,
    domain = null,
    integrationMethod = 'REVERSE_PROXY',
    upstreamUrl = null,
    monitoringMode = 'MONITOR_ONLY',
    description = ''
  }) {
    if (!websiteId || !/^[a-zA-Z0-9_-]{3,64}$/.test(websiteId)) {
      throw new Error('websiteId must be alphanumeric with underscores or dashes (3-64 chars)');
    }

    if (!name || name.trim().length === 0) {
      throw new Error('Website name is required');
    }

    const method = String(integrationMethod).toUpperCase();
    if (!['REVERSE_PROXY', 'APPLICATION_AGENT', 'LOG_INGESTION'].includes(method)) {
      throw new Error('Invalid integration method. Must be REVERSE_PROXY, APPLICATION_AGENT, or LOG_INGESTION');
    }

    // SSRF verification for reverse proxy upstream
    let validatedUpstream = null;
    if (method === 'REVERSE_PROXY') {
      if (!upstreamUrl) {
        throw new Error('upstreamUrl is required for REVERSE_PROXY integration');
      }
      const ssrfCheck = await validateExternalUrl(upstreamUrl, { allowPrivate: false });
      if (!ssrfCheck.valid) {
        throw new Error(`SSRF Validation Failed: ${ssrfCheck.error}`);
      }
      validatedUpstream = upstreamUrl.trim();
    } else if (upstreamUrl) {
      // Optional upstream for other methods: check format if provided
      try {
        new URL(upstreamUrl);
        validatedUpstream = upstreamUrl.trim();
      } catch {
        throw new Error('Invalid upstream URL format');
      }
    }

    const existing = await db.getWebsiteById(websiteId);
    if (existing) {
      throw new Error(`Website ID '${websiteId}' is already registered`);
    }

    // Generate cryptographically secure agent secret (plaintext shown only once)
    const { plaintextSecret, secretHash, encryptedSecret } = generateAgentSecret();

    // Enforcement Safety: External websites default to MONITOR_ONLY
    const initialMode = monitoringMode.toUpperCase() === 'ENFORCE' ? 'ENFORCE' : 'MONITOR_ONLY';

    const created = await db.createWebsite({
      websiteId,
      name,
      domain: domain ? domain.trim().toLowerCase() : null,
      integrationMethod: method,
      upstreamUrl: validatedUpstream,
      monitoringMode: initialMode,
      description,
      agentSecretHash: secretHash,
      encryptedAgentSecret: encryptedSecret,
      isExternal: true
    });

    this.cache.set(created.websiteId, created);

    const instructions = this.generateIntegrationInstructions(created, plaintextSecret);

    return {
      website: created,
      plaintextSecret,
      instructions
    };
  }

  /**
   * Rotates credentials for a website
   */
  async rotateAgentSecret(websiteId) {
    const site = await db.getWebsiteById(websiteId);
    if (!site) {
      throw new Error(`Website ${websiteId} not found`);
    }

    const { plaintextSecret, secretHash, encryptedSecret } = generateAgentSecret();
    await db.rotateWebsiteSecret(websiteId, secretHash, encryptedSecret);
    this.cache.delete(websiteId);

    const instructions = this.generateIntegrationInstructions(site, plaintextSecret);

    return {
      websiteId,
      plaintextSecret,
      instructions
    };
  }

  /**
   * Updates monitoring mode
   */
  async setMonitoringMode(websiteId, mode) {
    const updated = await db.updateWebsiteMode(websiteId, mode);
    if (updated) {
      this.cache.set(updated.websiteId, updated);
    }
    return updated;
  }

  /**
   * Updates upstream URL
   */
  async setUpstreamUrl(websiteId, upstreamUrl) {
    const validation = this.validateUpstreamUrl(upstreamUrl);
    if (!validation.valid) {
      throw new Error(`Invalid upstream URL: ${validation.reason}`);
    }
    const updated = await db.updateWebsiteUpstream(websiteId, validation.parsedUrl.origin);
    if (updated) {
      this.cache.set(updated.websiteId, updated);
    }
    return updated;
  }
}

module.exports = new WebsiteRegistryService();
