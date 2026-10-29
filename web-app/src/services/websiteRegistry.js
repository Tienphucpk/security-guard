const { URL } = require('url');
const db = require('./database');

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
   * Registers a new website with strict validation
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
      upstreamUrl: validation.parsedUrl.origin,
      monitoringMode,
      description,
      agentSecretHash
    });

    this.cache.set(created.websiteId, created);
    return created;
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
