const crypto = require('crypto');
const { normalizeIp } = require('../utils/ip.util');

// Regex for Combined Log Format:
// 127.0.0.1 - - [10/Oct/2026:13:55:36 +0700] "GET /api/users HTTP/1.1" 200 1234 "http://ref.com" "Mozilla/5.0..."
const COMBINED_LOG_REGEX = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?(?:.*)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

// Regex for Common Log Format:
// 127.0.0.1 - - [10/Oct/2026:13:55:36 +0700] "GET /api/users HTTP/1.1" 200 1234
const COMMON_LOG_REGEX = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?(?:.*)?"\s+(\d{3})\s+(\S+)/;

const SENSITIVE_PARAM_REGEX = /([?&])(password|passwd|token|access_token|secret|api_key|auth|session|apikey)=([^&#]*)/gi;

/**
 * Redacts sensitive parameters from URL queries
 */
function redactUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return '/';
  return urlStr.replace(SENSITIVE_PARAM_REGEX, '$1$2=[REDACTED]');
}

/**
 * Parses Apache/Nginx timestamp "10/Oct/2026:13:55:36 +0700" to ISO string
 */
function parseLogTimestamp(tsStr) {
  if (!tsStr) return new Date().toISOString();
  
  // Format: "10/Oct/2026:13:55:36 +0700"
  const match = tsStr.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/);
  if (match) {
    const months = {
      Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
      Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12'
    };
    const day = match[1];
    const month = months[match[2]] || '01';
    const year = match[3];
    const hour = match[4];
    const min = match[5];
    const sec = match[6];
    const tz = match[7];
    const tzFormatted = `${tz.substring(0, 3)}:${tz.substring(3, 5)}`;
    
    const isoLike = `${year}-${month}-${day}T${hour}:${min}:${sec}${tzFormatted}`;
    const d = new Date(isoLike);
    if (!isNaN(d.getTime())) {
      return d.toISOString();
    }
  }

  // Fallback to standard Date parse
  const parsed = new Date(tsStr);
  return !isNaN(parsed.getTime()) ? parsed.toISOString() : new Date().toISOString();
}

/**
 * Computes deduplication hash for an event
 */
function computeLogHash(entry) {
  const key = `${entry.websiteId}|${entry.timestamp}|${entry.ip}|${entry.method}|${entry.url}|${entry.statusCode}`;
  return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Parses raw text lines (Combined Log, Common Log, or JSON Lines) or an array of JSON objects
 * 
 * @param {string|Array<Object>} rawInput - Raw text content or array of log objects
 * @param {string} websiteId - Monitored website ID to attribute to
 * @param {Object} [options]
 * @param {number} [options.maxEntries=1000] - Maximum entries to parse per batch
 * @returns {{ entries: Array<Object>, totalReceived: number, parsedCount: number, errorCount: number, duplicatesSkipped: number, errors: Array<string> }}
 */
function parseIngestionLogs(rawInput, websiteId, options = {}) {
  const maxEntries = options.maxEntries || 1000;
  const entries = [];
  const errors = [];
  const seenHashes = new Set();
  let duplicatesSkipped = 0;
  let totalReceived = 0;

  if (Array.isArray(rawInput)) {
    totalReceived = rawInput.length;
    for (let i = 0; i < Math.min(rawInput.length, maxEntries); i++) {
      const item = rawInput[i];
      try {
        const rawIp = item.ip || item.client_ip || item.remote_addr || '127.0.0.1';
        const rawUrl = item.url || item.path || item.uri || '/';
        const method = (item.method || 'GET').toUpperCase();
        const statusCode = parseInt(item.statusCode || item.status || item.status_code || 200, 10);
        const userAgent = item.userAgent || item.user_agent || item.http_user_agent || 'unknown';
        const responseTime = parseFloat(item.responseTime || item.response_time || item.request_time || 0.0);
        const timestamp = parseLogTimestamp(item.timestamp || item.time || item.time_local || item.time_iso8601);

        const entry = {
          websiteId,
          timestamp,
          ip: normalizeIp(rawIp),
          method,
          url: redactUrl(rawUrl),
          statusCode,
          userAgent,
          responseTime: isNaN(responseTime) ? 0.0 : responseTime,
          isPassive: true
        };

        const hash = computeLogHash(entry);
        if (seenHashes.has(hash)) {
          duplicatesSkipped++;
          continue;
        }
        seenHashes.add(hash);
        entries.push(entry);
      } catch (err) {
        errors.push(`Row ${i + 1}: ${err.message}`);
      }
    }
    return {
      entries,
      totalReceived,
      parsedCount: entries.length,
      errorCount: errors.length,
      duplicatesSkipped,
      errors: errors.slice(0, 10)
    };
  }

  if (typeof rawInput === 'string') {
    const lines = rawInput.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    totalReceived = lines.length;

    for (let i = 0; i < Math.min(lines.length, maxEntries); i++) {
      const line = lines[i];
      try {
        // Try JSON line first
        if (line.startsWith('{') && line.endsWith('}')) {
          const item = JSON.parse(line);
          const rawIp = item.ip || item.client_ip || item.remote_addr || '127.0.0.1';
          const rawUrl = item.url || item.path || item.uri || '/';
          const method = (item.method || 'GET').toUpperCase();
          const statusCode = parseInt(item.statusCode || item.status || item.status_code || 200, 10);
          const userAgent = item.userAgent || item.user_agent || item.http_user_agent || 'unknown';
          const responseTime = parseFloat(item.responseTime || item.response_time || item.request_time || 0.0);
          const timestamp = parseLogTimestamp(item.timestamp || item.time || item.time_local || item.time_iso8601);

          const entry = {
            websiteId,
            timestamp,
            ip: normalizeIp(rawIp),
            method,
            url: redactUrl(rawUrl),
            statusCode,
            userAgent,
            responseTime: isNaN(responseTime) ? 0.0 : responseTime,
            isPassive: true
          };

          const hash = computeLogHash(entry);
          if (seenHashes.has(hash)) {
            duplicatesSkipped++;
            continue;
          }
          seenHashes.add(hash);
          entries.push(entry);
          continue;
        }

        // Try Combined / Common Log format
        const combinedMatch = line.match(COMBINED_LOG_REGEX);
        if (combinedMatch) {
          const [ , ip, , , tsStr, method, url, statusStr, , , userAgent ] = combinedMatch;
          const entry = {
            websiteId,
            timestamp: parseLogTimestamp(tsStr),
            ip: normalizeIp(ip),
            method: method.toUpperCase(),
            url: redactUrl(url),
            statusCode: parseInt(statusStr, 10) || 200,
            userAgent: userAgent || 'unknown',
            responseTime: 0.0,
            isPassive: true
          };

          const hash = computeLogHash(entry);
          if (seenHashes.has(hash)) {
            duplicatesSkipped++;
            continue;
          }
          seenHashes.add(hash);
          entries.push(entry);
          continue;
        }

        const commonMatch = line.match(COMMON_LOG_REGEX);
        if (commonMatch) {
          const [ , ip, , , tsStr, method, url, statusStr ] = commonMatch;
          const entry = {
            websiteId,
            timestamp: parseLogTimestamp(tsStr),
            ip: normalizeIp(ip),
            method: method.toUpperCase(),
            url: redactUrl(url),
            statusCode: parseInt(statusStr, 10) || 200,
            userAgent: 'unknown',
            responseTime: 0.0,
            isPassive: true
          };

          const hash = computeLogHash(entry);
          if (seenHashes.has(hash)) {
            duplicatesSkipped++;
            continue;
          }
          seenHashes.add(hash);
          entries.push(entry);
          continue;
        }

        errors.push(`Line ${i + 1}: Unrecognized log line format`);
      } catch (lineErr) {
        errors.push(`Line ${i + 1}: ${lineErr.message}`);
      }
    }
  }

  return {
    entries,
    totalReceived,
    parsedCount: entries.length,
    errorCount: errors.length,
    duplicatesSkipped,
    errors: errors.slice(0, 10)
  };
}

module.exports = {
  parseIngestionLogs,
  parseLogTimestamp,
  redactUrl,
  computeLogHash
};
