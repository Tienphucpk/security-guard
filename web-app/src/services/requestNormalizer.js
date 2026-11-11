/**
 * Request Normalizer & De-obfuscator for Security Guard
 * Normalizes multi-layered encodings (Double URL, Hex, HTML Entities, Comment Obfuscation)
 * and sanitizes sensitive fields before inspection and evidence storage.
 */

const SENSITIVE_KEYS = new Set([
  'password', 'pass', 'pwd', 'token', 'access_token', 'refresh_token',
  'secret', 'api_key', 'apikey', 'authorization', 'cookie', 'credit_card',
  'card_number', 'cvv', 'cvc', 'ssn'
]);

/**
 * Recursively decodes URL encoding up to maxIterations to unmask double-encoding attacks
 * (e.g., %2527 -> %27 -> ')
 * @param {string} rawStr
 * @param {number} maxIterations
 * @returns {string}
 */
function recursiveUrlDecode(rawStr, maxIterations = 3) {
  if (!rawStr || typeof rawStr !== 'string') return '';
  let current = rawStr;
  for (let i = 0; i < maxIterations; i++) {
    try {
      const decoded = decodeURIComponent(current.replace(/\+/g, ' '));
      if (decoded === current) break;
      current = decoded;
    } catch {
      // Malformed URI sequence: break to avoid crash
      break;
    }
  }
  return current;
}

/**
 * Decodes standard HTML entities (e.g., &quot;, &#39;, &#x27;, &lt;, &gt;)
 * @param {string} rawStr
 * @returns {string}
 */
function decodeHtmlEntities(rawStr) {
  if (!rawStr || typeof rawStr !== 'string') return '';
  return rawStr
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&#x0*27;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#0*60;/g, '<')
    .replace(/&#x0*3c;/gi, '<')
    .replace(/&#0*62;/g, '>')
    .replace(/&#x0*3e;/gi, '>')
    .replace(/&amp;/gi, '&');
}

/**
 * Normalizes SQL comment obfuscation (e.g. UN[comment]ION to UNION, --+ to --)
 * @param {string} rawStr
 * @returns {string}
 */
function normalizeSqlSyntax(rawStr) {
  if (!rawStr || typeof rawStr !== 'string') return '';
  let normalized = rawStr;
  // Known obfuscated split SQL keywords (e.g., UN/**/ION, SEL/**/ECT, OR/**/DER)
  normalized = normalized.replace(/un(?:\/\*[\s\S]*?\*\/)+ion/gi, 'UNION');
  normalized = normalized.replace(/sel(?:\/\*[\s\S]*?\*\/)+ect/gi, 'SELECT');
  normalized = normalized.replace(/or(?:\/\*[\s\S]*?\*\/)+der/gi, 'ORDER');
  normalized = normalized.replace(/fr(?:\/\*[\s\S]*?\*\/)+om/gi, 'FROM');
  normalized = normalized.replace(/wh(?:\/\*[\s\S]*?\*\/)+ere/gi, 'WHERE');
  // Replace remaining comment blocks with a space (e.g. SELECT/**/1 -> SELECT 1)
  normalized = normalized.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Strip null bytes
  normalized = normalized.replace(/\0/g, '');
  // Normalize multi-spaces
  return normalized.replace(/\s+/g, ' ').trim();
}

/**
 * Comprehensive multi-layer normalization for an input string
 * @param {string} rawStr
 * @returns {string}
 */
function normalizeText(rawStr) {
  if (!rawStr || typeof rawStr !== 'string') return '';
  let text = recursiveUrlDecode(rawStr);
  text = decodeHtmlEntities(text);
  text = normalizeSqlSyntax(text);
  return text.trim();
}

/**
 * Redacts sensitive fields from objects or query strings
 * @param {Object} obj
 * @returns {Object} Cleaned copy
 */
function redactObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const cleaned = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(k.toLowerCase())) {
      cleaned[k] = '[REDACTED]';
    } else if (typeof v === 'object' && v !== null) {
      cleaned[k] = redactObject(v);
    } else {
      cleaned[k] = v;
    }
  }
  return cleaned;
}

/**
 * Redacts sensitive query parameters from a URL path
 * @param {string} urlPath
 * @returns {string}
 */
function redactUrlQuery(urlPath) {
  if (!urlPath || typeof urlPath !== 'string') return '/';
  try {
    const parts = urlPath.split('?');
    if (parts.length < 2) return urlPath;
    const [pathPart, queryPart] = parts;
    const params = new URLSearchParams(queryPart);
    for (const key of params.keys()) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        params.set(key, '[REDACTED]');
      }
    }
    return `${pathPart}?${decodeURIComponent(params.toString())}`;
  } catch {
    return urlPath;
  }
}

/**
 * Sanitizes headers to eliminate sensitive authorization tokens and cookies from audits
 * @param {Object} headers
 * @returns {Object}
 */
function sanitizeHeaders(headers = {}) {
  const safe = {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'authorization' || lower === 'cookie' || lower === 'set-cookie' || lower.includes('secret')) {
      safe[key] = '[REDACTED]';
    } else {
      safe[key] = value;
    }
  }
  return safe;
}

module.exports = {
  recursiveUrlDecode,
  decodeHtmlEntities,
  normalizeSqlSyntax,
  normalizeText,
  redactObject,
  redactUrlQuery,
  sanitizeHeaders,
  SENSITIVE_KEYS
};
