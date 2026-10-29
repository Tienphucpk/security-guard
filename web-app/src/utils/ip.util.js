/**
 * IP Normalization Helper for SECURITY GUARD
 * Standardizes client IP addresses (converts IPv4-mapped IPv6, localhost, trims forwarded proxies)
 */

/**
 * Normalizes an IP address string to a clean standard format
 * @param {string|any} rawIp 
 * @returns {string} Normalized IP address
 */
function normalizeIp(rawIp) {
  if (!rawIp || typeof rawIp !== 'string') {
    return '127.0.0.1';
  }

  // Handle multiple forwarded IPs (take client leftmost IP)
  let ip = rawIp.split(',')[0].trim();

  // Handle IPv6 localhost
  if (ip === '::1' || ip === '::') {
    return '127.0.0.1';
  }

  // Convert IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  // Strip port if present in IPv4 (e.g. 127.0.0.1:8080 -> 127.0.0.1)
  // Be careful with IPv6 addresses that contain colons
  if (ip.includes('.') && ip.includes(':')) {
    const parts = ip.split(':');
    if (parts.length === 2 && parts[0].includes('.')) {
      ip = parts[0];
    }
  }

  return ip || '127.0.0.1';
}

module.exports = {
  normalizeIp
};
