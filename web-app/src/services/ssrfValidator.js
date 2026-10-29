const dns = require('dns').promises;
const net = require('net');

/**
 * Parses an IPv4 address string into a 32-bit integer for fast subnet matching
 */
function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Checks whether an IPv4 int falls inside a given CIDR network
 */
function matchCidr(ipInt, cidrIp, maskBits) {
  const cidrInt = ipv4ToInt(cidrIp);
  if (cidrInt === null) return false;
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (cidrInt & mask);
}

/**
 * Checks if an IPv4 address is in a reserved/private/link-local/loopback range
 */
function isRestrictedIpv4(ipStr) {
  const ipInt = ipv4ToInt(ipStr);
  if (ipInt === null) return true; // Malformed is considered restricted

  // Specific Cloud Metadata endpoint (always blocked)
  if (ipStr === '169.254.169.254') {
    return { restricted: true, reason: 'Cloud metadata IP 169.254.169.254 is forbidden' };
  }

  // 127.0.0.0/8 (Loopback)
  if (matchCidr(ipInt, '127.0.0.0', 8)) {
    return { restricted: true, isPrivate: true, reason: 'Loopback address (127.0.0.0/8) is restricted' };
  }

  // 10.0.0.0/8 (RFC 1918)
  if (matchCidr(ipInt, '10.0.0.0', 8)) {
    return { restricted: true, isPrivate: true, reason: 'Private network (10.0.0.0/8) is restricted' };
  }

  // 172.16.0.0/12 (RFC 1918)
  if (matchCidr(ipInt, '172.16.0.0', 12)) {
    return { restricted: true, isPrivate: true, reason: 'Private network (172.16.0.0/12) is restricted' };
  }

  // 192.168.0.0/16 (RFC 1918)
  if (matchCidr(ipInt, '192.168.0.0', 16)) {
    return { restricted: true, isPrivate: true, reason: 'Private network (192.168.0.0/16) is restricted' };
  }

  // 169.254.0.0/16 (Link-Local)
  if (matchCidr(ipInt, '169.254.0.0', 16)) {
    return { restricted: true, isPrivate: true, reason: 'Link-local address (169.254.0.0/16) is restricted' };
  }

  // 0.0.0.0/8 (Broadcast/Current network)
  if (matchCidr(ipInt, '0.0.0.0', 8)) {
    return { restricted: true, isPrivate: true, reason: 'Non-routable zero network (0.0.0.0/8) is restricted' };
  }

  // 100.64.0.0/10 (Carrier-grade NAT)
  if (matchCidr(ipInt, '100.64.0.0', 10)) {
    return { restricted: true, isPrivate: true, reason: 'Carrier-grade NAT (100.64.0.0/10) is restricted' };
  }

  // 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved)
  if (matchCidr(ipInt, '224.0.0.0', 4) || matchCidr(ipInt, '240.0.0.0', 4)) {
    return { restricted: true, isPrivate: true, reason: 'Multicast or reserved network is restricted' };
  }

  return { restricted: false };
}

/**
 * Checks if an IPv6 address is restricted
 */
function isRestrictedIpv6(ipStr) {
  const normalized = ipStr.toLowerCase().trim();

  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (normalized.startsWith('::ffff:')) {
    const v4 = normalized.replace('::ffff:', '');
    return isRestrictedIpv4(v4);
  }

  // Loopback (::1) or Unspecified (::)
  if (normalized === '::1' || normalized === '::') {
    return { restricted: true, isPrivate: true, reason: 'IPv6 loopback/unspecified is restricted' };
  }

  // Unique Local (fc00::/7) -> fc or fd prefix
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return { restricted: true, isPrivate: true, reason: 'IPv6 Unique Local Address (fc00::/7) is restricted' };
  }

  // Link-Local (fe80::/10) -> fe8, fe9, fea, feb
  if (/^fe[89ab]/i.test(normalized)) {
    return { restricted: true, isPrivate: true, reason: 'IPv6 Link-Local Address (fe80::/10) is restricted' };
  }

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) {
    return { restricted: true, isPrivate: true, reason: 'IPv6 Multicast is restricted' };
  }

  return { restricted: false };
}

/**
 * Validates a target URL against SSRF and DNS rebinding attacks.
 * 
 * @param {string} rawUrl - Target URL to inspect
 * @param {Object} options
 * @param {boolean} [options.allowPrivate=false] - Whether to allow private/loopback IP (e.g. for internal test sites)
 * @returns {Promise<{valid: boolean, error?: string, resolvedIps: string[], normalizedUrl?: string}>}
 */
async function validateExternalUrl(rawUrl, options = {}) {
  const { allowPrivate = false } = options;

  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'URL must be a non-empty string', resolvedIps: [] };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (err) {
    return { valid: false, error: `Invalid URL format: ${err.message}`, resolvedIps: [] };
  }

  // 1. Enforce scheme: only http: and https:
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { 
      valid: false, 
      error: `Unsupported protocol "${parsed.protocol}". Only http: and https: are allowed.`,
      resolvedIps: [] 
    };
  }

  // 2. Reject credentials in URL (user:pass@host)
  if (parsed.username || parsed.password) {
    return { 
      valid: false, 
      error: 'Userinfo credentials in URL are forbidden for security reasons', 
      resolvedIps: [] 
    };
  }

  const hostname = parsed.hostname;

  // 3. Reject local keywords if allowPrivate is false
  const lowerHost = hostname.toLowerCase();
  if (!allowPrivate) {
    if (lowerHost === 'localhost' || lowerHost.endsWith('.localhost') || lowerHost.endsWith('.local') || lowerHost.endsWith('.internal')) {
      return { 
        valid: false, 
        error: `Hostname "${hostname}" resolves to a local/internal domain and is forbidden for external integration.`,
        resolvedIps: [] 
      };
    }
  }

  // 4. DNS resolution: resolve all IP addresses
  let resolvedIps = [];
  try {
    // If hostname is already an IP address
    if (net.isIP(hostname)) {
      resolvedIps = [hostname];
    } else {
      const records = await dns.lookup(hostname, { all: true });
      resolvedIps = records.map(r => r.address);
    }
  } catch (dnsErr) {
    return { 
      valid: false, 
      error: `DNS resolution failed for hostname "${hostname}": ${dnsErr.message}`,
      resolvedIps: [] 
    };
  }

  if (resolvedIps.length === 0) {
    return { 
      valid: false, 
      error: `No IP addresses found for hostname "${hostname}"`,
      resolvedIps: [] 
    };
  }

  // 5. Inspect every resolved IP address
  for (const ip of resolvedIps) {
    const isV6 = net.isIPv6(ip);
    const check = isV6 ? isRestrictedIpv6(ip) : isRestrictedIpv4(ip);

    // Cloud metadata (169.254.169.254) is NEVER allowed even if allowPrivate=true
    if (ip === '169.254.169.254') {
      return { 
        valid: false, 
        error: 'Forbidden destination: AWS/GCP/Azure Cloud Metadata IP (169.254.169.254)',
        resolvedIps 
      };
    }

    if (check.restricted) {
      if (check.isPrivate && allowPrivate) {
        // Permitted only when explicitly allowed for internal demo/testing
        continue;
      }
      return { 
        valid: false, 
        error: `SSRF Violation: Resolved IP ${ip} is restricted (${check.reason || 'private or reserved range'}).`,
        resolvedIps 
      };
    }
  }

  return {
    valid: true,
    resolvedIps,
    normalizedUrl: parsed.origin + parsed.pathname + parsed.search
  };
}

module.exports = {
  validateExternalUrl,
  isRestrictedIpv4,
  isRestrictedIpv6
};
