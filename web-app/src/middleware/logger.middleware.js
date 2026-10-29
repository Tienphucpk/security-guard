const { logRequest } = require('../utils/logger');
const { normalizeIp } = require('../utils/ip.util');

/**
 * Middleware capturing HTTP request metadata, normalizing client IP, and logging metrics
 */
function requestLogger(req, res, next) {
  const startTime = Date.now();

  // Capture client IP and normalize IPv4-mapped IPv6 / proxies
  const rawIp = (
    req.headers['x-forwarded-for'] ||
    req.socket.remoteAddress ||
    req.ip ||
    '127.0.0.1'
  ).toString();

  const clientIp = normalizeIp(rawIp);

  // Attach listener on response finish event
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;

    const logEntry = {
      timestamp: new Date().toISOString(),
      ip: clientIp,
      method: req.method,
      url: req.originalUrl || req.url,
      statusCode: res.statusCode,
      userAgent: req.headers['user-agent'] || 'unknown',
      responseTime: responseTime
    };

    logRequest(logEntry);
  });

  next();
}

module.exports = requestLogger;
