const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const requestLogger = require('./middleware/logger.middleware');
const routes = require('./routes');

const app = express();
const PORT = process.env.WEB_PORT || 3000;
const HOST = process.env.WEB_HOST || '0.0.0.0';

// Body & Cookie parsing middleware with size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// Security Headers Middleware (OWASP defensive headers)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Serve static assets from public/
app.use(express.static(path.join(__dirname, '../public')));

// CORS Middleware (allow credentials with specific origins from Dashboard port 5173)
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (allowedOrigins.includes(origin) || origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:'))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  } else {
    res.header('Access-Control-Allow-Origin', '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-API-Key, X-Admin-Key');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Request logging foundation middleware (executed for all requests)
app.use(requestLogger);

// Mount application routes
app.use('/', routes);

// 404 Not Found handler
app.use((req, res) => {
  res.status(404).json({
    status: 404,
    error: 'Not Found',
    path: req.originalUrl,
    timestamp: new Date().toISOString()
  });
});

// Centralized error handling
app.use((err, req, res, next) => {
  // Handle payload too large error from body-parser
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({
      status: 413,
      error: 'Payload Too Large',
      message: 'Request entity exceeds allowable size limit (max 1MB)'
    });
  }

  // Handle syntax error from malformed JSON
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      status: 400,
      error: 'Bad Request',
      message: 'Malformed JSON payload'
    });
  }

  const statusCode = err.status || err.statusCode || 500;
  console.error('[SERVER ERROR]', err.stack);
  const isDev = (process.env.NODE_ENV || 'development') !== 'production';
  res.status(statusCode).json({
    status: statusCode,
    error: statusCode === 400 ? 'Bad Request' : 'Internal Server Error',
    message: isDev ? err.message : (statusCode === 400 ? 'Invalid request data' : 'An unexpected internal error occurred')
  });
});

// Start listening only when not imported as module
if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`===============================================`);
    console.log(` SECURITY GUARD - Web Application Running`);
    console.log(` URL: http://${HOST}:${PORT}`);
    console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(` Logging Active -> logs/requests.log`);
    console.log(`===============================================`);
  });
}

module.exports = app;
