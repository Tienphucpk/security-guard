/**
 * SECURITY GUARD - Real-World Integration Lab Target Web Application
 * Independent external web application simulating a production portal.
 * Default Port: 4005
 * Zero external dependencies (Pure Node.js HTTP server)
 */

const http = require('http');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '4005', 10);
const HOST = '127.0.0.1';

const ARTICLES = [
  { id: 1, title: 'Introduction to Modern Web Security Architectures', author: 'Dr. Jane Doe', category: 'Security' },
  { id: 2, title: 'Zero Trust Network Access in Enterprise Environments', author: 'Alex Smith', category: 'Infrastructure' },
  { id: 3, title: 'Machine Learning for Real-Time Threat Detection', author: 'Minh Nguyen', category: 'AI/ML' },
  { id: 4, title: 'Mitigating Web Application Vulnerabilities at Scale', author: 'Elena Rostova', category: 'DevSecOps' }
];

const COMMENTS = [];

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost:4005'}`);
  const pathname = parsedUrl.pathname;
  const searchParams = parsedUrl.searchParams;

  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'X-Upstream-Server': 'Integration-Lab-Portal-4005',
      'X-Powered-By': 'NodeJS/Standalone'
    });
    res.end(JSON.stringify(data, null, 2));
  };

  // 1. Health check
  if (pathname === '/health') {
    return sendJson(200, {
      status: 'ok',
      service: 'Integration Lab Portal',
      port: PORT,
      timestamp: new Date().toISOString()
    });
  }

  // 2. Portal Index
  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Integration Lab Portal</title>
        <style>
          body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #0b1329; color: #e2e8f0; }
          h1 { color: #38bdf8; }
          .card { background: #1e293b; padding: 15px; border-radius: 8px; margin: 12px 0; border: 1px solid #334155; }
          code { background: #0369a133; color: #38bdf8; padding: 2px 6px; border-radius: 4px; }
        </style>
      </head>
      <body>
        <h1>Enterprise Research Portal (Port ${PORT})</h1>
        <p>This is an independent standalone web application integrated into <strong>SECURITY GUARD</strong> via Reverse Proxy.</p>
        <div class="card">
          <h3>Available Endpoints</h3>
          <ul>
            <li><code>GET /health</code> - Health status check</li>
            <li><code>GET /api/articles?q=search_term</code> - Search research articles</li>
            <li><code>POST /api/comments</code> - Submit public feedback</li>
            <li><code>GET /api/profile?id=1</code> - View author profile</li>
          </ul>
        </div>
      </body>
      </html>
    `);
  }

  // 3. Search Articles
  if (pathname === '/api/articles') {
    const query = (searchParams.get('q') || '').toLowerCase();
    const results = query
      ? ARTICLES.filter(a => a.title.toLowerCase().includes(query) || a.author.toLowerCase().includes(query))
      : ARTICLES;
    return sendJson(200, {
      status: 'success',
      query: query || null,
      count: results.length,
      articles: results
    });
  }

  // 4. Submit Feedback / Comments
  if (pathname === '/api/comments' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const comment = {
          id: COMMENTS.length + 1,
          name: payload.name || 'Anonymous',
          comment: payload.comment || '',
          timestamp: new Date().toISOString()
        };
        COMMENTS.push(comment);
        return sendJson(201, { status: 'success', message: 'Comment submitted', comment });
      } catch {
        return sendJson(400, { status: 'error', message: 'Invalid JSON payload' });
      }
    });
    return;
  }

  // 5. User Profile
  if (pathname === '/api/profile') {
    const id = parseInt(searchParams.get('id') || '1', 10);
    const author = ARTICLES.find(a => a.id === id);
    if (!author) {
      return sendJson(404, { status: 'error', message: 'Author not found' });
    }
    return sendJson(200, { status: 'success', profile: author });
  }

  // Fallback 404
  return sendJson(404, { status: 'error', message: 'Endpoint not found on Integration Lab Portal' });
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[INTEGRATION LAB] Server listening on http://${HOST}:${PORT}`);
  });
}

module.exports = server;
