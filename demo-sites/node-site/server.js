/**
 * Demo Website 1: Node.js E-Commerce Shop
 * Port: 4001
 * Zero external dependencies (Pure Node.js HTTP server)
 */

const http = require('http');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '4001', 10);
const HOST = '0.0.0.0';

const PRODUCTS = [
  { id: 1, name: 'Laptop Pro 15', price: 1200, category: 'Electronics' },
  { id: 2, name: 'Wireless Noise-Cancelling Headphones', price: 180, category: 'Audio' },
  { id: 3, name: 'Mechanical Gaming Keyboard', price: 95, category: 'Accessories' },
  { id: 4, name: 'Ultra-Wide 4K Monitor', price: 450, category: 'Displays' },
  { id: 5, name: 'Ergonomic Office Chair', price: 220, category: 'Furniture' }
];

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost:4001'}`);
  const pathname = parsedUrl.pathname;

  // JSON helper
  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'X-App-Framework': 'Node.js/http-native',
      'X-App-Name': 'Node.js Demo Shop (:4001)'
    });
    res.end(JSON.stringify(data, null, 2));
  };

  // 1. Health check
  if (pathname === '/health') {
    return sendJson(200, {
      status: 'ok',
      app: 'demo-node-shop',
      technology: 'Node.js',
      port: PORT,
      timestamp: new Date().toISOString()
    });
  }

  // 2. Home page
  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Demo Node.js E-Commerce Shop</title>
        <style>
          body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #0f172a; color: #f8fafc; }
          h1 { color: #38bdf8; }
          .card { background: #1e293b; padding: 15px; border-radius: 8px; margin: 10px 0; border: 1px solid #334155; }
          a { color: #38bdf8; text-decoration: none; }
          code { background: #0284c722; color: #38bdf8; padding: 2px 6px; border-radius: 4px; }
        </style>
      </head>
      <body>
        <h1>🛒 Node.js Demo Shop (Port ${PORT})</h1>
        <p>Website thương mại điện tử thử nghiệm được bảo vệ và giám sát bởi <strong>Security Guard Gateway</strong>.</p>
        <div class="card">
          <h3>📦 Danh mục API:</h3>
          <ul>
            <li><code>GET /products</code> — Danh sách sản phẩm</li>
            <li><code>GET /search?q=laptop</code> — Tìm kiếm sản phẩm</li>
            <li><code>POST /feedback</code> — Gửi phản hồi</li>
            <li><code>GET /health</code> — Kiểm tra trạng thái</li>
          </ul>
        </div>
      </body>
      </html>
    `);
  }

  // 3. Products list
  if (pathname === '/products') {
    return sendJson(200, {
      app: 'demo-node-shop',
      total: PRODUCTS.length,
      products: PRODUCTS
    });
  }

  // 4. Product Search
  if (pathname === '/search') {
    const query = parsedUrl.searchParams.get('q') || '';
    const filtered = PRODUCTS.filter(p => p.name.toLowerCase().includes(query.toLowerCase()));
    return sendJson(200, {
      app: 'demo-node-shop',
      query: query,
      totalMatches: filtered.length,
      results: filtered
    });
  }

  // 5. Customer Feedback submission
  if (pathname === '/feedback' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let parsed = {};
      try { parsed = JSON.parse(body); } catch { parsed = { raw: body }; }
      return sendJson(200, {
        status: 'success',
        message: 'Feedback received successfully',
        feedback: parsed
      });
    });
    return;
  }

  // 404
  return sendJson(404, {
    error: 'Not Found',
    path: pathname,
    message: 'Page or endpoint not found on demo-node-shop'
  });
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[DEMO NODE SHOP] Running on http://${HOST}:${PORT}`);
  });
}

module.exports = server;
