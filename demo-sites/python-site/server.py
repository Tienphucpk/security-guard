"""
Demo Website 2: Python Corporate Portal & Directory Service
Port: 4002
Technology: Python HTTP Server (Zero extra pip dependencies)
"""

import sys
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = 4002
HOST = '0.0.0.0'

STAFF_DIRECTORY = [
    {"id": 101, "name": "Nguyen Van An", "role": "Security Analyst", "department": "SOC"},
    {"id": 102, "name": "Tran Thi Binh", "role": "DevOps Engineer", "department": "Infrastructure"},
    {"id": 103, "name": "Le Hoang Nam", "role": "Backend Lead", "department": "Platform"},
    {"id": 104, "name": "Pham Minh Duc", "role": "Database Administrator", "department": "Data"}
]

class PortalHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-App-Framework', 'Python/http.server')
        self.send_header('X-App-Name', 'Python Demo Portal (:4002)')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == '/health':
            return self._send_json(200, {
                "status": "ok",
                "app": "demo-python-portal",
                "technology": "Python",
                "port": PORT,
                "version": sys.version.split()[0]
            })

        if path in ['/', '/index.html']:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Python Demo Corporate Portal</title>
                <style>
                    body {{ font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #0f172a; color: #f8fafc; }}
                    h1 {{ color: #22c55e; }}
                    .card {{ background: #1e293b; padding: 15px; border-radius: 8px; margin: 10px 0; border: 1px solid #334155; }}
                    code {{ background: #15803d22; color: #4ade80; padding: 2px 6px; border-radius: 4px; }}
                </style>
            </head>
            <body>
                <h1>🐍 Python Demo Portal (Port {PORT})</h1>
                <p>Cổng thông tin nội bộ Python được bảo vệ và giám sát độc lập bởi <strong>Security Guard Gateway</strong>.</p>
                <div class="card">
                    <h3>📂 Endpoints:</h3>
                    <ul>
                        <li><code>GET /directory</code> — Danh bạ nhân sự</li>
                        <li><code>GET /lookup?user=nam</code> — Tra cứu nhân viên</li>
                        <li><code>POST /inquiry</code> — Gửi yêu cầu hỗ trợ</li>
                        <li><code>GET /health</code> — Kiểm tra trạng thái</li>
                    </ul>
                </div>
            </body>
            </html>
            """
            return self.wfile.write(html.encode('utf-8'))

        if path == '/directory':
            return self._send_json(200, {
                "app": "demo-python-portal",
                "total": len(STAFF_DIRECTORY),
                "staff": STAFF_DIRECTORY
            })

        if path == '/lookup':
            user_param = query.get('user', [''])[0]
            results = [s for s in STAFF_DIRECTORY if user_param.lower() in s['name'].lower() or user_param.lower() in s['role'].lower()]
            return self._send_json(200, {
                "app": "demo-python-portal",
                "query": user_param,
                "matches": len(results),
                "results": results
            })

        return self._send_json(404, {
            "error": "Not Found",
            "path": path,
            "message": "Resource not found on demo-python-portal"
        })

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/inquiry':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
            try:
                data = json.loads(body)
            except Exception:
                data = {"raw": body}
            return self._send_json(200, {
                "status": "success",
                "message": "Inquiry recorded by Python Demo Portal",
                "received": data
            })

        return self._send_json(404, {"error": "Not Found", "path": self.path})

    def log_message(self, format, *args):
        # Suppress stdout spam
        pass

def run():
    server = HTTPServer((HOST, PORT), PortalHandler)
    print(f"[DEMO PYTHON PORTAL] Running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    run()
