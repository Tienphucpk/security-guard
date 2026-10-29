/**
 * Controller handling public pages and views
 */

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Sample mock articles for search simulation
const mockArticles = [
  { id: 1, title: 'Tổng quan về An toàn và Bảo mật thông tin Website', category: 'Security Guide', snippet: 'Nghiên cứu các mối đe dọa phổ biến đối với ứng dụng web và các giải pháp phòng thủ đa tầng.' },
  { id: 2, title: 'Cơ chế hoạt động của Web Application Firewall (WAF)', category: 'Firewall', snippet: 'Phân tích cách WAF kiểm tra và lọc các gói tin HTTP request để phát hiện tấn công SQLi, XSS.' },
  { id: 3, title: 'Giới thiệu giải thuật Machine Learning trong phát hiện bất thường', category: 'Anomaly Detection', snippet: 'Ứng dụng thuật toán Isolation Forest để nhận diện các điểm dữ liệu dị biệt trong chuỗi request log.' },
  { id: 4, title: 'Hướng dẫn thiết lập môi trường Lab kiểm thử an ninh mạng', category: 'Lab Setup', snippet: 'Mô hình hóa hệ thống tấn công - phòng thủ cô lập sử dụng VMware Workstation và Kali Linux.' }
];

const pageController = {
  getHomePage: (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>SECURITY GUARD - Vulnerable Target Website</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h1>SECURITY GUARD</h1>
            <p class="subtitle">Ứng dụng Web Thử nghiệm - Môn Bảo mật & An toàn thông tin</p>
          </header>
          <div class="nav-links">
            <a href="/login" class="nav-btn">Đăng nhập</a>
            <a href="/register" class="nav-btn">Đăng ký</a>
            <a href="/dashboard" class="nav-btn">Dashboard người dùng</a>
            <a href="/profile" class="nav-btn">Profile</a>
            <a href="/search?q=security" class="nav-btn">Tìm kiếm thử nghiệm</a>
            <a href="/api/health" class="nav-btn status-btn">API Health Check</a>
          </div>
          <div class="card">
            <h3>Trạng thái Môi trường</h3>
            <p>Ứng dụng đang hoạt động và ghi nhận mọi HTTP request qua Logging Middleware.</p>
            <ul>
              <li><strong>Mục đích:</strong> Sinh traffic HTTP để kiểm thử hệ thống phát hiện hành vi bất thường.</li>
              <li><strong>Logging:</strong> Ghi log định dạng JSON vào file <code>logs/requests.log</code> và PostgreSQL.</li>
            </ul>
          </div>
        </div>
      </body>
      </html>
    `);
  },

  getDashboardPage: (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>User Dashboard - Security Guard</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>User Dashboard</h2>
            <p class="subtitle">Khu vực người dùng được bảo vệ</p>
          </header>
          <div class="card">
            <p>Chào mừng đến với trang quản trị cá nhân thử nghiệm.</p>
            <p style="margin-top: 1rem;"><a href="/" class="btn">Quay lại trang chủ</a> | <a href="/profile" class="btn">Xem hồ sơ</a></p>
          </div>
        </div>
      </body>
      </html>
    `);
  },

  getProfilePage: (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>User Profile - Security Guard</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>User Profile</h2>
          </header>
          <div class="card">
            <p><strong>Username:</strong> demo_user</p>
            <p><strong>Email:</strong> demo@securityguard.local</p>
            <p><strong>Role:</strong> Standard User</p>
            <p style="margin-top: 1rem;"><a href="/" class="btn">Quay lại trang chủ</a></p>
          </div>
        </div>
      </body>
      </html>
    `);
  },

  getSearchPage: (req, res) => {
    const rawQuery = req.query.q !== undefined ? String(req.query.q) : '';
    const safeQuery = escapeHtml(rawQuery);

    // Filter mock results if search query provided
    let results = [];
    if (rawQuery.trim() !== '') {
      const qLower = rawQuery.toLowerCase();
      results = mockArticles.filter(a => 
        a.title.toLowerCase().includes(qLower) || 
        a.snippet.toLowerCase().includes(qLower) ||
        a.category.toLowerCase().includes(qLower)
      );
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Search - Security Guard</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>Tìm kiếm Thử nghiệm</h2>
            <p class="subtitle">Mô phỏng truy vấn dữ liệu & tiếp nhận tham số URL (Query Parameters)</p>
          </header>

          <div class="form-card">
            <form method="GET" action="/search">
              <div class="form-group">
                <label for="q"><strong>Từ khóa tìm kiếm:</strong></label>
                <input type="text" id="q" name="q" value="${safeQuery}" placeholder="Nhập từ khóa tìm kiếm..." />
              </div>
              <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
                <button type="submit" class="btn btn-primary">Tìm kiếm</button>
                <a href="/search" class="btn">Xóa tìm kiếm</a>
                <a href="/" class="btn">Trang chủ</a>
              </div>
            </form>

            <div style="margin-top: 1.25rem; padding-top: 1rem; border-top: 1px dashed #e2e8f0;">
              <p style="font-size: 0.85rem; color: #64748b; margin-bottom: 0.5rem;">
                <strong>Gợi ý kịch bản Demo nhanh (Click để thử nghiệm):</strong>
              </p>
              <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                <a href="/search?q=security" class="nav-btn" style="font-size: 0.8rem; padding: 0.3rem 0.6rem;">Lưu lượng chuẩn: "security"</a>
                <a href="/search?q=' OR '1'='1" class="nav-btn" style="font-size: 0.8rem; padding: 0.3rem 0.6rem; border-color: #fca5a5; color: #b91c1c;">Mô phỏng SQLi: ' OR '1'='1</a>
                <a href="/search?q=%3Cscript%3Ealert(1)%3C/script%3E" class="nav-btn" style="font-size: 0.8rem; padding: 0.3rem 0.6rem; border-color: #fdba74; color: #c2410c;">Mô phỏng XSS: &lt;script&gt;</a>
                <a href="/search?q=../../etc/passwd" class="nav-btn" style="font-size: 0.8rem; padding: 0.3rem 0.6rem; border-color: #cbd5e1; color: #475569;">Path Traversal: ../../etc/passwd</a>
              </div>
            </div>
          </div>

          <div class="card">
            ${rawQuery.trim() !== '' ? `
              <div class="alert alert-success" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1.25rem;">
                <div>
                  <strong>✓ Yêu cầu HTTP đã được Logging Middleware ghi vết thành công!</strong>
                  <p style="font-size: 0.85rem; margin-top: 0.25rem;">
                    Method: <code>GET</code> | URL: <code>/search?q=${safeQuery}</code> | Trạng thái: <span style="font-weight: 600;">200 OK</span>
                  </p>
                </div>
                <a href="http://localhost:5173" target="_blank" class="btn" style="font-size: 0.8rem; background: #ffffff; color: #065f46; border-color: #a7f3d0;">
                  Mở Dashboard xem lưu lượng ↗
                </a>
              </div>
            ` : ''}

            <h3>Kết quả Tìm kiếm</h3>
            <p>Từ khóa hiện tại: <code>${safeQuery ? safeQuery : '(không có từ khóa)'}</code></p>
            
            ${rawQuery.trim() === '' ? `
              <p style="color: #64748b; margin-top: 0.75rem;">Nhập từ khóa hoặc bấm vào một trong các kịch bản mẫu ở trên để bắt đầu tìm kiếm.</p>
            ` : results.length > 0 ? `
              <div style="margin-top: 1rem;">
                <p style="font-size: 0.9rem; color: #10b981; margin-bottom: 0.75rem;">Tìm thấy ${results.length} bài viết phù hợp:</p>
                ${results.map(r => `
                  <div style="padding: 0.75rem; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 0.6rem; background: #f8fafc;">
                    <h4 style="color: #1e3a8a; margin-bottom: 0.25rem;">${r.title}</h4>
                    <span style="font-size: 0.75rem; background: #e0f2fe; color: #0369a1; padding: 0.15rem 0.4rem; border-radius: 4px;">${r.category}</span>
                    <p style="font-size: 0.88rem; color: #475569; margin-top: 0.35rem;">${r.snippet}</p>
                  </div>
                `).join('')}
              </div>
            ` : `
              <p style="color: #64748b; margin-top: 0.75rem;">Không tìm thấy bài viết nào phù hợp với từ khóa trên.</p>
            `}

            <div class="details-box" style="margin-top: 1.5rem;">
              <p><strong>Ghi vết bảo mật (Security Trace):</strong></p>
              <p style="font-size: 0.85rem; color: #64748b;">
                Mỗi khi bạn tìm kiếm, toàn bộ chuỗi URL (bao gồm cả query string <code>?q=...</code>) đều được Logging Middleware ghi nhận lập tức vào <code>web-app/logs/requests.log</code> và cơ sở dữ liệu. 
                Ở Phase 3, Detection Engine sẽ phân tích chuỗi này để phát hiện các dấu hiệu tấn công bất thường.
              </p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
  }
};

module.exports = pageController;
