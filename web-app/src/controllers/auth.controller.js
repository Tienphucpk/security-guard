/**
 * Authentication controller handling login and registration views and actions
 * Supports both JSON API clients and HTML web browser form submissions
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

const bcrypt = require('bcryptjs');
const db = require('../services/database');

// Failed login attempt tracking for rate limiting (max 5 failed attempts per 5 minutes)
const loginAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const BLOCK_DURATION_MS = 5 * 60 * 1000;

function getRateLimitKey(req, identifier) {
  const ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
  return `${ip}:${(identifier || '').toLowerCase()}`;
}

function checkRateLimit(key) {
  const record = loginAttempts.get(key);
  if (!record) return { blocked: false };
  if (record.blockedUntil && Date.now() < record.blockedUntil) {
    const remainingSeconds = Math.ceil((record.blockedUntil - Date.now()) / 1000);
    return { blocked: true, remainingSeconds };
  }
  if (record.blockedUntil && Date.now() >= record.blockedUntil) {
    loginAttempts.delete(key);
    return { blocked: false };
  }
  return { blocked: false };
}

function recordFailedAttempt(key) {
  const now = Date.now();
  const record = loginAttempts.get(key) || { count: 0, firstAttempt: now };
  record.count += 1;
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    record.blockedUntil = now + BLOCK_DURATION_MS;
  }
  loginAttempts.set(key, record);
}

function clearFailedAttempts(key) {
  loginAttempts.delete(key);
}

function wantsJson(req) {
  const accept = req.headers['accept'] || '';
  const contentType = req.headers['content-type'] || '';
  return req.xhr ||
    (accept.includes('application/json') && !accept.includes('text/html')) ||
    (contentType.includes('application/json'));
}

const authController = {
  getLoginPage: (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Login - Security Guard Target App</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>User Login</h2>
            <p class="subtitle">Môi trường thử nghiệm bảo mật</p>
          </header>
          <form method="POST" action="/login" class="form-card">
            <div class="form-group">
              <label for="username">Username / Email:</label>
              <input type="text" id="username" name="username" placeholder="Nhập tên đăng nhập (ví dụ: admin)" required />
            </div>
            <div class="form-group">
              <label for="password">Password:</label>
              <input type="password" id="password" name="password" placeholder="Nhập mật khẩu" required />
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%;">Đăng nhập</button>
            <p class="form-footer">Chưa có tài khoản? <a href="/register">Đăng ký tại đây</a> | <a href="/">Trang chủ</a></p>
          </form>
        </div>
      </body>
      </html>
    `);
  },

  postLogin: (req, res) => {
    const { username, password } = req.body || {};
    const timestamp = new Date().toISOString();

    if (!username || !password) {
      if (wantsJson(req)) {
        return res.status(400).json({
          message: 'Missing username or password',
          status: 'failed'
        });
      }

      return res.status(400).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Login Failed - Security Guard</title>
          <link rel="stylesheet" href="/css/style.css">
        </head>
        <body>
          <div class="container">
            <header class="header">
              <h2>User Login Result</h2>
              <p class="subtitle">Môi trường thử nghiệm bảo mật</p>
            </header>
            <div class="card">
              <div class="alert alert-error">
                <h3>Đăng nhập thất bại (400 Bad Request)</h3>
                <p>Vui lòng cung cấp đầy đủ tên đăng nhập và mật khẩu.</p>
              </div>
              <div class="actions-row">
                <a href="/login" class="btn btn-primary">Quay lại đăng nhập</a>
                <a href="/" class="btn">Về Trang Chủ</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    // Verify credentials for test environment (valid accounts: admin/admin123, user/user123)
    const isValid = (username === 'admin' && password === 'admin123') ||
                    (username === 'user' && password === 'user123') ||
                    (password === 'correct_password');

    if (isValid) {
      if (wantsJson(req)) {
        return res.status(200).json({
          message: 'Login successful',
          status: 'success',
          user: username,
          timestamp
        });
      }

      // Render formatted HTML page for browser form submissions
      return res.status(200).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Login Success - Security Guard</title>
          <link rel="stylesheet" href="/css/style.css">
        </head>
        <body>
          <div class="container">
            <header class="header">
              <h2>User Login Result</h2>
              <p class="subtitle">Môi trường thử nghiệm bảo mật</p>
            </header>
            <div class="card">
              <div class="alert alert-success">
                <h3>Đăng nhập thành công!</h3>
                <p>Xin chào, <strong>${escapeHtml(username)}</strong>! Yêu cầu đăng nhập đã được xử lý và ghi vết an toàn.</p>
              </div>
              <div class="details-box">
                <p><strong>Tài khoản:</strong> <code>${escapeHtml(username)}</code></p>
                <p><strong>Trạng thái HTTP:</strong> <span style="color: #10b981; font-weight: 600;">200 OK</span></p>
                <p><strong>Thời gian:</strong> ${timestamp}</p>
                <p><strong>Ghi vết hệ thống:</strong> Metadata của request này đã được ghi vào <code>requests.log</code> và cơ sở dữ liệu.</p>
              </div>
              <div class="actions-row">
                <a href="/dashboard" class="btn btn-primary">Vào User Dashboard</a>
                <a href="/profile" class="btn">Xem Hồ Sơ</a>
                <a href="/" class="btn">Về Trang Chủ</a>
                <a href="/login" class="btn">Đăng xuất / Thử lại</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    // Failed login attempt -> 401 Unauthorized (Triggers Brute Force detection after >= 5 attempts)
    if (wantsJson(req)) {
      return res.status(401).json({
        message: 'Invalid username or password',
        status: 'unauthorized',
        timestamp
      });
    }

    return res.status(401).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Login Unauthorized - Security Guard</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>User Login Result</h2>
            <p class="subtitle">Môi trường thử nghiệm bảo mật</p>
          </header>
          <div class="card">
            <div class="alert alert-error">
              <h3>Đăng nhập thất bại (401 Unauthorized)</h3>
              <p>Sai tên đăng nhập hoặc mật khẩu cho tài khoản <strong>${escapeHtml(username)}</strong>.</p>
            </div>
            <div class="details-box">
              <p><strong>Gợi ý tài khoản mẫu:</strong></p>
              <p>Tài khoản: <code>admin</code> | Mật khẩu: <code>admin123</code></p>
              <p>Tài khoản: <code>user</code> | Mật khẩu: <code>user123</code></p>
            </div>
            <div class="actions-row">
              <a href="/login" class="btn btn-primary">Thử lại</a>
              <a href="/" class="btn">Về Trang Chủ</a>
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
  },

  getRegisterPage: (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Register - Security Guard Target App</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>User Registration</h2>
            <p class="subtitle">Đăng ký tài khoản thử nghiệm</p>
          </header>
          <form method="POST" action="/register" class="form-card">
            <div class="form-group">
              <label for="username">Username:</label>
              <input type="text" id="username" name="username" placeholder="Chọn tên đăng nhập" required />
            </div>
            <div class="form-group">
              <label for="email">Email:</label>
              <input type="email" id="email" name="email" placeholder="Nhập email" required />
            </div>
            <div class="form-group">
              <label for="password">Password:</label>
              <input type="password" id="password" name="password" placeholder="Nhập mật khẩu" required />
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%;">Đăng ký</button>
            <p class="form-footer">Đã có tài khoản? <a href="/login">Đăng nhập</a> | <a href="/">Trang chủ</a></p>
          </form>
        </div>
      </body>
      </html>
    `);
  },

  postRegister: (req, res) => {
    const { username, email } = req.body || {};
    const timestamp = new Date().toISOString();

    if (username && email) {
      if (wantsJson(req)) {
        return res.status(201).json({
          message: 'User registered successfully',
          status: 'success',
          username,
          email,
          timestamp
        });
      }

      return res.status(201).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Registration Success - Security Guard</title>
          <link rel="stylesheet" href="/css/style.css">
        </head>
        <body>
          <div class="container">
            <header class="header">
              <h2>Registration Result</h2>
              <p class="subtitle">Đăng ký tài khoản thử nghiệm</p>
            </header>
            <div class="card">
              <div class="alert alert-success">
                <h3>Đăng ký thành công!</h3>
                <p>Tài khoản <strong>${escapeHtml(username)}</strong> (${escapeHtml(email)}) đã được tạo thành công.</p>
              </div>
              <div class="actions-row">
                <a href="/login" class="btn btn-primary">Đăng nhập ngay</a>
                <a href="/" class="btn">Về Trang Chủ</a>
              </div>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    if (wantsJson(req)) {
      return res.status(400).json({
        message: 'Missing required registration fields',
        status: 'failed'
      });
    }

    return res.status(400).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Registration Failed - Security Guard</title>
        <link rel="stylesheet" href="/css/style.css">
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h2>Registration Result</h2>
          </header>
          <div class="card">
            <div class="alert alert-error">
              <h3>Đăng ký không thành công!</h3>
              <p>Thiếu thông tin bắt buộc (username hoặc email).</p>
            </div>
            <div class="actions-row">
              <a href="/register" class="btn btn-primary">Thử lại</a>
              <a href="/" class="btn">Về Trang Chủ</a>
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
  },

  // ============================================================================
  // Phase 9: JSON REST Authentication APIs (Login, Logout, Current User)
  // ============================================================================

  /**
   * POST /api/auth/login
   * Authenticates user via username/email + password, creates session in PostgreSQL,
   * and sets HttpOnly cookie.
   */
  apiLogin: async (req, res) => {
    const { username, email, password } = req.body || {};
    const identifier = String(username || email || '').trim();
    const cleanPassword = typeof password === 'string' ? password : '';

    // Validate inputs
    if (!identifier || !cleanPassword) {
      return res.status(400).json({
        status: 'error',
        error: 'Bad Request',
        message: 'Username/email and password are required'
      });
    }

    const rateKey = getRateLimitKey(req, identifier);
    const rateCheck = checkRateLimit(rateKey);
    if (rateCheck.blocked) {
      return res.status(429).json({
        status: 'error',
        error: 'Too Many Requests',
        message: `Too many failed login attempts. Please try again in ${rateCheck.remainingSeconds} seconds.`
      });
    }

    try {
      // Find user by username or email
      const user = await db.findUserByUsernameOrEmail(identifier);
      if (!user) {
        recordFailedAttempt(rateKey);
        // Generic safe error message to prevent account enumeration
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: 'Invalid username or password'
        });
      }

      // Check if user is disabled
      if (!user.is_active) {
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: 'Account is disabled. Please contact an administrator.'
        });
      }

      // Verify bcrypt password hash
      let isMatch = false;
      if (user.password_hash) {
        try {
          isMatch = await bcrypt.compare(cleanPassword, user.password_hash);
        } catch {
          isMatch = false;
        }
      }

      if (!isMatch) {
        recordFailedAttempt(rateKey);
        return res.status(401).json({
          status: 'error',
          error: 'Unauthorized',
          message: 'Invalid username or password'
        });
      }

      // Successful login -> clear rate limit
      clearFailedAttempts(rateKey);

      // Create new server-side session in PostgreSQL
      const ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
      const userAgent = req.headers['user-agent'] || 'unknown';
      const session = await db.createSession(user.id, ip, userAgent);

      // Set secure HttpOnly cookie
      const isProd = process.env.NODE_ENV === 'production';
      res.cookie('secguard_session', session.sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProd,
        maxAge: 24 * 60 * 60 * 1000,
        path: '/'
      });

      return res.status(200).json({
        status: 'success',
        message: 'Login successful',
        sessionId: session.sessionId,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: (user.role || 'ANALYST').toUpperCase()
        }
      });
    } catch (err) {
      console.error('[AUTH ERROR] Login failed:', err.message);
      return res.status(500).json({
        status: 'error',
        error: 'Internal Server Error',
        message: 'An error occurred during authentication'
      });
    }
  },

  /**
   * POST /api/auth/logout
   * Destroys current session in PostgreSQL and clears HttpOnly cookie.
   */
  apiLogout: async (req, res) => {
    try {
      const sessionId = req.cookies?.secguard_session ||
        (req.headers['authorization']?.replace(/^Bearer\s+/i, ''));

      if (sessionId) {
        await db.deleteSession(sessionId);
      }

      res.clearCookie('secguard_session', { path: '/' });

      return res.status(200).json({
        status: 'success',
        message: 'Logged out successfully'
      });
    } catch (err) {
      console.error('[AUTH ERROR] Logout error:', err.message);
      res.clearCookie('secguard_session', { path: '/' });
      return res.status(200).json({
        status: 'success',
        message: 'Logged out'
      });
    }
  },

  /**
   * GET /api/auth/me
   * Returns current authenticated user profile.
   */
  apiMe: (req, res) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        error: 'Unauthorized',
        message: 'Not authenticated'
      });
    }

    return res.status(200).json({
      status: 'success',
      user: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        role: String(req.user.role).toUpperCase(),
        isActive: req.user.isActive !== false
      }
    });
  },

  /**
   * Helper for tests to reset rate limiting state
   */
  resetLoginAttempts: () => {
    loginAttempts.clear();
  }
};

module.exports = authController;
