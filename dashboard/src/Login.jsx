import React, { useState } from 'react';

export default function Login({ onLoginSuccess }) {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!identifier.trim() || !password) {
      setErrorMsg('Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.');
      return;
    }

    setLoading(true);
    setErrorMsg('');

    try {
      const res = await fetch('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          username: identifier.trim(),
          password
        })
      });

      const data = await res.json();

      if (res.ok && data.status === 'success') {
        onLoginSuccess(data.user);
      } else {
        setErrorMsg(data.message || 'Đăng nhập thất bại. Vui lòng kiểm tra lại thông tin.');
      }
    } catch (err) {
      setErrorMsg('Không thể kết nối đến máy chủ xác thực. Vui lòng thử lại sau.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (user, pass) => {
    setIdentifier(user);
    setPassword(pass);
    setErrorMsg('');
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: '#0b1120',
      padding: '1.5rem',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '440px',
        backgroundColor: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '12px',
        padding: '2.25rem',
        boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4)'
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🛡️</div>
          <h1 style={{
            color: '#38bdf8',
            fontSize: '1.6rem',
            fontWeight: 700,
            letterSpacing: '0.05em',
            margin: '0 0 0.25rem 0'
          }}>
            SECURITY GUARD
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', margin: 0 }}>
            Hệ thống Giám sát & Phát hiện Bất thường Website
          </p>
          <div style={{
            display: 'inline-block',
            marginTop: '0.5rem',
            padding: '0.2rem 0.6rem',
            backgroundColor: 'rgba(56, 189, 248, 0.12)',
            color: '#38bdf8',
            borderRadius: '9999px',
            fontSize: '0.75rem',
            fontWeight: 600,
            border: '1px solid rgba(56, 189, 248, 0.3)'
          }}>
            Đăng nhập Hệ thống (Phase 9 RBAC)
          </div>
        </div>

        {/* Error Alert */}
        {errorMsg && (
          <div style={{
            padding: '0.75rem 1rem',
            marginBottom: '1.25rem',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#f87171',
            borderRadius: '8px',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <span>⚠️</span>
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', color: '#e2e8f0', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Tên đăng nhập hoặc Email:
            </label>
            <input
              type="text"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              placeholder="admin hoặc email..."
              autoFocus
              required
              style={{
                width: '100%',
                padding: '0.65rem 0.9rem',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#f8fafc',
                fontSize: '0.9rem',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', color: '#e2e8f0', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Mật khẩu:
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              style={{
                width: '100%',
                padding: '0.65rem 0.9rem',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '6px',
                color: '#f8fafc',
                fontSize: '0.9rem',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.75rem',
              backgroundColor: '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.95rem',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.7 : 1,
              transition: 'background-color 0.2s',
              boxShadow: '0 4px 6px -1px rgba(2, 132, 199, 0.3)'
            }}
          >
            {loading ? 'Đang xác thực...' : 'Đăng nhập vào Dashboard'}
          </button>
        </form>

        {/* Demo Quick-Fill Accounts */}
        <div style={{
          marginTop: '1.75rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid #334155',
          textAlign: 'center'
        }}>
          <p style={{ color: '#64748b', fontSize: '0.78rem', marginBottom: '0.6rem' }}>
            Tài khoản thử nghiệm báo cáo đồ án (1-Click điền mẫu):
          </p>
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
            <button
              type="button"
              onClick={() => handleQuickFill('admin', 'Admin@123456')}
              style={{
                padding: '0.35rem 0.75rem',
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                color: '#38bdf8',
                borderRadius: '6px',
                fontSize: '0.78rem',
                cursor: 'pointer',
                fontWeight: 600
              }}
            >
              👑 Admin (Toàn quyền)
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill('analyst', 'Analyst@123456')}
              style={{
                padding: '0.35rem 0.75rem',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                color: '#4ade80',
                borderRadius: '6px',
                fontSize: '0.78rem',
                cursor: 'pointer',
                fontWeight: 600
              }}
            >
              🛡️ Analyst (Phân tích viên)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
