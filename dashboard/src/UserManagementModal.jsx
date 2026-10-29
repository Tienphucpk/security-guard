import React, { useState, useEffect } from 'react';

export default function UserManagementModal({ isOpen, onClose, currentAdminId }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // New user form state
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('ANALYST');
  const [creating, setCreating] = useState(false);

  // Fetch users on open
  const fetchUsers = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch('http://localhost:3000/api/users', {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      } else {
        const err = await res.json().catch(() => ({}));
        setErrorMsg(err.message || 'Không thể tải danh sách tài khoản.');
      }
    } catch (err) {
      setErrorMsg('Lỗi kết nối máy chủ.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchUsers();
      setErrorMsg('');
      setSuccessMsg('');
    }
  }, [isOpen]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setCreating(true);

    try {
      const res = await fetch('http://localhost:3000/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          username: newUsername.trim(),
          email: newEmail.trim(),
          password: newPassword,
          role: newRole
        })
      });

      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setSuccessMsg(`Tạo tài khoản '${newUsername}' thành công!`);
        setNewUsername('');
        setNewEmail('');
        setNewPassword('');
        setNewRole('ANALYST');
        fetchUsers();
      } else {
        setErrorMsg(data.message || 'Lỗi khi tạo tài khoản.');
      }
    } catch {
      setErrorMsg('Không thể kết nối đến máy chủ.');
    } finally {
      setCreating(false);
    }
  };

  const handleToggleStatus = async (user) => {
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await fetch(`http://localhost:3000/api/users/${user.id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ isActive: !user.isActive })
      });

      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setSuccessMsg(`Đã ${!user.isActive ? 'kích hoạt' : 'vô hiệu hóa'} tài khoản '${user.username}'.`);
        fetchUsers();
      } else {
        setErrorMsg(data.message || 'Lỗi khi cập nhật trạng thái.');
      }
    } catch {
      setErrorMsg('Lỗi kết nối.');
    }
  };

  const handleChangeRole = async (user) => {
    setErrorMsg('');
    setSuccessMsg('');
    const targetRole = user.role === 'ADMIN' ? 'ANALYST' : 'ADMIN';
    try {
      const res = await fetch(`http://localhost:3000/api/users/${user.id}/role`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ role: targetRole })
      });

      const data = await res.json();
      if (res.ok && data.status === 'success') {
        setSuccessMsg(`Đã chuyển vai trò của '${user.username}' sang ${targetRole}.`);
        fetchUsers();
      } else {
        setErrorMsg(data.message || 'Lỗi khi đổi vai trò.');
      }
    } catch {
      setErrorMsg('Lỗi kết nối.');
    }
  };

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(11, 17, 32, 0.85)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '1.5rem'
    }}>
      <div style={{
        width: '100%',
        maxWidth: '850px',
        maxHeight: '90vh',
        backgroundColor: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '12px',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}>
        {/* Modal Header */}
        <div style={{
          padding: '1.25rem 1.5rem',
          borderBottom: '1px solid #334155',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '1.3rem' }}>👥</span>
            <h2 style={{ fontSize: '1.2rem', color: '#f8fafc', margin: 0, fontWeight: 700 }}>
              Quản trị Người dùng & Phân quyền RBAC (Phase 9)
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              fontSize: '1.5rem',
              cursor: 'pointer',
              lineHeight: 1
            }}
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1 }}>
          {/* Notifications */}
          {errorMsg && (
            <div style={{
              padding: '0.65rem 1rem',
              marginBottom: '1rem',
              backgroundColor: 'rgba(239, 68, 68, 0.2)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              color: '#f87171',
              borderRadius: '6px',
              fontSize: '0.85rem'
            }}>
              ⚠️ {errorMsg}
            </div>
          )}
          {successMsg && (
            <div style={{
              padding: '0.65rem 1rem',
              marginBottom: '1rem',
              backgroundColor: 'rgba(34, 197, 94, 0.2)',
              border: '1px solid rgba(34, 197, 94, 0.4)',
              color: '#4ade80',
              borderRadius: '6px',
              fontSize: '0.85rem'
            }}>
              ✓ {successMsg}
            </div>
          )}

          {/* Create User Section */}
          <div style={{
            backgroundColor: '#0f172a',
            border: '1px solid #334155',
            borderRadius: '8px',
            padding: '1.25rem',
            marginBottom: '1.5rem'
          }}>
            <h3 style={{ fontSize: '0.95rem', color: '#38bdf8', margin: '0 0 1rem 0', fontWeight: 600 }}>
              + Thêm Tài khoản Mới
            </h3>
            <form onSubmit={handleCreateUser} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem', alignItems: 'flex-end' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: '#94a3b8', marginBottom: '0.35rem' }}>Tên đăng nhập:</label>
                <input
                  type="text"
                  placeholder="ví dụ: analyst2"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  required
                  style={{ width: '100%', padding: '0.45rem 0.65rem', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: '#94a3b8', marginBottom: '0.35rem' }}>Email:</label>
                <input
                  type="email"
                  placeholder="analyst2@securityguard.local"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  required
                  style={{ width: '100%', padding: '0.45rem 0.65rem', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: '#94a3b8', marginBottom: '0.35rem' }}>Mật khẩu (≥ 6 ký tự):</label>
                <input
                  type="password"
                  placeholder="••••••••"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  style={{ width: '100%', padding: '0.45rem 0.65rem', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc', fontSize: '0.85rem', boxSizing: 'border-box' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: '#94a3b8', marginBottom: '0.35rem' }}>Vai trò:</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  style={{ width: '100%', padding: '0.45rem 0.65rem', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#f8fafc', fontSize: '0.85rem', boxSizing: 'border-box' }}
                >
                  <option value="ANALYST">🛡️ ANALYST</option>
                  <option value="ADMIN">👑 ADMIN</option>
                </select>
              </div>

              <div>
                <button
                  type="submit"
                  disabled={creating}
                  style={{
                    width: '100%',
                    padding: '0.48rem 0.75rem',
                    backgroundColor: '#0284c7',
                    border: 'none',
                    borderRadius: '4px',
                    color: '#ffffff',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    cursor: creating ? 'not-allowed' : 'pointer'
                  }}
                >
                  {creating ? 'Đang tạo...' : '+ Tạo Tài Khoản'}
                </button>
              </div>
            </form>
          </div>

          {/* User List Table */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h3 style={{ fontSize: '0.95rem', color: '#f8fafc', margin: 0, fontWeight: 600 }}>
              Danh sách Tài khoản ({users.length})
            </h3>
            <button
              onClick={fetchUsers}
              disabled={loading}
              style={{
                background: 'transparent',
                border: '1px solid #334155',
                borderRadius: '4px',
                color: '#94a3b8',
                padding: '0.25rem 0.6rem',
                fontSize: '0.78rem',
                cursor: 'pointer'
              }}
            >
              🔄 Tải lại
            </button>
          </div>

          {loading ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#94a3b8' }}>Đang tải danh sách người dùng...</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ backgroundColor: '#0f172a', borderBottom: '1px solid #334155', textAlign: 'left' }}>
                  <th style={{ padding: '0.65rem 0.75rem', color: '#94a3b8' }}>ID</th>
                  <th style={{ padding: '0.65rem 0.75rem', color: '#94a3b8' }}>Tài khoản</th>
                  <th style={{ padding: '0.65rem 0.75rem', color: '#94a3b8' }}>Email</th>
                  <th style={{ padding: '0.65rem 0.75rem', color: '#94a3b8' }}>Vai trò</th>
                  <th style={{ padding: '0.65rem 0.75rem', color: '#94a3b8' }}>Trạng thái</th>
                  <th style={{ padding: '0.65rem 0.75rem', color: '#94a3b8', textAlign: 'right' }}>Thao tác</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isAdmin = u.role === 'ADMIN';
                  return (
                    <tr key={u.id} style={{ borderBottom: '1px solid #334155' }}>
                      <td style={{ padding: '0.65rem 0.75rem', color: '#64748b' }}>#{u.id}</td>
                      <td style={{ padding: '0.65rem 0.75rem', fontWeight: 600, color: '#f8fafc' }}>
                        {u.username}
                        {u.id === currentAdminId && <span style={{ fontSize: '0.7rem', color: '#38bdf8', marginLeft: '0.35rem' }}>(Bạn)</span>}
                      </td>
                      <td style={{ padding: '0.65rem 0.75rem', color: '#94a3b8' }}>{u.email}</td>
                      <td style={{ padding: '0.65rem 0.75rem' }}>
                        <span style={{
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          backgroundColor: isAdmin ? 'rgba(56, 189, 248, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                          color: isAdmin ? '#38bdf8' : '#4ade80',
                          border: `1px solid ${isAdmin ? 'rgba(56, 189, 248, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
                        }}>
                          {isAdmin ? '👑 ADMIN' : '🛡️ ANALYST'}
                        </span>
                      </td>
                      <td style={{ padding: '0.65rem 0.75rem' }}>
                        <span style={{
                          color: u.isActive ? '#4ade80' : '#f87171',
                          fontWeight: 600,
                          fontSize: '0.8rem'
                        }}>
                          {u.isActive ? '● Đang hoạt động' : '○ Đã khóa'}
                        </span>
                      </td>
                      <td style={{ padding: '0.65rem 0.75rem', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '0.4rem', justifyContent: 'flex-end' }}>
                          <button
                            type="button"
                            onClick={() => handleChangeRole(u)}
                            title="Đổi vai trò giữa ADMIN và ANALYST"
                            style={{
                              padding: '0.25rem 0.5rem',
                              backgroundColor: 'transparent',
                              border: '1px solid #475569',
                              borderRadius: '4px',
                              color: '#cbd5e1',
                              fontSize: '0.75rem',
                              cursor: 'pointer'
                            }}
                          >
                            Đổi Role
                          </button>
                          <button
                            type="button"
                            onClick={() => handleToggleStatus(u)}
                            title={u.isActive ? 'Khóa tài khoản này' : 'Kích hoạt lại'}
                            style={{
                              padding: '0.25rem 0.5rem',
                              backgroundColor: u.isActive ? 'rgba(239, 68, 68, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                              border: `1px solid ${u.isActive ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                              borderRadius: '4px',
                              color: u.isActive ? '#f87171' : '#4ade80',
                              fontSize: '0.75rem',
                              cursor: 'pointer'
                            }}
                          >
                            {u.isActive ? 'Khóa' : 'Kích hoạt'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Modal Footer */}
        <div style={{
          padding: '1rem 1.5rem',
          borderTop: '1px solid #334155',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: '#0f172a'
        }}>
          <span style={{ fontSize: '0.78rem', color: '#64748b' }}>
            🔒 Quy tắc an toàn: Không thể khóa hoặc hạ quyền tài khoản ADMIN đang hoạt động cuối cùng.
          </span>
          <button
            onClick={onClose}
            style={{
              padding: '0.4rem 1rem',
              backgroundColor: '#334155',
              border: 'none',
              borderRadius: '4px',
              color: '#f8fafc',
              cursor: 'pointer',
              fontSize: '0.85rem'
            }}
          >
            Đóng
          </button>
        </div>
      </div>
    </div>
  );
}
