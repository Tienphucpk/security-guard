import React, { useState, useEffect, useCallback } from 'react';

export default function WebsiteMonitoringSection({ currentUser, onActionMessage }) {
  const [websites, setWebsites] = useState([]);
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedWebsite, setSelectedWebsite] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    policyType: 'IP_BLOCK',
    matchValue: '',
    action: 'BLOCK',
    reason: ''
  });

  const isAdmin = currentUser?.role === 'ADMIN';

  // Fetch registered websites
  const fetchWebsites = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:3000/api/websites', {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.websites)) {
          setWebsites(data.websites);
        }
      }
    } catch (err) {
      console.warn('Failed to load websites:', err.message);
    }
  }, []);

  // Fetch recent enforcement audits
  const fetchAudits = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:3000/api/websites/audit?limit=15', {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.audits)) {
          setAudits(data.audits);
        }
      }
    } catch (err) {
      console.warn('Failed to load audit logs:', err.message);
    }
  }, []);

  // Fetch policies for selected website
  const fetchPolicies = useCallback(async (websiteId) => {
    setPoliciesLoading(true);
    try {
      const res = await fetch(`http://localhost:3000/api/websites/${websiteId}/policies`, {
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setPolicies(data.policies || []);
      }
    } catch (err) {
      console.warn('Failed to load policies:', err.message);
    } finally {
      setPoliciesLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWebsites();
    fetchAudits();
    const timer = setInterval(() => {
      fetchWebsites();
      fetchAudits();
    }, 4000);
    return () => clearInterval(timer);
  }, [fetchWebsites, fetchAudits]);

  // Toggle monitoring mode (ADMIN only)
  const handleToggleMode = async (website) => {
    const newMode = website.monitoringMode === 'ENFORCE' ? 'MONITOR_ONLY' : 'ENFORCE';
    try {
      const res = await fetch(`http://localhost:3000/api/websites/${website.websiteId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ monitoringMode: newMode })
      });
      if (res.ok) {
        onActionMessage?.({
          type: 'success',
          text: `Đã chuyển website '${website.name}' sang chế độ ${newMode}.`
        });
        fetchWebsites();
      } else {
        const err = await res.json().catch(() => ({}));
        onActionMessage?.({ type: 'error', text: err.error || 'Không thể đổi chế độ' });
      }
    } catch (err) {
      onActionMessage?.({ type: 'error', text: err.message });
    }
  };

  // Open policy manager modal
  const handleOpenPolicies = (site) => {
    setSelectedWebsite(site);
    fetchPolicies(site.websiteId);
  };

  // Create new policy
  const handleCreatePolicy = async (e) => {
    e.preventDefault();
    if (!newPolicy.matchValue || !newPolicy.reason) {
      alert('Vui lòng nhập giá trị khớp (IP hoặc Path) và lý do chặn.');
      return;
    }

    let matchCriteria = {};
    if (newPolicy.policyType === 'IP_BLOCK') {
      matchCriteria = { ip: newPolicy.matchValue.trim() };
    } else if (newPolicy.policyType === 'PATH_RESTRICT') {
      matchCriteria = { path_prefix: newPolicy.matchValue.trim() };
    }

    try {
      const res = await fetch(`http://localhost:3000/api/websites/${selectedWebsite.websiteId}/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          policyType: newPolicy.policyType,
          matchCriteria,
          action: newPolicy.action,
          reason: newPolicy.reason
        })
      });
      if (res.ok) {
        setNewPolicy({ policyType: 'IP_BLOCK', matchValue: '', action: 'BLOCK', reason: '' });
        fetchPolicies(selectedWebsite.websiteId);
        onActionMessage?.({ type: 'success', text: 'Đã tạo chính sách bảo mật mới thành công.' });
      } else {
        const err = await res.json().catch(() => ({}));
        onActionMessage?.({ type: 'error', text: err.error || 'Lỗi khi tạo policy' });
      }
    } catch (err) {
      onActionMessage?.({ type: 'error', text: err.message });
    }
  };

  // Delete policy
  const handleDeletePolicy = async (policyId) => {
    if (!window.confirm(`Bạn có chắc muốn xóa chính sách #${policyId}?`)) return;
    try {
      const res = await fetch(`http://localhost:3000/api/websites/${selectedWebsite.websiteId}/policies/${policyId}`, {
        method: 'DELETE',
        credentials: 'include'
      });
      if (res.ok) {
        fetchPolicies(selectedWebsite.websiteId);
        onActionMessage?.({ type: 'success', text: `Đã xóa chính sách #${policyId}.` });
      }
    } catch (err) {
      onActionMessage?.({ type: 'error', text: err.message });
    }
  };

  return (
    <section style={{ marginBottom: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <h2 className="section-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>🌐</span> Giám sát Đa Website & Active Enforcement (Phase 10)
          </h2>
          <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
            Giám sát qua Gateway (Port 8080) và thực thi chính sách tự động (Allow / Block Policy) cho các website được ủy quyền.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: '4px', background: '#0284c722', color: '#38bdf8', border: '1px solid #0284c755' }}>
            Gateway Reverse-Proxy: <code>http://localhost:8080</code>
          </span>
        </div>
      </div>

      {/* Website Cards Grid */}
      <div className="grid-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', marginBottom: '1.25rem' }}>
        {websites.map((site) => {
          const isEnforce = site.monitoringMode === 'ENFORCE';
          return (
            <div key={site.websiteId} className="card" style={{ padding: '1.2rem', border: `1px solid ${isEnforce ? '#ef444455' : '#38bdf855'}`, position: 'relative' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>{site.name}</h3>
                  <code style={{ fontSize: '0.75rem', color: '#94a3b8' }}>ID: {site.websiteId}</code>
                </div>
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    padding: '0.2rem 0.6rem',
                    borderRadius: '9999px',
                    backgroundColor: isEnforce ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                    color: isEnforce ? '#f87171' : '#4ade80',
                    border: `1px solid ${isEnforce ? 'rgba(239, 68, 68, 0.4)' : 'rgba(34, 197, 94, 0.4)'}`
                  }}
                >
                  {isEnforce ? '🛡️ ENFORCE (Chặn chủ động)' : '👁️ MONITOR_ONLY (Chỉ cảnh báo)'}
                </span>
              </div>

              <div style={{ fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.75rem' }}>
                <div style={{ marginBottom: '0.25rem' }}>
                  <span style={{ color: '#64748b' }}>Upstream Target: </span>
                  <code style={{ color: '#38bdf8' }}>{site.upstreamUrl}</code>
                </div>
                <div style={{ marginBottom: '0.25rem' }}>
                  <span style={{ color: '#64748b' }}>Gateway URL: </span>
                  <code style={{ color: '#a78bfa' }}>http://localhost:8080/site/{site.websiteId}/</code>
                </div>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{site.description}</div>
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid #334155' }}>
                {isAdmin ? (
                  <button
                    onClick={() => handleToggleMode(site)}
                    style={{
                      flex: 1,
                      fontSize: '0.78rem',
                      padding: '0.35rem 0.65rem',
                      borderRadius: '4px',
                      border: 'none',
                      cursor: 'pointer',
                      fontWeight: 600,
                      backgroundColor: isEnforce ? '#22c55e' : '#ef4444',
                      color: '#ffffff'
                    }}
                  >
                    {isEnforce ? '👁️ Đổi sang MONITOR_ONLY' : '🛡️ Kích hoạt ENFORCE'}
                  </button>
                ) : (
                  <span style={{ fontSize: '0.75rem', color: '#64748b', fontStyle: 'italic' }}>
                    (Chỉ ADMIN được quyền thay đổi chế độ)
                  </span>
                )}

                <button
                  onClick={() => handleOpenPolicies(site)}
                  style={{
                    fontSize: '0.78rem',
                    padding: '0.35rem 0.65rem',
                    borderRadius: '4px',
                    border: '1px solid #475569',
                    background: 'transparent',
                    color: '#cbd5e1',
                    cursor: 'pointer'
                  }}
                >
                  ⚙️ Policies
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Enforcement Audit Trail */}
      <div className="card" style={{ padding: '1rem' }}>
        <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '0.9rem', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span>📜</span> Lịch sử Thực thi & Đưa ra Quyết định (Enforcement Audit Trail)
        </h3>
        {audits.length === 0 ? (
          <div style={{ color: '#64748b', fontSize: '0.8rem', padding: '1rem', textAlign: 'center' }}>
            Chưa có hành vi chặn nào được kích hoạt. Gửi request tấn công qua Gateway để kiểm tra.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="traffic-table" style={{ fontSize: '0.78rem' }}>
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Website</th>
                  <th>Hành động</th>
                  <th>Client IP</th>
                  <th>Target Path</th>
                  <th>Nguyên nhân / Quy tắc khớp</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((item) => {
                  const isBlocked = item.action === 'BLOCKED';
                  return (
                    <tr key={item.id} style={{ background: isBlocked ? 'rgba(239, 68, 68, 0.08)' : 'transparent' }}>
                      <td style={{ color: '#94a3b8', whiteSpace: 'nowrap' }}>
                        {item.createdAt ? new Date(item.createdAt).toLocaleTimeString() : 'Vừa xong'}
                      </td>
                      <td>
                        <code style={{ color: '#38bdf8' }}>{item.websiteId}</code>
                      </td>
                      <td>
                        <span
                          style={{
                            padding: '0.15rem 0.45rem',
                            borderRadius: '4px',
                            fontWeight: 700,
                            fontSize: '0.7rem',
                            backgroundColor: isBlocked ? '#ef444433' : '#22c55e33',
                            color: isBlocked ? '#f87171' : '#4ade80',
                            border: `1px solid ${isBlocked ? '#ef444466' : '#22c55e66'}`
                          }}
                        >
                          {item.action}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'monospace', color: '#e2e8f0' }}>{item.clientIp}</td>
                      <td style={{ fontFamily: 'monospace', color: '#cbd5e1' }}>{item.targetPath}</td>
                      <td style={{ color: isBlocked ? '#fca5a5' : '#94a3b8' }}>
                        {item.reason} {item.matchedRule ? `[${item.matchedRule}]` : ''}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Policy Management Modal */}
      {selectedWebsite && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div style={{
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '12px',
            maxWidth: '650px',
            width: '100%',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: '1.5rem',
            color: '#f8fafc'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem' }}>
                ⚙️ Quản lý Chính sách Bảo mật — <span style={{ color: '#38bdf8' }}>{selectedWebsite.name}</span>
              </h3>
              <button
                onClick={() => setSelectedWebsite(null)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '1.2rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            {/* List Policies */}
            <div style={{ marginBottom: '1.5rem' }}>
              <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.85rem', color: '#94a3b8' }}>Chính sách hiện hành:</h4>
              {policiesLoading ? (
                <div style={{ fontSize: '0.8rem', color: '#64748b' }}>Đang tải chính sách...</div>
              ) : policies.length === 0 ? (
                <div style={{ fontSize: '0.8rem', color: '#64748b', fontStyle: 'italic' }}>Chưa có chính sách tùy chỉnh nào. Các luật phát hiện chung đang hoạt động mặc định.</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {policies.map(p => {
                    let crit = p.matchCriteria;
                    if (typeof crit === 'string') { try { crit = JSON.parse(crit); } catch {} }
                    return (
                      <div key={p.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem 0.75rem', background: '#0f172a', borderRadius: '6px', border: '1px solid #334155' }}>
                        <div>
                          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: p.action === 'BLOCK' ? '#f87171' : '#4ade80', marginRight: '0.5rem' }}>
                            [{p.action}]
                          </span>
                          <strong style={{ fontSize: '0.8rem' }}>{p.policyType}:</strong> <code style={{ color: '#38bdf8' }}>{crit?.ip || crit?.path_prefix || JSON.stringify(crit)}</code>
                          <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{p.reason}</div>
                        </div>
                        {isAdmin && (
                          <button
                            onClick={() => handleDeletePolicy(p.id)}
                            style={{ background: 'transparent', border: '1px solid #ef444455', color: '#ef4444', borderRadius: '4px', padding: '0.2rem 0.5rem', cursor: 'pointer', fontSize: '0.75rem' }}
                          >
                            Xóa
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Add Policy Form (Admin only) */}
            {isAdmin && (
              <form onSubmit={handleCreatePolicy} style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid #334155' }}>
                <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '0.85rem', color: '#38bdf8' }}>➕ Thêm Quy tắc / Chính sách mới:</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <div>
                    <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Loại chính sách:</label>
                    <select
                      value={newPolicy.policyType}
                      onChange={e => setNewPolicy({ ...newPolicy, policyType: e.target.value })}
                      style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#fff', padding: '0.35rem', borderRadius: '4px', fontSize: '0.8rem' }}
                    >
                      <option value="IP_BLOCK">IP_BLOCK (Chặn IP cụ thể)</option>
                      <option value="PATH_RESTRICT">PATH_RESTRICT (Chặn đường dẫn)</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Hành động:</label>
                    <select
                      value={newPolicy.action}
                      onChange={e => setNewPolicy({ ...newPolicy, action: e.target.value })}
                      style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#fff', padding: '0.35rem', borderRadius: '4px', fontSize: '0.8rem' }}
                    >
                      <option value="BLOCK">BLOCK (Chặn truy cập)</option>
                      <option value="ALLOW">ALLOW (Ngoại lệ - Cho phép qua)</option>
                    </select>
                  </div>
                </div>

                <div style={{ marginBottom: '0.5rem' }}>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                    {newPolicy.policyType === 'IP_BLOCK' ? 'Địa chỉ IP cần chặn:' : 'Tiền tố đường dẫn (Path Prefix):'}
                  </label>
                  <input
                    type="text"
                    placeholder={newPolicy.policyType === 'IP_BLOCK' ? 'Ví dụ: 198.51.100.42' : 'Ví dụ: /admin'}
                    value={newPolicy.matchValue}
                    onChange={e => setNewPolicy({ ...newPolicy, matchValue: e.target.value })}
                    style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#fff', padding: '0.35rem 0.5rem', borderRadius: '4px', fontSize: '0.8rem' }}
                  />
                </div>

                <div style={{ marginBottom: '0.75rem' }}>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Lý do / Ghi chú quy tắc:</label>
                  <input
                    type="text"
                    placeholder="Ví dụ: Chặn IP nghi ngờ tấn công Brute Force"
                    value={newPolicy.reason}
                    onChange={e => setNewPolicy({ ...newPolicy, reason: e.target.value })}
                    style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', color: '#fff', padding: '0.35rem 0.5rem', borderRadius: '4px', fontSize: '0.8rem' }}
                  />
                </div>

                <button
                  type="submit"
                  style={{ width: '100%', padding: '0.45rem', backgroundColor: '#0284c7', border: 'none', borderRadius: '4px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
                >
                  Áp dụng Chính sách
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
