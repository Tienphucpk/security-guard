import React, { useState, useEffect, useCallback } from 'react';

export default function WebsiteMonitoringSection({ currentUser, onActionMessage }) {
  const [websites, setWebsites] = useState([]);
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedWebsite, setSelectedWebsite] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [verifyingId, setVerifyingId] = useState(null);
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [credentialModalData, setCredentialModalData] = useState(null);

  // New policy form state
  const [newPolicy, setNewPolicy] = useState({
    policyType: 'IP_BLOCK',
    matchValue: '',
    action: 'BLOCK',
    reason: ''
  });

  // External website registration form state
  const [regForm, setRegForm] = useState({
    websiteId: '',
    name: '',
    domain: '',
    integrationMethod: 'REVERSE_PROXY',
    upstreamUrl: '',
    description: '',
    monitoringMode: 'MONITOR_ONLY'
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

  // Connection verification & diagnostics
  const handleVerify = async (website) => {
    setVerifyingId(website.websiteId);
    try {
      const res = await fetch(`http://localhost:3000/api/websites/${website.websiteId}/verify`, {
        method: 'POST',
        credentials: 'include'
      });
      const data = await res.json();
      if (res.ok) {
        onActionMessage?.({
          type: data.healthStatus === 'HEALTHY' ? 'success' : 'warning',
          text: `[${website.name}] Trạng thái: ${data.healthStatus} — ${data.diagnostic}`
        });
        fetchWebsites();
      } else {
        onActionMessage?.({ type: 'error', text: data.error || 'Kiểm tra kết nối thất bại' });
      }
    } catch (err) {
      onActionMessage?.({ type: 'error', text: `Lỗi kết nối: ${err.message}` });
    } finally {
      setVerifyingId(null);
    }
  };

  // Credential rotation
  const handleRotateSecret = async (website) => {
    if (!window.confirm(`Bạn có chắc muốn cấp lại khóa bí mật (Secret Key) cho '${website.name}'? Khóa cũ sẽ bị vô hiệu hóa ngay lập tức.`)) {
      return;
    }
    try {
      const res = await fetch(`http://localhost:3000/api/websites/${website.websiteId}/rotate-secret`, {
        method: 'POST',
        credentials: 'include'
      });
      const data = await res.json();
      if (res.ok) {
        setCredentialModalData({
          websiteName: website.name,
          websiteId: website.websiteId,
          plaintextSecret: data.plaintextSecret,
          instructions: data.instructions
        });
        onActionMessage?.({ type: 'success', text: `Đã tạo Secret Key mới cho '${website.name}'.` });
      } else {
        onActionMessage?.({ type: 'error', text: data.error || 'Không thể xoay secret' });
      }
    } catch (err) {
      onActionMessage?.({ type: 'error', text: err.message });
    }
  };

  // Submit new external website registration
  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    if (!regForm.websiteId || !regForm.name) {
      alert('Vui lòng điền mã Website ID và Tên Website.');
      return;
    }
    if (regForm.integrationMethod === 'REVERSE_PROXY' && !regForm.upstreamUrl) {
      alert('Vui lòng nhập Upstream URL cho phương thức REVERSE_PROXY.');
      return;
    }

    try {
      const res = await fetch('http://localhost:3000/api/websites/external', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(regForm)
      });
      const data = await res.json();
      if (res.ok) {
        setShowRegisterModal(false);
        setCredentialModalData({
          websiteName: data.website.name,
          websiteId: data.website.websiteId,
          plaintextSecret: data.plaintextSecret,
          instructions: data.instructions
        });
        setRegForm({
          websiteId: '',
          name: '',
          domain: '',
          integrationMethod: 'REVERSE_PROXY',
          upstreamUrl: '',
          description: '',
          monitoringMode: 'MONITOR_ONLY'
        });
        fetchWebsites();
        onActionMessage?.({ type: 'success', text: `Đã đăng ký website '${data.website.name}' thành công!` });
      } else {
        alert(data.error || 'Lỗi khi đăng ký website');
      }
    } catch (err) {
      alert(`Lỗi: ${err.message}`);
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

  const getMethodBadge = (method) => {
    switch (method) {
      case 'APPLICATION_AGENT':
        return { label: '🧩 Application Agent', bg: 'rgba(168, 85, 247, 0.2)', border: '#a855f755', color: '#c084fc' };
      case 'LOG_INGESTION':
        return { label: '📋 Log Ingestion', bg: 'rgba(245, 158, 11, 0.2)', border: '#f59e0b55', color: '#fbbf24' };
      default:
        return { label: '🔀 Reverse Proxy', bg: 'rgba(56, 189, 248, 0.2)', border: '#38bdf855', color: '#38bdf8' };
    }
  };

  const getHealthBadge = (status) => {
    switch (status) {
      case 'HEALTHY':
        return { label: '● HEALTHY', color: '#4ade80', bg: 'rgba(34, 197, 94, 0.15)' };
      case 'DEGRADED':
        return { label: '● DEGRADED', color: '#fbbf24', bg: 'rgba(245, 158, 11, 0.15)' };
      case 'UNHEALTHY':
        return { label: '● UNHEALTHY', color: '#f87171', bg: 'rgba(239, 68, 68, 0.15)' };
      default:
        return { label: '○ UNKNOWN', color: '#94a3b8', bg: 'rgba(148, 163, 184, 0.15)' };
    }
  };

  return (
    <section style={{ marginBottom: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          <h2 className="section-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>🌐</span> Giám sát Website & Active Enforcement (Phase 11)
          </h2>
          <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
            Giám sát đa nền tảng qua Reverse Proxy Gateway, Application Agent middleware hoặc Log Ingestion với xác thực HMAC và SSRF Boundary.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', borderRadius: '4px', background: '#0284c722', color: '#38bdf8', border: '1px solid #0284c755' }}>
            Gateway Proxy: <code>http://localhost:8080</code>
          </span>
          {isAdmin && (
            <button
              onClick={() => setShowRegisterModal(true)}
              style={{
                fontSize: '0.8rem',
                fontWeight: 600,
                padding: '0.35rem 0.75rem',
                borderRadius: '6px',
                border: 'none',
                background: '#0284c7',
                color: '#fff',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem'
              }}
            >
              <span>➕</span> Đăng ký Website Ngoài
            </button>
          )}
        </div>
      </div>

      {/* Website Cards Grid */}
      <div className="grid-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', marginBottom: '1.25rem' }}>
        {websites.map((site) => {
          const isEnforce = site.monitoringMode === 'ENFORCE';
          const methodInfo = getMethodBadge(site.integrationMethod);
          const healthInfo = getHealthBadge(site.healthStatus);

          return (
            <div
              key={site.websiteId}
              className="card"
              style={{
                padding: '1.2rem',
                border: `1px solid ${isEnforce ? '#ef444455' : '#38bdf844'}`,
                position: 'relative',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}
            >
              <div>
                {/* Header row: Name & Badges */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#f8fafc' }}>{site.name}</h3>
                    <code style={{ fontSize: '0.75rem', color: '#94a3b8' }}>ID: {site.websiteId}</code>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.25rem' }}>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '9999px',
                        backgroundColor: isEnforce ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                        color: isEnforce ? '#f87171' : '#4ade80',
                        border: `1px solid ${isEnforce ? 'rgba(239, 68, 68, 0.4)' : 'rgba(34, 197, 94, 0.4)'}`
                      }}
                    >
                      {isEnforce ? '🛡️ ENFORCE' : '👁️ MONITOR_ONLY'}
                    </span>
                    <span
                      style={{
                        fontSize: '0.65rem',
                        padding: '0.1rem 0.4rem',
                        borderRadius: '4px',
                        backgroundColor: methodInfo.bg,
                        color: methodInfo.color,
                        border: `1px solid ${methodInfo.border}`
                      }}
                    >
                      {methodInfo.label}
                    </span>
                  </div>
                </div>

                {/* Details section */}
                <div style={{ fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.75rem', lineHeight: '1.4' }}>
                  {site.domain && (
                    <div style={{ marginBottom: '0.2rem' }}>
                      <span style={{ color: '#64748b' }}>Domain: </span>
                      <code style={{ color: '#f1f5f9' }}>{site.domain}</code>
                    </div>
                  )}
                  {site.upstreamUrl && (
                    <div style={{ marginBottom: '0.2rem' }}>
                      <span style={{ color: '#64748b' }}>Upstream: </span>
                      <code style={{ color: '#38bdf8' }}>{site.upstreamUrl}</code>
                    </div>
                  )}
                  {site.integrationMethod === 'REVERSE_PROXY' && (
                    <div style={{ marginBottom: '0.2rem' }}>
                      <span style={{ color: '#64748b' }}>Gateway URL: </span>
                      <code style={{ color: '#a78bfa' }}>http://localhost:8080/site/{site.websiteId}/</code>
                    </div>
                  )}
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                    {site.description || 'Chưa có mô tả'}
                  </div>
                </div>

                {/* Health & Diagnostic Bar */}
                <div
                  style={{
                    padding: '0.45rem 0.6rem',
                    background: '#0f172a',
                    borderRadius: '6px',
                    border: '1px solid #334155',
                    fontSize: '0.75rem',
                    marginBottom: '0.75rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, color: healthInfo.color }}>{healthInfo.label}</span>
                    <span style={{ color: '#64748b', fontSize: '0.7rem' }}>
                      {site.lastEventAt ? `Event: ${new Date(site.lastEventAt).toLocaleTimeString()}` : 'Chưa có telemetry'}
                    </span>
                  </div>
                  {site.healthDiagnostic && (
                    <div style={{ color: '#94a3b8', fontSize: '0.7rem', marginTop: '0.2rem', wordBreak: 'break-word' }}>
                      {site.healthDiagnostic}
                    </div>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '0.4rem', paddingTop: '0.75rem', borderTop: '1px solid #334155', flexWrap: 'wrap' }}>
                {isAdmin && (
                  <button
                    onClick={() => handleToggleMode(site)}
                    style={{
                      flex: 1,
                      minWidth: '110px',
                      fontSize: '0.75rem',
                      padding: '0.35rem 0.5rem',
                      borderRadius: '4px',
                      border: 'none',
                      cursor: 'pointer',
                      fontWeight: 600,
                      backgroundColor: isEnforce ? '#22c55e' : '#ef4444',
                      color: '#ffffff'
                    }}
                  >
                    {isEnforce ? '👁️ MONITOR_ONLY' : '🛡️ ENFORCE'}
                  </button>
                )}

                <button
                  onClick={() => handleVerify(site)}
                  disabled={verifyingId === site.websiteId}
                  style={{
                    fontSize: '0.75rem',
                    padding: '0.35rem 0.55rem',
                    borderRadius: '4px',
                    border: '1px solid #38bdf855',
                    background: '#0284c722',
                    color: '#38bdf8',
                    cursor: verifyingId === site.websiteId ? 'wait' : 'pointer'
                  }}
                >
                  {verifyingId === site.websiteId ? '⏳ Đang kiểm tra...' : '🔍 Verify'}
                </button>

                <button
                  onClick={() => handleOpenPolicies(site)}
                  style={{
                    fontSize: '0.75rem',
                    padding: '0.35rem 0.55rem',
                    borderRadius: '4px',
                    border: '1px solid #475569',
                    background: 'transparent',
                    color: '#cbd5e1',
                    cursor: 'pointer'
                  }}
                >
                  ⚙️ Policies
                </button>

                {isAdmin && site.isExternal && (
                  <button
                    onClick={() => handleRotateSecret(site)}
                    title="Xoay lại Secret Key xác thực"
                    style={{
                      fontSize: '0.75rem',
                      padding: '0.35rem 0.55rem',
                      borderRadius: '4px',
                      border: '1px solid #f59e0b55',
                      background: '#f59e0b11',
                      color: '#fbbf24',
                      cursor: 'pointer'
                    }}
                  >
                    🔄 Secret
                  </button>
                )}
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

      {/* Register External Website Modal (ADMIN only) */}
      {showRegisterModal && (
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
            maxWidth: '550px',
            width: '100%',
            padding: '1.5rem',
            color: '#f8fafc'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem' }}>
                ➕ Đăng ký Tích hợp Website Mới (External Site)
              </h3>
              <button
                onClick={() => setShowRegisterModal(false)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '1.2rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleRegisterSubmit}>
              <div style={{ marginBottom: '0.75rem' }}>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>
                  Mã Website ID (Duy nhất, chữ và số):
                </label>
                <input
                  type="text"
                  required
                  placeholder="Ví dụ: site_prod_blog"
                  value={regForm.websiteId}
                  onChange={e => setRegForm({ ...regForm, websiteId: e.target.value })}
                  style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', color: '#fff', padding: '0.4rem', borderRadius: '4px', fontSize: '0.85rem' }}
                />
              </div>

              <div style={{ marginBottom: '0.75rem' }}>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>
                  Tên Hiển thị Website:
                </label>
                <input
                  type="text"
                  required
                  placeholder="Ví dụ: Cổng thông tin doanh nghiệp"
                  value={regForm.name}
                  onChange={e => setRegForm({ ...regForm, name: e.target.value })}
                  style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', color: '#fff', padding: '0.4rem', borderRadius: '4px', fontSize: '0.85rem' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>
                    Phương thức Tích hợp:
                  </label>
                  <select
                    value={regForm.integrationMethod}
                    onChange={e => setRegForm({ ...regForm, integrationMethod: e.target.value })}
                    style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', color: '#fff', padding: '0.4rem', borderRadius: '4px', fontSize: '0.85rem' }}
                  >
                    <option value="REVERSE_PROXY">Reverse Proxy (Port 8080)</option>
                    <option value="APPLICATION_AGENT">Application Agent (Middleware)</option>
                    <option value="LOG_INGESTION">Log Ingestion (Passive logs)</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>
                    Tên miền (Domain / Hostname):
                  </label>
                  <input
                    type="text"
                    placeholder="Ví dụ: blog.example.com"
                    value={regForm.domain}
                    onChange={e => setRegForm({ ...regForm, domain: e.target.value })}
                    style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', color: '#fff', padding: '0.4rem', borderRadius: '4px', fontSize: '0.85rem' }}
                  />
                </div>
              </div>

              {regForm.integrationMethod === 'REVERSE_PROXY' && (
                <div style={{ marginBottom: '0.75rem' }}>
                  <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>
                    Upstream URL (Địa chỉ máy chủ đích):
                  </label>
                  <input
                    type="url"
                    required
                    placeholder="https://example-backend.com hoặc http://8.8.8.8"
                    value={regForm.upstreamUrl}
                    onChange={e => setRegForm({ ...regForm, upstreamUrl: e.target.value })}
                    style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', color: '#fff', padding: '0.4rem', borderRadius: '4px', fontSize: '0.85rem' }}
                  />
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>
                    ⚠️ SSRF Boundary: Hệ thống tự động chặn IP Private, Loopback, Link-Local và Cloud Metadata.
                  </div>
                </div>
              )}

              <div style={{ marginBottom: '0.75rem' }}>
                <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>
                  Mô tả / Ghi chú:
                </label>
                <input
                  type="text"
                  placeholder="Ghi chú thêm về website này..."
                  value={regForm.description}
                  onChange={e => setRegForm({ ...regForm, description: e.target.value })}
                  style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', color: '#fff', padding: '0.4rem', borderRadius: '4px', fontSize: '0.85rem' }}
                />
              </div>

              <div style={{ padding: '0.5rem', background: '#0f172a', borderRadius: '6px', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '1rem' }}>
                ℹ️ <strong>Nguyên tắc an toàn:</strong> Website mới đăng ký sẽ luôn mặc định ở chế độ <code>MONITOR_ONLY</code> để theo dõi trước. Chế độ <code>ENFORCE</code> cần thao tác kích hoạt tường minh của Quản trị viên.
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  style={{ padding: '0.45rem 0.9rem', background: 'transparent', border: '1px solid #475569', color: '#cbd5e1', borderRadius: '4px', cursor: 'pointer' }}
                >
                  Hủy
                </button>
                <button
                  type="submit"
                  style={{ padding: '0.45rem 1rem', background: '#0284c7', border: 'none', color: '#fff', borderRadius: '4px', fontWeight: 600, cursor: 'pointer' }}
                >
                  Đăng ký & Cấp Secret Key
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Credential & Instructions Modal */}
      {credentialModalData && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.85)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100,
          padding: '1rem'
        }}>
          <div style={{
            background: '#1e293b',
            border: '1px solid #38bdf8',
            borderRadius: '12px',
            maxWidth: '650px',
            width: '100%',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: '1.5rem',
            color: '#f8fafc'
          }}>
            <h3 style={{ margin: '0 0 0.5rem 0', color: '#38bdf8' }}>
              🔑 Khóa Xác thực & Hướng dẫn Tích hợp: {credentialModalData.websiteName}
            </h3>

            <div style={{ padding: '0.75rem', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef444466', borderRadius: '6px', color: '#fca5a5', fontSize: '0.8rem', marginBottom: '1rem' }}>
              ⚠️ <strong>Lưu ý quan trọng:</strong> Khóa bí mật (Agent Secret) chỉ được hiển thị <strong>MỘT LẦN DUY NHẤT</strong>. Hãy sao chép và lưu trữ an toàn ngay bây giờ. Hệ thống không lưu trữ khóa ở dạng plaintext.
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Agent Secret Key:</label>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                <input
                  type="text"
                  readOnly
                  value={credentialModalData.plaintextSecret}
                  style={{ flex: 1, background: '#0f172a', border: '1px solid #0284c7', color: '#38bdf8', padding: '0.5rem', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.85rem' }}
                />
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(credentialModalData.plaintextSecret);
                    alert('Đã sao chép Secret Key vào bộ nhớ tạm!');
                  }}
                  style={{ padding: '0.5rem 0.8rem', background: '#0284c7', border: 'none', color: '#fff', borderRadius: '4px', cursor: 'pointer', fontWeight: 600 }}
                >
                  Sao chép
                </button>
              </div>
            </div>

            {/* Instructions */}
            {credentialModalData.instructions && (
              <div style={{ background: '#0f172a', padding: '1rem', borderRadius: '8px', border: '1px solid #334155', fontSize: '0.8rem', marginBottom: '1rem' }}>
                <h4 style={{ margin: '0 0 0.5rem 0', color: '#f1f5f9' }}>{credentialModalData.instructions.summary}</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', marginBottom: '0.75rem' }}>
                  {credentialModalData.instructions.steps?.map((step, idx) => (
                    <div key={idx} style={{ color: '#cbd5e1' }}>{step}</div>
                  ))}
                </div>
                {(credentialModalData.instructions.curlExample || credentialModalData.instructions.codeSnippet) && (
                  <pre style={{ background: '#020617', padding: '0.75rem', borderRadius: '6px', color: '#38bdf8', overflowX: 'auto', fontSize: '0.75rem', margin: 0 }}>
                    <code>{credentialModalData.instructions.curlExample || credentialModalData.instructions.codeSnippet}</code>
                  </pre>
                )}
              </div>
            )}

            <button
              onClick={() => setCredentialModalData(null)}
              style={{ width: '100%', padding: '0.6rem', background: '#334155', border: 'none', color: '#fff', borderRadius: '6px', fontWeight: 600, cursor: 'pointer' }}
            >
              Tôi đã lưu trữ khóa an toàn — Đóng
            </button>
          </div>
        </div>
      )}

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
