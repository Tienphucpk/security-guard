import React, { useState, useEffect, useCallback, useRef } from 'react';
import Login from './Login';
import UserManagementModal from './UserManagementModal';
import WebsiteMonitoringSection from './WebsiteMonitoringSection';

export default function App() {
  // Phase 9: Session Authentication State
  const [currentUser, setCurrentUser] = useState(null);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [userModalOpen, setUserModalOpen] = useState(false);

  const [systemStatus, setSystemStatus] = useState({
    webApp: 'Online',
    detectionEngine: 'Online',
    database: 'Online',
    mlEngine: 'Shadow (v1.0.0)',
    gateway: 'Online (:8080)'
  });

  const [stats, setStats] = useState({
    totalRequests: 0,
    suspiciousRequests: 0,
    alerts: 0
  });

  const [alertStats, setAlertStats] = useState({
    totalAlerts: 0,
    newAlerts: 0,
    acknowledgedAlerts: 0,
    resolvedAlerts: 0,
    criticalSeverity: 0,
    highSeverity: 0,
    mediumSeverity: 0,
    lowSeverity: 0,
    mlAlerts: 0
  });

  const [alerts, setAlerts] = useState([]);
  const [recentLogs, setRecentLogs] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Filters & Pagination State
  const [filters, setFilters] = useState({
    status: '',
    severity: '',
    sort: 'newest',
    search: '',
    websiteId: ''
  });
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [totalPages, setTotalPages] = useState(1);
  const [totalAlertsCount, setTotalAlertsCount] = useState(0);

  // Real-Time SSE & Toast Notification State
  const [sseConnected, setSseConnected] = useState(false);
  const [liveToast, setLiveToast] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);

  // Phase 9: Verify session on application load
  useEffect(() => {
    const verifyAuth = async () => {
      try {
        const res = await fetch('http://localhost:3000/api/auth/me', {
          credentials: 'include'
        });
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'success' && data.user) {
            setCurrentUser(data.user);
          } else {
            setCurrentUser(null);
          }
        } else {
          setCurrentUser(null);
        }
      } catch {
        setCurrentUser(null);
      } finally {
        setCheckingAuth(false);
      }
    };
    verifyAuth();
  }, []);

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:3000/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
    } catch {}
    setCurrentUser(null);
    setActionMessage({ type: 'success', text: 'Đã đăng xuất khỏi hệ thống an toàn.' });
  };

  const getAuthHeaders = () => {
    return { 'Content-Type': 'application/json' };
  };

  const eventSourceRef = useRef(null);

  // Fetch Alerts function
  const fetchAlerts = useCallback(async (targetPage = page, currentFilters = filters) => {
    try {
      const params = new URLSearchParams();
      params.append('page', targetPage);
      params.append('limit', limit);
      if (currentFilters.status) params.append('status', currentFilters.status);
      if (currentFilters.severity) params.append('severity', currentFilters.severity);
      if (currentFilters.websiteId) params.append('websiteId', currentFilters.websiteId);
      if (currentFilters.sort) params.append('sort', currentFilters.sort);
      if (currentFilters.search) {
        // If search looks like IP, search by IP, else query string
        if (/^\d{1,3}\./.test(currentFilters.search)) {
          params.append('ip', currentFilters.search);
        }
      }

      const res = await fetch(`http://localhost:3000/api/alerts?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.alerts)) {
          setAlerts(data.alerts);
          setTotalAlertsCount(data.total || 0);
          setTotalPages(data.totalPages || 1);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch alerts:', err.message);
    }
  }, [page, limit, filters]);

  // Fetch Summary Statistics
  const fetchStats = useCallback(async () => {
    try {
      const [statsRes, alertStatsRes] = await Promise.all([
        fetch('http://localhost:3000/api/logs/stats').catch(() => null),
        fetch('http://localhost:3000/api/alerts/stats').catch(() => null)
      ]);

      if (statsRes && statsRes.ok) {
        const statsData = await statsRes.json();
        if (statsData && statsData.stats) {
          setStats((prev) => ({
            ...prev,
            totalRequests: statsData.stats.totalRequests || 0
          }));
        }
      }

      if (alertStatsRes && alertStatsRes.ok) {
        const aData = await alertStatsRes.json();
        if (aData && aData.stats) {
          const s = aData.stats;
          setAlertStats({
            totalAlerts: s.totalAlerts || 0,
            newAlerts: s.newAlerts || 0,
            acknowledgedAlerts: s.acknowledgedAlerts || 0,
            resolvedAlerts: s.resolvedAlerts || 0,
            criticalSeverity: s.criticalSeverity || 0,
            highSeverity: s.highSeverity || 0,
            mediumSeverity: s.mediumSeverity || 0,
            lowSeverity: s.lowSeverity || 0,
            mlAlerts: s.mlAlerts || 0
          });
          setStats((prev) => ({
            ...prev,
            suspiciousRequests: s.totalAlerts || 0,
            alerts: s.totalAlerts || 0
          }));
        }
      }
    } catch {
      // Graceful fallback
    }
  }, []);

  // Fetch Health & Live Logs
  const fetchHealthAndLogs = useCallback(async () => {
    // 1. Web App & DB Health
    try {
      const webRes = await fetch('http://localhost:3000/api/health');
      if (webRes.ok) {
        const webData = await webRes.json();
        setSystemStatus((prev) => ({
          ...prev,
          webApp: 'Online',
          database: webData.database === 'connected' ? 'Online' : 'Degraded (File Mode)'
        }));
      } else {
        setSystemStatus((prev) => ({ ...prev, webApp: 'Offline' }));
      }
    } catch {
      setSystemStatus((prev) => ({ ...prev, webApp: 'Offline' }));
    }

    // 2. Detection Engine Health & ML Status
    try {
      const engineRes = await fetch('http://localhost:5000/health');
      if (engineRes.ok) {
        const engineData = await engineRes.json();
        const mode = (engineData.ml_mode || 'shadow').toUpperCase();
        const version = engineData.ml_model_version || '1.0.0';
        setSystemStatus((prev) => ({
          ...prev,
          detectionEngine: 'Online',
          mlEngine: `${mode} (v${version})`
        }));
      } else {
        setSystemStatus((prev) => ({ ...prev, detectionEngine: 'Offline', mlEngine: 'Offline' }));
      }
    } catch {
      setSystemStatus((prev) => ({ ...prev, detectionEngine: 'Offline', mlEngine: 'Offline' }));
    }

    // 3. Recent 5 HTTP Request Logs
    try {
      const logsRes = await fetch('http://localhost:3000/api/logs?limit=5');
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        if (logsData && Array.isArray(logsData.logs)) {
          setRecentLogs(logsData.logs);
        }
      }
    } catch {
      // Fallback
    }

    // 4. Phase 10: Monitoring Gateway Health Check
    try {
      const gwRes = await fetch('http://localhost:8080/health');
      if (gwRes.ok) {
        setSystemStatus((prev) => ({ ...prev, gateway: 'Online (:8080)' }));
      } else {
        setSystemStatus((prev) => ({ ...prev, gateway: 'Offline' }));
      }
    } catch {
      setSystemStatus((prev) => ({ ...prev, gateway: 'Offline' }));
    }

    setLastUpdated(new Date().toLocaleTimeString());
  }, []);

  // Initial Data Fetch & Periodic Background Polling
  useEffect(() => {
    fetchHealthAndLogs();
    fetchStats();
    fetchAlerts(page, filters);

    const healthInterval = setInterval(() => {
      fetchHealthAndLogs();
      fetchStats();
      // If SSE is disconnected, use polling fallback for alerts
      if (!sseConnected) {
        fetchAlerts(page, filters);
      }
    }, 3000);

    return () => clearInterval(healthInterval);
  }, [fetchHealthAndLogs, fetchStats, fetchAlerts, page, filters, sseConnected]);

  // Setup Server-Sent Events (SSE) Stream
  useEffect(() => {
    let es;
    try {
      es = new EventSource('http://localhost:3000/api/alerts/stream');
      eventSourceRef.current = es;

      es.addEventListener('connected', () => {
        setSseConnected(true);
      });

      es.addEventListener('alert_created', (event) => {
        try {
          const newAlert = JSON.parse(event.data);
          // Show Toast Notification
          setLiveToast(newAlert);
          // Refresh alerts list & statistics
          fetchAlerts(page, filters);
          fetchStats();
        } catch (e) {
          console.error('Error handling SSE alert_created:', e);
        }
      });

      es.addEventListener('alert_updated', (event) => {
        try {
          const updated = JSON.parse(event.data);
          // Update in-memory alert list
          setAlerts((prevAlerts) =>
            prevAlerts.map((a) => (a.id === updated.id ? { ...a, ...updated } : a))
          );
          // If modal is currently viewing this alert, update it too
          setSelectedAlert((prev) => (prev && prev.id === updated.id ? { ...prev, ...updated } : prev));
          fetchStats();
        } catch (e) {
          console.error('Error handling SSE alert_updated:', e);
        }
      });

      es.onerror = () => {
        setSseConnected(false);
      };
    } catch (err) {
      setSseConnected(false);
    }

    return () => {
      if (es) {
        es.close();
      }
    };
  }, [fetchAlerts, fetchStats, page, filters]);

  // Auto-dismiss live toast after 6 seconds
  useEffect(() => {
    if (liveToast) {
      const timer = setTimeout(() => setLiveToast(null), 6000);
      return () => clearTimeout(timer);
    }
  }, [liveToast]);

  // Lifecycle Action Handlers
  const handleAcknowledge = async (alertId) => {
    setActionLoadingId(alertId);
    setActionMessage(null);
    try {
      const res = await fetch(`http://localhost:3000/api/alerts/${alertId}/acknowledge`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        // Update alert locally
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: 'acknowledged', updatedAt: data.alert?.updatedAt } : a))
        );
        if (selectedAlert && selectedAlert.id === alertId) {
          setSelectedAlert((prev) => ({ ...prev, status: 'acknowledged', updatedAt: data.alert?.updatedAt }));
        }
        setActionMessage({ type: 'success', text: `Cảnh báo #${alertId} đã được chuyển sang ACKNOWLEDGED.` });
        fetchStats();
      } else {
        const err = await res.json().catch(() => ({}));
        const statusNote = res.status === 401 ? ' (401 Unauthorized - Yêu cầu xác thực)' :
                           res.status === 403 ? ' (403 Forbidden - Vai trò không đủ quyền)' : '';
        setActionMessage({
          type: 'error',
          text: `[Lỗi ${res.status}] ${err.error || err.message || 'Lỗi khi cập nhật trạng thái.'}${statusNote}`
        });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message || 'Không thể kết nối đến Web App.' });
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleResolve = async (alertId) => {
    setActionLoadingId(alertId);
    setActionMessage(null);
    try {
      const res = await fetch(`http://localhost:3000/api/alerts/${alertId}/resolve`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        credentials: 'include'
      });
      if (res.ok) {
        const data = await res.json();
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: 'resolved', updatedAt: data.alert?.updatedAt } : a))
        );
        if (selectedAlert && selectedAlert.id === alertId) {
          setSelectedAlert((prev) => ({ ...prev, status: 'resolved', updatedAt: data.alert?.updatedAt }));
        }
        setActionMessage({ type: 'success', text: `Cảnh báo #${alertId} đã được chuyển sang RESOLVED.` });
        fetchStats();
      } else {
        const err = await res.json().catch(() => ({}));
        const statusNote = res.status === 401 ? ' (401 Unauthorized - Yêu cầu xác thực)' :
                           res.status === 403 ? ' (403 Forbidden - Vai trò không đủ quyền)' : '';
        setActionMessage({
          type: 'error',
          text: `[Lỗi ${res.status}] ${err.error || err.message || 'Lỗi khi cập nhật trạng thái.'}${statusNote}`
        });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message || 'Không thể kết nối đến Web App.' });
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleReopen = async (alertId) => {
    setActionLoadingId(alertId);
    setActionMessage(null);
    try {
      const res = await fetch(`http://localhost:3000/api/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        credentials: 'include',
        body: JSON.stringify({ status: 'new' })
      });
      if (res.ok) {
        const data = await res.json();
        setAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: 'new', updatedAt: data.alert?.updatedAt } : a))
        );
        if (selectedAlert && selectedAlert.id === alertId) {
          setSelectedAlert((prev) => ({ ...prev, status: 'new', updatedAt: data.alert?.updatedAt }));
        }
        setActionMessage({ type: 'success', text: `Cảnh báo #${alertId} đã được mở lại (NEW).` });
        fetchStats();
      } else {
        const err = await res.json().catch(() => ({}));
        const statusNote = res.status === 401 ? ' (401 Unauthorized - Yêu cầu xác thực)' :
                           res.status === 403 ? ' (403 Forbidden - Vai trò không đủ quyền)' : '';
        setActionMessage({
          type: 'error',
          text: `[Lỗi ${res.status}] ${err.error || err.message || 'Lỗi khi mở lại cảnh báo.'}${statusNote}`
        });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message || 'Không thể kết nối đến Web App.' });
    } finally {
      setActionLoadingId(null);
    }
  };

  // Open Alert Details Modal
  const openAlertDetails = async (alert) => {
    setModalLoading(true);
    setSelectedAlert(alert);
    try {
      const res = await fetch(`http://localhost:3000/api/alerts/${alert.id}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.alert) {
          setSelectedAlert(data.alert);
        }
      }
    } catch (e) {
      console.warn('Could not fetch full alert detail:', e.message);
    } finally {
      setModalLoading(false);
    }
  };

  // Filter change handler
  const handleFilterChange = (key, value) => {
    const updated = { ...filters, [key]: value };
    setFilters(updated);
    setPage(1);
    fetchAlerts(1, updated);
  };

  const getSeverityBadgeClass = (severity) => {
    const s = (severity || 'MEDIUM').toUpperCase();
    if (s === 'CRITICAL') return 'badge-sev badge-sev-critical';
    if (s === 'HIGH') return 'badge-sev badge-sev-high';
    if (s === 'MEDIUM') return 'badge-sev badge-sev-medium';
    return 'badge-sev badge-sev-low';
  };

  const getStatusBadge = (status) => {
    const s = (status || 'NEW').toUpperCase();
    if (s === 'ACKNOWLEDGED') return <span className="badge-sev badge-status-ack">ACKNOWLEDGED</span>;
    if (s === 'RESOLVED') return <span className="badge-sev badge-status-resolved">RESOLVED</span>;
    return <span className="badge-sev badge-status-new">NEW</span>;
  };

  // Phase 9: If verifying session on initial mount
  if (checkingAuth) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#0b1120',
        color: '#38bdf8',
        fontSize: '1.1rem',
        fontWeight: 600,
        fontFamily: 'sans-serif'
      }}>
        🛡️ Đang kiểm tra phiên làm việc bảo mật...
      </div>
    );
  }

  // Phase 9: If not authenticated, render Login Page
  if (!currentUser) {
    return <Login onLoginSuccess={(user) => setCurrentUser(user)} />;
  }

  return (
    <div className="dashboard-container">
      {/* Header */}
      <header className="header">
        <div>
          <h1>
            SECURITY GUARD
            <span className="badge-tag">Môn: BM&ATTT</span>
          </h1>
          <p className="subtitle">
            Hệ thống phát hiện hành vi bất thường trên Website (Web Anomaly Detection System)
          </p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
            {/* User Profile Pill */}
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem',
              padding: '0.25rem 0.75rem',
              backgroundColor: currentUser?.role === 'ADMIN' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(34, 197, 94, 0.15)',
              color: currentUser?.role === 'ADMIN' ? '#38bdf8' : '#4ade80',
              border: `1px solid ${currentUser?.role === 'ADMIN' ? 'rgba(56, 189, 248, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
              borderRadius: '9999px',
              fontSize: '0.8rem',
              fontWeight: 600
            }}>
              👤 {currentUser?.username} ({currentUser?.role === 'ADMIN' ? '👑 ADMIN' : '🛡️ ANALYST'})
            </span>

            {/* Admin Only: User Management Button */}
            {currentUser?.role === 'ADMIN' && (
              <button
                onClick={() => setUserModalOpen(true)}
                style={{
                  padding: '0.28rem 0.65rem',
                  backgroundColor: '#0284c7',
                  border: 'none',
                  borderRadius: '6px',
                  color: '#ffffff',
                  fontSize: '0.78rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.3rem'
                }}
              >
                👥 Quản lý Người dùng
              </button>
            )}

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              style={{
                padding: '0.28rem 0.65rem',
                backgroundColor: 'transparent',
                border: '1px solid #475569',
                borderRadius: '6px',
                color: '#cbd5e1',
                fontSize: '0.78rem',
                cursor: 'pointer'
              }}
            >
              🚪 Đăng xuất
            </button>

            <span className={`sse-badge ${sseConnected ? 'sse-badge-live' : 'sse-badge-polling'}`}>
              <span className={`sse-dot ${sseConnected ? 'sse-dot-live' : 'sse-dot-polling'}`}></span>
              {sseConnected ? 'Live SSE Stream' : 'Polling (Fallback)'}
            </span>
          </div>
          {lastUpdated && (
            <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.35rem' }}>
              Cập nhật lần cuối: {lastUpdated}
            </p>
          )}
        </div>
      </header>

      {/* Real-time Toast Alert Notification */}
      {liveToast && (
        <div className="alert-toast-banner">
          <div className="alert-toast-content">
            <span style={{ fontSize: '1.25rem' }}>🚨</span>
            <div>
              <strong>Phát hiện cảnh báo mới:</strong> [{liveToast.alertType}] từ IP <code style={{ color: '#f8fafc' }}>{liveToast.sourceIp}</code> (Risk: {liveToast.riskScore || liveToast.risk_score})
              <div style={{ fontSize: '0.8rem', color: '#fca5a5' }}>{liveToast.targetUrl} - {liveToast.description}</div>
            </div>
          </div>
          <div className="alert-toast-actions">
            <button
              className="btn btn-sm btn-primary"
              onClick={() => {
                openAlertDetails(liveToast);
                setLiveToast(null);
              }}
            >
              Xem ngay
            </button>
            <button
              className="btn btn-sm"
              style={{ background: 'transparent', color: '#cbd5e1' }}
              onClick={() => setLiveToast(null)}
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Action Message Feedback */}
      {actionMessage && (
        <div
          style={{
            padding: '0.6rem 1rem',
            marginBottom: '1rem',
            borderRadius: '6px',
            fontSize: '0.85rem',
            background: actionMessage.type === 'success' ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)',
            color: actionMessage.type === 'success' ? '#4ade80' : '#f87171',
            border: `1px solid ${actionMessage.type === 'success' ? 'rgba(34, 197, 94, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontWeight: 'bold' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* System Status Section */}
      <section>
        <h2 className="section-title">System Status</h2>
        <div className="grid-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
          <div className="card status-item">
            <span className="status-name">Web Application</span>
            <span className={`status-pill ${systemStatus.webApp === 'Online' ? 'status-online' : 'status-degraded'}`}>
              <span className={`status-dot ${systemStatus.webApp !== 'Online' ? 'status-dot-warning' : ''}`}></span>
              {systemStatus.webApp}
            </span>
          </div>

          <div className="card status-item">
            <span className="status-name">Detection Engine</span>
            <span className={`status-pill ${systemStatus.detectionEngine === 'Online' ? 'status-online' : 'status-degraded'}`}>
              <span className={`status-dot ${systemStatus.detectionEngine !== 'Online' ? 'status-dot-warning' : ''}`}></span>
              {systemStatus.detectionEngine}
            </span>
          </div>

          <div className="card status-item">
            <span className="status-name">PostgreSQL Database</span>
            <span className={`status-pill ${systemStatus.database === 'Online' ? 'status-online' : 'status-degraded'}`}>
              <span className={`status-dot ${systemStatus.database !== 'Online' ? 'status-dot-warning' : ''}`}></span>
              {systemStatus.database}
            </span>
          </div>

          <div className="card status-item">
            <span className="status-name">Machine Learning (ML)</span>
            <span className={`status-pill ${systemStatus.mlEngine && !systemStatus.mlEngine.includes('Offline') ? 'status-online' : 'status-degraded'}`}>
              <span className={`status-dot ${!systemStatus.mlEngine || systemStatus.mlEngine.includes('Offline') ? 'status-dot-warning' : ''}`}></span>
              {systemStatus.mlEngine || 'Shadow (v1.0.0)'}
            </span>
          </div>

          <div className="card status-item">
            <span className="status-name">Monitoring Gateway</span>
            <span className={`status-pill ${systemStatus.gateway && systemStatus.gateway.includes('Online') ? 'status-online' : 'status-degraded'}`}>
              <span className={`status-dot ${!systemStatus.gateway || !systemStatus.gateway.includes('Online') ? 'status-dot-warning' : ''}`}></span>
              {systemStatus.gateway || 'Online (:8080)'}
            </span>
          </div>
        </div>
      </section>

      {/* Phase 10: Multi-Website Monitoring & Active Enforcement Section */}
      <WebsiteMonitoringSection currentUser={currentUser} onActionMessage={setActionMessage} />

      {/* Alert Lifecycle Metrics Section (Phase 4 & 6) */}
      <section>
        <h2 className="section-title">Alert Lifecycle & Detection Metrics</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
          <div className="card stat-card">
            <span className="stat-label">Tổng Cảnh Báo</span>
            <span className="stat-value">{alertStats.totalAlerts}</span>
            <span className="stat-info">Tất cả cảnh báo đã ghi nhận</span>
          </div>

          <div className="card stat-card" style={{ borderColor: 'rgba(56, 189, 248, 0.4)' }}>
            <span className="stat-label" style={{ color: '#38bdf8' }}>Cần Xử Lý (NEW)</span>
            <span className="stat-value" style={{ color: '#38bdf8' }}>{alertStats.newAlerts}</span>
            <span className="stat-info">Chờ phân tích & tiếp nhận</span>
          </div>

          <div className="card stat-card" style={{ borderColor: 'rgba(168, 85, 247, 0.4)' }}>
            <span className="stat-label" style={{ color: '#c084fc' }}>Đang Xử Lý (ACK)</span>
            <span className="stat-value" style={{ color: '#c084fc' }}>{alertStats.acknowledgedAlerts}</span>
            <span className="stat-info">Đã tiếp nhận điều tra</span>
          </div>

          <div className="card stat-card" style={{ borderColor: 'rgba(34, 197, 94, 0.4)' }}>
            <span className="stat-label" style={{ color: '#4ade80' }}>Đã Xử Lý (RESOLVED)</span>
            <span className="stat-value" style={{ color: '#4ade80' }}>{alertStats.resolvedAlerts}</span>
            <span className="stat-info">Đã khắc phục / đóng</span>
          </div>

          <div className="card stat-card" style={{ borderColor: 'rgba(239, 68, 68, 0.4)' }}>
            <span className="stat-label" style={{ color: '#f87171' }}>Mức Độ Cao / Khẩn</span>
            <span className="stat-value" style={{ color: '#f87171' }}>
              {(alertStats.criticalSeverity || 0) + (alertStats.highSeverity || 0)}
            </span>
            <span className="stat-info">Critical ({alertStats.criticalSeverity}) | High ({alertStats.highSeverity})</span>
          </div>

          <div className="card stat-card" style={{ borderColor: 'rgba(192, 132, 252, 0.4)' }}>
            <span className="stat-label" style={{ color: '#c084fc' }}>Phát Hiện Máy Học</span>
            <span className="stat-value" style={{ color: '#c084fc' }}>{alertStats.mlAlerts || 0}</span>
            <span className="stat-info">Isolation Forest Outliers</span>
          </div>
        </div>

        {/* Phase 7 & 8: Detection Expansion & Offline Benchmark Summary */}
        <div className="card" style={{ background: 'rgba(15, 23, 42, 0.75)', border: '1px solid #334155', padding: '0.85rem 1.25rem', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', borderBottom: '1px dashed #334155', paddingBottom: '0.65rem' }}>
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🛡️ Năng Lực Phát Hiện Thực Nghiệm (Offline Benchmark Validation)</span>
                <span className="badge-tag" style={{ fontSize: '0.7rem' }}>Phase 8 Verified</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                8 Luật Chữ Ký (SQLi, XSS, Brute Force, Scanner, Traffic, Suspicious URL, Path Traversal, Command Injection) + Isolation Forest
              </div>
            </div>
            <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Holdout Accuracy / F1</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#4ade80' }}>97.5% / 0.974</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Unseen Generalization (v3)</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#38bdf8' }}>93.8% (Recall: 92.5%)</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>HTTP RTT (p50)</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f59e0b' }}>3.75 ms (E2E)</div>
              </div>
            </div>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '0.45rem', fontStyle: 'italic' }}>
            * Lưu ý: Thống kê trên đo lường từ tập mẫu kiểm chuẩn độc lập (80 mẫu). Điểm số ML Anomaly Score (0-100) là khoảng cách ngoại lai thống kê Isolation Forest, không phải xác suất toán học của cuộc tấn công.
          </div>
        </div>
      </section>

      {/* Alert Management Table & Controls Section */}
      <section>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <h2 className="section-title" style={{ margin: 0 }}>
            <span>Quản Lý Cảnh Báo An Ninh (Alert Management)</span>
          </h2>
          <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
            Hiển thị {alerts.length} / {totalAlertsCount} cảnh báo
          </span>
        </div>

        {/* Filters Toolbar */}
        <div className="filter-toolbar">
          <div className="filter-group">
            <label className="filter-label">Trạng thái</label>
            <select
              className="filter-control"
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
            >
              <option value="">Tất cả trạng thái</option>
              <option value="new">NEW (Cần xử lý)</option>
              <option value="acknowledged">ACKNOWLEDGED (Đang xử lý)</option>
              <option value="resolved">RESOLVED (Đã xử lý)</option>
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Mức độ (Severity)</label>
            <select
              className="filter-control"
              value={filters.severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
            >
              <option value="">Tất cả mức độ</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Website</label>
            <select
              className="filter-control"
              value={filters.websiteId || ''}
              onChange={(e) => handleFilterChange('websiteId', e.target.value)}
            >
              <option value="">Tất cả website</option>
              <option value="site_demo_node">site_demo_node (Node Shop)</option>
              <option value="site_demo_python">site_demo_python (Python Portal)</option>
              <option value="default_web_app">default_web_app (Main Web)</option>
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Sắp xếp</label>
            <select
              className="filter-control"
              value={filters.sort}
              onChange={(e) => handleFilterChange('sort', e.target.value)}
            >
              <option value="newest">Mới nhất trước</option>
              <option value="oldest">Cũ nhất trước</option>
              <option value="risk_desc">Risk Score cao nhất</option>
              <option value="risk_asc">Risk Score thấp nhất</option>
            </select>
          </div>

          <div className="filter-group" style={{ flexGrow: 1 }}>
            <label className="filter-label">Tìm kiếm (IP)</label>
            <input
              type="text"
              className="filter-control"
              placeholder="Nhập IP (ví dụ: 127.0.0.1)..."
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
            />
          </div>

          <div className="filter-group" style={{ alignSelf: 'flex-end' }}>
            <button
              className="btn btn-detail"
              onClick={() => {
                fetchAlerts(page, filters);
                fetchStats();
              }}
            >
              🔄 Làm mới
            </button>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="card" style={{ padding: '0', overflow: 'hidden', marginBottom: '2rem' }}>
          {alerts.length === 0 ? (
            <div className="empty-state">
              Không tìm thấy cảnh báo nào phù hợp với bộ lọc hiện tại.
            </div>
          ) : (
            <div className="traffic-table-container">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Thời gian</th>
                    <th>Client IP</th>
                    <th>Loại tấn công</th>
                    <th>Mức độ</th>
                    <th>Risk Score</th>
                    <th>Website</th>
                    <th>Mục tiêu (URL)</th>
                    <th>Trạng thái</th>
                    <th style={{ textAlign: 'center' }}>Thao tác</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => {
                    const timeStr = alert.createdAt || alert.timestamp;
                    const formattedTime = timeStr ? new Date(timeStr).toLocaleString() : 'N/A';
                    const ip = alert.sourceIp || alert.ip || '127.0.0.1';
                    const type = alert.alertType || alert.type || 'ANOMALY';
                    const severity = alert.severity || 'MEDIUM';
                    const riskScore = alert.riskScore !== undefined ? alert.riskScore : (alert.risk_score || 0);
                    const url = alert.targetUrl || alert.url || '/';
                    const status = (alert.status || 'NEW').toLowerCase();
                    const isBusy = actionLoadingId === alert.id;

                    return (
                      <tr key={alert.id} style={{ background: severity === 'CRITICAL' || severity === 'HIGH' ? 'rgba(239, 68, 68, 0.04)' : 'transparent' }}>
                        <td style={{ color: '#64748b', fontFamily: 'monospace' }}>#{alert.id}</td>
                        <td style={{ color: '#94a3b8', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                          {formattedTime}
                        </td>
                        <td style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>
                          {ip}
                        </td>
                        <td>
                          {type === 'ML_ANOMALY' ? (
                            <span className="badge-ml">
                              <span className="badge-ml-icon">🤖</span> ML_ANOMALY
                            </span>
                          ) : type === 'PATH_TRAVERSAL' ? (
                            <span className="badge-trav">
                              📁 PATH_TRAVERSAL
                            </span>
                          ) : type === 'COMMAND_INJECTION' ? (
                            <span className="badge-cmdi">
                              ⚡ COMMAND_INJECTION
                            </span>
                          ) : (
                            <span style={{ fontWeight: 600, color: '#f8fafc' }}>
                              {type}
                            </span>
                          )}
                        </td>
                        <td>
                          <span className={getSeverityBadgeClass(severity)}>
                            {severity}
                          </span>
                        </td>
                        <td>
                          <span className="badge-risk-score">
                            {riskScore} / 100
                          </span>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.75rem', padding: '0.15rem 0.4rem', borderRadius: '4px', backgroundColor: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.25)', fontFamily: 'monospace' }}>
                            {alert.websiteId || 'default_web_app'}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'monospace', maxWidth: '200px', wordBreak: 'break-all', fontSize: '0.82rem' }}>
                          {url}
                        </td>
                        <td>
                          {getStatusBadge(status)}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '0.35rem', justifyContent: 'center' }}>
                            <button
                              className="btn btn-sm btn-detail"
                              onClick={() => openAlertDetails(alert)}
                              title="Xem chi tiết cảnh báo"
                            >
                              Chi tiết
                            </button>

                            {status === 'new' && (
                              <button
                                className="btn btn-sm btn-ack"
                                disabled={isBusy}
                                onClick={() => handleAcknowledge(alert.id)}
                                title="Xác nhận tiếp nhận cảnh báo"
                              >
                                {isBusy ? '...' : 'Tiếp nhận'}
                              </button>
                            )}

                            {status === 'acknowledged' && (
                              <button
                                className="btn btn-sm btn-resolve"
                                disabled={isBusy}
                                onClick={() => handleResolve(alert.id)}
                                title="Đánh dấu đã giải quyết"
                              >
                                {isBusy ? '...' : 'Giải quyết'}
                              </button>
                            )}

                            {status === 'resolved' && (
                              <button
                                className="btn btn-sm btn-reopen"
                                disabled={isBusy}
                                onClick={() => handleReopen(alert.id)}
                                title="Mở lại cảnh báo cần xử lý"
                              >
                                {isBusy ? '...' : 'Mở lại'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="pagination-bar">
              <span>Trang {page} trên tổng {totalPages}</span>
              <div className="pagination-actions">
                <button
                  className="btn btn-sm btn-detail"
                  disabled={page <= 1}
                  onClick={() => {
                    const nextP = page - 1;
                    setPage(nextP);
                    fetchAlerts(nextP, filters);
                  }}
                >
                  ◀ Trước
                </button>
                <button
                  className="btn btn-sm btn-detail"
                  disabled={page >= totalPages}
                  onClick={() => {
                    const nextP = page + 1;
                    setPage(nextP);
                    fetchAlerts(nextP, filters);
                  }}
                >
                  Sau ▶
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Live HTTP Requests (Traffic Monitor) */}
      <section>
        <h2 className="section-title">
          <span>Live HTTP Requests (Lưu lượng Thời gian thực)</span>
          <span style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 'normal' }}>
            5 requests mới nhất
          </span>
        </h2>
        <div className="card" style={{ padding: '0', overflow: 'hidden', marginBottom: '2rem' }}>
          {recentLogs.length === 0 ? (
            <div className="empty-state">Chưa có request nào được ghi nhận.</div>
          ) : (
            <div className="traffic-table-container">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th>Thời gian</th>
                    <th>Method</th>
                    <th>URL / Path</th>
                    <th>Status</th>
                    <th>Client IP</th>
                    <th>Độ trễ</th>
                  </tr>
                </thead>
                <tbody>
                  {recentLogs.map((log, idx) => {
                    const method = (log.method || 'GET').toUpperCase();
                    const status = parseInt(log.statusCode, 10) || 200;
                    return (
                      <tr key={idx}>
                        <td style={{ color: '#94a3b8', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td>
                          <span className={`badge-method ${method === 'POST' ? 'badge-post' : 'badge-get'}`}>
                            {method}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'monospace', maxWidth: '300px', wordBreak: 'break-all' }}>
                          {log.url}
                        </td>
                        <td>
                          <span className={`badge-status ${status >= 500 ? 'badge-status-500' : status >= 400 ? 'badge-status-404' : 'badge-status-200'}`}>
                            {status}
                          </span>
                        </td>
                        <td style={{ color: '#cbd5e1' }}>
                          {log.ip || '127.0.0.1'}
                        </td>
                        <td style={{ color: '#94a3b8' }}>
                          {log.responseTime !== undefined ? `${log.responseTime}ms` : '0ms'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* Alert Details Modal */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <span>Chi tiết Cảnh báo #{selectedAlert.id}</span>
                {getStatusBadge(selectedAlert.status)}
              </div>
              <button className="modal-close-btn" onClick={() => setSelectedAlert(null)}>
                ×
              </button>
            </div>

            <div className="modal-body">
              {modalLoading && <div style={{ color: '#38bdf8' }}>Đang tải dữ liệu chi tiết...</div>}

              <div className="modal-grid-2">
                <div>
                  <div className="detail-label">Loại tấn công (Alert Type)</div>
                  <div className="detail-value" style={{ color: '#f8fafc', fontWeight: 'bold' }}>
                    {selectedAlert.alertType || selectedAlert.type}
                  </div>
                </div>
                <div>
                  <div className="detail-label">Mức độ nguy hiểm (Severity)</div>
                  <div>{getSeverityBadgeClass(selectedAlert.severity) && <span className={getSeverityBadgeClass(selectedAlert.severity)}>{selectedAlert.severity}</span>}</div>
                </div>
              </div>

              <div className="modal-grid-2">
                <div>
                  <div className="detail-label">Client IP Nguồn</div>
                  <div className="detail-value" style={{ fontFamily: 'monospace' }}>
                    {selectedAlert.sourceIp || selectedAlert.ip}
                  </div>
                </div>
                <div>
                  <div className="detail-label">Risk Score</div>
                  <div className="detail-value" style={{ color: '#fb923c', fontWeight: 'bold', fontSize: '1.1rem' }}>
                    {selectedAlert.riskScore !== undefined ? selectedAlert.riskScore : selectedAlert.risk_score} / 100
                  </div>
                </div>
              </div>

              <div>
                <div className="detail-label">HTTP Method & Mục tiêu (URL)</div>
                <div className="detail-block" style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                  <strong style={{ color: '#38bdf8' }}>{selectedAlert.method || 'GET'}</strong> {selectedAlert.targetUrl || selectedAlert.url}
                </div>
              </div>

              <div>
                <div className="detail-label">Mô tả phát hiện (Detection Reason)</div>
                <div className="detail-block" style={{ color: '#cbd5e1', fontSize: '0.85rem', lineHeight: 1.5 }}>
                  {selectedAlert.description || 'Không có mô tả chi tiết'}
                </div>
              </div>

              <div className="modal-grid-2">
                <div>
                  <div className="detail-label">Thời điểm phát hiện</div>
                  <div className="detail-value" style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                    {selectedAlert.createdAt ? new Date(selectedAlert.createdAt).toLocaleString() : selectedAlert.timestamp || 'N/A'}
                  </div>
                </div>
                <div>
                  <div className="detail-label">Thời điểm cập nhật trạng thái</div>
                  <div className="detail-value" style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                    {selectedAlert.updatedAt ? new Date(selectedAlert.updatedAt).toLocaleString() : 'Chưa cập nhật'}
                  </div>
                </div>
              </div>

              {/* Linked Request Log Information (if available) */}
              {selectedAlert.requestLog && (
                <div>
                  <div className="detail-label" style={{ color: '#38bdf8' }}>
                    Thông tin HTTP Request Log liên quan (Database Link)
                  </div>
                  <div className="detail-block" style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>
                    <p><strong>Log ID:</strong> #{selectedAlert.requestLog.id}</p>
                    <p><strong>HTTP Status:</strong> {selectedAlert.requestLog.statusCode || selectedAlert.requestLog.status_code}</p>
                    <p><strong>User Agent:</strong> {selectedAlert.requestLog.userAgent || selectedAlert.requestLog.user_agent || 'N/A'}</p>
                    <p><strong>Độ trễ phản hồi:</strong> {selectedAlert.requestLog.responseTime || selectedAlert.requestLog.response_time_ms}ms</p>
                  </div>
                </div>
              )}

              {/* Machine Learning Metadata (Phase 6) */}
              {(selectedAlert.details?.ml_result || selectedAlert.alertType === 'ML_ANOMALY') && (
                <div className="ml-details-card">
                  <div className="detail-label" style={{ color: '#c084fc', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
                    <span>🤖</span> Phân tích Machine Learning (Isolation Forest)
                  </div>
                  <div style={{ fontSize: '0.82rem', color: '#cbd5e1', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem' }}>
                    <div>
                      <strong>Model Version:</strong> {selectedAlert.details?.ml_result?.model_version || '1.0.0'}
                    </div>
                    <div>
                      <strong>ML Anomaly Score:</strong> <span style={{ color: '#fb923c', fontWeight: 'bold' }}>{selectedAlert.details?.ml_result?.anomaly_score !== undefined ? `${selectedAlert.details.ml_result.anomaly_score} / 100` : 'N/A'}</span>
                    </div>
                    <div>
                      <strong>Decision Raw Score:</strong> {selectedAlert.details?.ml_result?.raw_score !== undefined ? selectedAlert.details.ml_result.raw_score : 'N/A'}
                    </div>
                    <div>
                      <strong>Chế độ hoạt động:</strong> {selectedAlert.details?.ml_result?.mode || 'active'}
                    </div>
                  </div>
                  {selectedAlert.details?.ml_result?.reason && (
                    <div style={{ fontSize: '0.8rem', color: '#e9d5ff', marginTop: '0.5rem', fontStyle: 'italic', borderTop: '1px dashed rgba(168, 85, 247, 0.3)', paddingTop: '0.4rem' }}>
                      {selectedAlert.details.ml_result.reason}
                    </div>
                  )}
                  <div style={{ fontSize: '0.72rem', color: '#a855f7', marginTop: '0.4rem', opacity: 0.85 }}>
                    * Điểm số ngoại lai Isolation Forest (0-100), không phải xác suất toán học của cuộc tấn công.
                  </div>
                </div>
              )}
            </div>

            <div className="modal-footer">
              {String(selectedAlert.status).toLowerCase() === 'new' && (
                <button
                  className="btn btn-ack"
                  disabled={actionLoadingId === selectedAlert.id}
                  onClick={() => handleAcknowledge(selectedAlert.id)}
                >
                  ✓ Tiếp nhận (Acknowledge)
                </button>
              )}

              {String(selectedAlert.status).toLowerCase() === 'acknowledged' && (
                <button
                  className="btn btn-resolve"
                  disabled={actionLoadingId === selectedAlert.id}
                  onClick={() => handleResolve(selectedAlert.id)}
                >
                  ✓ Đánh dấu đã giải quyết (Resolve)
                </button>
              )}

              {String(selectedAlert.status).toLowerCase() === 'resolved' && (
                <button
                  className="btn btn-reopen"
                  disabled={actionLoadingId === selectedAlert.id}
                  onClick={() => handleReopen(selectedAlert.id)}
                >
                  ↺ Mở lại (Reopen)
                </button>
              )}

              <button className="btn btn-primary" onClick={() => setSelectedAlert(null)}>
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}

      {/* User Management Modal (Phase 9 Admin RBAC) */}
      <UserManagementModal
        isOpen={userModalOpen}
        onClose={() => setUserModalOpen(false)}
        currentAdminId={currentUser?.id}
      />

      {/* Footer */}
      <footer className="footer">
        SECURITY GUARD &copy; 2026 - Đồ án môn Bảo mật và An toàn thông tin - Phase 6: Machine Learning Anomaly Detection & Monitoring
      </footer>
    </div>
  );
}
