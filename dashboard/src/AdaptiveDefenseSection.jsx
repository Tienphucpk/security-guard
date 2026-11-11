import React, { useState, useEffect } from 'react';

export default function AdaptiveDefenseSection({ currentUser, onActionMessage }) {
  const [evidenceList, setEvidenceList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filterDecision, setFilterDecision] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [benchmarkModalOpen, setBenchmarkModalOpen] = useState(false);
  const [benchmarkTab, setBenchmarkTab] = useState('comparison');

  const fetchEvidence = async () => {
    setLoading(true);
    try {
      const url = new URL('http://localhost:3000/api/monitoring/evidence');
      url.searchParams.set('limit', '25');
      if (filterDecision) {
        url.searchParams.set('decision', filterDecision);
      }
      const res = await fetch(url.toString(), { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'success' && Array.isArray(data.evidence)) {
          setEvidenceList(data.evidence);
        }
      }
    } catch (err) {
      console.warn('Failed to fetch evidence:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvidence();
    const interval = setInterval(fetchEvidence, 12000);
    return () => clearInterval(interval);
  }, [filterDecision]);

  // Derived metrics from evidence
  const totalEvidence = evidenceList.length;
  const blockedCount = evidenceList.filter(e => e.decision === 'BLOCK').length;
  const monitorCount = evidenceList.filter(e => e.decision === 'MONITOR').length;
  const avgRisk = totalEvidence > 0 
    ? Math.round(evidenceList.reduce((acc, e) => acc + (parseFloat(e.riskScore) || 0), 0) / totalEvidence)
    : 0;

  return (
    <section style={{ marginTop: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2 className="section-title" style={{ margin: 0 }}>Adaptive Hybrid Defense & Evidence Aggregation</h2>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            Hệ thống phòng thủ tương thích: chuẩn hóa đa tầng, hợp lực quy tắc & máy học (Isolation Forest), truy vết chuỗi chứng cứ.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button 
            className="btn btn-secondary" 
            onClick={() => setBenchmarkModalOpen(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', borderColor: '#38bdf8', color: '#38bdf8' }}
          >
            📊 Xem Kết Quả Benchmark Thực Nghiệm
          </button>
          <button 
            className="btn btn-secondary" 
            onClick={fetchEvidence} 
            disabled={loading}
          >
            {loading ? 'Đang tải...' : '🔄 Làm mới chứng cứ'}
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
        <div className="card stat-card" style={{ borderColor: 'rgba(56, 189, 248, 0.4)' }}>
          <span className="stat-label" style={{ color: '#38bdf8' }}>Hồ Sơ Chứng Cứ</span>
          <span className="stat-value" style={{ color: '#38bdf8' }}>{totalEvidence}</span>
          <span className="stat-info">Yêu cầu được phân tích & lưu vết</span>
        </div>

        <div className="card stat-card" style={{ borderColor: 'rgba(239, 68, 68, 0.4)' }}>
          <span className="stat-label" style={{ color: '#f87171' }}>Chặn Tích Cực (BLOCK)</span>
          <span className="stat-value" style={{ color: '#f87171' }}>{blockedCount}</span>
          <span className="stat-info">Mã trạng thái 403 Forbidden</span>
        </div>

        <div className="card stat-card" style={{ borderColor: 'rgba(234, 179, 8, 0.4)' }}>
          <span className="stat-label" style={{ color: '#facc15' }}>Giám Sát Cảnh Báo (MONITOR)</span>
          <span className="stat-value" style={{ color: '#facc15' }}>{monitorCount}</span>
          <span className="stat-info">Ghi vết không làm gián đoạn</span>
        </div>

        <div className="card stat-card" style={{ borderColor: 'rgba(34, 197, 94, 0.4)' }}>
          <span className="stat-label" style={{ color: '#4ade80' }}>Điểm Rủi Ro TB (Risk Score)</span>
          <span className="stat-value" style={{ color: '#4ade80' }}>{avgRisk}<span style={{ fontSize: '1rem' }}>/100</span></span>
          <span className="stat-info">Chỉ số rủi ro hợp lực thích ứng</span>
        </div>
      </div>

      {/* Filter and Evidence Table */}
      <div className="card" style={{ padding: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 style={{ margin: 0, fontSize: '1rem', color: '#f8fafc' }}>
            Bảng Truy Vết Chuỗi Chứng Cứ Gần Nhất (Detection Evidence Audit Trail)
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>Lọc theo quyết định:</span>
            <select 
              value={filterDecision} 
              onChange={(e) => setFilterDecision(e.target.value)}
              className="form-input" 
              style={{ width: 'auto', padding: '0.3rem 0.6rem', fontSize: '0.85rem' }}
            >
              <option value="">Tất cả quyết định</option>
              <option value="BLOCK">BLOCK (Chặn 403)</option>
              <option value="MONITOR">MONITOR (Giám sát)</option>
              <option value="ALLOW">ALLOW (Cho phép)</option>
            </select>
          </div>
        </div>

        {evidenceList.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: '#94a3b8' }}>
            Chưa có bản ghi chứng cứ nào. Các yêu cầu qua Gateway sẽ xuất hiện tại đây theo thời gian thực.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="table" style={{ width: '100%', fontSize: '0.875rem' }}>
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Request ID</th>
                  <th>Website ID</th>
                  <th>Quy Tắc Vi Phạm</th>
                  <th>Điểm ML Anomaly</th>
                  <th>Điểm Rủi Ro</th>
                  <th>Quyết Định</th>
                  <th>Thao Tác</th>
                </tr>
              </thead>
              <tbody>
                {evidenceList.map((item) => {
                  const isBlocked = item.decision === 'BLOCK';
                  const isMonitor = item.decision === 'MONITOR';
                  const ruleList = Array.isArray(item.ruleMatches) ? item.ruleMatches : [];
                  const score = parseFloat(item.riskScore) || 0;
                  const isExpanded = expandedId === item.id;

                  return (
                    <React.Fragment key={item.id}>
                      <tr style={{ background: isExpanded ? 'rgba(56, 189, 248, 0.05)' : 'transparent' }}>
                        <td style={{ whiteSpace: 'nowrap', color: '#94a3b8' }}>
                          {item.timestamp ? new Date(item.timestamp).toLocaleTimeString('vi-VN') : '—'}
                        </td>
                        <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#38bdf8' }}>
                          {item.requestId ? item.requestId.slice(0, 16) : '—'}
                        </td>
                        <td>
                          <span style={{ background: '#334155', padding: '2px 6px', borderRadius: '4px', fontSize: '0.75rem' }}>
                            {item.websiteId}
                          </span>
                        </td>
                        <td>
                          {ruleList.length > 0 ? (
                            <span style={{ 
                              color: item.ruleSeverity === 'CRITICAL' ? '#f87171' : item.ruleSeverity === 'HIGH' ? '#fb923c' : '#facc15',
                              fontWeight: 600
                            }}>
                              {ruleList.join(', ')} ({item.ruleSeverity})
                            </span>
                          ) : (
                            <span style={{ color: '#64748b' }}>Không có</span>
                          )}
                        </td>
                        <td style={{ fontFamily: 'monospace' }}>
                          {typeof item.mlAnomalyScore === 'number' ? (
                            <span style={{ color: item.mlAnomalyScore > 50 ? '#c084fc' : '#94a3b8' }}>
                              {item.mlAnomalyScore.toFixed(1)} (th={item.mlThreshold || -0.026})
                            </span>
                          ) : '0.0'}
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <div style={{ width: '48px', height: '6px', background: '#334155', borderRadius: '3px', overflow: 'hidden' }}>
                              <div style={{ 
                                width: `${Math.min(100, score)}%`, 
                                height: '100%', 
                                background: score >= 70 ? '#ef4444' : score >= 35 ? '#eab308' : '#22c55e' 
                              }} />
                            </div>
                            <span style={{ 
                              fontWeight: 600, 
                              color: score >= 70 ? '#f87171' : score >= 35 ? '#facc15' : '#4ade80' 
                            }}>
                              {score.toFixed(1)}
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className={`status-pill ${
                            isBlocked ? 'status-degraded' : isMonitor ? 'status-warning' : 'status-online'
                          }`} style={{ fontSize: '0.75rem', padding: '2px 8px' }}>
                            {item.decision}
                          </span>
                        </td>
                        <td>
                          <button 
                            className="btn btn-secondary" 
                            style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                            onClick={() => setExpandedId(isExpanded ? null : item.id)}
                          >
                            {isExpanded ? 'Ẩn' : 'Chi tiết'}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan="8" style={{ background: '#0f172a', padding: '1rem', borderLeft: '3px solid #38bdf8' }}>
                            <div style={{ fontSize: '0.85rem' }}>
                              <div style={{ marginBottom: '0.5rem' }}>
                                <strong style={{ color: '#38bdf8' }}>Lý do quyết định (Decision Reason):</strong>{' '}
                                <span style={{ color: '#f8fafc' }}>{item.decisionReason || 'Normal traffic'}</span>
                              </div>
                              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                                <div>
                                  <strong style={{ color: '#94a3b8' }}>Thời gian phân tích:</strong> {item.processingTimeMs || 0} ms
                                </div>
                                <div>
                                  <strong style={{ color: '#94a3b8' }}>Đặc trưng bất thường phát hiện:</strong>{' '}
                                  {Array.isArray(item.matchedFeatures) && item.matchedFeatures.length > 0 
                                    ? item.matchedFeatures.join(', ') 
                                    : 'Không có đặc trưng dị biệt'}
                                </div>
                              </div>
                              {item.evidence && (
                                <div style={{ marginTop: '0.75rem' }}>
                                  <strong style={{ color: '#94a3b8' }}>Dữ liệu bằng chứng cấu trúc (Structured Evidence):</strong>
                                  <pre style={{ 
                                    background: '#1e293b', 
                                    padding: '0.5rem', 
                                    borderRadius: '4px', 
                                    marginTop: '0.25rem', 
                                    fontSize: '0.75rem', 
                                    overflowX: 'auto',
                                    color: '#cbd5e1' 
                                  }}>
                                    {typeof item.evidence === 'string' ? item.evidence : JSON.stringify(item.evidence, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Experimental Benchmark Results Modal */}
      {benchmarkModalOpen && (
        <div className="modal-overlay" onClick={() => setBenchmarkModalOpen(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '900px', width: '90%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #334155', paddingBottom: '0.75rem' }}>
              <h3 style={{ margin: 0, color: '#38bdf8' }}>📊 Kết Quả Benchmark Thực Nghiệm Độc Lập</h3>
              <button className="btn btn-secondary" onClick={() => setBenchmarkModalOpen(false)} style={{ padding: '2px 8px' }}>✕</button>
            </div>

            {/* Modal Tabs */}
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.5rem' }}>
              <button 
                className={`btn ${benchmarkTab === 'comparison' ? 'btn-primary' : 'btn-secondary'}`} 
                onClick={() => setBenchmarkTab('comparison')}
                style={{ fontSize: '0.85rem' }}
              >
                So Sánh 3 Phương Pháp
              </button>
              <button 
                className={`btn ${benchmarkTab === 'confusion' ? 'btn-primary' : 'btn-secondary'}`} 
                onClick={() => setBenchmarkTab('confusion')}
                style={{ fontSize: '0.85rem' }}
              >
                Ma Trận Nhầm Lẫn
              </button>
              <button 
                className={`btn ${benchmarkTab === 'ablation' ? 'btn-primary' : 'btn-secondary'}`} 
                onClick={() => setBenchmarkTab('ablation')}
                style={{ fontSize: '0.85rem' }}
              >
                Nghiên Cứu Triệt Tiêu (Ablation)
              </button>
              <button 
                className={`btn ${benchmarkTab === 'vectors' ? 'btn-primary' : 'btn-secondary'}`} 
                onClick={() => setBenchmarkTab('vectors')}
                style={{ fontSize: '0.85rem' }}
              >
                Theo Nhóm Tấn Công
              </button>
            </div>

            {/* Tab 1: Method Comparison */}
            {benchmarkTab === 'comparison' && (
              <div>
                <table className="table" style={{ width: '100%', fontSize: '0.85rem' }}>
                  <thead>
                    <tr>
                      <th>Chỉ Số</th>
                      <th>(A) Rule-Based Only</th>
                      <th>(B) ML Only (Isolation Forest)</th>
                      <th style={{ color: '#38bdf8' }}>(C) Adaptive Hybrid (Security Guard)</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><strong>Accuracy (Độ chính xác toàn cục)</strong></td>
                      <td>91.67%</td>
                      <td>82.00%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>93.67% (+2.0%)</td>
                    </tr>
                    <tr>
                      <td><strong>Precision (Độ chuẩn xác)</strong></td>
                      <td>100.0%</td>
                      <td>97.92%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>100.0%</td>
                    </tr>
                    <tr>
                      <td><strong>Recall (Tỷ lệ phát hiện tấn công)</strong></td>
                      <td>75.0%</td>
                      <td>47.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>81.0% (+6.0% vs Rule, +34% vs ML)</td>
                    </tr>
                    <tr>
                      <td><strong>F1-Score</strong></td>
                      <td>85.71%</td>
                      <td>63.51%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>89.50% (+3.79%)</td>
                    </tr>
                    <tr>
                      <td><strong>False Positive Rate (Báo động giả)</strong></td>
                      <td>0.0%</td>
                      <td style={{ color: '#f87171' }}>0.5% (báo nhầm URL dài)</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>0.0% (Triệt tiêu báo sai)</td>
                    </tr>
                    <tr>
                      <td><strong>Thời gian xử lý trung bình</strong></td>
                      <td>0.035 ms</td>
                      <td>11.998 ms</td>
                      <td>12.244 ms</td>
                    </tr>
                    <tr>
                      <td><strong>Tỷ lệ chặn thành công (ENFORCE)</strong></td>
                      <td>75.0%</td>
                      <td>N/A (Chỉ cảnh báo)</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>78.0% (Chặn sạch SQLi, XSS, Path Trav)</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            {/* Tab 2: Confusion Matrices */}
            {benchmarkTab === 'confusion' && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                <div className="card" style={{ padding: '0.75rem', background: '#0f172a' }}>
                  <h4 style={{ margin: '0 0 0.5rem 0', color: '#94a3b8', fontSize: '0.85rem' }}>Method A: Rule-Based Only</h4>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', background: '#1e293b', padding: '0.5rem', borderRadius: '4px' }}>
                    TP = 75 &nbsp;&nbsp;&nbsp;&nbsp; FP = 0<br/>
                    FN = 25 &nbsp;&nbsp;&nbsp;&nbsp; TN = 200
                  </div>
                </div>

                <div className="card" style={{ padding: '0.75rem', background: '#0f172a' }}>
                  <h4 style={{ margin: '0 0 0.5rem 0', color: '#94a3b8', fontSize: '0.85rem' }}>Method B: ML Only (Isolation Forest)</h4>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', background: '#1e293b', padding: '0.5rem', borderRadius: '4px' }}>
                    TP = 47 &nbsp;&nbsp;&nbsp;&nbsp; FP = 1<br/>
                    FN = 53 &nbsp;&nbsp;&nbsp;&nbsp; TN = 199
                  </div>
                </div>

                <div className="card" style={{ padding: '0.75rem', background: '#0f172a', borderColor: '#38bdf8' }}>
                  <h4 style={{ margin: '0 0 0.5rem 0', color: '#38bdf8', fontSize: '0.85rem' }}>Method C: Adaptive Hybrid</h4>
                  <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', background: '#1e293b', padding: '0.5rem', borderRadius: '4px' }}>
                    TP = 81 &nbsp;&nbsp;&nbsp;&nbsp; FP = 0<br/>
                    FN = 19 &nbsp;&nbsp;&nbsp;&nbsp; TN = 200
                  </div>
                </div>
              </div>
            )}

            {/* Tab 3: Ablation Study */}
            {benchmarkTab === 'ablation' && (
              <div>
                <table className="table" style={{ width: '100%', fontSize: '0.85rem' }}>
                  <thead>
                    <tr>
                      <th>Cấu Hình</th>
                      <th>Mô Tả</th>
                      <th>Recall</th>
                      <th>Precision</th>
                      <th>F1-Score</th>
                      <th>FPR</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Ablation 1</td>
                      <td>Chỉ dùng luật regex cố định</td>
                      <td>75.0%</td>
                      <td>100.0%</td>
                      <td>85.71%</td>
                      <td>0.0%</td>
                    </tr>
                    <tr>
                      <td>Ablation 2</td>
                      <td>Chỉ dùng Isolation Forest không giám sát</td>
                      <td>47.0%</td>
                      <td>97.92%</td>
                      <td>63.51%</td>
                      <td>0.5%</td>
                    </tr>
                    <tr>
                      <td>Ablation 3</td>
                      <td>Hợp lực không có chuẩn hóa giải mã (No Normalizer)</td>
                      <td>86.0%</td>
                      <td>98.85%</td>
                      <td>91.98%</td>
                      <td>0.5%</td>
                    </tr>
                    <tr style={{ background: 'rgba(56, 189, 248, 0.1)' }}>
                      <td style={{ color: '#38bdf8', fontWeight: 600 }}>Ablation 4</td>
                      <td style={{ color: '#38bdf8', fontWeight: 600 }}>Hệ Thống Đầy Đủ (Chuẩn hóa + Luật + ML + Hợp lực thích ứng)</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>81.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>100.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>89.50%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>0.0%</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            {/* Tab 4: Vectors */}
            {benchmarkTab === 'vectors' && (
              <div>
                <table className="table" style={{ width: '100%', fontSize: '0.85rem' }}>
                  <thead>
                    <tr>
                      <th>Nhóm Tấn Công</th>
                      <th>Số Lượng Mẫu</th>
                      <th>Rule Hit</th>
                      <th>ML Hit</th>
                      <th>Hybrid Hit</th>
                      <th>Chặn (ENFORCE)</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><strong>SQL Injection (SQLi)</strong></td>
                      <td>25</td>
                      <td>84.0%</td>
                      <td>36.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>84.0%</td>
                      <td style={{ color: '#f87171', fontWeight: 600 }}>84.0%</td>
                    </tr>
                    <tr>
                      <td><strong>Cross-Site Scripting (XSS)</strong></td>
                      <td>25</td>
                      <td>100.0%</td>
                      <td>64.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>100.0%</td>
                      <td style={{ color: '#f87171', fontWeight: 600 }}>100.0%</td>
                    </tr>
                    <tr>
                      <td><strong>Path Traversal</strong></td>
                      <td>20</td>
                      <td>100.0%</td>
                      <td>35.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>100.0%</td>
                      <td style={{ color: '#f87171', fontWeight: 600 }}>100.0%</td>
                    </tr>
                    <tr>
                      <td><strong>Command Injection</strong></td>
                      <td>15</td>
                      <td>80.0%</td>
                      <td>26.7%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>80.0%</td>
                      <td style={{ color: '#f87171', fontWeight: 600 }}>80.0%</td>
                    </tr>
                    <tr>
                      <td><strong>Brute Force (Dò mật khẩu)</strong></td>
                      <td>15</td>
                      <td>20.0%</td>
                      <td>60.0%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>20.0%</td>
                      <td>0.0% (Rate limit)</td>
                    </tr>
                    <tr>
                      <td><strong>Benign Normal (Hợp lệ)</strong></td>
                      <td>200</td>
                      <td>0.0%</td>
                      <td>0.5%</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>0.0% (Sạch)</td>
                      <td style={{ color: '#4ade80', fontWeight: 600 }}>0.0% Chặn nhầm</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            )}

            <div style={{ marginTop: '1rem', textAlign: 'right', borderTop: '1px solid #334155', paddingTop: '0.75rem' }}>
              <button className="btn btn-secondary" onClick={() => setBenchmarkModalOpen(false)}>Đóng</button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
