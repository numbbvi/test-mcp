import React, { useState, useEffect, useRef } from 'react';
import Pagination from '../../components/Pagination';
import { apiGet, apiPut } from '../../utils/api';
import './PermissionViolation.css';

const PermissionViolation = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const paginationRef = useRef(pagination);

  useEffect(() => {
    paginationRef.current = pagination;
  }, [pagination]);

  useEffect(() => {
    fetchLogs();
  }, [pagination.page]);

  // 실시간 업데이트를 위한 폴링
  useEffect(() => {
    let intervalId = null;
    let latestId = 0;

    const checkForUpdates = async () => {
      try {
        const data = await apiGet('/permission-violation/logs/latest');
        if (data.success && data.latestId > latestId) {
          latestId = data.latestId;
          // 현재 페이지가 1페이지일 때만 자동으로 로그 새로고침
          if (paginationRef.current.page === 1) {
            fetchLogs(true); // silent 모드로 새로고침
          }
        }
      } catch (error) {
        console.error('최신 로그 확인 실패:', error);
      }
    };

    // 3초마다 확인
    intervalId = setInterval(checkForUpdates, 3000);

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, []);

  const fetchLogs = async (silent = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }
      
      const queryParams = new URLSearchParams();
      queryParams.append('page', pagination.page);
      queryParams.append('limit', '20');

      const data = await apiGet(`/permission-violation/logs?${queryParams}`);
      
      if (data.success) {
        const fetchedLogs = data.data || [];
        setLogs(fetchedLogs);
        
        if (data.pagination) {
          setPagination(prev => ({
            ...prev,
            ...data.pagination
          }));
        }
      } else {
        setLogs([]);
        setPagination(prev => ({
          ...prev,
          total: 0,
          totalPages: 1
        }));
      }
      
    } catch (error) {
      console.error('권한 위반 로그 조회 실패:', error);
      setLogs([]);
      setPagination(prev => ({
        ...prev,
        total: 0,
        totalPages: 1
      }));
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    try {
      const date = new Date(dateString.replace(' ', 'T'));
      return date.toLocaleString('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch (error) {
      return dateString;
    }
  };

  const getViolationTypeText = (type) => {
    const types = {
      'unauthorized_access': '무단 접근',
      'team_restriction': '팀 제한',
      'tool_restriction': 'Tool 제한',
      'server_restriction': '서버 제한'
    };
    return types[type] || type;
  };

  const getSeverityText = (severity) => {
    const severities = {
      'high': '높음',
      'medium': '보통',
      'low': '낮음'
    };
    return severities[severity] || severity;
  };

  const getSeverityBadgeClass = (severity) => {
    return `severity-${severity?.toLowerCase() || 'medium'}`;
  };

  const getStatusText = (status) => {
    const statuses = {
      'pending': '대기',
      'resolved': '해결됨',
      'ignored': '무시됨'
    };
    return statuses[status] || status;
  };

  const getStatusBadgeClass = (status) => {
    return `status-${status?.toLowerCase() || 'pending'}`;
  };

  const handleSort = (column) => {
    if (sortColumn === column) {
      if (sortDirection === 'desc') {
        setSortDirection('asc');
      } else if (sortDirection === 'asc') {
        setSortColumn(null);
        setSortDirection(null);
      }
    } else {
      setSortColumn(column);
      setSortDirection('desc');
    }
  };

  const sortedLogs = sortColumn && sortDirection ? [...logs].sort((a, b) => {
    let aValue = a[sortColumn];
    let bValue = b[sortColumn];

    if (sortColumn === 'timestamp') {
      if (!aValue && !bValue) return 0;
      if (!aValue) return 1;
      if (!bValue) return -1;
      
      const dateA = new Date(aValue.replace(' ', 'T'));
      const dateB = new Date(bValue.replace(' ', 'T'));
      
      return sortDirection === 'desc' ? dateB - dateA : dateA - dateB;
    }

    if (sortColumn === 'severity') {
      const severityOrder = { 'high': 3, 'medium': 2, 'low': 1 };
      aValue = severityOrder[aValue?.toLowerCase()] || 0;
      bValue = severityOrder[bValue?.toLowerCase()] || 0;
      return sortDirection === 'asc' ? aValue - bValue : bValue - aValue;
    }

    aValue = (aValue || '').toString().toLowerCase();
    bValue = (bValue || '').toString().toLowerCase();
    
    return sortDirection === 'asc' 
      ? aValue.localeCompare(bValue)
      : bValue.localeCompare(aValue);
  }) : logs;

  const getSortIcon = (column) => {
    if (sortColumn !== column || !sortDirection) {
      return (
        <span className="sort-icon">
          <svg width="16" height="16" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M6 2L3 5H9L6 2Z" fill="#999"/>
            <path d="M6 10L9 7H3L6 10Z" fill="#999"/>
          </svg>
        </span>
      );
    }
    return (
      <span className="sort-icon active">
        {sortDirection === 'asc' ? (
          <svg width="16" height="16" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M6 2L3 5H9L6 2Z" fill="#666"/>
          </svg>
        ) : (
          <svg width="16" height="16" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M6 10L9 7H3L6 10Z" fill="#666"/>
          </svg>
        )}
      </span>
    );
  };

  const handleViewDetail = (log) => {
    setSelectedLog(log);
  };

  const handleCloseDetail = () => {
    setSelectedLog(null);
  };

  const handleUpdateStatus = async (status, notes = '') => {
    if (!selectedLog) return;

    try {
      await apiPut(`/permission-violation/logs/${selectedLog.id}/status`, {
        status,
        notes
      });
      
      alert('상태가 업데이트되었습니다.');
      fetchLogs();
      handleCloseDetail();
    } catch (error) {
      console.error('상태 업데이트 실패:', error);
      alert('상태 업데이트 중 오류가 발생했습니다.');
    }
  };

  useEffect(() => {
    if (!selectedLog) return;

    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        handleCloseDetail();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [selectedLog]);

  if (loading) {
    return <div className="permission-violation-loading">로딩 중...</div>;
  }

  return (
    <div className="permission-violation-container">
      <div className="permission-violation-left">
        <section className="permission-violation-page">
          <div className="permission-violation-header">
            <h1>권한 위반 로그</h1>
            <button onClick={() => fetchLogs()} className="btn-refresh">
              새로고침
            </button>
          </div>

          <div className="permission-violation-logs-container">
            <div className="permission-violation-table-wrapper">
              <table className="permission-violation-table">
                <thead>
                  <tr>
                    <th className="sortable" onClick={() => handleSort('timestamp')}>
                      탐지 시간
                      {getSortIcon('timestamp')}
                    </th>
                    <th>사용자</th>
                    <th>MCP 서버</th>
                    <th>Tool</th>
                    <th>위반 유형</th>
                    <th>심각도</th>
                    <th>상태</th>
                    <th>작업</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedLogs.length === 0 ? (
                    <tr>
                      <td colSpan="8" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                        데이터가 없습니다.
                      </td>
                    </tr>
                  ) : (
                    sortedLogs.map((log) => (
                      <tr 
                        key={log.id}
                        className={`permission-violation-table-row ${selectedLog?.id === log.id ? 'selected' : ''}`}
                        onClick={() => handleViewDetail(log)}
                      >
                        <td>{formatDate(log.timestamp)}</td>
                        <td>{log.username || log.employee_id || log.source_ip || '-'}</td>
                        <td>{log.mcp_server_name || '-'}</td>
                        <td>{log.tool_name || '-'}</td>
                        <td>{getViolationTypeText(log.violation_type)}</td>
                        <td>
                          <span className={`severity-badge ${getSeverityBadgeClass(log.severity)}`}>
                            {getSeverityText(log.severity)}
                          </span>
                        </td>
                        <td>
                          <span className={`status-badge ${getStatusBadgeClass(log.status)}`}>
                            {getStatusText(log.status)}
                          </span>
                        </td>
                        <td>
                          <button 
                            className="btn-view-detail"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleViewDetail(log);
                            }}
                          >
                            상세보기
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <Pagination
            currentPage={pagination.page}
            totalPages={pagination.totalPages}
            onPageChange={(page) => setPagination(prev => ({ ...prev, page }))}
          />
        </section>
      </div>

      {selectedLog && (
        <div className="permission-violation-right">
          <div className="permission-violation-detail-content">
            <div className="permission-violation-detail-header">
              <div className="permission-violation-detail-title">
                <h2>권한 위반 상세 정보</h2>
              </div>
              <button className="btn-close" onClick={handleCloseDetail}>×</button>
            </div>
            <div className="permission-violation-detail-body">
              <div className="detail-section">
                <h3>기본 정보</h3>
                <div className="detail-item">
                  <span className="detail-label">탐지 시간:</span>
                  <span className="detail-value">{formatDate(selectedLog.timestamp)}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">사용자:</span>
                  <span className="detail-value">{selectedLog.username || selectedLog.employee_id || selectedLog.source_ip || '-'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">사원번호:</span>
                  <span className="detail-value">{selectedLog.employee_id || '-'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">IP 주소:</span>
                  <span className="detail-value">{selectedLog.source_ip || '-'}</span>
                </div>
              </div>

              <div className="detail-section">
                <h3>위반 정보</h3>
                <div className="detail-item">
                  <span className="detail-label">MCP 서버:</span>
                  <span className="detail-value">{selectedLog.mcp_server_name || '-'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Tool:</span>
                  <span className="detail-value">{selectedLog.tool_name || '-'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">위반 유형:</span>
                  <span className="detail-value">{getViolationTypeText(selectedLog.violation_type)}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">심각도:</span>
                  <span className="detail-value">
                    <span className={`severity-badge ${getSeverityBadgeClass(selectedLog.severity)}`}>
                      {getSeverityText(selectedLog.severity)}
                    </span>
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">사유:</span>
                  <span className="detail-value">{selectedLog.reason || '-'}</span>
                </div>
              </div>

              <div className="detail-section">
                <h3>처리 정보</h3>
                <div className="detail-item">
                  <span className="detail-label">상태:</span>
                  <span className="detail-value">
                    <span className={`status-badge ${getStatusBadgeClass(selectedLog.status)}`}>
                      {getStatusText(selectedLog.status)}
                    </span>
                  </span>
                </div>
                {selectedLog.notes && (
                  <div className="detail-item">
                    <span className="detail-label">메모:</span>
                    <span className="detail-value">{selectedLog.notes}</span>
                  </div>
                )}
              </div>

              <div className="detail-actions">
                <button 
                  className="btn-action resolved"
                  onClick={() => handleUpdateStatus('resolved')}
                >
                  해결됨
                </button>
                <button 
                  className="btn-action ignored"
                  onClick={() => handleUpdateStatus('ignored')}
                >
                  무시
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PermissionViolation;

