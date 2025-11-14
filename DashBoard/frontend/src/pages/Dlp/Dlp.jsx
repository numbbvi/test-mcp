import React, { useState, useEffect, useRef } from 'react';
import './Dlp.css';

const Dlp = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedViolationType, setSelectedViolationType] = useState('all');
  const [violationTypes, setViolationTypes] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const [isRotating, setIsRotating] = useState(false);
  const paginationRef = useRef(pagination);

  // pagination ref 업데이트
  useEffect(() => {
    paginationRef.current = pagination;
  }, [pagination]);

  // 위반 유형 목록 가져오기
  useEffect(() => {
    const fetchViolationTypes = async () => {
      try {
        const res = await fetch('http://localhost:3001/api/dlp/violation-types');
        const data = await res.json();
        if (data.success) {
          setViolationTypes(data.data || []);
        }
      } catch (error) {
        console.error('위반 유형 목록 로드 실패:', error);
      }
    };
    fetchViolationTypes();
  }, []);

  useEffect(() => {
    setPagination(prev => ({ ...prev, page: 1 }));
  }, [searchQuery, selectedViolationType]);

  useEffect(() => {
    fetchLogs();
  }, [pagination.page]);

  // 실시간 업데이트를 위한 SSE 연결
  useEffect(() => {
    let eventSource = null;
    let reconnectTimeout = null;

    const connectSSE = () => {
      try {
        // 기존 연결이 있으면 종료
        if (eventSource) {
          eventSource.close();
        }

        eventSource = new EventSource('http://localhost:3001/api/dlp/logs/stream');

        eventSource.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            
            if (data.type === 'newLog' && data.data) {
              // 현재 페이지가 1페이지일 때만 자동으로 로그 추가
              const currentPage = paginationRef.current.page;
              
              if (currentPage === 1) {
                setLogs(prevLogs => {
                  // 중복 체크 (이미 있는 로그는 추가하지 않음)
                  const exists = prevLogs.some(log => log.id === data.data.id);
                  if (exists) return prevLogs;
                  
                  // 새로운 로그를 맨 앞에 추가
                  return [data.data, ...prevLogs].slice(0, 20);
                });
                
                // 총 개수 증가
                setPagination(prev => ({ ...prev, total: prev.total + 1 }));
              }
            }
          } catch (error) {
            console.error('SSE 메시지 파싱 오류:', error);
          }
        };

        eventSource.onerror = (error) => {
          console.error('SSE 연결 오류:', error);
          // 연결이 끊어지면 재연결 시도
          if (eventSource) {
            eventSource.close();
            eventSource = null;
          }
          // 3초 후 재연결
          reconnectTimeout = setTimeout(() => {
            connectSSE();
          }, 3000);
        };
      } catch (error) {
        console.error('SSE 연결 실패:', error);
      }
    };

    connectSSE();

    // 컴포넌트 언마운트 시 연결 종료
    return () => {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []); // 한 번만 연결


  const fetchLogs = async () => {
    try {
      setLoading(true);
      
      const queryParams = new URLSearchParams();
      queryParams.append('page', pagination.page);
      queryParams.append('limit', '20');

      const res = await fetch(`http://localhost:3001/api/dlp/logs?${queryParams}`);
      const data = await res.json();
      
      if (data.success) {
        const fetchedLogs = data.data || [];
        setLogs(fetchedLogs);
        
        setPagination(prev => ({
          ...prev,
          total: fetchedLogs.length || 0,
          totalPages: Math.ceil((fetchedLogs.length || 0) / 20) || 1
        }));
      } else {
        setLogs([]);
        setPagination(prev => ({
          ...prev,
          total: 0,
          totalPages: 1
        }));
      }
      
    } catch (error) {
      console.error('DLP 로그 조회 실패:', error);
      setLogs([]);
      setPagination(prev => ({
        ...prev,
        total: 0,
        totalPages: 1
      }));
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return '-';
    // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
    const match = dateString.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (match) {
      const [, year, month, day, hours, minutes, seconds] = match;
      return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }
    return dateString;
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      default: return 'severity-medium';
    }
  };

  const getSeverityText = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'high': return '높음';
      case 'medium': return '중간';
      case 'low': return '낮음';
      default: return severity || '알 수 없음';
    }
  };

  const getViolationTypeText = (type) => {
    const types = {
      'personal_info': '개인정보',
      'financial_info': '금융정보',
      'system_info': '시스템정보',
      'auth_info': '인증정보',
      'data_transmission': '데이터 전송'
    };
    return types[type] || type || '알 수 없음';
  };

  const handleSort = (column) => {
    if (sortColumn === column) {
      if (sortDirection === 'desc') {
        setSortDirection('asc');
      } else if (sortDirection === 'asc') {
        // 정렬 해제
        setSortColumn(null);
        setSortDirection(null);
      }
    } else {
      setSortColumn(column);
      setSortDirection('desc');
    }
  };

  // 검색 및 위반 유형 필터링
  const filteredLogs = logs.filter(log => {
    // 검색어 필터링
    if (searchQuery) {
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch = (
        (log.username && log.username.toLowerCase().includes(searchLower)) ||
        (log.employee_id && log.employee_id.toLowerCase().includes(searchLower)) ||
        (log.source_ip && log.source_ip.toLowerCase().includes(searchLower)) ||
        (log.violation_type && log.violation_type.toLowerCase().includes(searchLower))
      );
      if (!matchesSearch) return false;
    }
    
    // 위반 유형 필터링
    if (selectedViolationType && selectedViolationType !== 'all') {
      if (log.violation_type !== selectedViolationType) return false;
    }
    
    return true;
  });

  const sortedLogs = sortColumn && sortDirection ? [...filteredLogs].sort((a, b) => {
    let aValue = a[sortColumn];
    let bValue = b[sortColumn];

    // 날짜/시간 정렬
    if (sortColumn === 'timestamp') {
      if (!aValue && !bValue) return 0;
      if (!aValue) return 1;
      if (!bValue) return -1;
      
      // Date 객체로 변환하여 비교
      const dateA = new Date(aValue.replace(' ', 'T'));
      const dateB = new Date(bValue.replace(' ', 'T'));
      
      if (sortDirection === 'desc') {
        // 내림차순: 최신이 위 (더 큰 값이 앞)
        return dateB - dateA;
      } else {
        // 오름차순: 오래된 것이 위 (더 작은 값이 앞)
        return dateA - dateB;
      }
    }

    // 심각도 정렬 (high > medium > low)
    if (sortColumn === 'severity') {
      const severityOrder = { 'high': 3, 'medium': 2, 'low': 1 };
      aValue = severityOrder[aValue?.toLowerCase()] || 0;
      bValue = severityOrder[bValue?.toLowerCase()] || 0;
      return sortDirection === 'asc' ? aValue - bValue : bValue - aValue;
    }

    // 문자열 정렬
    aValue = (aValue || '').toString().toLowerCase();
    bValue = (bValue || '').toString().toLowerCase();
    
    if (sortDirection === 'asc') {
      return aValue.localeCompare(bValue);
    } else {
      return bValue.localeCompare(aValue);
    }
  }) : filteredLogs;

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

  const handleViewDetail = async (log) => {
    // 사용자 정보 가져오기 (IP로 조회)
    let userInfo = null;
    if (log.source_ip) {
      try {
        // IP 매핑 테이블에서 조회
        const mappingRes = await fetch(`http://localhost:3001/api/ip-mappings/${log.source_ip}`);
        if (mappingRes.ok) {
          const mappingData = await mappingRes.json();
          if (mappingData.success && mappingData.data) {
            userInfo = {
              username: mappingData.data.username,
              employee_id: mappingData.data.employee_id
            };
          }
        }
      } catch (error) {
        console.error('IP 매핑 조회 실패:', error);
      }

      // 매핑이 없으면 사용자 테이블에서 직접 IP로 조회 시도
      if (!userInfo) {
        try {
          const userRes = await fetch(`http://localhost:3001/api/users?ip=${log.source_ip}`);
          const userData = await userRes.json();
          if (userData.success && userData.data && userData.data.length > 0) {
            const user = userData.data[0];
            userInfo = {
              username: user.username,
              employee_id: user.employee_id
            };
          }
        } catch (error) {
          console.error('사용자 조회 실패:', error);
        }
      }
    }

    // 로그에 이미 사용자 정보가 있으면 그것을 사용
    if (!userInfo && log.username) {
      userInfo = {
        username: log.username,
        employee_id: log.employee_id
      };
    }

    setSelectedLog({
      ...log,
      userInfo
    });
  };

  const handleCloseDetail = () => {
    setSelectedLog(null);
  };

  // ESC 키로 상세보기 닫기
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
    return <div className="dlp-loading">로딩 중...</div>;
  }

  return (
    <div className="dlp-container">
      <div className="dlp-left">
    <section className="dlp-page">
          <div className="dlp-header">
      <h1>DLP Violation Logs</h1>
      </div>

      <div className="dlp-controls">
        <div className="search-and-filter-container">
          <div className="search-container">
            <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
              <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            <input
              type="text"
              className="search-input"
              placeholder="Search users"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <select
            className="violation-type-dropdown"
            value={selectedViolationType}
            onChange={(e) => setSelectedViolationType(e.target.value)}
          >
            <option value="all">전체 위반 유형</option>
            {violationTypes.map(vt => (
              <option key={vt.type} value={vt.type}>
                {vt.type}
              </option>
            ))}
          </select>
        </div>
        <button 
          onClick={() => {
            setIsRotating(true);
            fetchLogs();
          }} 
          className="btn-refresh" 
          title="새로고침"
        >
          <svg 
            className={`refresh-icon ${isRotating ? 'rotating' : ''}`}
            onAnimationEnd={() => setIsRotating(false)}
            width="20" 
            height="20" 
            viewBox="0 0 24 24" 
            fill="none" 
            xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M1 4V10H7" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M23 20V14H17" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10M23 14L18.36 18.36A9 9 0 0 1 3.51 15" stroke="#003153" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
      </div>

      <div className="dlp-logs-container">
        <div className="dlp-table-wrapper">
          <table className="dlp-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('timestamp')}>
                  탐지 시간
                  {getSortIcon('timestamp')}
                </th>
                <th>사용자</th>
                <th>위반 유형</th>
                <th className="sortable" onClick={() => handleSort('severity')}>
                  심각도
                  {getSortIcon('severity')}
                </th>
                <th>내용</th>
                <th>작업</th>
              </tr>
            </thead>
            <tbody>
              {sortedLogs.length === 0 ? (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                    데이터가 없습니다.
                  </td>
                </tr>
              ) : (
                sortedLogs.map((log) => (
                  <tr 
                    key={log.id}
                        className={`dlp-table-row ${selectedLog?.id === log.id ? 'selected' : ''}`}
                    onClick={() => handleViewDetail(log)}
                  >
                    <td>{formatDate(log.timestamp)}</td>
                    <td>{log.username || log.employee_id || log.source_ip || '-'}</td>
                    <td>{getViolationTypeText(log.violation_type)}</td>
                    <td>
                      <span className={`severity-badge ${getSeverityBadgeClass(log.severity)}`}>
                        {getSeverityText(log.severity)}
                      </span>
                    </td>
                    <td className="content-cell">
                      {log.original_text ? (
                        <span className="content-preview">
                          {log.original_text.substring(0, 50)}{log.original_text.length > 50 ? '...' : ''}
                        </span>
                      ) : '-'}
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
        </section>
      </div>

      {selectedLog && (
        <div className={`dlp-detail-drawer is-open`}>
          <div 
            className="dlp-detail-drawer__backdrop"
            onClick={handleCloseDetail}
          />
          <aside className="dlp-detail-drawer__panel" role="dialog" aria-modal="true">
            <header className="dlp-detail-drawer__header">
              <div>
                <p className="dlp-detail-drawer__eyebrow">DLP Violation</p>
                <h2 className="dlp-detail-drawer__title">DLP 위반 상세 정보</h2>
              </div>
              <button 
                type="button" 
                className="dlp-detail-drawer__close"
                onClick={handleCloseDetail}
                aria-label="Close details"
              >
                &times;
              </button>
            </header>
            <div className="dlp-detail-drawer__content">
              <section className="dlp-detail-drawer__section">
                <h3>기본 정보</h3>
                <div className="dlp-detail-drawer__info-grid">
                  <div className="dlp-detail-drawer__info-item">
                    <span className="dlp-detail-drawer__info-label">위반 ID</span>
                    <span className="dlp-detail-drawer__info-value">{selectedLog.id}</span>
                  </div>
                  <div className="dlp-detail-drawer__info-item">
                    <span className="dlp-detail-drawer__info-label">위반 유형</span>
                    <span className="dlp-detail-drawer__info-value">{getViolationTypeText(selectedLog.violation_type)}</span>
                  </div>
                  <div className="dlp-detail-drawer__info-item">
                    <span className="dlp-detail-drawer__info-label">심각도</span>
                    <span className="dlp-detail-drawer__info-value">
                      <span className={`severity-badge ${getSeverityBadgeClass(selectedLog.severity)}`}>
                        {getSeverityText(selectedLog.severity)}
                      </span>
                    </span>
                  </div>
                  <div className="dlp-detail-drawer__info-item">
                    <span className="dlp-detail-drawer__info-label">탐지 시간</span>
                    <span className="dlp-detail-drawer__info-value">{formatDate(selectedLog.timestamp)}</span>
                  </div>
                  <div className="dlp-detail-drawer__info-item">
                    <span className="dlp-detail-drawer__info-label">IP 주소</span>
                    <span className="dlp-detail-drawer__info-value">{selectedLog.source_ip || '-'}</span>
                  </div>
                  <div className="dlp-detail-drawer__info-item">
                    <span className="dlp-detail-drawer__info-label">액션 타입</span>
                    <span className="dlp-detail-drawer__info-value">{selectedLog.action_type || '-'}</span>
                  </div>
                </div>
              </section>

              <section className="dlp-detail-drawer__section">
                <h3>사용자 정보</h3>
                <div className="dlp-detail-drawer__info-grid">
                  {selectedLog.userInfo ? (
                    <>
                      <div className="dlp-detail-drawer__info-item">
                        <span className="dlp-detail-drawer__info-label">사용자명</span>
                        <span className="dlp-detail-drawer__info-value">{selectedLog.userInfo.username || '-'}</span>
                      </div>
                      <div className="dlp-detail-drawer__info-item">
                        <span className="dlp-detail-drawer__info-label">사원번호</span>
                        <span className="dlp-detail-drawer__info-value">{selectedLog.userInfo.employee_id || '-'}</span>
                      </div>
                    </>
                  ) : selectedLog.username ? (
                    <>
                      <div className="dlp-detail-drawer__info-item">
                        <span className="dlp-detail-drawer__info-label">사용자명</span>
                        <span className="dlp-detail-drawer__info-value">{selectedLog.username}</span>
                      </div>
                      <div className="dlp-detail-drawer__info-item">
                        <span className="dlp-detail-drawer__info-label">사원번호</span>
                        <span className="dlp-detail-drawer__info-value">{selectedLog.employee_id || '-'}</span>
                      </div>
                    </>
                  ) : (
                    <div className="dlp-detail-drawer__info-item" style={{ gridColumn: '1 / -1' }}>
                      <span className="dlp-detail-drawer__info-label">사용자 정보</span>
                      <span className="dlp-detail-drawer__info-value">IP 주소로 조회된 사용자 정보가 없습니다.</span>
                    </div>
                  )}
                </div>
              </section>

              {selectedLog.original_text && (
                <section className="dlp-detail-drawer__section">
                  <h3>Original Text</h3>
                  <div className="dlp-detail-drawer__code-box">
                    <pre>{selectedLog.original_text}</pre>
                  </div>
                </section>
              )}

              {selectedLog.masked_text && (
                <section className="dlp-detail-drawer__section">
                  <h3>Masked Text</h3>
                  <div className="dlp-detail-drawer__code-box">
                    <pre>{selectedLog.masked_text}</pre>
                  </div>
                </section>
              )}

              {selectedLog.original_json && (
                <section className="dlp-detail-drawer__section">
                  <h3>Original JSON</h3>
                  <div className="dlp-detail-drawer__code-box">
                    <pre>{(() => {
                      try {
                        // 문자열인 경우 파싱 시도
                        if (typeof selectedLog.original_json === 'string') {
                          const parsed = JSON.parse(selectedLog.original_json);
                          return JSON.stringify(parsed, null, 2);
                        }
                        // 이미 객체인 경우
                        return JSON.stringify(selectedLog.original_json, null, 2);
                      } catch (error) {
                        // 파싱 실패 시 원본 그대로 표시
                        return selectedLog.original_json;
                      }
                    })()}</pre>
                  </div>
                </section>
              )}
            </div>
          </aside>
        </div>
      )}
    </div>
  );
};

export default Dlp;