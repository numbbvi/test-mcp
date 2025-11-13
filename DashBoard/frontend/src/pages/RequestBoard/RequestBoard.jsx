import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Pagination from '../../components/Pagination';
import './RequestBoard.css';

const RequestBoard = () => {
  const navigate = useNavigate();
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [filter, setFilter] = useState('all'); // all, pending, approved, rejected
  const [reviewForm, setReviewForm] = useState({ status: '', comment: '', server_description: '', allowed_teams: [], tools: [] });
  const [user, setUser] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [scannedTools, setScannedTools] = useState([]);
  const [scanningTools, setScanningTools] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [analyzingRisk, setAnalyzingRisk] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState({ bomtori: 0, scanner: 0 });
  const [riskAnalysisResult, setRiskAnalysisResult] = useState(null);
  const [analysisCompleted, setAnalysisCompleted] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [detailPanelWidth, setDetailPanelWidth] = useState(600);
  const [isResizing, setIsResizing] = useState(false);
  const detailPanelRef = useRef(null);

  useEffect(() => {
    // 로그인한 사용자 정보 가져오기
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  useEffect(() => {
    setPagination(prev => ({ ...prev, page: 1 }));
  }, [filter]);

  useEffect(() => {
    fetchRequests();
  }, [filter, pagination.page]);

  // ESC 키로 상세보기 닫기
  useEffect(() => {
    if (!selectedRequest) return;

    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        handleCloseDetail();
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [selectedRequest]);

  // Resize 기능
  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e) => {
      if (!isResizing) return;
      const newWidth = window.innerWidth - e.clientX;
      const minWidth = 400;
      const maxWidth = window.innerWidth * 0.9;
      if (newWidth >= minWidth && newWidth <= maxWidth) {
        setDetailPanelWidth(newWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isResizing]);

  const handleResizeStart = (e) => {
    e.preventDefault();
    setIsResizing(true);
  };

  const fetchRequests = async () => {
    try {
      setLoading(true);
      
      const queryParams = new URLSearchParams();
      if (filter !== 'all') {
        queryParams.append('status', filter);
      }
      queryParams.append('page', pagination.page);
      queryParams.append('limit', '20');
      
      // JWT 토큰 가져오기
      const token = localStorage.getItem('token');
      const headers = {
        'Content-Type': 'application/json'
      };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`http://localhost:3001/api/marketplace/requests?${queryParams}`, {
        headers
      });
      const data = await res.json();
      
      if (data.success) {
        setRequests(data.data || []);
        setPagination(prev => ({
          ...prev,
          total: data.pagination?.total || 0,
          totalPages: data.pagination?.totalPages || 1
        }));
      } else {
        setRequests([]);
        setPagination(prev => ({
          ...prev,
          total: 0,
          totalPages: 1
        }));
      }
      
    } catch (error) {
      console.error('등록 요청 목록 로드 실패:', error);
      setRequests([]);
    } finally {
      setLoading(false);
    }
  };

  const handleViewDetail = async (request) => {
    setSelectedRequest(request);
    setReviewForm({ status: '', comment: '', server_description: request.description || '', allowed_teams: [], tools: [] });
    setScannedTools([]);
    setScanResult(null);
    setAnalyzingRisk(false);
    setAnalysisProgress(0);
    setRiskAnalysisResult(null);
    setAnalysisCompleted(false);

    // scanned가 1이면 분석 결과를 불러옴
    if (request.scanned === 1) {
      const scanPath = request.github_link || request.file_path;
      if (scanPath) {
        try {
          const token = localStorage.getItem('token');
          
          // Code 취약점 확인
          const codeRes = await fetch(`http://localhost:3001/api/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}`, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          const codeData = await codeRes.json();
          
          // OSS 취약점 확인
          let ossVulns = 0;
          let scanId = null;
          
          if (codeData.success && codeData.data && codeData.data.length > 0) {
            scanId = codeData.data[0]?.scan_id || null;
            const codeVulns = codeData.data.length;
            
            // OSS 취약점도 확인
            if (scanId) {
              try {
                const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
                  headers: {
                    'Authorization': `Bearer ${token}`
                  }
                });
                const ossData = await ossRes.json();
                if (ossData.success && ossData.data) {
                  ossVulns = ossData.data.length || 0;
                }
              } catch (ossError) {
                console.error('OSS 취약점 조회 실패:', ossError);
              }
            }
            
            // 스캔 결과가 있으면
            setRiskAnalysisResult({
              ossVulnerabilities: ossVulns,
              codeVulnerabilities: codeVulns,
              toolVulnerabilities: 0,
              scanId: scanId
            });
            setAnalysisCompleted(true);
          } else {
            // 스캔 결과가 없으면 (데이터가 없을 수도 있음)
            setRiskAnalysisResult({
              ossVulnerabilities: 0,
              codeVulnerabilities: 0,
              toolVulnerabilities: 0,
              scanId: null
            });
            setAnalysisCompleted(true);
          }
        } catch (error) {
          console.error('스캔 결과 조회 실패:', error);
          // 조회 실패 시에도 스캔 완료로 표시 (scanned === 1이므로)
          setRiskAnalysisResult({
            ossVulnerabilities: 0,
            codeVulnerabilities: 0,
            toolVulnerabilities: 0,
            scanId: null
          });
          setAnalysisCompleted(true);
        }
      }
    }
  };

  const handleRunAnalysis = async () => {
    if (!selectedRequest?.github_link && !selectedRequest?.file_path) {
      alert('GitHub 링크 또는 파일 경로가 필요합니다.');
      return;
    }

    setAnalyzingRisk(true);
    setAnalysisProgress({ bomtori: 0, scanner: 0 });
    setRiskAnalysisResult(null);
    setAnalysisCompleted(false);
    setAnalysisError(null);

    try {
      const token = localStorage.getItem('token');
      
      // 스캔 시작
      const res = await fetch('http://localhost:3001/api/risk-assessment/scan-code', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          github_url: selectedRequest.github_link || null,
          repository_path: selectedRequest.file_path || null,
          mcp_server_name: selectedRequest.name
        })
      });

      const data = await res.json();
      
      if (!data.success || !data.scan_id) {
        setAnalysisError(data.message || '스캔 시작 실패');
        setAnalyzingRisk(false);
        setAnalysisProgress({ bomtori: 0, scanner: 0 });
        return;
      }
      
      const scanId = data.scan_id;
      
      // 진행률 폴링
      const pollProgress = async () => {
        while (true) {
          try {
            const progressRes = await fetch(`http://localhost:3001/api/risk-assessment/scan-progress?scan_id=${scanId}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
            
            if (progressRes.ok) {
              const progressData = await progressRes.json();
              if (progressData.success && progressData.data) {
                const progress = progressData.data;
                
                // 진행률 업데이트 (오류가 있어도 진행률은 업데이트)
                setAnalysisProgress({
                  bomtori: progress.bomtori !== null ? progress.bomtori : 0,
                  scanner: progress.scanner || 0
                });
                
                // 개별 스캐너 오류 확인
                const errorMessages = [];
                if (progress.bomtoriError) {
                  errorMessages.push(progress.bomtoriError);
                }
                if (progress.scannerError) {
                  errorMessages.push(progress.scannerError);
                }
                
                // 오류 발생 확인 (status가 'failed'이거나 개별 오류가 있으면)
                if (progress.status === 'failed' || errorMessages.length > 0) {
                  const errorMessage = progress.error || errorMessages.join(' / ') || '스캔 중 오류가 발생했습니다.';
                  setAnalysisError(errorMessage);
                  setAnalyzingRisk(false);
                  // 진행률은 유지하되 오류 메시지 표시
                  break;
                }
                
                // 둘 다 완료되었는지 확인
                if (progress.status === 'completed') {
                  // 완료 후 취약점 개수 조회
                  try {
                    const vulnRes = await fetch(`http://localhost:3001/api/risk-assessment/code-vulnerabilities?scan_id=${scanId}`, {
                      headers: {
                        'Authorization': `Bearer ${token}`
                      }
                    });
                    const vulnData = await vulnRes.json();
                    
                    const codeVulns = vulnData.success ? (vulnData.data?.length || 0) : 0;
                    
                    // OSS 취약점 개수 조회
                    try {
                      const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
                        headers: {
                          'Authorization': `Bearer ${token}`
                        }
                      });
                      const ossData = await ossRes.json();
                      const ossVulns = ossData.success ? (ossData.data?.length || 0) : 0;
                      
                      setRiskAnalysisResult({
                        ossVulnerabilities: ossVulns,
                        codeVulnerabilities: codeVulns,
                        toolVulnerabilities: 0,
                        scanId: scanId
                      });
                    } catch (error) {
                      console.error('OSS 취약점 개수 조회 실패:', error);
                      setRiskAnalysisResult({
                        ossVulnerabilities: 0,
                        codeVulnerabilities: codeVulns,
                        toolVulnerabilities: 0,
                        scanId: scanId
                      });
                    }
                    
                    setAnalysisCompleted(true);
                    setAnalyzingRisk(false);
                    
                    // 스캔 완료 후 요청 목록을 다시 불러와서 scanned 필드 업데이트
                    fetchRequests();
                    // 현재 선택된 요청도 업데이트
                    if (selectedRequest) {
                      const updatedRequest = { ...selectedRequest, scanned: 1 };
                      setSelectedRequest(updatedRequest);
                    }
                    break;
                  } catch (error) {
                    console.error('취약점 개수 조회 실패:', error);
                    setRiskAnalysisResult({
                      ossVulnerabilities: 0,
                      codeVulnerabilities: 0,
                      toolVulnerabilities: 0,
                      scanId: scanId
                    });
                    setAnalysisCompleted(true);
                    setAnalyzingRisk(false);
                    break;
                  }
                }
              }
            }
          } catch (error) {
            console.error('진행률 조회 오류:', error);
          }
          
          await new Promise(resolve => setTimeout(resolve, 1000)); // 1초마다 폴링
        }
      };
      
      // 진행률 폴링 시작
      pollProgress();
    } catch (error) {
      console.error('분석 오류:', error);
      setAnalysisError('분석 중 오류가 발생했습니다: ' + (error.message || '알 수 없는 오류'));
      setAnalyzingRisk(false);
      setAnalysisProgress({ bomtori: 0, scanner: 0 });
    }
  };

  const handleViewRiskDetail = () => {
    if (!riskAnalysisResult?.scanId) return;
    
    // Risk Assessment result 페이지로 이동
    localStorage.setItem('riskAssessmentScanId', riskAnalysisResult.scanId);
    localStorage.setItem('riskAssessmentGithubUrl', selectedRequest.github_link);
    localStorage.setItem('riskAssessmentServerName', selectedRequest.name);
    
    // Risk Assessment 페이지로 이동
    navigate('/risk-assessment');
  };
  
  const handleScanTools = async () => {
    // Sandbox 스캔만 사용
    setShowScanModal(true);
    setScanningTools(true);
    setScanResult(null);
    
    try {
      if (!selectedRequest?.github_link) {
        alert('GitHub 링크가 필요합니다.');
        setScanningTools(false);
        setShowScanModal(false);
        return;
      }
      
      const url = `http://localhost:3001/api/marketplace/scan-tools?request_id=${selectedRequest.id}&use_sandbox=true`;
      
      const res = await fetch(url);
      const data = await res.json();
      
      if (data.success) {
        setScanResult({
          ...data.data,
          method: data.data.method || 'unknown'
        });
        if (data.data.tools.length > 0) {
          const tools = data.data.tools.map(toolName => ({
            name: toolName,
            allowed_teams: []
          }));
          setScannedTools(tools);
          setReviewForm(prev => ({ ...prev, tools: tools }));
        }
      } else {
        setScanResult({
          tools: [],
          files: [],
          repository: null,
          branch: null,
          method: 'none',
          error: data.message || '스캔 실패'
        });
      }
    } catch (error) {
      console.error('Tool 스캔 오류:', error);
      setScanResult({
        tools: [],
        files: [],
        repository: null,
        branch: null,
        method: 'none',
        error: '스캔 중 오류가 발생했습니다.'
      });
    } finally {
      setScanningTools(false);
    }
  };
  
  const handleCloseScanModal = () => {
    setShowScanModal(false);
    setScanResult(null);
  };
  
  const handleApplyScanResults = () => {
    if (scanResult && scanResult.tools.length > 0) {
      const tools = scanResult.tools.map(toolName => ({
        name: toolName,
        allowed_teams: []
      }));
      setScannedTools(tools);
      setReviewForm(prev => ({ ...prev, tools: tools }));
      setShowScanModal(false);
    }
  };

  const handleCloseDetail = () => {
    setSelectedRequest(null);
    setReviewForm({ status: '', comment: '', server_description: '', allowed_teams: [], tools: [] });
    setScannedTools([]);
    setScanResult(null);
    setShowScanModal(false);
  };

  const handleReview = async () => {
    if (!reviewForm.status) {
      alert('승인 또는 거부를 선택해주세요.');
      return;
    }

    // 승인 시 서버 설명 필수 확인
    if (reviewForm.status === 'approved' && !reviewForm.server_description.trim()) {
      alert('승인 시 서버 설명은 필수입니다.');
      return;
    }

    try {
      const res = await fetch(`http://localhost:3001/api/marketplace/requests/${selectedRequest.id}/review`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: reviewForm.status,
          review_comment: reviewForm.comment || null,
          server_description: reviewForm.server_description || null,
          allowed_teams: reviewForm.allowed_teams.length > 0 ? reviewForm.allowed_teams : null,
          tools: reviewForm.tools.length > 0 ? reviewForm.tools : null
        })
      });

      const data = await res.json();
      if (data.success) {
        alert(data.message);
        fetchRequests();
        handleCloseDetail();
      } else {
        alert(data.message || '검토 처리 중 오류가 발생했습니다.');
      }
    } catch (error) {
      console.error('검토 처리 실패:', error);
      alert('검토 처리 중 오류가 발생했습니다.');
    }
  };

        // 관리자인지 확인
        const isAdmin = user && (
          (Array.isArray(user.roles) && user.roles.includes('admin')) || 
          user.role === 'admin'
        );

        // 백엔드에서 역할별 필터링을 처리하므로 클라이언트 사이드 필터링 불필요
        let filteredRequests = requests;
        
        // 검색어 필터링
        if (searchTerm) {
          filteredRequests = filteredRequests.filter(request => 
            request.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            request.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            request.description?.toLowerCase().includes(searchTerm.toLowerCase())
          );
        }

  // 정렬 핸들러
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

  // 정렬 아이콘 렌더링
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

  // 정렬 적용
  if (sortColumn && sortDirection) {
    filteredRequests = [...filteredRequests].sort((a, b) => {
      let aValue = a[sortColumn];
      let bValue = b[sortColumn];

      // 신청 시간 정렬
      if (sortColumn === 'created_at') {
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

      // 문자열 정렬
      aValue = (aValue || '').toString().toLowerCase();
      bValue = (bValue || '').toString().toLowerCase();
      
      if (sortDirection === 'asc') {
        return aValue.localeCompare(bValue);
      } else {
        return bValue.localeCompare(aValue);
      }
    });
  }

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case 'pending': return 'status-pending';
      case 'approved': return 'status-approved';
      case 'rejected': return 'status-rejected';
      default: return '';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'pending': return '대기중';
      case 'approved': return '승인됨';
      case 'rejected': return '거부됨';
      default: return status;
    }
  };

  if (loading) {
    return <div>로딩 중...</div>;
  }

  return (
    <div className="request-board-container">
      <div className="request-board-left">
    <section className="request-board">
      <div className="board-header">
        <h1>Register Board</h1>
        <div className="request-board-tabs">
          <button 
            className={`request-board-tab ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            전체
          </button>
          <button 
            className={`request-board-tab ${filter === 'pending' ? 'active' : ''}`}
            onClick={() => setFilter('pending')}
          >
            대기중
          </button>
          <button 
            className={`request-board-tab ${filter === 'approved' ? 'active' : ''}`}
            onClick={() => setFilter('approved')}
          >
            승인됨
          </button>
          <button 
            className={`request-board-tab ${filter === 'rejected' ? 'active' : ''}`}
            onClick={() => setFilter('rejected')}
          >
            거부됨
          </button>
        </div>
      </div>

      <div className="list-page__controls">
        <div className="search-container">
          <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
            <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <input
            type="text"
            className="search-input"
            placeholder="Search Servers"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="requests-table-container">
          <table className="requests-table">
            <thead>
              <tr>
                <th>요청자</th>
                <th className="sortable" onClick={(e) => { e.stopPropagation(); handleSort('created_at'); }} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                  신청 시간
                  {getSortIcon('created_at')}
                </th>
                <th>제목</th>
                <th>상태</th>
                <th>작업</th>
              </tr>
            </thead>
            <tbody>
                {filteredRequests.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="empty-state">데이터가 없습니다.</td>
                  </tr>
                ) : (
                  filteredRequests.map(request => (
                    <tr 
                      key={request.id}
                      className={selectedRequest?.id === request.id ? 'selected' : ''}
                      onClick={() => handleViewDetail(request)}
                    >
                  <td>
                    {request.requester?.username || '알 수 없음'}
                    <br />
                    <span className="employee-id">({request.requester?.employee_id || '-'})</span>
                  </td>
                  <td>
                    {(() => {
                      if (!request.created_at) return '-';
                      // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
                      const match = request.created_at.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                      if (match) {
                        const [, year, month, day, hours, minutes, seconds] = match;
                        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                      }
                      return request.created_at;
                    })()}
                  </td>
                  <td className="request-title-cell">
                    {request.title || request.name}
                  </td>
                  <td>
                    <span className={`status-badge ${getStatusBadgeClass(request.status)}`}>
                      {getStatusText(request.status)}
                    </span>
                  </td>
                  <td>
                    <button 
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewDetail(request);
                          }}
                      className="btn-view-detail"
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

          <Pagination
            currentPage={pagination.page}
            totalPages={pagination.totalPages}
            onPageChange={(page) => setPagination(prev => ({ ...prev, page }))}
          />
        </section>
      </div>

      {selectedRequest && (
        <div 
          className={`request-board-right ${isResizing ? 'resizing' : ''}`}
          style={{ width: `${detailPanelWidth}px` }}
          ref={detailPanelRef}
        >
          <div 
            className="request-board-resize-handle"
            onMouseDown={handleResizeStart}
          />
          <div className="request-detail-content">
            <div className="request-detail-header">
              <div className="request-detail-title">
              <h2>{selectedRequest.title || selectedRequest.name}</h2>
              </div>
              <button className="btn-close" onClick={handleCloseDetail}>×</button>
            </div>
            <div className="request-detail-body">
              <div className="detail-section">
                <h3>요청 정보</h3>
                <div className="detail-item">
                  <strong>요청자:</strong> {selectedRequest.requester?.username || '알 수 없음'}
                  ({selectedRequest.requester?.employee_id || '-'})
                </div>
                <div className="detail-item">
                  <strong>팀:</strong> {selectedRequest.requester?.team || '-'}
                </div>
                <div className="detail-item">
                  <strong>직책:</strong> {selectedRequest.requester?.position || '-'}
                </div>
                <div className="detail-item">
                  <strong>요청일:</strong> {(() => {
                    if (!selectedRequest.created_at) return '-';
                    // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
                    const match = selectedRequest.created_at.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                    if (match) {
                      const [, year, month, day, hours, minutes, seconds] = match;
                      return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                    }
                    return selectedRequest.created_at;
                  })()}
                </div>
              </div>

              <div className="detail-section">
                <h3>서버 정보</h3>
                <div className="detail-item">
                  <strong>이름:</strong> {selectedRequest.name}
                </div>
                <div className="detail-item">
                  <strong>설명:</strong>
                  <p className="detail-text">{selectedRequest.description || '설명 없음'}</p>
                </div>
                {selectedRequest.connection_snippet && (
                  <div className="detail-item">
                    <strong>Connection:</strong>
                    <div className="code-box">
                      <pre><code>{selectedRequest.connection_snippet}</code></pre>
                    </div>
                  </div>
                )}
              </div>

              {selectedRequest.status === 'pending' && (
                <div className="detail-section">
                  <h3>위험도 분석</h3>
                  {/* 스캔 여부에 따라 버튼 표시 조건 변경 */}
                  {/* scanned가 0이거나 null이면 Run Analysis 버튼만 표시 */}
                  {(!selectedRequest.scanned || selectedRequest.scanned === 0) && (
                    <div style={{ marginBottom: '16px' }}>
                      {analysisError ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          <div style={{ 
                            fontSize: '0.9rem', 
                            color: '#dc2626',
                            padding: '12px',
                            backgroundColor: '#fee2e2',
                            borderRadius: '6px',
                            border: '1px solid #fecaca'
                          }}>
                            {analysisError}
                          </div>
                          <button
                            onClick={() => {
                              setAnalysisError(null);
                              handleRunAnalysis();
                            }}
                            className="btn-refresh"
                            style={{ width: '100%' }}
                          >
                            다시 시도
                          </button>
                        </div>
                      ) : (
                        <>
                          <button
                            onClick={handleRunAnalysis}
                            className="btn-refresh"
                            disabled={analyzingRisk || (!selectedRequest.github_link && !selectedRequest.file_path)}
                            style={{ width: '100%', marginBottom: '16px' }}
                          >
                            {analyzingRisk ? 'Analyzing...' : 'Run Analysis'}
                          </button>
                          {analyzingRisk && (
                        <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                          {selectedRequest.github_link && selectedRequest.github_link.includes('github.com') && (
                            <div>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '0.85rem', color: '#666' }}>
                                <span>SBOM/SCA</span>
                                <span>{typeof analysisProgress === 'object' ? `${analysisProgress.bomtori || 0}%` : '0%'}</span>
                              </div>
                              <div style={{
                                width: '100%',
                                height: '8px',
                                backgroundColor: '#e0e0e0',
                                borderRadius: '4px',
                                overflow: 'hidden'
                              }}>
                                <div style={{
                                  width: `${typeof analysisProgress === 'object' ? (analysisProgress.bomtori || 0) : 0}%`,
                                  height: '100%',
                                  backgroundColor: '#17a2b8',
                                  transition: 'width 0.3s ease'
                                }}></div>
                              </div>
                            </div>
                          )}
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '0.85rem', color: '#666' }}>
                              <span>Code Scanner</span>
                              <span>{typeof analysisProgress === 'object' ? `${analysisProgress.scanner || 0}%` : `${analysisProgress || 0}%`}</span>
                            </div>
                            <div style={{
                              width: '100%',
                              height: '8px',
                              backgroundColor: '#e0e0e0',
                              borderRadius: '4px',
                              overflow: 'hidden'
                            }}>
                              <div style={{
                                width: `${typeof analysisProgress === 'object' ? (analysisProgress.scanner || 0) : (analysisProgress || 0)}%`,
                                height: '100%',
                                backgroundColor: '#003153',
                                transition: 'width 0.3s ease'
                              }}></div>
                            </div>
                          </div>
                        </div>
                      )}
                        </>
                      )}
                    </div>
                  )}
                  {/* scanned가 1이면 분석 결과와 승인/거절 버튼 표시 */}
                  {selectedRequest.scanned === 1 && (
                    <div>
                      {riskAnalysisResult && (
                        <>
                          <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(3, 1fr)',
                            gap: '16px',
                            marginBottom: '16px'
                          }}>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#f8f9fa',
                              borderRadius: '8px',
                              textAlign: 'center'
                            }}>
                              <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '8px' }}>OSS 취약점</div>
                              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#333' }}>
                                {riskAnalysisResult.ossVulnerabilities || 0}
                              </div>
                            </div>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#f8f9fa',
                              borderRadius: '8px',
                              textAlign: 'center'
                            }}>
                              <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '8px' }}>Code 취약점</div>
                              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#333' }}>
                                {riskAnalysisResult.codeVulnerabilities || 0}
                              </div>
                            </div>
                            <div style={{
                              padding: '16px',
                              backgroundColor: '#f8f9fa',
                              borderRadius: '8px',
                              textAlign: 'center'
                            }}>
                              <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '8px' }}>Tool 취약점</div>
                              <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#333' }}>
                                {riskAnalysisResult.toolVulnerabilities || 0}
                              </div>
                            </div>
                          </div>
                          {riskAnalysisResult.scanId && (
                            <button
                              onClick={handleViewRiskDetail}
                              className="btn-refresh"
                              style={{ width: '100%', marginBottom: '24px' }}
                            >
                              상세보기
                            </button>
                          )}
                        </>
                      )}

                      {/* 분석 결과가 있을 때만 검토 폼 표시 */}
                      {isAdmin && (
                        <div className="review-form" style={{ marginTop: '24px', paddingTop: '24px', borderTop: '1px solid #ddd' }}>
                          <h3 style={{ marginBottom: '16px' }}>검토</h3>
                          <label>
                            <strong>서버 설명 (필수)</strong>
                            <textarea
                              value={reviewForm.server_description}
                              onChange={(e) => setReviewForm({ ...reviewForm, server_description: e.target.value })}
                              placeholder="Marketplace에 표시될 서버 설명을 입력하세요..."
                              rows="5"
                              required
                            />
                          </label>
                          {selectedRequest.github_link && (
                            <label style={{ marginTop: '16px' }}>
                              <strong>GitHub 링크</strong>
                              <div style={{ marginTop: '8px', padding: '12px', backgroundColor: '#f8f9fa', borderRadius: '4px' }}>
                                <a 
                                  href={selectedRequest.github_link} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  style={{ color: '#003153', textDecoration: 'none', wordBreak: 'break-all' }}
                                >
                                  {selectedRequest.github_link}
                                </a>
                              </div>
                            </label>
                          )}
                          <label style={{ marginTop: '16px' }}>
                            <strong>접근 가능 팀 선택 (선택)</strong>
                            <div className="team-checkboxes" style={{ marginTop: '8px' }}>
                              {['Developer', 'Security', 'Management', 'HR'].map(team => (
                                <label key={team} style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                                  <input
                                    type="checkbox"
                                    checked={reviewForm.allowed_teams.includes(team)}
                                    onChange={(e) => {
                                      let newAllowedTeams;
                                      if (e.target.checked) {
                                        newAllowedTeams = [...reviewForm.allowed_teams, team];
                                      } else {
                                        newAllowedTeams = reviewForm.allowed_teams.filter(t => t !== team);
                                      }
                                      
                                      // 접근 가능 팀 선택 시 모든 Tool의 allowed_teams에 자동으로 추가/제거
                                      const updatedTools = reviewForm.tools.map(tool => {
                                        if (e.target.checked) {
                                          // 체크 시: 해당 팀이 없으면 추가
                                          if (!tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: [...tool.allowed_teams, team] };
                                          }
                                        } else {
                                          // 체크 해제 시: Tool의 allowed_teams에서도 제거
                                          if (tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: tool.allowed_teams.filter(t => t !== team) };
                                          }
                                        }
                                        return tool;
                                      });
                                      
                                      // scannedTools도 동기화 (UI 표시용)
                                      const updatedScannedTools = scannedTools.map(tool => {
                                        if (e.target.checked) {
                                          if (!tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: [...tool.allowed_teams, team] };
                                          }
                                        } else {
                                          if (tool.allowed_teams.includes(team)) {
                                            return { ...tool, allowed_teams: tool.allowed_teams.filter(t => t !== team) };
                                          }
                                        }
                                        return tool;
                                      });
                                      
                                      setReviewForm({
                                        ...reviewForm,
                                        allowed_teams: newAllowedTeams,
                                        tools: updatedTools
                                      });
                                      setScannedTools(updatedScannedTools);
                                    }}
                                    style={{ marginRight: '8px' }}
                                  />
                                  <span>{team}</span>
                                </label>
                              ))}
                            </div>
                            <p style={{ marginTop: '8px', fontSize: '0.85rem', color: '#6c5d53' }}>
                              선택하지 않으면 모든 팀이 접근 가능합니다.
                            </p>
                          </label>
                          <label style={{ marginTop: '16px' }}>
                            <strong>검토 코멘트 (선택)</strong>
                            <textarea
                              value={reviewForm.comment}
                              onChange={(e) => setReviewForm({ ...reviewForm, comment: e.target.value })}
                              placeholder="검토 코멘트를 입력하세요..."
                              rows="4"
                            />
                          </label>
                          <div className="review-form-actions" style={{ marginTop: '20px', display: 'flex', gap: '12px' }}>
                            <button
                              className={`btn-review ${reviewForm.status === 'approved' ? 'btn-approve active' : 'btn-approve'}`}
                              onClick={() => {
                                if (!reviewForm.server_description.trim()) {
                                  alert('승인 시 서버 설명은 필수입니다.');
                                  return;
                                }
                                setReviewForm({ ...reviewForm, status: 'approved' });
                                handleReview();
                              }}
                              style={{ flex: 1 }}
                            >
                              승인
                            </button>
                            <button
                              className={`btn-review ${reviewForm.status === 'rejected' ? 'btn-reject active' : 'btn-reject'}`}
                              onClick={() => {
                                setReviewForm({ ...reviewForm, status: 'rejected' });
                                handleReview();
                              }}
                              style={{ flex: 1 }}
                            >
                              거부
                            </button>
                            <button 
                              onClick={handleCloseDetail} 
                              className="btn-cancel-review"
                              style={{ flex: 1 }}
                            >
                              취소
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}


              {selectedRequest.status === 'pending' && !isAdmin && (
                <div className="detail-section">
                  <h3>상태</h3>
                  <div className="detail-item">
                    <strong>현재 상태:</strong>{' '}
                    <span className={`status-badge ${getStatusBadgeClass(selectedRequest.status)}`}>
                      {getStatusText(selectedRequest.status)}
                    </span>
                    <p style={{ marginTop: '8px', color: '#6c5d53' }}>
                      검토 대기 중입니다. 관리자가 검토 후 결과를 알려드립니다.
                    </p>
                  </div>
                </div>
              )}

              {selectedRequest.status !== 'pending' && (
                <div className="detail-section">
                  <h3>검토 결과</h3>
                  <div className="detail-item">
                    <strong>상태:</strong>{' '}
                    <span className={`status-badge ${getStatusBadgeClass(selectedRequest.status)}`}>
                      {getStatusText(selectedRequest.status)}
                    </span>
                  </div>
                  {selectedRequest.reviewer && (
                    <div className="detail-item">
                      <strong>검토자:</strong> {selectedRequest.reviewer?.username || '알 수 없음'}
                      {selectedRequest.reviewed_at && (
                        <span className="review-date">
                          ({(() => {
                            if (!selectedRequest.reviewed_at) return '';
                            // SQLite datetime 문자열을 직접 파싱 (시간대 변환 없이)
                            const match = selectedRequest.reviewed_at.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                            if (match) {
                              const [, year, month, day, hours, minutes, seconds] = match;
                              return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                            }
                            return selectedRequest.reviewed_at;
                          })()})
                        </span>
                      )}
                    </div>
                  )}
                  {selectedRequest.review_comment && (
                    <div className="detail-item">
                      <strong>검토 코멘트:</strong>
                      <p className="detail-text">{selectedRequest.review_comment}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tool 스캔 결과 모달 */}
      {showScanModal && (
        <div className="modal-overlay" onClick={handleCloseScanModal} style={{ zIndex: 1001 }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '1200px', width: '95%', maxHeight: '80vh', overflowY: 'auto' }}>
            <div className="modal-header">
              <h2>🔍 Tool 스캔 결과</h2>
              <button className="btn-close" onClick={handleCloseScanModal}>×</button>
            </div>
            <div className="modal-body">
              {scanningTools ? (
                <div style={{ padding: '40px', textAlign: 'center' }}>
                  <p style={{ fontSize: '1.1rem', color: '#6c5d53' }}>스캔 중...</p>
                  <p style={{ fontSize: '0.9rem', color: '#999', marginTop: '8px' }}>GitHub 리포지토리를 분석하고 있습니다.</p>
                </div>
              ) : scanResult ? (
                <>
                  <div className="detail-section">
                    <h3>스캔 정보</h3>
                    <div className="detail-item">
                      <strong>리포지토리:</strong> {scanResult.repository || '-'}
                    </div>
                    <div className="detail-item">
                      <strong>브랜치:</strong> {scanResult.branch || '-'}
                    </div>
                    <div className="detail-item">
                      <strong>스캔된 파일:</strong> {scanResult.files.length > 0 ? scanResult.files.join(', ') : '-'}
                    </div>
                    {scanResult.commitSha && (
                      <div className="detail-item">
                        <strong>커밋 SHA:</strong> {scanResult.commitSha.substring(0, 8)}...
                      </div>
                    )}
                    {scanResult.runCommand && (
                      <div className="detail-item">
                        <strong>실행 명령어:</strong> {scanResult.runCommand} ({scanResult.runType || 'unknown'})
                      </div>
                    )}
                  </div>

                  {scanResult.error ? (
                    <div className="detail-section">
                      <div style={{ padding: '16px', backgroundColor: '#fff3cd', borderRadius: '4px', color: '#856404' }}>
                        <strong>오류:</strong> {scanResult.error}
                      </div>
                    </div>
                  ) : (
                    <div className="detail-section">
                      <h3>
                        발견된 Tool 목록
                        {scanResult.method && (
                          <span style={{ 
                            marginLeft: '12px', 
                            fontSize: '0.85rem', 
                            color: scanResult.method === 'sandbox_docker' ? '#007bff' : 
                                   scanResult.method === 'mcp_protocol' ? '#4a9b3a' : '#6c5d53',
                            fontWeight: 'normal'
                          }}>
                            ({scanResult.method === 'sandbox_docker' ? '🔒 Sandbox' : 
                              scanResult.method === 'mcp_protocol' ? '✅ MCP Protocol' : 
                              scanResult.method === 'code_scan' ? '📝 코드 스캔' : '❓ 알 수 없음'})
                          </span>
                        )}
                      </h3>
                      {scanResult.tools.length > 0 ? (
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '12px', marginTop: '12px' }}>
                          {scanResult.tools.map((tool, index) => (
                            <div
                              key={tool}
                              style={{
                                padding: '16px',
                                backgroundColor: '#f8f6f3',
                                border: '1px solid #c7b199',
                                borderRadius: '8px',
                                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '1.2rem' }}>🔧</span>
                                <strong style={{ color: '#6c5d53' }}>{tool}</strong>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ padding: '16px', backgroundColor: '#f5f5f5', borderRadius: '4px', color: '#6c5d53' }}>
                          <p>Tool을 찾을 수 없습니다.</p>
                          <p style={{ fontSize: '0.85rem', marginTop: '8px', color: '#999' }}>
                            리포지토리에서 MCP Tool 정의를 찾을 수 없습니다. 수동으로 입력하거나 확인이 필요합니다.
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {scanResult.tools.length > 0 && (
                    <div style={{ marginTop: '20px', padding: '16px', backgroundColor: '#e8f5e9', borderRadius: '4px' }}>
                      <p style={{ fontSize: '0.9rem', color: '#2e7d32', marginBottom: '12px' }}>
                        ✅ {scanResult.tools.length}개의 Tool이 발견되었습니다. 적용하면 승인 폼에 자동으로 추가됩니다.
                      </p>
                      <button
                        onClick={handleApplyScanResults}
                        style={{
                          padding: '10px 20px',
                          backgroundColor: '#4a9b3a',
                          color: '#fff',
                          border: 'none',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          fontSize: '1rem',
                          fontWeight: 'bold'
                        }}
                      >
                        결과 적용
                      </button>
                    </div>
                  )}
                </>
              ) : null}
            </div>
            <div style={{ padding: '16px', borderTop: '1px solid #ddd', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={handleCloseScanModal}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#6c5d53',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                닫기
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RequestBoard;

