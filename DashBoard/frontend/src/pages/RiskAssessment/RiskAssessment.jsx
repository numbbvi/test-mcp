import React, { useState, useEffect, useRef } from 'react';
import './RiskAssessment.css';

const RiskAssessment = () => {
  const [viewMode, setViewMode] = useState('list'); // 'list' or 'result'
  const [selectedTab, setSelectedTab] = useState('Total Vulnerabilities');
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [codeIssues, setCodeIssues] = useState([]);
  const [analysisUrl, setAnalysisUrl] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [mcpServers, setMcpServers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [serverFilter, setServerFilter] = useState('all'); // all, pending, approved
  const [analyzingServers, setAnalyzingServers] = useState({}); // { serverId: true/false }
  const [analysisProgressServers, setAnalysisProgressServers] = useState({}); // { serverId: progress }
  const [scanErrors, setScanErrors] = useState({}); // { serverId: errorMessage }
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);
  const [vulnerabilitySortColumn, setVulnerabilitySortColumn] = useState('severity'); // 기본값: severity
  const [vulnerabilitySortDirection, setVulnerabilitySortDirection] = useState('desc'); // 기본값: 높은 순
  const [serverName, setServerName] = useState('');
  const [ossIssues, setOssIssues] = useState([]);
  const [sbomScannerData, setSbomScannerData] = useState([]);
  const [toolValidationIssues, setToolValidationIssues] = useState([]);
  const [detailPanelWidth, setDetailPanelWidth] = useState(600);
  const [isResizing, setIsResizing] = useState(false);
  const detailPanelRef = useRef(null);

  // 스캔 결과를 Risk Assessment 형식으로 변환
  const formatScanResults = (findings) => {
    if (!findings || !Array.isArray(findings)) {
      return [];
    }

    // 파일 확장자로 언어 추론
    const getLanguageFromFile = (filePath) => {
      if (!filePath) return 'Unknown';
      const ext = filePath.split('.').pop()?.toLowerCase();
      const languageMap = {
        'js': 'JavaScript',
        'jsx': 'JavaScript',
        'ts': 'TypeScript',
        'tsx': 'TypeScript',
        'py': 'Python',
        'java': 'Java',
        'go': 'Go',
        'rb': 'Ruby',
        'php': 'PHP',
        'cpp': 'C++',
        'c': 'C',
        'cs': 'C#',
        'swift': 'Swift',
        'kt': 'Kotlin',
        'rs': 'Rust'
      };
      return languageMap[ext] || ext?.toUpperCase() || 'Unknown';
    };

    // rule_id에서 접두사 제거하고 취약점 이름 추출
    const extractVulnerabilityName = (ruleId) => {
      if (!ruleId) return 'Unknown Vulnerability';
      
      // go/, ts/, mcp/ 등의 접두사 제거
      const parts = ruleId.split('/');
      if (parts.length > 1) {
        // 접두사 제거 후 남은 부분을 취약점 이름으로 사용
        const vulnerabilityName = parts.slice(1).join('/');
        // 하이픈을 공백으로 변환하고 각 단어의 첫 글자를 대문자로
        return vulnerabilityName
          .split('-')
          .map(word => word.charAt(0).toUpperCase() + word.slice(1))
          .join(' ');
      }
      
      // 접두사가 없으면 그대로 사용하되 하이픈을 공백으로 변환
      return ruleId
        .split('-')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
    };

    return findings.map((finding, index) => ({
      id: index + 101,
      vulnerability: extractVulnerabilityName(finding.rule_id) || finding.message || 'Unknown Vulnerability',
      severity: finding.severity || 'unknown',
      language: finding.language || getLanguageFromFile(finding.file),
      reachability: 'Reachable',
      vulnerablePackage: finding.file ? `${finding.file}:${finding.line || 0}` : 'Unknown',
      description: finding.message || finding.description || 'No description available',
      references: {
        advisory: finding.cwe || 'Code Review',
        nvd: null
      },
      introducedThrough: finding.file || 'Unknown',
      paths: 1,
      type: 'Code',
      // finding.json의 모든 필드 보존
      rawFinding: finding, // 원본 데이터 전체 보존
      rule_id: finding.rule_id,
      cwe: finding.cwe,
      file: finding.file,
      line: finding.line,
      column: finding.column,
      code_snippet: finding.code_snippet || '',
      pattern_type: finding.pattern_type || '',
      pattern: finding.pattern || '',
      confidence: finding.confidence || 1.0
    }));
  };

  // 분석 시작 핸들러 (리스트 뷰에서 서버별 분석)
  const handleServerAnalysis = async (server) => {
    if (!server.github_link && !server.file_path) {
      alert('GitHub 링크 또는 파일 경로가 필요합니다.');
      return;
    }

    setAnalyzingServers(prev => ({ ...prev, [server.id]: true }));
    setAnalysisProgressServers(prev => ({ ...prev, [server.id]: { bomtori: 0, scanner: 0 } }));

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
          github_url: server.github_link || null,
          repository_path: server.file_path || null,
          mcp_server_name: server.name
        })
      });

      const data = await res.json();
      
      if (!data.success || !data.scan_id) {
        alert(data.message || '스캔 시작 실패');
        setAnalyzingServers(prev => {
          const newState = { ...prev };
          delete newState[server.id];
          return newState;
        });
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
                setAnalysisProgressServers(prev => ({
                  ...prev,
                  [server.id]: {
                    bomtori: progress.bomtori !== null ? progress.bomtori : 0,
                    scanner: progress.scanner || 0
                  }
                }));
                
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
                  // 오류 상태 설정
                  const errorMessage = progress.error || errorMessages.join(' / ') || '스캔 중 오류가 발생했습니다.';
                  setScanErrors(prev => ({
                    ...prev,
                    [server.id]: errorMessage
                  }));
                  setAnalyzingServers(prev => {
                    const newState = { ...prev };
                    delete newState[server.id];
                    return newState;
                  });
                  // 진행률은 유지하되 오류 메시지 표시
                  break;
                }
                
                // 둘 다 완료되었는지 확인
                if (progress.status === 'completed') {
                  // 완료 후 결과 로드
                  try {
                    const vulnRes = await fetch(`http://localhost:3001/api/risk-assessment/code-vulnerabilities?scan_id=${scanId}`, {
                      headers: {
                        'Authorization': `Bearer ${token}`
                      }
                    });
                    const vulnData = await vulnRes.json();
                    
                    if (vulnData.success && vulnData.data) {
                      const formattedIssues = formatScanResults(vulnData.data);
                      setCodeIssues(formattedIssues);
                    } else {
                      setCodeIssues([]);
                    }
                    
                    // OSS Vulnerabilities 로드
                    try {
                      const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
                        headers: {
                          'Authorization': `Bearer ${token}`
                        }
                      });
                      const ossData = await ossRes.json();
                      
                      if (ossData.success && ossData.data) {
                        setOssIssues(ossData.data);
                      } else {
                        setOssIssues([]);
                      }
                    } catch (error) {
                      console.error('OSS 취약점 데이터 로드 실패:', error);
                      setOssIssues([]);
                    }
                    
                    // Tool Validation은 현재 데이터베이스에 저장되지 않음
                    setToolValidationIssues([]);
                    setSbomScannerData([]);
                    
                    // 결과 뷰로 전환
                    setAnalysisUrl(server.github_link || server.file_path || '');
                    setServerName(server.name || '');
                    setViewMode('result');
                    setSelectedTab('Code Vulnerabilities');
                    
                    // 서버 목록 새로고침
                    const loadMcpServers = async () => {
                      try {
                        const token = localStorage.getItem('token');
                        let statusParam = '';
                        if (serverFilter === 'pending') {
                          statusParam = '?status=pending';
                        } else if (serverFilter === 'approved') {
                          statusParam = '?status=approved';
                        } else {
                          statusParam = '?status=all';
                        }
                        
                        // 모든 서버를 가져오기 위해 limit를 매우 큰 값으로 설정
                        statusParam += statusParam.includes('?') ? '&limit=10000' : '?limit=10000';
                        
                        const res = await fetch(`http://localhost:3001/api/marketplace${statusParam}`, {
                          headers: {
                            'Authorization': `Bearer ${token}`
                          }
                        });
                        const data = await res.json();
                        if (data.success) {
                          setMcpServers(data.data || []);
                        }
                      } catch (error) {
                        console.error('MCP 서버 목록 로드 실패:', error);
                      }
                    };
                    
                    loadMcpServers();
                  } catch (error) {
                    console.error('결과 로드 실패:', error);
                  }
                  
                  // 상태 초기화
                  setTimeout(() => {
                    setAnalyzingServers(prev => {
                      const newState = { ...prev };
                      delete newState[server.id];
                      return newState;
                    });
                    setAnalysisProgressServers(prev => {
                      const newState = { ...prev };
                      delete newState[server.id];
                      return newState;
                    });
                  }, 1000);
                  
                  break;
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

      // 진행률 폴링이 완료되면 결과가 자동으로 로드됨
    } catch (error) {
      console.error('분석 오류:', error);
      alert('분석 중 오류가 발생했습니다.');
      setAnalyzingServers(prev => {
        const newState = { ...prev };
        delete newState[server.id];
        return newState;
      });
      setAnalysisProgressServers(prev => {
        const newState = { ...prev };
        delete newState[server.id];
        return newState;
      });
    }
  };

  // 분석 시작 핸들러 (기존 - 폼에서 사용)
  const handleStartAnalysis = async (e) => {
    e.preventDefault();
    if (!analysisUrl.trim()) {
      alert('GitHub URL을 입력해주세요.');
      return;
    }

    setAnalyzing(true);
    setAnalysisProgress(0);

    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:3001/api/risk-assessment/scan-code', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          github_url: analysisUrl
        })
      });

      const data = await res.json();
      
      if (data.success) {
        // scan_id로 취약점 데이터 로드
        const scanId = data.data?.scan_id || data.scan_id || null;
        if (scanId) {
          try {
            const vulnRes = await fetch(`http://localhost:3001/api/risk-assessment/code-vulnerabilities?scan_id=${scanId}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
            const vulnData = await vulnRes.json();
            
            if (vulnData.success && vulnData.data) {
              const formattedIssues = formatScanResults(vulnData.data);
              setCodeIssues(formattedIssues);
            } else {
              setCodeIssues([]);
            }
            
            // OSS Vulnerabilities 로드
            try {
              const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
                headers: {
                  'Authorization': `Bearer ${token}`
                }
              });
              const ossData = await ossRes.json();
              
              if (ossData.success && ossData.data) {
                setOssIssues(ossData.data);
              } else {
                setOssIssues([]);
              }
            } catch (error) {
              console.error('OSS 취약점 데이터 로드 실패:', error);
              setOssIssues([]);
            }
          } catch (error) {
            console.error('취약점 데이터 로드 실패:', error);
            setCodeIssues([]);
            setOssIssues([]);
          }
        } else {
          setCodeIssues([]);
          setOssIssues([]);
        }
        
        // Tool Validation은 현재 데이터베이스에 저장되지 않음
        setToolValidationIssues([]);
        setSbomScannerData([]);
        
        // 결과 뷰로 전환
        // 서버 이름 추출 (analysisUrl에서 또는 mcp_server_name에서)
        const serverNameFromUrl = analysisUrl.match(/github\.com\/[^\/]+\/([^\/]+)/)?.[1] || '';
        setServerName(serverNameFromUrl);
        setViewMode('result');
        setSelectedTab('Code Vulnerabilities');
      } else {
        alert(data.message || '분석 실패');
        // 실패 시 빈 배열로 설정
        setCodeIssues([]);
        setOssIssues([]);
        setToolValidationIssues([]);
        setSbomScannerData([]);
      }
    } catch (error) {
      console.error('분석 오류:', error);
      alert('분석 중 오류가 발생했습니다.');
    } finally {
      setAnalyzing(false);
      setAnalysisProgress(0);
    }
  };

  // MCP 서버 목록 로드 (필터 변경 시 실시간으로 가져오기)
  useEffect(() => {
    const loadMcpServers = async () => {
      try {
        const token = localStorage.getItem('token');
        
        // status 파라미터 설정
        let statusParam = '';
        if (serverFilter === 'pending') {
          statusParam = '?status=pending';
        } else if (serverFilter === 'approved') {
          statusParam = '?status=approved';
        } else {
          statusParam = '?status=all';
        }
        
        // 모든 서버를 가져오기 위해 limit를 매우 큰 값으로 설정
        statusParam += statusParam.includes('?') ? '&limit=10000' : '?limit=10000';
        
        const res = await fetch(`http://localhost:3001/api/marketplace${statusParam}`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        const data = await res.json();
        if (data.success) {
          setMcpServers(data.data || []);
        }
      } catch (error) {
        console.error('MCP 서버 목록 로드 실패:', error);
      }
    };
    
    if (viewMode === 'list') {
      loadMcpServers();
    }
  }, [viewMode, serverFilter]);

  // localStorage에서 scanId를 읽어서 자동으로 결과 뷰로 전환
  useEffect(() => {
    const scanId = localStorage.getItem('riskAssessmentScanId');
    const githubUrl = localStorage.getItem('riskAssessmentGithubUrl');
    const savedServerName = localStorage.getItem('riskAssessmentServerName');
    
    if (scanId && githubUrl) {
      // scanId로 취약점 데이터 로드
      const loadScanResults = async () => {
        try {
          const token = localStorage.getItem('token');
          
          // Code Vulnerabilities 로드
          const codeRes = await fetch(`http://localhost:3001/api/risk-assessment/code-vulnerabilities?scan_id=${scanId}`, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          const codeData = await codeRes.json();
          
          if (codeData.success && codeData.data) {
            const formattedIssues = formatScanResults(codeData.data);
            setCodeIssues(formattedIssues);
          } else {
            setCodeIssues([]);
          }
          
          // OSS Vulnerabilities 로드
          try {
            const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
              headers: {
                'Authorization': `Bearer ${token}`
              }
            });
            const ossData = await ossRes.json();
            
            if (ossData.success && ossData.data) {
              setOssIssues(ossData.data);
            } else {
              setOssIssues([]);
            }
          } catch (error) {
            console.error('OSS 취약점 데이터 로드 실패:', error);
            setOssIssues([]);
          }
          
          // Tool Validation은 현재 데이터베이스에 저장되지 않음
          setToolValidationIssues([]);
          setSbomScannerData([]);
          
          setAnalysisUrl(githubUrl);
          setServerName(savedServerName || '');
          setViewMode('result');
          setSelectedTab('Code Vulnerabilities');
          
          // localStorage에서 제거
          localStorage.removeItem('riskAssessmentScanId');
          localStorage.removeItem('riskAssessmentGithubUrl');
          localStorage.removeItem('riskAssessmentServerName');
        } catch (error) {
          console.error('스캔 결과 로드 실패:', error);
          // 오류 발생 시 빈 배열로 설정
          setCodeIssues([]);
          setOssIssues([]);
          setToolValidationIssues([]);
          setSbomScannerData([]);
        }
      };
      
      loadScanResults();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const tabs = ['Total Vulnerabilities', 'OSS Vulnerabilities', 'Code Vulnerabilities', 'Tool Validation'];

  const getSeverityColor = (score) => {
    if (score >= 9.0) return '#dc3545'; // 빨간색
    if (score >= 7.0) return '#fd7e14'; // 주황색
    if (score >= 4.0) return '#ffc107'; // 노란색
    return '#28a745'; // 초록색
  };


  // ESC 키로 상세보기 닫기
  useEffect(() => {
    if (!selectedIssue) return;

    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        setSelectedIssue(null);
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [selectedIssue]);

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


  // 심각도 점수 계산 함수 (CVSS 점수 우선, 없으면 심각도 텍스트를 점수로 변환)
  const getSeverityScore = (severity, cvss) => {
    // CVSS 점수가 있으면 사용
    if (cvss !== null && cvss !== undefined) {
      return cvss;
    }
    
    // 심각도 텍스트를 점수로 변환
    const severityLower = (severity || 'unknown').toLowerCase();
    const severityMap = {
      'critical': 9.5,
      'high': 8.0,
      'medium': 6.0,
      'low': 4.0,
      'info': 2.0,
      'unknown': 0
    };
    return severityMap[severityLower] || 0;
  };

  const getCurrentIssues = () => {
    let issues = [];
    
    switch (selectedTab) {
      case 'OSS Vulnerabilities':
        // OSS 취약점에 id 추가
        issues = ossIssues.map((issue, index) => ({
          ...issue,
          id: issue.id || `oss-${index}-${issue.package?.name}-${issue.vulnerability?.id}`,
          severityScore: getSeverityScore(issue.vulnerability?.severity, issue.vulnerability?.cvss)
        }));
        break;
      case 'Code Vulnerabilities':
        issues = codeIssues.map(issue => ({
          ...issue,
          severityScore: getSeverityScore(issue.severity, null)
        }));
        break;
      case 'Tool Validation':
        issues = toolValidationIssues;
        break;
      case 'Total Vulnerabilities':
        const ossWithScore = ossIssues.map((issue, index) => ({
          ...issue,
          id: issue.id || `oss-${index}-${issue.package?.name}-${issue.vulnerability?.id}`,
          severityScore: getSeverityScore(issue.vulnerability?.severity, issue.vulnerability?.cvss)
        }));
        const codeWithScore = codeIssues.map(issue => ({
          ...issue,
          severityScore: getSeverityScore(issue.severity, null)
        }));
        issues = [...ossWithScore, ...codeWithScore, ...toolValidationIssues];
        break;
      default:
        return [];
    }
    
    // 정렬 적용
    if (vulnerabilitySortColumn && vulnerabilitySortDirection) {
      issues.sort((a, b) => {
        let aValue, bValue;
        
        if (vulnerabilitySortColumn === 'severity') {
          aValue = a.severityScore || 0;
          bValue = b.severityScore || 0;
        } else if (vulnerabilitySortColumn === 'cvss') {
          aValue = a.vulnerability?.cvss || a.cvss || 0;
          bValue = b.vulnerability?.cvss || b.cvss || 0;
        } else {
          aValue = a[vulnerabilitySortColumn] || '';
          bValue = b[vulnerabilitySortColumn] || '';
        }
        
        if (vulnerabilitySortDirection === 'desc') {
          return bValue > aValue ? 1 : bValue < aValue ? -1 : 0;
        } else {
          return aValue > bValue ? 1 : aValue < bValue ? -1 : 0;
        }
      });
    }
    
    return issues;
  };

  const renderSBOMScannerContent = () => {
    return (
      <div className="sbom-scanner-content">
        <div className="sbom-scanner-summary">
          <div className="summary-card">
            <h3>Total Components</h3>
            <p className="summary-number">{sbomScannerData.length}</p>
          </div>
          <div className="summary-card">
            <h3>Vulnerable Components</h3>
            <p className="summary-number">{sbomScannerData.filter(c => c.vulnerabilities > 0).length}</p>
          </div>
          <div className="summary-card">
            <h3>Last Scanned</h3>
            <p className="summary-date">{sbomScannerData[0]?.lastScanned || '-'}</p>
          </div>
        </div>
        <div className="sbom-scanner-table">
          <table>
            <thead>
              <tr>
                <th>Component</th>
                <th>Type</th>
                <th>Vulnerabilities</th>
                <th>Licenses</th>
                <th>Last Scanned</th>
              </tr>
            </thead>
            <tbody>
              {sbomScannerData.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                    데이터가 없습니다.
                  </td>
                </tr>
              ) : (
                sbomScannerData.map(item => (
                  <tr key={item.id}>
                    <td className="package-name">{item.component}</td>
                    <td>
                      <span className="type-badge">{item.type}</span>
                    </td>
                    <td>
                      {item.vulnerabilities > 0 ? (
                        <span className="vuln-count">{item.vulnerabilities}</span>
                      ) : (
                        <span className="no-vuln">0</span>
                      )}
                    </td>
                    <td>{item.licenses.join(', ')}</td>
                    <td>{item.lastScanned}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderIssuesTable = () => {
    const issues = getCurrentIssues();
    
    return (
      <div>
        <div className="issues-table">
          <table>
          <thead>
            <tr>
              {selectedTab === 'Code Vulnerabilities' || selectedTab === 'Total Vulnerabilities' ? (
                <>
                  <th>Vulnerability</th>
                  <th className="sortable" onClick={(e) => { e.stopPropagation(); handleVulnerabilitySort('severity'); }} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                    Severity
                    {getVulnerabilitySortIcon('severity')}
                  </th>
                  {selectedTab === 'Code Vulnerabilities' ? (
                    <>
                      <th>Language</th>
                      <th>Vulnerable package</th>
                      <th>상세보기</th>
                    </>
                  ) : (
                    <>
                      <th>Type</th>
                      <th>Vulnerable package</th>
                      <th>상세보기</th>
                    </>
                  )}
                </>
              ) : (
                <>
                  <th>Vulnerability ID</th>
                  <th className="sortable" onClick={(e) => { e.stopPropagation(); handleVulnerabilitySort('cvss'); }} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                    CVSS
                    {getVulnerabilitySortIcon('cvss')}
                  </th>
                  <th>Reachability</th>
                  <th>Package</th>
                  <th>Current Version</th>
                  <th>Fix Version</th>
                  <th>Dependency Type</th>
                  <th>License</th>
                  <th>상세보기</th>
                </>
              )}
            </tr>
          </thead>
          <tbody>
            {issues.length === 0 ? (
              <tr>
                <td colSpan={selectedTab === 'OSS Vulnerabilities' ? 9 : 5} style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                  데이터가 없습니다.
                </td>
              </tr>
            ) : (
              issues.map(issue => {
                const getSeverityColor = (severity) => {
                  const severityLower = (severity || 'unknown').toLowerCase();
                  if (severityLower === 'high') return '#dc3545';
                  if (severityLower === 'medium') return '#ffc107';
                  if (severityLower === 'low') return '#17a2b8';
                  if (severityLower === 'info') return '#6c757d';
                  return '#6c757d';
                };
                
                if (selectedTab === 'Code Vulnerabilities' || selectedTab === 'Total Vulnerabilities') {
                  // Code Vulnerabilities 또는 Total Vulnerabilities 테이블 구조
                  const isOssIssue = issue.package && issue.vulnerability;
                  const severity = isOssIssue ? issue.vulnerability?.severity : issue.severity;
                  const severityScore = issue.severityScore || 0;
                  
                  return (
                    <tr
                      key={issue.id}
                      className={selectedIssue?.id === issue.id ? 'selected' : ''}
                      onClick={() => setSelectedIssue(issue)}
                    >
                      <td>
                        {isOssIssue 
                          ? (issue.vulnerability?.title || issue.vulnerability?.cve || issue.vulnerability?.id || 'Unknown Vulnerability')
                          : issue.vulnerability
                        }
                      </td>
                      <td>
                        <span style={{
                          padding: '4px 8px',
                          borderRadius: '4px',
                          backgroundColor: getSeverityColor(severity),
                          color: '#fff',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          textTransform: 'uppercase'
                        }}>
                          {severity || 'unknown'}
                        </span>
                      </td>
                      <td>
                        {selectedTab === 'Total Vulnerabilities' ? (
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '4px',
                            backgroundColor: isOssIssue ? '#17a2b8' : '#6c757d',
                            color: '#fff',
                            fontSize: '0.75rem',
                            fontWeight: 600
                          }}>
                            {isOssIssue ? 'OSS' : 'Code'}
                          </span>
                        ) : (
                          issue.language || 'Unknown'
                        )}
                      </td>
                      <td className="package-name">
                        {isOssIssue 
                          ? `${issue.package?.name || 'Unknown'}${issue.package?.current_version ? ` (${issue.package.current_version})` : ''}`
                          : issue.vulnerablePackage
                        }
                      </td>
                      <td>
                        <button 
                          className="fix-button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIssue(issue);
                          }}
                        >
                          상세보기
                        </button>
                      </td>
                    </tr>
                  );
                } else {
                  // OSS Vulnerabilities 테이블 구조 (detail.js 참고)
                  const pkg = issue.package || {};
                  const vuln = issue.vulnerability || {};
                  const cvss = vuln.cvss || 0;
                  const severity = vuln.severity || 'unknown';
                  
                  // CVSS 점수에 따른 색상 클래스 (detail.js 참고)
                  const getCvssSeverityClass = (score) => {
                    if (score === null || score === undefined || isNaN(score)) return '';
                    if (score >= 9) return 'cvss-pill--critical';
                    if (score >= 7) return 'cvss-pill--high';
                    if (score >= 4) return 'cvss-pill--medium';
                    return 'cvss-pill--low';
                  };
                  
                  const cvssSeverityClass = getCvssSeverityClass(cvss);
                  
                  // Dependency type 라벨 및 클래스
                  const dependencyType = (pkg.dependency_type || '').toLowerCase();
                  const dependencyTypeLabel = dependencyType === 'direct' ? 'Direct' : dependencyType === 'transitive' ? 'Transitive' : 'Unknown';
                  const dependencyTypeClass = dependencyType === 'direct' ? 'dependency-pill dependency-pill--direct' : 
                                               dependencyType === 'transitive' ? 'dependency-pill dependency-pill--transitive' : 
                                               'dependency-pill dependency-pill--unknown';
                  
                  // Reachability 상태
                  let reachabilityStatus = 'unknown';
                  let reachabilityBadge = '';
                  if (issue.reachable === true) {
                    reachabilityStatus = 'reachable';
                    reachabilityBadge = '↺ Reachable';
                  } else if (issue.reachable === false) {
                    reachabilityStatus = 'unreachable';
                    reachabilityBadge = 'Ø Unreachable';
                  }
                  
                  // License 추출
                  const license = pkg.license || (Array.isArray(pkg.licenses) && pkg.licenses[0]) || '';
                  
                  return (
                    <tr
                      key={issue.id || `${pkg.name}-${vuln.id}`}
                      className={selectedIssue?.id === issue.id ? 'selected' : ''}
                      onClick={() => setSelectedIssue(issue)}
                    >
                      <td>
                        <div className="vuln-cell">
                          {vuln.cve || vuln.id || '-'}
                        </div>
                      </td>
                      <td>
                        {Number.isFinite(cvss) && cvss > 0 ? (
                          <span className={`cvss-pill ${cvssSeverityClass}`}>
                            {cvss.toFixed(1)}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        {reachabilityStatus !== 'unknown' ? (
                          <span className={`reachability-badge reachability-badge--${reachabilityStatus}`}>
                            {reachabilityBadge}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td className="package-name">{pkg.name || 'Unknown'}</td>
                      <td>
                        {pkg.current_version ? (
                          <span className="oss-table__value" title={pkg.current_version}>
                            {pkg.current_version}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        {pkg.fixed_version || (Array.isArray(pkg.all_fixed_versions) && pkg.all_fixed_versions.length > 0) ? (
                          <span className="oss-table__value" style={{ color: '#28a745', fontWeight: 600 }} title={pkg.fixed_version || pkg.all_fixed_versions[0]}>
                            {pkg.fixed_version || pkg.all_fixed_versions[0]}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        <span className={dependencyTypeClass}>
                          {dependencyTypeLabel}
                        </span>
                      </td>
                      <td>
                        {license ? (
                          <span className="oss-table__value" title={license}>
                            {license}
                          </span>
                        ) : (
                          <span style={{ color: '#6c757d' }}>-</span>
                        )}
                      </td>
                      <td>
                        <button 
                          className="oss-detail-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIssue(issue);
                          }}
                        >
                          View Detail
                        </button>
                      </td>
                    </tr>
                  );
                }
              })
            )}
          </tbody>
        </table>
        </div>
      </div>
    );
  };

  // 정렬 핸들러 (서버 리스트용)
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

  // 취약점 정렬 핸들러
  const handleVulnerabilitySort = (column) => {
    if (vulnerabilitySortColumn === column) {
      if (vulnerabilitySortDirection === 'desc') {
        setVulnerabilitySortDirection('asc');
      } else if (vulnerabilitySortDirection === 'asc') {
        // 기본값으로 리셋 (높은 순)
        setVulnerabilitySortDirection('desc');
      }
    } else {
      setVulnerabilitySortColumn(column);
      setVulnerabilitySortDirection('desc');
    }
  };

  // 취약점 정렬 아이콘 표시 (Download Logs와 동일한 형식)
  const getVulnerabilitySortIcon = (column) => {
    if (vulnerabilitySortColumn !== column || !vulnerabilitySortDirection) {
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
        {vulnerabilitySortDirection === 'asc' ? (
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

  // 리스트 뷰 렌더링
  const renderListView = () => {
    // 서버 필터링은 백엔드에서 처리되므로, 검색어만 클라이언트에서 필터링
    let filteredServers = mcpServers.filter(server => 
      server.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // 정렬 적용
    if (sortColumn && sortDirection) {
      filteredServers = [...filteredServers].sort((a, b) => {
        let aValue = a[sortColumn];
        let bValue = b[sortColumn];

        // 분석 시간 정렬
        if (sortColumn === 'analysis_timestamp') {
          if (!aValue && !bValue) return 0;
          if (!aValue || aValue === '-') return 1;
          if (!bValue || bValue === '-') return -1;
          
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

    return (
      <div className="risk-assessment-container">
        <div className="risk-assessment-left">
          <div className="risk-assessment-header">
            <h1>Risk Assessment</h1>
          </div>

          <section className="list-page__controls-row">
            <div className="list-page__header">
              <div>
                <h2>MCP Server List</h2>
              </div>
              <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                <button
                  className={`request-board-tab ${serverFilter === 'all' ? 'active' : ''}`}
                  onClick={() => setServerFilter('all')}
                  style={{ padding: '8px 16px', fontSize: '0.9rem' }}
                >
                  전체 서버
                </button>
                <button
                  className={`request-board-tab ${serverFilter === 'pending' ? 'active' : ''}`}
                  onClick={() => setServerFilter('pending')}
                  style={{ padding: '8px 16px', fontSize: '0.9rem' }}
                >
                  대기중인 서버
                </button>
                <button
                  className={`request-board-tab ${serverFilter === 'approved' ? 'active' : ''}`}
                  onClick={() => setServerFilter('approved')}
                  style={{ padding: '8px 16px', fontSize: '0.9rem' }}
                >
                  승인된 서버
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
          </section>

          <div className="table-wrapper">
            <table className="requests-table">
              <thead>
                <tr>
                  <th>MCP 서버</th>
                  <th>스택</th>
                  <th>패키지</th>
                  <th>취약점</th>
                  <th>도달 가능</th>
                  <th>위험도</th>
                  <th className="sortable" onClick={() => handleSort('analysis_timestamp')} style={{ cursor: 'pointer', userSelect: 'none', position: 'relative', paddingRight: '24px' }}>
                    분석 시간
                    {getSortIcon('analysis_timestamp')}
                  </th>
                  <th>위험도 산정</th>
                  <th>상세보기</th>
                </tr>
              </thead>
              <tbody>
                {filteredServers.length === 0 ? (
                  <tr>
                    <td colSpan="9" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                      {searchTerm ? '검색 결과가 없습니다.' : 'MCP 서버가 없습니다.'}
                    </td>
                  </tr>
                ) : (
                  filteredServers.map(server => {
                    const isAnalyzing = analyzingServers[server.id] || false;
                    const progressData = analysisProgressServers[server.id];
                    const progress = typeof progressData === 'object' 
                      ? (progressData.bomtori !== null && progressData.bomtori !== undefined 
                          ? Math.round((progressData.bomtori + progressData.scanner) / 2)
                          : progressData.scanner || 0)
                      : (progressData || 0);
                    const bomtoriProgress = typeof progressData === 'object' ? (progressData.bomtori !== null ? progressData.bomtori : 0) : 0;
                    const scannerProgress = typeof progressData === 'object' ? (progressData.scanner || 0) : (progressData || 0);
                    const hasBomtori = server.github_link && server.github_link.includes('github.com');
                    
                    return (
                      <tr key={server.id} className="system-row">
                        <td>
                          <div className="system-row__title">{server.name}</div>
                        </td>
                        <td className="system-row__stack">-</td>
                        <td className="system-row__packages">-</td>
                        <td className="system-row__vulns">-</td>
                        <td className="system-row__reachable">-</td>
                        <td className="system-row__risk">-</td>
                        <td className="system-row__timestamp">
                          {server.analysis_timestamp 
                            ? (() => {
                                const match = server.analysis_timestamp.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
                                if (match) {
                                  const [, year, month, day, hours, minutes, seconds] = match;
                                  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
                                }
                                return server.analysis_timestamp;
                              })()
                            : '-'}
                        </td>
                        <td className="system-row__analysis">
                          {scanErrors[server.id] ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
                              <div style={{ 
                                fontSize: '0.75rem', 
                                color: '#dc2626',
                                padding: '8px',
                                backgroundColor: '#fee2e2',
                                borderRadius: '4px',
                                border: '1px solid #fecaca'
                              }}>
                                {scanErrors[server.id]}
                              </div>
                              <button
                                onClick={() => {
                                  setScanErrors(prev => {
                                    const newState = { ...prev };
                                    delete newState[server.id];
                                    return newState;
                                  });
                                  handleServerAnalysis(server);
                                }}
                                style={{
                                  padding: '6px 12px',
                                  fontSize: '0.75rem',
                                  backgroundColor: '#003153',
                                  color: '#fff',
                                  border: 'none',
                                  borderRadius: '4px',
                                  cursor: 'pointer',
                                  fontWeight: '500'
                                }}
                              >
                                다시 시도
                              </button>
                            </div>
                          ) : isAnalyzing ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', width: '100%' }}>
                              {hasBomtori && (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#666' }}>
                                    <span>SBOM/SCA</span>
                                    <span>{bomtoriProgress}%</span>
                                  </div>
                                  <div style={{
                                    width: '100%',
                                    height: '4px',
                                    backgroundColor: '#e0e0e0',
                                    borderRadius: '2px',
                                    overflow: 'hidden'
                                  }}>
                                    <div style={{
                                      width: `${bomtoriProgress}%`,
                                      height: '100%',
                                      backgroundColor: '#17a2b8',
                                      transition: 'width 0.3s ease'
                                    }}></div>
                                  </div>
                                </div>
                              )}
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#666' }}>
                                  <span>Code Scanner</span>
                                  <span>{scannerProgress}%</span>
                                </div>
                                <div style={{
                                  width: '100%',
                                  height: '4px',
                                  backgroundColor: '#e0e0e0',
                                  borderRadius: '2px',
                                  overflow: 'hidden'
                                }}>
                                  <div style={{
                                    width: `${scannerProgress}%`,
                                    height: '100%',
                                    backgroundColor: '#003153',
                                    transition: 'width 0.3s ease'
                                  }}></div>
                                </div>
                              </div>
                            </div>
                          ) : (
                            <button
                              className="btn-refresh"
                              onClick={() => handleServerAnalysis(server)}
                              style={{ 
                                padding: '6px 12px', 
                                fontSize: '0.85rem',
                                width: '100%'
                              }}
                            >
                              Run Analysis
                            </button>
                          )}
                        </td>
                        <td className="system-row__link">
                          <button 
                            className="btn btn--ghost"
                            onClick={async () => {
                              const scanPath = server.github_link || server.file_path;
                              if (!scanPath) {
                                alert('스캔 경로가 없습니다.');
                                return;
                              }
                              
                              try {
                                const token = localStorage.getItem('token');
                                
                                // scan_path로 최신 스캔 결과 조회
                                const res = await fetch(`http://localhost:3001/api/risk-assessment/code-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}`, {
                                  headers: {
                                    'Authorization': `Bearer ${token}`
                                  }
                                });
                                const data = await res.json();
                                
                                if (data.success && data.data && data.data.length > 0) {
                                  // 취약점 데이터가 있으면 포맷팅하여 설정
                                  const formattedIssues = formatScanResults(data.data);
                                  setCodeIssues(formattedIssues);
                                  
                                  // scan_id 추출 (첫 번째 취약점에서)
                                  const scanId = data.data[0]?.scan_id || null;
                                  
                                  // OSS Vulnerabilities 로드
                                  if (scanId) {
                                    try {
                                      const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_id=${scanId}`, {
                                        headers: {
                                          'Authorization': `Bearer ${token}`
                                        }
                                      });
                                      const ossData = await ossRes.json();
                                      
                                      if (ossData.success && ossData.data) {
                                        setOssIssues(ossData.data);
                                      } else {
                                        setOssIssues([]);
                                      }
                                    } catch (error) {
                                      console.error('OSS 취약점 데이터 로드 실패:', error);
                                      setOssIssues([]);
                                    }
                                  } else {
                                    // scan_path로 OSS 취약점 조회
                                    try {
                                      const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}`, {
                                        headers: {
                                          'Authorization': `Bearer ${token}`
                                        }
                                      });
                                      const ossData = await ossRes.json();
                                      
                                      if (ossData.success && ossData.data) {
                                        setOssIssues(ossData.data);
                                      } else {
                                        setOssIssues([]);
                                      }
                                    } catch (error) {
                                      console.error('OSS 취약점 데이터 로드 실패:', error);
                                      setOssIssues([]);
                                    }
                                  }
                                } else {
                                  // 취약점 데이터가 없으면 빈 배열로 설정
                                  setCodeIssues([]);
                                  
                                  // scan_path로 OSS 취약점 조회 시도
                                  try {
                                    const ossRes = await fetch(`http://localhost:3001/api/risk-assessment/oss-vulnerabilities?scan_path=${encodeURIComponent(scanPath)}`, {
                                      headers: {
                                        'Authorization': `Bearer ${token}`
                                      }
                                    });
                                    const ossData = await ossRes.json();
                                    
                                    if (ossData.success && ossData.data) {
                                      setOssIssues(ossData.data);
                                    } else {
                                      setOssIssues([]);
                                    }
                                  } catch (error) {
                                    console.error('OSS 취약점 데이터 로드 실패:', error);
                                    setOssIssues([]);
                                  }
                                }
                                
                                // Tool Validation은 현재 데이터베이스에 저장되지 않음
                                setToolValidationIssues([]);
                                setSbomScannerData([]);
                                
                                // 결과 뷰로 전환
                                setAnalysisUrl(scanPath);
                                setServerName(server.name || '');
                                setViewMode('result');
                                setSelectedTab('Code Vulnerabilities');
                              } catch (error) {
                                console.error('스캔 결과 로드 실패:', error);
                                alert('스캔 결과를 불러오는 중 오류가 발생했습니다.');
                              }
                            }}
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // 결과 뷰 렌더링
  const renderResultView = () => {
    return (
      <div className="risk-assessment-container">
        <div className="risk-assessment-left">
          {/* Breadcrumb */}
          <div className="risk-assessment-breadcrumb">
            <button 
              className="breadcrumb-link"
              onClick={() => {
                setViewMode('list');
                setSelectedIssue(null);
                setAnalysisUrl('');
              }}
            >
              Analysis
            </button>
            <span className="breadcrumb-separator"> &gt; </span>
            <span className="breadcrumb-current">Result</span>
          </div>

          <div className="risk-assessment-header">
            <h1>{serverName ? `Risk Assessment: ${serverName}` : 'Risk Assessment'}</h1>
            <div className="risk-assessment-tabs">
              {tabs.map(tab => (
                <button
                  key={tab}
                  className={`risk-assessment-tab ${selectedTab === tab ? 'active' : ''}`}
                  onClick={() => {
                    setSelectedTab(tab);
                    setSelectedIssue(null);
                  }}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          <div className="risk-assessment-summary">
            <span className="results-count">
              {selectedTab === 'Total Vulnerabilities' 
                ? `${getCurrentIssues().length} total vulnerabilities`
                : `${getCurrentIssues().length} matching results`}
            </span>
            <select className="filter-dropdown">
              <option>Filter by Application: All</option>
            </select>
          </div>
          {selectedTab === 'Total Vulnerabilities' ? renderSBOMScannerContent() : renderIssuesTable()}
        </div>

        {selectedIssue && (
          <div 
            className={`risk-assessment-right ${isResizing ? 'resizing' : ''}`}
            style={{ width: `${detailPanelWidth}px` }}
            ref={detailPanelRef}
          >
            <div 
              className="risk-assessment-resize-handle"
              onMouseDown={handleResizeStart}
            />
            <div className="vulnerability-details">
              <div className="vulnerability-header">
                <div className="vulnerability-title">
                  <div>
                    <h2>{selectedIssue.vulnerability}</h2>
                    <span className="vulnerability-type">{selectedIssue.type} vulnerability</span>
                  </div>
                </div>
                <button className="btn-close" onClick={() => setSelectedIssue(null)}>×</button>
              </div>

              <div className="vulnerability-info">
                <div className="info-section" style={{ flexWrap: 'wrap', gap: '16px' }}>
                  <div className="severity-box" style={{ 
                    backgroundColor: (() => {
                      const severity = (selectedIssue.severity || 'unknown').toLowerCase();
                      if (severity === 'high') return '#dc3545';
                      if (severity === 'medium') return '#ffc107';
                      if (severity === 'low') return '#17a2b8';
                      if (severity === 'info') return '#6c757d';
                      return '#6c757d';
                    })()
                  }}>
                    {(selectedIssue.severity || 'unknown').toUpperCase()}
                  </div>
                  <div className="info-item" style={{ flex: '1', minWidth: '200px' }}>
                    <strong>Rule ID</strong>
                    <code>{selectedIssue.rule_id || 'N/A'}</code>
                  </div>
                  {selectedIssue.file && (
                    <div className="info-item" style={{ flex: '1 1 100%', minWidth: '200px' }}>
                      <strong>File</strong>
                      <code style={{ display: 'block', marginTop: '4px' }}>{selectedIssue.file}</code>
                    </div>
                  )}
                  {selectedIssue.line && (
                    <div className="info-item" style={{ flex: '1', minWidth: '150px' }}>
                      <strong>Line</strong>
                      <code>{selectedIssue.line}{selectedIssue.column && ` (Column: ${selectedIssue.column})`}</code>
                    </div>
                  )}
                </div>

                <div className="description-box">
                  <strong>Description</strong>
                  <p>{selectedIssue.description || selectedIssue.message || 'No description available'}</p>
                </div>

                {selectedIssue.cwe && (
                  <div className="description-box">
                    <strong>CWE</strong>
                    <p>{selectedIssue.cwe}</p>
                  </div>
                )}

                {selectedIssue.code_snippet && (
                  <div className="description-box" style={{ marginTop: '16px' }}>
                    <strong>Code Snippet</strong>
                    <pre className="code-snippet">
                      {selectedIssue.code_snippet}
                    </pre>
                  </div>
                )}

                <div className="info-section" style={{ marginTop: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  {selectedIssue.pattern_type && (
                    <div className="info-item">
                      <strong>Pattern Type</strong>
                      <code>{selectedIssue.pattern_type}</code>
                    </div>
                  )}
                  {selectedIssue.pattern && (
                    <div className="info-item">
                      <strong>Pattern</strong>
                      <code>{selectedIssue.pattern}</code>
                    </div>
                  )}
                  {selectedIssue.language && (
                    <div className="info-item">
                      <strong>Language</strong>
                      <code>{selectedIssue.language}</code>
                    </div>
                  )}
                </div>

              </div>

              {selectedIssue.rawFinding && (
                <div className="description-box" style={{ marginTop: '24px' }}>
                  <strong>Raw Finding Data</strong>
                  <pre style={{
                    background: '#f5f5f5',
                    padding: '16px',
                    borderRadius: '6px',
                    overflow: 'auto',
                    fontSize: '0.8rem',
                    marginTop: '12px',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    maxHeight: '400px',
                    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                    lineHeight: '1.5',
                    border: '1px solid #e0e0e0'
                  }}>
                    {JSON.stringify(selectedIssue.rawFinding, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  return viewMode === 'list' ? renderListView() : renderResultView();
};

export default RiskAssessment;


