import React, { useState, useEffect } from 'react';
import Pagination from '../../components/Pagination';
import './DownloadLogs.css';

const DownloadLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTeam, setSelectedTeam] = useState('');
  const [teams, setTeams] = useState([]);
  const [teamDropdownOpen, setTeamDropdownOpen] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [sortColumn, setSortColumn] = useState(null);
  const [sortDirection, setSortDirection] = useState(null);

  // 팀 목록 가져오기
  useEffect(() => {
    fetchTeams();
  }, []);

  useEffect(() => {
    setPagination(prev => ({ ...prev, page: 1 }));
  }, [searchQuery, selectedTeam]);

  useEffect(() => {
    fetchLogs();
  }, [searchQuery, selectedTeam, pagination.page]);

  const fetchTeams = async () => {
    try {
      const res = await fetch('http://localhost:3001/api/file/download-logs/teams');
      const data = await res.json();
      if (data.success) {
        setTeams(data.data || []);
      }
    } catch (error) {
      console.error('팀 목록 조회 실패:', error);
    }
  };

  const fetchLogs = async () => {
    try {
      setLoading(true);
      
      const queryParams = new URLSearchParams();
      if (searchQuery) {
        queryParams.append('search', searchQuery);
      }
      if (selectedTeam) {
        queryParams.append('team', selectedTeam);
      }
      queryParams.append('page', pagination.page);
      queryParams.append('limit', '20');
      
      const res = await fetch(`http://localhost:3001/api/file/download-logs?${queryParams}`);
      const data = await res.json();
      
      if (data.success) {
        const fetchedLogs = data.data || [];
        
        setLogs(fetchedLogs);
        setPagination(prev => ({
          ...prev,
          total: data.pagination?.total || fetchedLogs.length || 0,
          totalPages: data.pagination?.totalPages || Math.ceil((fetchedLogs.length || 0) / 20) || 1
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
      console.error('다운로드 로그 조회 실패:', error);
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
    // 형식: 'YYYY-MM-DD HH:MM:SS'
    const match = dateString.match(/(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (match) {
      const [, year, month, day, hours, minutes, seconds] = match;
      return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }
    // 파싱 실패 시 원본 반환
    return dateString;
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

  const sortedLogs = sortColumn && sortDirection ? [...logs].sort((a, b) => {
    let aValue = a[sortColumn];
    let bValue = b[sortColumn];

    // 날짜/시간 정렬
    if (sortColumn === 'downloaded_at') {
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

  if (loading) {
    return <div>로딩 중...</div>;
  }

  return (
    <section className="download-logs">
      <div className="download-logs-header">
        <h1>Download Logs</h1>
        <button onClick={() => fetchLogs()} className="btn-refresh">새로고침</button>
      </div>

      <div className="filters">
        <div className="search-container">
          <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
            <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <input
            type="text"
            className="search-input"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="사용자 또는 사원번호 검색"
          />
        </div>

        <div className="controls-right">
          <div className="sort-dropdown">
            <button 
              className="sort-button" 
              onClick={(e) => {
                e.stopPropagation();
                setTeamDropdownOpen(!teamDropdownOpen);
              }}
            >
              {selectedTeam || '전체 팀'}
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
            {teamDropdownOpen && (
              <>
                <div 
                  className="sort-menu-overlay"
                  onClick={() => setTeamDropdownOpen(false)}
                />
                <div className={`sort-menu ${teamDropdownOpen ? 'open' : ''}`}>
                  <div className="sort-menu-header">팀 선택</div>
                  <button 
                    className={`sort-option ${selectedTeam === '' ? 'selected' : ''}`}
                    onClick={() => {
                      setSelectedTeam('');
                      setTeamDropdownOpen(false);
                    }}
                  >
                    전체 팀
                  </button>
                  {teams.map((team) => (
                    <button 
                      key={team}
                      className={`sort-option ${selectedTeam === team ? 'selected' : ''}`}
                      onClick={() => {
                        setSelectedTeam(team);
                        setTeamDropdownOpen(false);
                      }}
                    >
                      {team}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="logs-table-container">
        <div className="logs-table-wrapper">
          <table className="logs-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('downloaded_at')}>
                  다운로드 시간
                  {getSortIcon('downloaded_at')}
                </th>
                <th>사용자</th>
                <th>사원번호</th>
                <th>팀</th>
                <th>MCP 서버</th>
                <th>파일명</th>
                <th>IP 주소</th>
              </tr>
            </thead>
            <tbody>
              {sortedLogs.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                    다운로드 로그가 없습니다.
                  </td>
                </tr>
              ) : (
                sortedLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{formatDate(log.downloaded_at)}</td>
                    <td>{log.username || '-'}</td>
                    <td>{log.employee_id || '-'}</td>
                    <td>{log.team || '-'}</td>
                    <td>{log.mcp_server_name || '-'}</td>
                    <td className="file-name-cell">{log.file_name || log.file_path || '-'}</td>
                    <td>{log.ip_address || '-'}</td>
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
  );
};

export default DownloadLogs;
