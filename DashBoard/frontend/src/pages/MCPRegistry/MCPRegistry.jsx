import React, { useState, useEffect } from 'react';
import Pagination from '../../components/Pagination';
import MCPRegistryDetail from './MCPRegistryDetail';
import downloadIcon from '../../assets/marketplace/download.png';
import './MCPRegistry.css';

const MCPRegistry = () => {
  const [mcpServers, setMcpServers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('newest');
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const [selectedServerId, setSelectedServerId] = useState(null);

  // MCP 서버 목록 가져오기
  useEffect(() => {
    fetchServers();
  }, [pagination.page, searchQuery, sortBy]);

  const fetchServers = async () => {
    try {
      setLoading(true);
      
      const savedUser = localStorage.getItem('user');
      let userTeam = null;
      
      if (savedUser) {
        const user = JSON.parse(savedUser);
        userTeam = user.team || null;
      }
      
      const queryParams = new URLSearchParams();
      if (userTeam) {
        queryParams.append('team', userTeam);
      }
      queryParams.append('status', 'approved'); // MCP Registry는 승인된 서버만 표시
      queryParams.append('page', pagination.page);
      queryParams.append('limit', '12');
      
      const res = await fetch(`http://localhost:3001/api/marketplace?${queryParams}`);
      const data = await res.json();
      
      if (data.success) {
        let servers = data.data || [];
        
        // 검색 필터링
        if (searchQuery) {
          servers = servers.filter(server => 
            server.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            (server.short_description && server.short_description.toLowerCase().includes(searchQuery.toLowerCase()))
          );
        }

        // 정렬
        if (sortBy === 'newest') {
          servers = [...servers].reverse();
        } else if (sortBy === 'oldest') {
          // 이미 정렬된 상태
        } else if (sortBy === 'a-z') {
          servers = [...servers].sort((a, b) => a.name.localeCompare(b.name));
        } else if (sortBy === 'z-a') {
          servers = [...servers].sort((a, b) => b.name.localeCompare(a.name));
        }

        // 페이징 처리
        const limit = 12;
        const offset = (pagination.page - 1) * limit;
        const paginatedServers = servers.slice(offset, offset + limit);
        
        setMcpServers(paginatedServers);
        setPagination(prev => ({
          ...prev,
          total: servers.length,
          totalPages: Math.ceil(servers.length / limit)
        }));
      } else {
        setMcpServers([]);
        setPagination(prev => ({
          ...prev,
          total: 0,
          totalPages: 1
        }));
      }
      
    } catch (error) {
      console.error('서버 목록 로드 실패:', error);
    } finally {
      setLoading(false);
    }
  };

  // 카테고리 추출 (임시로 description 기반)
  const getCategory = (server) => {
    const desc = (server.short_description || server.description || '').toLowerCase();
    if (desc.includes('database') || desc.includes('postgres') || desc.includes('mysql')) {
      return 'DATABASE';
    } else if (desc.includes('slack') || desc.includes('communication') || desc.includes('chat')) {
      return 'COMMUNICATION';
    } else if (desc.includes('github') || desc.includes('git') || desc.includes('repository')) {
      return 'CODE REPOSITORY';
    } else if (desc.includes('devops') || desc.includes('deploy') || desc.includes('docker')) {
      return 'DEVOPS';
    }
    return 'DEVOPS';
  };

  // Provider 추출 (임시로 name 기반)
  const getProvider = (server) => {
    // 실제로는 서버 데이터에 provider 필드가 있어야 함
    return 'modelcontextprotocol';
  };

  if (loading) {
    return (
      <section className="mcp-registry-section">
        <h1>MCP Registry</h1>
        <p>로딩 중...</p>
      </section>
    );
  }

  return (
    <section className="mcp-registry-section">
      <h1>MCP Registry</h1>
      {/* 검색 및 필터 섹션 */}
      <div className="mcp-registry-controls">
        <div className="search-container">
          <svg className="search-icon" width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z" stroke="currentColor" strokeWidth="1.5"/>
            <path d="M10 10L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <input
            type="text"
            className="search-input"
            placeholder="Search servers"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="controls-right">
          <div className="view-toggle">
            <button
              className={`view-btn ${viewMode === 'list' ? 'active' : ''}`}
              onClick={() => setViewMode('list')}
              title="List view"
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="3" width="12" height="1.5" fill="currentColor"/>
                <rect x="2" y="7.25" width="12" height="1.5" fill="currentColor"/>
                <rect x="2" y="11.5" width="12" height="1.5" fill="currentColor"/>
              </svg>
            </button>
            <button
              className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`}
              onClick={() => setViewMode('grid')}
              title="Grid view"
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="2" width="5" height="5" fill="currentColor"/>
                <rect x="9" y="2" width="5" height="5" fill="currentColor"/>
                <rect x="2" y="9" width="5" height="5" fill="currentColor"/>
                <rect x="9" y="9" width="5" height="5" fill="currentColor"/>
              </svg>
            </button>
          </div>

          <div className="sort-dropdown">
            <button 
              className="sort-button" 
              onClick={(e) => {
                e.stopPropagation();
                setSortMenuOpen(!sortMenuOpen);
              }}
            >
              Sorting
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
            {sortMenuOpen && (
              <>
                <div 
                  className="sort-menu-overlay"
                  onClick={() => setSortMenuOpen(false)}
                />
                <div className={`sort-menu ${sortMenuOpen ? 'open' : ''}`}>
                  <div className="sort-menu-header">Sorting</div>
                  <button 
                    className={`sort-option ${sortBy === 'newest' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('newest');
                      setSortMenuOpen(false);
                    }}
                  >
                    Newest first
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'oldest' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('oldest');
                      setSortMenuOpen(false);
                    }}
                  >
                    Oldest first
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'a-z' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('a-z');
                      setSortMenuOpen(false);
                    }}
                  >
                    A to Z
                  </button>
                  <button 
                    className={`sort-option ${sortBy === 'z-a' ? 'selected' : ''}`}
                    onClick={() => {
                      setSortBy('z-a');
                      setSortMenuOpen(false);
                    }}
                  >
                    Z to A
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 서버 카드 그리드 또는 표 */}
      {viewMode === 'list' ? (
        <div className="mcp-table-container">
          <table className="mcp-table">
            <thead>
              <tr>
                <th>서버 이름</th>
                <th>설명</th>
                <th>작업</th>
              </tr>
            </thead>
            <tbody>
              {mcpServers.length === 0 ? (
                <tr>
                  <td colSpan="3" style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
                    데이터가 없습니다.
                  </td>
                </tr>
              ) : (
                mcpServers.map((server) => (
                  <tr
                    key={server.id}
                    className={selectedServerId === server.id ? 'selected' : ''}
                    onClick={() => setSelectedServerId(server.id)}
                  >
                    <td className="server-name-cell">{server.name}</td>
                    <td className="server-description-cell">
                      {server.short_description || server.description || 'No description available.'}
                    </td>
                    <td>
                      <button 
                        className="table-view-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedServerId(server.id);
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
      ) : (
        <div className="mcp-grid">
        {mcpServers.map((server) => (
          <div
            className="mcp-card"
            key={server.id}
            onClick={() => setSelectedServerId(server.id)}
          >
            <div className="card-top-row">
              <div className="card-icon">
                <div className="icon-placeholder">
                  {server.name.charAt(0).toUpperCase()}
                </div>
              </div>
              <div className="card-header">
                <button 
                  className="card-add-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedServerId(server.id);
                  }}
                  title="View details"
                >
                  <img src={downloadIcon} alt="Download" style={{ width: '18px', height: '18px' }} />
                </button>
              </div>
            </div>

            <div className="card-content">
              <h2 className="card-title">{server.name}</h2>
              <p className="card-description">
                {server.short_description || server.description || 'No description available.'}
              </p>
            </div>
          </div>
        ))}
      </div>
      )}

      {pagination.totalPages > 1 && (
        <Pagination
          currentPage={pagination.page}
          totalPages={pagination.totalPages}
          onPageChange={(page) => setPagination(prev => ({ ...prev, page }))}
        />
      )}

      {/* 상세 페이지 모달 */}
      {selectedServerId && (
        <MCPRegistryDetail
          serverId={selectedServerId}
          onClose={() => setSelectedServerId(null)}
        />
      )}
    </section>
  );
};

export default MCPRegistry;