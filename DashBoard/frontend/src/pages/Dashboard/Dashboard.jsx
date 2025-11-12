import React, { useState, useEffect } from 'react';
import { apiGet } from '../../utils/api';
import './Dashboard.css';

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  const [dateRange, setDateRange] = useState(7);
  const [selectedTab, setSelectedTab] = useState('total');
  
  // 트래픽 데이터
  const [trafficByApp, setTrafficByApp] = useState([]);
  const [trafficByHost, setTrafficByHost] = useState([]);
  
  // 실시간 탐지 결과
  const [detections, setDetections] = useState([]);
  
  // 사용자 통계
  const [userStats, setUserStats] = useState(null);
  const [userDistribution, setUserDistribution] = useState([]);
  const [trafficGraph, setTrafficGraph] = useState([]);
  
  // MCP 서버 통계
  const [mcpServerStats, setMcpServerStats] = useState(null);
  
  // 데이터 로드
  useEffect(() => {
    loadDashboardData();
    // 실시간 업데이트 (30초마다)
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, [dateRange]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // API 호출로 데이터 가져오기
      const [trafficAppRes, trafficHostRes, detectionsRes, statsRes, distributionRes, mcpStatsRes] = await Promise.all([
        apiGet(`/dashboard/traffic/app?days=${dateRange}`),
        apiGet(`/dashboard/traffic/host?days=${dateRange}`),
        apiGet(`/dashboard/detections?days=${dateRange}&limit=10`),
        apiGet(`/dashboard/statistics?days=${dateRange}`),
        apiGet(`/dashboard/user-distribution?days=${dateRange}`),
        apiGet(`/dashboard/mcp-server-stats`)
      ]);
      
      if (trafficAppRes.success) {
        setTrafficByApp(trafficAppRes.data || []);
      }
      
      if (trafficHostRes.success) {
        setTrafficByHost(trafficHostRes.data || []);
      }
      
      if (detectionsRes.success) {
        setDetections(detectionsRes.data || []);
      }
      
      if (statsRes.success) {
        setUserStats(statsRes.data || null);
        if (statsRes.data?.trafficGraph) {
          setTrafficGraph(statsRes.data.trafficGraph);
        }
      }
      
      if (distributionRes.success) {
        setUserDistribution(distributionRes.data || []);
      }
      
      if (mcpStatsRes.success) {
        setMcpServerStats(mcpStatsRes.data || null);
      }
      
    } catch (error) {
      console.error('Dashboard 데이터 로드 오류:', error);
    } finally {
      setLoading(false);
    }
  };

  // DLP 탐지 태그 색상
  const getDetectionTagColor = (tag) => {
    const colors = {
      'PII': '#EF4444',
      'Secret Info': '#F59E0B',
      'Credential Info': '#DC2626',
      'Unknown Link': '#8B5CF6',
      'RBAC Violation': '#DC2626'
    };
    return colors[tag] || '#6B7280';
  };

  // 원그래프 생성 (MCP 서버별 사용자 분포)
  const generateDonutChart = (data) => {
    if (!data || data.length === 0) return null;
    
    const total = data.reduce((sum, item) => sum + item.user_count, 0);
    let currentPercent = 0;
    const colors = ['#003153', '#1866E1', '#3B82F6', '#60A5FA', '#93C5FD', '#C7D2FE'];
    
    const segments = data.map((item, index) => {
      const percent = (item.user_count / total) * 100;
      const startPercent = currentPercent;
      currentPercent += percent;
      const endPercent = currentPercent;
      
      return {
        ...item,
        startPercent,
        endPercent,
        percent,
        color: colors[index % colors.length]
      };
    });

    return segments;
  };

  const donutSegments = generateDonutChart(userDistribution);
  const maxTraffic = trafficByApp.length > 0 ? Math.max(...trafficByApp.map(t => t.usage_count)) : 1;

  return (
    <div className="dashboard-page">
      {/* 헤더 */}
      <div className="dashboard-header-section">
        <div className="dashboard-welcome">
          <h1>Welcome, Admin.</h1>
        </div>
        <div className="dashboard-tabs-section">
          <div className="dashboard-actions">
            <select 
              className="date-range"
              value={dateRange}
              onChange={(e) => setDateRange(parseInt(e.target.value))}
            >
              <option value={7}>Data range: last 7 days</option>
              <option value={30}>Data range: last 30 days</option>
              <option value={90}>Data range: last 90 days</option>
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="loading-message">데이터를 불러오는 중...</div>
      ) : (
        <>
          {/* 주요 지표 카드 */}
          <div className="dashboard-stats-grid">
            <div className="stat-card primary">
              <div className="stat-content">
                <div className="stat-number">{userStats?.userStats?.total_users || 0}</div>
                <div className="stat-label">MCP Server Users</div>
              </div>
            </div>
            <div className="stat-card secondary">
              <div className="stat-content">
                <div className="stat-number">{userStats?.inactiveUsers || 0}</div>
                <div className="stat-label">Inactive Users (30d)</div>
              </div>
            </div>
            <div className="stat-card tool-card">
              <div className="stat-content">
                <div className="stat-number">{userStats?.outdatedServers || 0}</div>
                <div className="stat-label">Outdated Servers</div>
              </div>
            </div>
            <div className="stat-card tool-card">
              <div className="stat-content">
                <div className="stat-number">{userStats?.pendingRequests || 0}</div>
                <div className="stat-label">Pending Requests</div>
              </div>
            </div>
          </div>

          {/* MCP 서버 통계 섹션 */}
          {mcpServerStats && (
            <div className="dashboard-content-grid">
              <div className="content-card mcp-servers-overview">
                <div className="mcp-servers-header">
                  <h3>MCP servers by category</h3>
                  <div className="mcp-servers-total">{mcpServerStats.total}</div>
                </div>
                <div className="category-bars">
                  {mcpServerStats.categories.map((category, index) => (
                    <div key={index} className="category-bar-item">
                      <div className="category-label-row">
                        <span className="category-name">{category.name}</span>
                        <span className="category-count">({category.count})</span>
                      </div>
                      <div className="bar-container">
                        <div 
                          className="bar-fill"
                          style={{ 
                            width: `${mcpServerStats.total > 0 ? (category.count / mcpServerStats.total) * 100 : 0}%`,
                            backgroundColor: category.color
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
                <div className="category-legend">
                  {mcpServerStats.categories.map((category, index) => (
                    <div key={index} className="legend-item">
                      <div 
                        className="legend-color" 
                        style={{ backgroundColor: category.color }}
                      />
                      <span className="legend-name">{category.name}</span>
                      <span className="legend-count">({category.count})</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* 원형 진행 표시기 */}
              <div className="content-card">
                <div className="donut-charts">
                  <div className="donut-card">
                    <div 
                      className="donut-chart" 
                      style={{ 
                        background: `conic-gradient(#FCD34D 0% ${mcpServerStats.stats.withCredentials.percent}%, #F3F4F6 ${mcpServerStats.stats.withCredentials.percent}% 100%)` 
                      }}
                    >
                      <div className="donut-inner">
                        <div className="donut-percentage">{mcpServerStats.stats.withCredentials.percent}%</div>
                        <div className="donut-label">With stored credentials</div>
                      </div>
                    </div>
                  </div>
                  <div className="donut-card">
                    <div 
                      className="donut-chart" 
                      style={{ 
                        background: `conic-gradient(#F59E0B 0% ${mcpServerStats.stats.withRisks.percent}%, #F3F4F6 ${mcpServerStats.stats.withRisks.percent}% 100%)` 
                      }}
                    >
                      <div className="donut-inner">
                        <div className="donut-percentage">{mcpServerStats.stats.withRisks.percent}%</div>
                        <div className="donut-label">With risks</div>
                      </div>
                    </div>
                  </div>
                  <div className="donut-card">
                    <div 
                      className="donut-chart" 
                      style={{ 
                        background: `conic-gradient(#EF4444 0% ${mcpServerStats.stats.withIssues.percent}%, #F3F4F6 ${mcpServerStats.stats.withIssues.percent}% 100%)` 
                      }}
                    >
                      <div className="donut-inner">
                        <div className="donut-percentage">{mcpServerStats.stats.withIssues.percent}%</div>
                        <div className="donut-label">With issues</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* MCP 서버 트래픽 */}
          <div className="dashboard-content-grid">
            <div className="content-card">
              <h3>MCP Server Traffic by Application</h3>
              <div className="traffic-bars">
                {trafficByApp.length > 0 ? (
                  trafficByApp.map((app, index) => (
                    <div key={index} className="traffic-bar-item">
                      <div className="traffic-label-row">
                        <span className="traffic-name">{app.app_name}</span>
                        <span className="traffic-count">{app.usage_count} requests</span>
                      </div>
                      <div className="bar-container">
                        <div 
                          className="bar-fill"
                          style={{ 
                            width: `${(app.usage_count / maxTraffic) * 100}%`,
                            backgroundColor: '#003153'
                          }}
                        />
                      </div>
                      <div className="traffic-meta">
                        <span>{app.unique_users} unique users</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="no-data">No traffic data available</div>
                )}
              </div>
            </div>

            {/* Host별 사용량 */}
            {trafficByHost.length > 0 && (
              <div className="content-card">
                <h3>Traffic by Host</h3>
                <div className="traffic-bars">
                  {trafficByHost.slice(0, 10).map((host, index) => (
                    <div key={index} className="traffic-bar-item">
                      <div className="traffic-label-row">
                        <span className="traffic-name">{host.host}</span>
                        <span className="traffic-count">{host.usage_count} requests</span>
                      </div>
                      <div className="bar-container">
                        <div 
                          className="bar-fill"
                          style={{ 
                            width: `${(host.usage_count / maxTraffic) * 100}%`,
                            backgroundColor: '#1866E1'
                          }}
                        />
                      </div>
                      <div className="traffic-meta">
                        <span>{host.unique_users} users, {host.unique_servers} servers</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 사용자 통계 및 원그래프 */}
          <div className="dashboard-content-grid">
            <div className="content-card">
              <h3>MCP Server User Distribution</h3>
              {donutSegments && donutSegments.length > 0 ? (
                <div className="donut-chart-container">
                  <div className="donut-chart-wrapper">
                    <svg width="200" height="200" viewBox="0 0 200 200">
                      {donutSegments.map((segment, index) => {
                        const startAngle = (segment.startPercent / 100) * 360 - 90;
                        const endAngle = (segment.endPercent / 100) * 360 - 90;
                        const largeArcFlag = segment.percent > 50 ? 1 : 0;
                        
                        const x1 = 100 + 70 * Math.cos((startAngle * Math.PI) / 180);
                        const y1 = 100 + 70 * Math.sin((startAngle * Math.PI) / 180);
                        const x2 = 100 + 70 * Math.cos((endAngle * Math.PI) / 180);
                        const y2 = 100 + 70 * Math.sin((endAngle * Math.PI) / 180);
                        
                        const pathData = [
                          `M 100 100`,
                          `L ${x1} ${y1}`,
                          `A 70 70 0 ${largeArcFlag} 1 ${x2} ${y2}`,
                          `Z`
                        ].join(' ');
                        
                        return (
                          <path
                            key={index}
                            d={pathData}
                            fill={segment.color}
                            stroke="#fff"
                            strokeWidth="2"
                          />
                        );
                      })}
                    </svg>
                    <div className="donut-inner">
                      <div className="donut-total">{userStats?.userStats?.total_users || 0}</div>
                      <div className="donut-label">Total Users</div>
                    </div>
                  </div>
                  <div className="donut-legend">
                    {donutSegments.map((segment, index) => (
                      <div key={index} className="legend-item">
                        <div 
                          className="legend-color" 
                          style={{ backgroundColor: segment.color }}
                        />
                        <span className="legend-name">{segment.server_name}</span>
                        <span className="legend-count">({segment.user_count})</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="no-data">No user distribution data</div>
              )}
            </div>

            {/* 취약점 통계 */}
            <div className="content-card">
              <h3>Vulnerability Statistics (30 days)</h3>
              {userStats?.vulnerabilityStats && userStats.vulnerabilityStats.length > 0 ? (
                <div className="vulnerability-stats">
                  {userStats.vulnerabilityStats.map((stat, index) => (
                    <div key={index} className="vulnerability-stat-item">
                      <div className="vuln-label-row">
                        <span className="vuln-type">{stat.violation_type}</span>
                        <span className="vuln-count">{stat.count}</span>
                      </div>
                      <div className="vuln-severity">
                        <span className={`severity-badge severity-${stat.severity}`}>
                          {stat.severity}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-data">No vulnerability data</div>
              )}
            </div>
          </div>

          {/* 트래픽 그래프 */}
          {trafficGraph.length > 0 && (
            <div className="content-card" style={{ marginBottom: '24px' }}>
              <h3>Traffic Graph (Last 30 Days)</h3>
              <div className="traffic-graph">
                <div className="graph-bars">
                  {trafficGraph.map((point, index) => {
                    const maxCount = Math.max(...trafficGraph.map(p => p.count));
                    return (
                      <div key={index} className="graph-bar">
                        <div 
                          className="graph-bar-fill"
                          style={{
                            height: `${(point.count / maxCount) * 100}%`,
                            backgroundColor: '#003153'
                          }}
                        />
                        <div className="graph-bar-label">{point.date}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* 실시간 탐지 결과 */}
          <div className="content-card detection-results">
            <h3>Real-time Detection Results</h3>
            <div className="detection-table-container">
              <table className="detection-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>User</th>
                    <th>MCP Server</th>
                    <th>Tool</th>
                    <th>Direction</th>
                    <th>Request/Response</th>
                    <th>Detection Tags</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {detections.length > 0 ? (
                    detections.map((detection, index) => (
                      <tr key={index}>
                        <td>{new Date(detection.timestamp).toLocaleString()}</td>
                        <td>
                          <div className="user-info">
                            <div>{detection.username || detection.employee_id || 'Unknown'}</div>
                            {detection.team && <div className="user-team">{detection.team}</div>}
                          </div>
                        </td>
                        <td>{detection.mcp_server_name || '-'}</td>
                        <td>{detection.tool_name || '-'}</td>
                        <td>
                          <span className={`direction-badge direction-${detection.direction}`}>
                            {detection.direction}
                          </span>
                        </td>
                        <td>
                          <div className="request-response">
                            {detection.request_content && (
                              <div className="content-item">
                                <strong>Request:</strong> 
                                <div className="content-text">{detection.request_content.substring(0, 100)}...</div>
                              </div>
                            )}
                            {detection.response_content && (
                              <div className="content-item">
                                <strong>Response:</strong> 
                                <div className="content-text">{detection.response_content.substring(0, 100)}...</div>
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="detection-tags">
                            {detection.detection_tags && detection.detection_tags.map((tag, tagIndex) => (
                              <span
                                key={tagIndex}
                                className="detection-tag"
                                style={{ backgroundColor: getDetectionTagColor(tag) }}
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <span className={`severity-badge severity-${detection.severity}`}>
                            {detection.severity}
                          </span>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="8" style={{ textAlign: 'center', padding: '20px', color: '#666' }}>
                        No detection results available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
