const db = require('../config/db');
const { getKoreaTimeSQLite } = require('../utils/dateTime');
const dlpLogModel = require('../models/dlpLog');

const dashboardController = {
  // MCP 서버 트래픽 통계 (앱별 사용량)
  getMcpTrafficByApp: (req, res) => {
    try {
      const { days = 7 } = req.query;
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      // 한국 시간으로 변환 (UTC+9)
      const koreaStartDate = new Date(startDate.getTime() + (9 * 60 * 60 * 1000));
      const koreaStartDateStr = koreaStartDate.toISOString().replace('T', ' ').substring(0, 19);

      const query = `
        SELECT 
          ms.name as app_name,
          ms.id as server_id,
          COUNT(utl.id) as usage_count,
          COUNT(DISTINCT utl.user_id) as unique_users
        FROM mcp_tool_usage_logs utl
        JOIN mcp_servers ms ON utl.mcp_server_id = ms.id
        WHERE utl.used_at >= ?
        GROUP BY ms.id, ms.name
        ORDER BY usage_count DESC
      `;

      const traffic = db.prepare(query).all(koreaStartDateStr);
      
      res.json({
        success: true,
        data: traffic
      });
    } catch (error) {
      console.error('MCP 트래픽 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '트래픽 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // Host별 사용량
  getMcpTrafficByHost: (req, res) => {
    try {
      const { days = 7 } = req.query;
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - parseInt(days));
      // 한국 시간으로 변환 (UTC+9)
      const koreaStartDate = new Date(startDate.getTime() + (9 * 60 * 60 * 1000));
      const koreaStartDateStr = koreaStartDate.toISOString().replace('T', ' ').substring(0, 19);

      const query = `
        SELECT 
          utl.ip_address as host,
          COUNT(utl.id) as usage_count,
          COUNT(DISTINCT utl.user_id) as unique_users,
          COUNT(DISTINCT utl.mcp_server_id) as unique_servers
        FROM mcp_tool_usage_logs utl
        WHERE utl.used_at >= ? AND utl.ip_address IS NOT NULL
        GROUP BY utl.ip_address
        ORDER BY usage_count DESC
        LIMIT 20
      `;

      const traffic = db.prepare(query).all(koreaStartDateStr);
      
      res.json({
        success: true,
        data: traffic
      });
    } catch (error) {
      console.error('Host별 트래픽 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'Host별 트래픽 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 실시간 탐지 결과 (DLP + RBAC)
  getDetectionResults: (req, res) => {
    try {
      const { limit = 50, offset = 0 } = req.query;
      
      // DLP 탐지 결과
      const dlpLogs = dlpLogModel.findAll({
        limit: parseInt(limit),
        offset: parseInt(offset)
      });

      // RBAC 위반 로그 (mcp_tool_usage_logs에서 권한 없는 사용 추출)
      // 실제로는 별도 테이블이 필요하지만, 현재는 mcp_tool_permissions와 비교
      const rbacViolations = db.prepare(`
        SELECT 
          utl.id,
          utl.user_id,
          u.username,
          u.employee_id,
          u.team,
          ms.name as mcp_server_name,
          utl.action as tool_name,
          utl.details,
          utl.used_at as timestamp,
          utl.ip_address,
          'RBAC' as detection_type
        FROM mcp_tool_usage_logs utl
        JOIN users u ON utl.user_id = u.id
        JOIN mcp_servers ms ON utl.mcp_server_id = ms.id
        LEFT JOIN mcp_tool_permissions mtp ON utl.user_id = mtp.user_id 
          AND utl.mcp_server_id = mtp.mcp_server_id
        WHERE mtp.id IS NULL
        ORDER BY utl.used_at DESC
        LIMIT ? OFFSET ?
      `).all(parseInt(limit), parseInt(offset));

      // DLP 로그를 탐지 결과 형식으로 변환
      const dlpDetections = dlpLogs.map(log => ({
        id: log.id,
        user_id: log.user_id,
        username: log.username,
        employee_id: log.employee_id,
        team: null, // DLP 로그에는 team 정보가 없을 수 있음
        mcp_server_name: null, // DLP 로그에는 서버 정보가 없을 수 있음
        tool_name: null,
        request_content: log.original_text || log.masked_text,
        response_content: log.original_json ? JSON.stringify(log.original_json) : null,
        direction: log.action_type === 'request' ? 'in' : 'out',
        detection_tags: [log.violation_type],
        detection_type: 'DLP',
        severity: log.severity,
        timestamp: log.timestamp
      }));

      // RBAC 위반을 탐지 결과 형식으로 변환
      const rbacDetections = rbacViolations.map(log => ({
        id: log.id,
        user_id: log.user_id,
        username: log.username,
        employee_id: log.employee_id,
        team: log.team,
        mcp_server_name: log.mcp_server_name,
        tool_name: log.tool_name,
        request_content: log.details,
        response_content: null,
        direction: 'in',
        detection_tags: ['RBAC Violation'],
        detection_type: 'RBAC',
        severity: 'high',
        timestamp: log.timestamp
      }));

      // 시간순으로 정렬하여 합치기
      const allDetections = [...dlpDetections, ...rbacDetections]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, parseInt(limit));

      res.json({
        success: true,
        data: allDetections,
        total: allDetections.length
      });
    } catch (error) {
      console.error('탐지 결과 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '탐지 결과 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 사용자 통계
  getUserStatistics: (req, res) => {
    try {
      // 1. MCP Server 사용자 수 (원그래프용)
      const userStats = db.prepare(`
        SELECT 
          COUNT(DISTINCT utl.user_id) as total_users,
          COUNT(DISTINCT CASE WHEN utl.used_at >= datetime('now', '-7 days') THEN utl.user_id END) as active_users_7d,
          COUNT(DISTINCT CASE WHEN utl.used_at >= datetime('now', '-30 days') THEN utl.user_id END) as active_users_30d
        FROM mcp_tool_usage_logs utl
      `).get();

      // 2. Health check 안 된 사용자 수 (최근 30일간 사용하지 않은 사용자)
      const inactiveUsers = db.prepare(`
        SELECT COUNT(DISTINCT u.id) as count
        FROM users u
        LEFT JOIN mcp_tool_usage_logs utl ON u.id = utl.user_id 
          AND utl.used_at >= datetime('now', '-30 days')
        WHERE u.is_active = 1 AND utl.id IS NULL
      `).get();

      // 3. 검증 날짜 오래된 MCP 서버 (30일 이상 업데이트 안 된 서버)
      const outdatedServers = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE updated_at < datetime('now', '-30 days')
          OR updated_at IS NULL
      `).get();

      // 4. 취약점 관련 통계 (DLP 위반 기준)
      const vulnerabilityStats = db.prepare(`
        SELECT 
          violation_type,
          COUNT(*) as count,
          severity
        FROM dlp_violation_logs
        WHERE timestamp >= datetime('now', '-30 days')
        GROUP BY violation_type, severity
      `).all();

      // 5. 트래픽 그래프 데이터 (시간별)
      const trafficGraph = db.prepare(`
        SELECT 
          DATE(used_at) as date,
          COUNT(*) as count
        FROM mcp_tool_usage_logs
        WHERE used_at >= datetime('now', '-30 days')
        GROUP BY DATE(used_at)
        ORDER BY date ASC
      `).all();

      // 6. 신청 들어온 MCP Server 수
      const pendingRequests = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_register_requests
        WHERE status = 'pending'
      `).get();

      res.json({
        success: true,
        data: {
          userStats,
          inactiveUsers: inactiveUsers.count,
          outdatedServers: outdatedServers.count,
          vulnerabilityStats,
          trafficGraph,
          pendingRequests: pendingRequests.count
        }
      });
    } catch (error) {
      console.error('사용자 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 통계 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버별 사용자 분포 (원그래프용)
  getMcpUserDistribution: (req, res) => {
    try {
      const query = `
        SELECT 
          ms.name as server_name,
          COUNT(DISTINCT utl.user_id) as user_count
        FROM mcp_servers ms
        LEFT JOIN mcp_tool_usage_logs utl ON ms.id = utl.mcp_server_id
          AND utl.used_at >= datetime('now', '-30 days')
        GROUP BY ms.id, ms.name
        HAVING user_count > 0
        ORDER BY user_count DESC
      `;

      const distribution = db.prepare(query).all();
      
      res.json({
        success: true,
        data: distribution
      });
    } catch (error) {
      console.error('MCP 서버별 사용자 분포 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '사용자 분포 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버 통계 (개수 및 카테고리별 분포)
  getMcpServerStats: (req, res) => {
    try {
      // 전체 MCP 서버 개수
      const totalServers = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved'
      `).get();

      // 카테고리별 분포 (현재는 description이나 name 기반으로 분류)
      // 실제 카테고리 필드가 없으므로 샘플 데이터로 구성
      // 추후 카테고리 필드가 추가되면 수정 필요
      const categories = [
        { name: 'Databases & Storage', count: 0, color: '#8B5CF6' },
        { name: 'Productivity & Workflow', count: 0, color: '#3B82F6' },
        { name: 'Coding Documentation', count: 0, color: '#14B8A6' },
        { name: 'Containerization & Orchestration', count: 0, color: '#F59E0B' },
        { name: 'Code Repositories & Versioning', count: 0, color: '#60A5FA' },
        { name: 'Project Management', count: 0, color: '#003153' }
      ];

      // 전체 서버를 카테고리별로 분류 (임시로 균등 분배)
      const total = totalServers.count || 0;
      const perCategory = Math.floor(total / categories.length);
      const remainder = total % categories.length;
      
      categories.forEach((cat, index) => {
        cat.count = perCategory + (index < remainder ? 1 : 0);
      });

      // 통계 정보
      const withCredentials = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved' AND connection_config IS NOT NULL
      `).get();

      const withRisks = db.prepare(`
        SELECT COUNT(DISTINCT ms.id) as count
        FROM mcp_servers ms
        JOIN dlp_violation_logs dlp ON ms.id = dlp.mcp_server_id
        WHERE ms.status = 'approved'
      `).get();

      const withIssues = db.prepare(`
        SELECT COUNT(*) as count
        FROM mcp_servers
        WHERE status = 'approved' AND updated_at < datetime('now', '-30 days')
      `).get();

      const credentialsPercent = total > 0 ? Math.round((withCredentials.count / total) * 100) : 0;
      const risksPercent = total > 0 ? Math.round((withRisks.count / total) * 100) : 0;
      const issuesPercent = total > 0 ? Math.round((withIssues.count / total) * 100) : 0;

      res.json({
        success: true,
        data: {
          total: total,
          categories: categories,
          stats: {
            withCredentials: {
              count: withCredentials.count,
              percent: credentialsPercent
            },
            withRisks: {
              count: withRisks.count,
              percent: risksPercent
            },
            withIssues: {
              count: withIssues.count,
              percent: issuesPercent
            }
          }
        }
      });
    } catch (error) {
      console.error('MCP 서버 통계 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'MCP 서버 통계 조회 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = dashboardController;

