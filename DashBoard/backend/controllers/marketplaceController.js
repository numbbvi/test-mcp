const mcpServerModel = require('../models/mcpServer');
const mcpRequestModel = require('../models/mcpRequest');
const db = require('../config/db');
const { scanGitHubForTools } = require('../utils/githubToolScanner');
const { scanToolsFromRequest, getToolsFromSshServer, getToolsFromMcpServer } = require('../utils/mcpToolScanner');
const { scanToolsFromSandbox } = require('../utils/mcpSandboxScanner');

const marketplaceController = {
  // MCP 서버 목록 조회 (팀별 필터링, 페이징, status 필터링)
  // mcp_servers와 mcp_register_requests를 모두 포함
  getMcpServers: (req, res) => {
    try {
      // 쿼리 파라미터에서 사용자 팀 정보 받기
      const userTeam = req.query.team || null;
      const status = req.query.status || null; // 'all', 'pending', 'approved' 등
      const { page = 1, limit = 12 } = req.query;
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      const offset = (pageNum - 1) * limitNum;
      
      let servers = [];
      let total;
      
      // status 필터링
      let statusFilter = null;
      if (status && status !== 'all') {
        statusFilter = status; // 'pending' 또는 'approved'
      }
      
      // 1. mcp_servers 테이블에서 서버 조회
      let approvedServers = [];
      if (userTeam) {
        // 특정 팀이 접근 가능한 서버만 조회
        let teamServers = mcpServerModel.findByTeam(userTeam);
        
        // status 필터링 적용
        if (statusFilter) {
          teamServers = teamServers.filter(server => server.status === statusFilter);
        }
        approvedServers = teamServers;
      } else {
        // 팀 정보가 없으면 모든 서버 조회 (관리자 등)
        approvedServers = mcpServerModel.findAll(statusFilter);
      }
      
      // 2. mcp_register_requests 테이블에서 서버 조회 (Register Board의 서버들)
      // MCP Registry에서는 승인된 서버만 표시하므로, register_requests는 제외
      // (register_requests는 Register Board에서만 사용)
      let registerRequests = [];
      // status가 명시적으로 'all'이거나 null이면 모든 요청 조회 (Risk Assessment 등에서 사용)
      // MCP Registry는 status=approved를 전달하므로 register_requests는 비어있음
      if (statusFilter === 'approved') {
        // 승인된 요청만 (mcp_servers에 이미 승인되어 있으므로 제외)
        registerRequests = [];
      } else if (statusFilter === 'all' || !statusFilter) {
        // status가 'all'이거나 없으면 모든 요청 조회 (Risk Assessment 등에서 사용)
        registerRequests = mcpRequestModel.findAll();
      } else {
        // 특정 status 필터 (예: 'pending')
        registerRequests = mcpRequestModel.findAll(statusFilter);
      }
      
      // 3. 두 목록을 합치기 (중복 제거: name 기준)
      const serverMap = new Map();
      
      // mcp_servers 추가
      approvedServers.forEach(server => {
        serverMap.set(server.name, {
          id: `server_${server.id}`,
          name: server.name,
          description: server.description,
          short_description: server.short_description,
          status: server.status,
          github_link: server.github_link,
          file_path: server.file_path,
          analysis_timestamp: server.analysis_timestamp || null,
          source: 'mcp_servers'
        });
      });
      
      // mcp_register_requests 추가 (중복되지 않는 경우만)
      registerRequests.forEach(request => {
        if (!serverMap.has(request.name)) {
          serverMap.set(request.name, {
            id: `request_${request.id}`,
            name: request.name,
            description: request.description,
            short_description: null,
            status: request.status,
            github_link: request.github_link,
            file_path: request.file_path,
            analysis_timestamp: request.analysis_timestamp || null,
            source: 'mcp_register_requests'
          });
        }
      });
      
      // Map을 배열로 변환
      servers = Array.from(serverMap.values());
      
      // status 필터링 재적용 (합친 후)
      if (statusFilter) {
        servers = servers.filter(server => server.status === statusFilter);
      }
      
      total = servers.length;
      
      // 페이징 적용
      servers = servers.slice(offset, offset + limitNum);
      
      // 각 서버의 최신 분석 시간 및 통계 조회
      const list = servers.map(({ id, name, description, short_description, status, github_link, file_path, analysis_timestamp: existing_timestamp }) => {
        // 이미 analysis_timestamp가 있으면 사용, 없으면 code_vulnerabilities에서 조회
        let analysis_timestamp = existing_timestamp || null;
        const scanPath = github_link || file_path;
        
        // 패키지 개수 및 코드 취약점 개수 초기화
        let package_count = 0;
        let code_vulnerability_count = 0;
        
        // scanPath가 있으면 통계 조회
        if (scanPath) {
          try {
            // 서버 이름 추출 (매칭용)
            const pathParts = scanPath.split('/');
            const serverName = pathParts.length > 0 ? pathParts[pathParts.length - 1].replace(/\.git$/, '') : '';
            
            // 정확한 매칭 먼저 시도
            try {
              // 코드 취약점 개수 조회 (정확한 매칭)
              const codeVulnStmt = db.prepare(`
                SELECT COUNT(*) as count
                FROM code_vulnerabilities
                WHERE scan_path = ?
              `);
              const codeVulnCount = codeVulnStmt.get(scanPath);
              
              if (codeVulnCount && codeVulnCount.count > 0) {
                code_vulnerability_count = codeVulnCount.count;
                
                // 최신 scan_timestamp 조회
                const latestScanStmt = db.prepare(`
                  SELECT MAX(scan_timestamp) as latest_timestamp 
                  FROM code_vulnerabilities 
                  WHERE scan_path = ?
                `);
                const latestScan = latestScanStmt.get(scanPath);
                if (latestScan && latestScan.latest_timestamp) {
                  analysis_timestamp = latestScan.latest_timestamp;
                }
              }
              
              // 패키지 개수 조회 (정확한 매칭)
              const packageStmt = db.prepare(`
                SELECT COUNT(DISTINCT package_name) as count
                FROM oss_vulnerabilities
                WHERE scan_path = ?
                  AND package_name IS NOT NULL 
                  AND package_name != ''
              `);
              const packageCount = packageStmt.get(scanPath);
              
              if (packageCount && packageCount.count > 0) {
                package_count = packageCount.count;
              }
            } catch (exactError) {
              // 정확한 매칭 실패 시 무시
            }
            
            // 정확한 매칭이 실패하면 부분 매칭 시도
            if (code_vulnerability_count === 0 && package_count === 0 && serverName) {
              try {
                // 서버 이름으로 부분 매칭
                const likePattern = `%${serverName}%`;
                
                // 코드 취약점 개수 조회
                const codeVulnStmt = db.prepare(`
                  SELECT COUNT(*) as count
                  FROM code_vulnerabilities
                  WHERE scan_path LIKE ?
                `);
                const codeVulnCount = codeVulnStmt.get(likePattern);
                
                if (codeVulnCount && codeVulnCount.count > 0) {
                  code_vulnerability_count = codeVulnCount.count;
                  
                  // 최신 scan_timestamp 조회
                  const latestScanStmt = db.prepare(`
                    SELECT MAX(scan_timestamp) as latest_timestamp 
                    FROM code_vulnerabilities 
                    WHERE scan_path LIKE ?
                  `);
                  const latestScan = latestScanStmt.get(likePattern);
                  if (latestScan && latestScan.latest_timestamp) {
                    analysis_timestamp = latestScan.latest_timestamp;
                  }
                }
                
                // 패키지 개수 조회
                const packageStmt = db.prepare(`
                  SELECT COUNT(DISTINCT package_name) as count
                  FROM oss_vulnerabilities
                  WHERE scan_path LIKE ?
                    AND package_name IS NOT NULL 
                    AND package_name != ''
                `);
                const packageCount = packageStmt.get(likePattern);
                
                if (packageCount && packageCount.count > 0) {
                  package_count = packageCount.count;
                }
              } catch (likeError) {
                // 부분 매칭 실패 시 무시
              }
            }
          } catch (e) {
            // 조회 실패 시 무시
            console.error('통계 조회 실패:', e.message);
          }
        }
        
        return {
        id: id.toString(),
        name,
          description: description || short_description || '', // 상세 페이지용
          short_description: short_description || description || '', // 카드 표지용
          status, // status 필드 추가
          github_link, // GitHub 링크 추가
          file_path: file_path || null, // 파일 경로 추가
          analysis_timestamp: analysis_timestamp || null, // 분석 시간 추가
          package_count: package_count || 0, // 패키지 개수
          code_vulnerability_count: code_vulnerability_count || 0 // 코드 취약점 개수
        };
      });
      
      res.json({
        success: true,
        data: list,
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: total,
          totalPages: Math.ceil(total / limitNum)
        }
      });
    } catch (error) {
      console.error('MCP 서버 목록 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '서버 목록을 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버 상세 조회
  getMcpServerDetail: (req, res) => {
    try {
      const { id } = req.params;
      const server = mcpServerModel.findById(parseInt(id));
      
      if (!server) {
        return res.status(404).json({
          success: false,
          message: 'MCP Server not found'
        });
      }
      
      res.json({
        success: true,
        data: {
          id: server.id.toString(),
          title: server.name,
          description: server.description,
          connectionSnippet: server.connection_snippet,
          file_path: server.file_path
        }
      });
    } catch (error) {
      console.error('MCP 서버 상세 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '서버 정보를 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버 등록 요청
  createMcpRequest: (req, res) => {
    try {
      const { name, description, connection, github, user_id } = req.body;
      
      // 필수 필드 검증
      if (!name || !name.trim()) {
        return res.status(400).json({
          success: false,
          message: 'MCP Server Name은 필수입니다.'
        });
      }
      
      if (!description || !description.trim()) {
        return res.status(400).json({
          success: false,
          message: 'MCP Server Description은 필수입니다.'
        });
      }
      
      if (!connection || !connection.trim()) {
        return res.status(400).json({
          success: false,
          message: 'Connection은 필수입니다.'
        });
      }
      
      // GitHub 링크나 파일 중 하나는 반드시 있어야 함
      const files = req.files || {};
      const hasFile = files.file && files.file[0];
      const hasGithub = github && github.trim();
      
      if (!hasGithub && !hasFile) {
        return res.status(400).json({
          success: false,
          message: 'Github Link 또는 File Upload 중 하나는 필수입니다.'
        });
      }
      
      // 사용자 ID 확인
      if (!user_id) {
        return res.status(400).json({
          success: false,
          message: '사용자 정보가 필요합니다. 로그인해주세요.'
        });
      }
      
      // 서버 이름 중복 체크 (mcp_servers와 mcp_register_requests 모두 확인)
      const trimmedName = name.trim();
      const existingServer = db.prepare(`
        SELECT name FROM mcp_servers WHERE name = ?
      `).get(trimmedName);
      
      const existingRequest = db.prepare(`
        SELECT name FROM mcp_register_requests WHERE name = ?
      `).get(trimmedName);
      
      if (existingServer || existingRequest) {
        return res.status(400).json({
          success: false,
          message: `이미 존재하는 MCP 서버 이름입니다: "${trimmedName}". 다른 이름을 사용해주세요.`
        });
      }
      
      // 파일 업로드 처리 (multer 미들웨어로 처리됨)
      // req.files는 fields()를 사용할 때 배열 형태
      const filePath = files.file && files.file[0] ? `/uploads/${files.file[0].filename}` : null;
      const imagePath = files.image && files.image[0] ? `/uploads/${files.image[0].filename}` : null;
      
      // 사용자 ID 사용 (req.user는 추후 JWT 토큰으로 대체)
      const requestedBy = parseInt(user_id);
      const title = name; // 제목은 이름과 동일하게 설정
      const connectionSnippet = connection || null;
      
      const request = mcpRequestModel.create(title, name, description, connectionSnippet, github, filePath, requestedBy, 'normal', imagePath);
      
      res.json({
        success: true,
        message: '등록 요청이 접수되었습니다.',
        data: {
          id: request.id,
          title: request.title,
          name: request.name,
          description: request.description,
          github: request.github_link,
          status: request.status,
          priority: request.priority,
          image_path: request.image_path
        }
      });
    } catch (error) {
      console.error('등록 요청 오류:', error);
      console.error('오류 스택:', error.stack);
      res.status(500).json({
        success: false,
        message: `등록 요청 중 오류가 발생했습니다: ${error.message || error.toString()}`
      });
    }
  },

  // 등록 요청 목록 조회 (게시판 형태, 역할별 필터링)
  getMcpRequests: (req, res) => {
    try {
      const { status, page = 1, limit = 20 } = req.query;
      const pageNum = parseInt(page);
      const limitNum = parseInt(limit);
      
      // 사용자 정보 가져오기 (JWT 미들웨어에서 설정됨)
      const user = req.user;
      if (!user) {
        return res.status(401).json({
          success: false,
          message: '인증이 필요합니다.'
        });
      }

      // 역할 확인
      const userRoles = user.roles || [];
      const isAdmin = userRoles.includes('admin');
      const isManager = userRoles.includes('manager');
      
      // 역할에 따라 필터링 파라미터 설정
      let userId = null;
      let userTeam = null;
      
      if (isAdmin) {
        // admin: 모든 요청 보기
        userId = null;
        userTeam = null;
      } else if (isManager) {
        // manager: 자신의 팀에서 신청한 것만
        userTeam = user.team;
        userId = null;
      } else {
        // user: 자신이 신청한 것만
        userId = user.id;
        userTeam = null;
      }
      
      // status가 'approved'인 경우, mcp_servers 테이블과 JOIN하여 실제로 생성된 것만 조회
      let result;
      if (status === 'approved') {
        // 승인된 요청 중 mcp_servers에 실제로 생성된 것만 조회
        const offset = (pageNum - 1) * limitNum;
        let countQuery, dataQuery, params = [];
        
        const conditions = ['mr.status = ?'];
        params.push('approved');
        
        if (userId !== null) {
          conditions.push('mr.requested_by = ?');
          params.push(userId);
        } else if (userTeam !== null) {
          conditions.push(`mr.requested_by IN (SELECT id FROM users WHERE team = ?)`);
          params.push(userTeam);
        }
        
        // mcp_servers와 JOIN하여 실제로 생성된 것만
        conditions.push('ms.name = mr.name');
        conditions.push('ms.status = ?');
        params.push('approved');
        
        const whereClause = `WHERE ${conditions.join(' AND ')}`;
        
        countQuery = `
          SELECT COUNT(*) as total 
          FROM mcp_register_requests mr
          INNER JOIN mcp_servers ms ON ms.name = mr.name AND ms.status = 'approved'
          ${whereClause}
        `;
        dataQuery = `
          SELECT mr.* 
          FROM mcp_register_requests mr
          INNER JOIN mcp_servers ms ON ms.name = mr.name AND ms.status = 'approved'
          ${whereClause}
          ORDER BY mr.created_at DESC 
          LIMIT ? OFFSET ?
        `;
        
        params.push(limitNum, offset);
        
        const totalResult = db.prepare(countQuery).get(...params.slice(0, -2));
        const total = totalResult.total;
        const data = db.prepare(dataQuery).all(...params);
        
        result = {
          data,
          pagination: {
            page: pageNum,
            limit: limitNum,
            total: total,
            totalPages: Math.ceil(total / limitNum)
          }
        };
      } else {
        result = mcpRequestModel.findAllPaginated(status || null, pageNum, limitNum, userId, userTeam);
      }
      
      // 요청자 정보 포함
      const requestsWithUser = result.data.map(request => {
        const requester = db.prepare('SELECT id, username, employee_id, team, position FROM users WHERE id = ?').get(request.requested_by);
        const reviewer = request.reviewed_by 
          ? db.prepare('SELECT id, username, employee_id FROM users WHERE id = ?').get(request.reviewed_by)
          : null;
        
        return {
          ...request,
          requester: requester,
          reviewer: reviewer
        };
      });
      
      res.json({
        success: true,
        data: requestsWithUser,
        pagination: result.pagination
      });
    } catch (error) {
      console.error('등록 요청 목록 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '요청 목록을 불러오는 중 오류가 발생했습니다.'
      });
    }
  },

  // 등록 요청 승인/거부 (관리자용)
  reviewRequest: (req, res) => {
    try {
      const { id } = req.params;
      const { status, review_comment, server_description } = req.body; // status: 'approved' or 'rejected'
      const reviewedBy = req.user?.id || null;
      
      if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({
          success: false,
          message: '유효하지 않은 상태입니다. (approved 또는 rejected)'
        });
      }
      
      // 먼저 요청 정보 조회
      const request = mcpRequestModel.findById(id);
      if (!request) {
        return res.status(404).json({
          success: false,
          message: '등록 요청을 찾을 수 없습니다.'
        });
      }
      
      // 승인된 경우 MCP 서버로 승격 (mcp_servers에 생성 먼저)
      if (status === 'approved') {
          // description: 요청자가 입력한 원본 설명 (상세 페이지용)
          // short_description: 관리자가 입력한 설명 (카드 표지용)
          const finalShortDescription = server_description || request.description || '';
          
          // allowed_teams: 관리자가 선택한 팀 목록
          const allowedTeams = req.body.allowed_teams || null; // 배열 형태로 전달받음
          
          // tools: 관리자가 입력한 Tool 목록
          // 형식 1: ["tool1", "tool2"] - 단순 배열
          // 형식 2: [{ name: "tool1", allowed_teams: ["Developer"] }, ...] - 상세 정보
          let tools = req.body.tools || null;
          let toolNames = null; // DB에 저장할 Tool 이름 배열
          
          if (tools && Array.isArray(tools) && tools.length > 0) {
            // 첫 번째 요소가 객체인지 문자열인지 확인
            if (typeof tools[0] === 'object' && tools[0].name) {
              // 상세 형식: Tool 이름만 추출
              toolNames = tools.map(tool => tool.name);
            } else {
              // 단순 배열 형식: 그대로 사용
              toolNames = tools;
            }
          }
          
        // 중복 이름 체크 (이미 같은 이름의 승인된 서버가 있는지 확인)
        const existingServer = db.prepare('SELECT id FROM mcp_servers WHERE name = ? AND status = ?').get(request.name, 'approved');
        if (existingServer) {
          // 이미 존재하는 경우, 기존 서버 정보 업데이트
          console.log(`서버가 이미 존재합니다: ${request.name}, 기존 서버 업데이트`);
          const updateStmt = db.prepare(`
            UPDATE mcp_servers 
            SET description = ?, short_description = ?, github_link = ?, connection_snippet = ?, file_path = ?, allowed_teams = ?, tools = ?, updated_at = datetime('now', '+9 hours')
            WHERE name = ? AND status = ?
          `);
          const allowedTeamsJson = allowedTeams ? JSON.stringify(allowedTeams) : null;
          const toolsJson = toolNames ? JSON.stringify(toolNames) : null;
          updateStmt.run(
            request.description || '',
            finalShortDescription,
            request.github_link,
            request.connection_snippet || null,
            request.file_path,
            allowedTeamsJson,
            toolsJson,
            request.name,
            'approved'
          );
          var server = { id: existingServer.id, name: request.name };
        } else {
          // MCP 서버 생성 (Tool 이름만 저장)
          var server = mcpServerModel.create(
            request.name,
            request.description || '', // 원본 설명 유지
            finalShortDescription,      // 관리자 설명을 카드 표지용으로 저장
            request.github_link,
            request.connection_snippet || null,
            request.file_path,
            request.requested_by,
            allowedTeams,              // 팀 접근 권한
            toolNames                  // Tool 이름 목록만 저장
          );
        }

          // Tool별 팀 권한 저장 (mcp_tool_team_permissions)
          // tools는 원본 req.body.tools (Tool별 팀 권한 정보 포함)
          if (tools && Array.isArray(tools) && tools.length > 0 && reviewedBy) {
            const toolTeamPermStmt = db.prepare(`
              INSERT INTO mcp_tool_team_permissions 
              (mcp_server_id, tool_name, team, permission_type, created_by)
              VALUES (?, ?, ?, ?, ?)
            `);

            // tools는 Tool별 팀 권한 정보를 포함할 수 있음
            // 형식 1: ["tool1", "tool2"] - 단순 배열
            // 형식 2: [{ name: "tool1", allowed_teams: ["Developer"] }, ...] - 상세 정보
            if (Array.isArray(tools) && tools.length > 0) {
              // 첫 번째 요소가 객체인지 문자열인지 확인
              if (typeof tools[0] === 'object' && tools[0].name) {
                // 상세 형식: Tool별 팀 권한 설정
                tools.forEach(tool => {
                  if (tool.name && tool.allowed_teams && Array.isArray(tool.allowed_teams) && tool.allowed_teams.length > 0) {
                    tool.allowed_teams.forEach(team => {
                      try {
                        toolTeamPermStmt.run(
                          server.id,
                          tool.name,
                          team,
                          'allow',
                          reviewedBy
                        );
                      } catch (e) {
                        // UNIQUE 제약조건 위반 시 무시 (이미 존재)
                        console.log(`Tool 권한 저장 건너뜀: ${tool.name} - ${team}`);
                      }
                    });
                  }
                });
              } else {
                // 단순 배열 형식: 모든 Tool에 allowed_teams 적용
                const teams = allowedTeams || [];
                if (teams.length > 0) {
                  tools.forEach(toolName => {
                    teams.forEach(team => {
                      try {
                        toolTeamPermStmt.run(
                          server.id,
                          toolName,
                          team,
                          'allow',
                          reviewedBy
                        );
                      } catch (e) {
                        // UNIQUE 제약조건 위반 시 무시
                        console.log(`Tool 권한 저장 건너뜀: ${toolName} - ${team}`);
                      }
                    });
                  });
                }
              }
            }
          }
        
        // mcp_servers 생성/업데이트가 성공한 후에만 mcp_register_requests의 status 업데이트
        mcpRequestModel.updateStatus(id, status, reviewedBy, review_comment);
      } else {
        // 거부된 경우는 바로 status 업데이트
        mcpRequestModel.updateStatus(id, status, reviewedBy, review_comment);
      }
      
      res.json({
        success: true,
        message: `요청이 ${status === 'approved' ? '승인' : '거부'}되었습니다.`
      });
    } catch (error) {
      console.error('요청 검토 오류:', error);
      res.status(500).json({
        success: false,
        message: '요청 검토 중 오류가 발생했습니다.'
      });
    }
  },

  // GitHub 링크 또는 등록 요청에서 Tool 목록 스캔 (Sandbox만 사용)
  scanGitHubTools: async (req, res) => {
    try {
      const { github_url, request_id, use_sandbox } = req.query;

      // 등록 요청 ID가 있으면 요청 정보로 스캔
      if (request_id) {
        const request = mcpRequestModel.findById(parseInt(request_id));
        if (!request) {
          return res.status(404).json({
            success: false,
            message: '등록 요청을 찾을 수 없습니다.'
          });
        }

        // Sandbox 스캔만 사용
        if (use_sandbox === 'true' && request.github_link) {
          try {
            console.log('🔒 Sandbox 스캔 시작:', request.github_link);
            const result = await scanToolsFromSandbox(request.github_link);
            return res.json({
              success: true,
              data: {
                tools: result.tools,
                toolDetails: result.toolDetails || [],
                method: result.method || 'sandbox_docker',
                repository: result.repository,
                branch: result.branch,
                commitSha: result.commitSha,
                runCommand: result.runCommand,
                runType: result.runType,
                files: []
              }
            });
          } catch (error) {
            console.error('Sandbox 스캔 실패:', error.message);
            return res.status(500).json({
              success: false,
              message: error.message || 'Sandbox 스캔 중 오류가 발생했습니다.',
              data: {
                tools: [],
                files: [],
                repository: null,
                branch: null,
                method: 'none'
              }
            });
          }
        }

        return res.status(400).json({
          success: false,
          message: 'GitHub 링크가 필요합니다.'
        });
      }

      // GitHub URL만 있는 경우
      if (!github_url) {
        return res.status(400).json({
          success: false,
          message: 'github_url 또는 request_id 파라미터가 필요합니다.'
        });
      }

      // Sandbox 스캔만 사용
      if (use_sandbox === 'true') {
        try {
          console.log('🔒 Sandbox 스캔 시작:', github_url);
          const result = await scanToolsFromSandbox(github_url);
          return res.json({
            success: true,
            data: {
              tools: result.tools,
              toolDetails: result.toolDetails || [],
              method: result.method || 'sandbox_docker',
              repository: result.repository,
              branch: result.branch,
              commitSha: result.commitSha,
              runCommand: result.runCommand,
              runType: result.runType,
              files: []
            }
          });
        } catch (error) {
          console.error('Sandbox 스캔 실패:', error.message);
          return res.status(500).json({
            success: false,
            message: error.message || 'Sandbox 스캔 중 오류가 발생했습니다.',
            data: {
              tools: [],
              files: [],
              repository: null,
              branch: null,
              method: 'none'
            }
          });
        }
      }

      return res.status(400).json({
        success: false,
        message: 'use_sandbox=true 파라미터가 필요합니다.'
      });
    } catch (error) {
      console.error('Tool 스캔 오류:', error);
      res.status(500).json({
        success: false,
        message: error.message || 'Tool 스캔 중 오류가 발생했습니다.',
        data: {
          tools: [],
          files: [],
          repository: null,
          branch: null,
          method: 'none'
        }
      });
    }
  },

  // 등록 요청 삭제 (관리자 또는 요청자 본인)
  deleteMcpRequest: (req, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.id || null;
      
      // 요청 정보 조회
      const request = mcpRequestModel.findById(id);
      if (!request) {
        return res.status(404).json({
          success: false,
          message: '등록 요청을 찾을 수 없습니다.'
        });
      }
      
      // 권한 확인: 관리자이거나 요청자 본인만 삭제 가능
      // req.user.roles는 배열이거나 객체일 수 있음
      let isAdmin = false;
      if (req.user?.roles) {
        if (Array.isArray(req.user.roles)) {
          isAdmin = req.user.roles.some(role => 
            (typeof role === 'string' && role === 'admin') || 
            (typeof role === 'object' && role.name === 'admin')
          );
        } else if (req.user.roles === 'admin' || req.user.role === 'admin') {
          isAdmin = true;
        }
      }
      // role 필드도 확인 (하위 호환성)
      if (!isAdmin && (req.user?.role === 'admin')) {
        isAdmin = true;
      }
      const isOwner = userId && request.requested_by === userId;
      
      if (!isAdmin && !isOwner) {
        return res.status(403).json({
          success: false,
          message: '삭제 권한이 없습니다. 관리자이거나 요청자 본인만 삭제할 수 있습니다.'
        });
      }
      
      // 승인된 요청인 경우 관련 MCP 서버도 삭제할지 확인
      if (request.status === 'approved') {
        const db = require('../config/db');
        const relatedServer = db.prepare('SELECT id FROM mcp_servers WHERE name = ? AND status = ?').get(request.name, 'approved');
        if (relatedServer) {
          // 관련 서버도 함께 삭제
          mcpServerModel.delete(relatedServer.id);
        }
      }
      
      // 등록 요청 삭제
      const result = mcpRequestModel.delete(id);
      
      if (result.changes === 0) {
        return res.status(404).json({
          success: false,
          message: '등록 요청을 찾을 수 없습니다.'
        });
      }
      
      res.json({
        success: true,
        message: '등록 요청이 삭제되었습니다.'
      });
    } catch (error) {
      console.error('등록 요청 삭제 오류:', error);
      res.status(500).json({
        success: false,
        message: '등록 요청 삭제 중 오류가 발생했습니다.'
      });
    }
  },

  // MCP 서버 삭제 (관리자용)
  deleteMcpServer: (req, res) => {
    try {
      const { id } = req.params;
      const server = mcpServerModel.findById(parseInt(id));
      
      if (!server) {
        return res.status(404).json({
          success: false,
          message: 'MCP 서버를 찾을 수 없습니다.'
        });
      }

      // 서버 삭제 전에 관련된 등록 요청 찾기
      // 이름과 생성자로 매칭하여 승인된 요청 찾기
      const db = require('../config/db');
      const relatedRequest = db.prepare(`
        SELECT id FROM mcp_register_requests 
        WHERE name = ? AND requested_by = ? AND status = 'approved'
        ORDER BY created_at DESC
        LIMIT 1
      `).get(server.name, server.created_by);

      // MCP 서버 삭제
      mcpServerModel.delete(parseInt(id));

      // 관련된 등록 요청도 삭제
      if (relatedRequest) {
        mcpRequestModel.delete(relatedRequest.id);
      }
      
      res.json({
        success: true,
        message: 'MCP 서버와 관련 등록 요청이 삭제되었습니다.'
      });
    } catch (error) {
      console.error('MCP 서버 삭제 오류:', error);
      res.status(500).json({
        success: false,
        message: '서버 삭제 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = marketplaceController;

