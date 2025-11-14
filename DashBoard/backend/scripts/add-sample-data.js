#!/usr/bin/env node
/**
 * 샘플 데이터 추가 스크립트
 * - Users: 팀 2개, 각 팀에 2명씩
 * - MCP Registry: 2개
 * - Register Board: 승인됨 2개, 대기중 2개, 거부됨 2개
 * - DLP 데이터: 여러 개
 * - Download Logs: 여러 개
 * - Risk Assessment: 대기중인 서버 2개에 대해 OSS, Code, Tool, Total 정보
 */

const db = require('../config/db');

// 비밀번호 해시 함수 (간단한 버전 - 실제로는 bcrypt 사용)
function hashPassword(password) {
  // 실제 환경에서는 bcrypt를 사용해야 하지만, 샘플 데이터이므로 간단하게 처리
  // 실제로는: const bcrypt = require('bcryptjs'); return bcrypt.hashSync(password, 10);
  return password; // 샘플 데이터이므로 평문 사용 (실제 환경에서는 절대 금지!)
}

function getKoreaTime() {
  const now = new Date();
  const koreaTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
  return koreaTime.toISOString().replace('T', ' ').substring(0, 19);
}

async function addSampleData() {
  try {
    console.log('=== 샘플 데이터 추가 시작 ===\n');

    // 1. Users 추가 (팀 2개, 각 팀에 2명씩)
    console.log('[1/6] Users 추가 중...');
    const team1 = 'Development';
    const team2 = 'Security';
    
    const users = [
      { username: 'dev1', employee_id: 'EMP001', email: 'dev1@example.com', password: 'password123', team: team1, position: 'Developer' },
      { username: 'dev2', employee_id: 'EMP002', email: 'dev2@example.com', password: 'password123', team: team1, position: 'Senior Developer' },
      { username: 'sec1', employee_id: 'EMP003', email: 'sec1@example.com', password: 'password123', team: team2, position: 'Security Analyst' },
      { username: 'sec2', employee_id: 'EMP004', email: 'sec2@example.com', password: 'password123', team: team2, position: 'Security Engineer' }
    ];

    const userStmt = db.prepare(`
      INSERT OR IGNORE INTO users (username, employee_id, email, password, team, position, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const userIds = [];
    for (const user of users) {
      try {
        const result = userStmt.run(
          user.username,
          user.employee_id,
          user.email,
          hashPassword(user.password),
          user.team,
          user.position,
          getKoreaTime(),
          getKoreaTime()
        );
        if (result.lastInsertRowid) {
          userIds.push(result.lastInsertRowid);
          console.log(`  ✓ User 추가: ${user.username} (ID: ${result.lastInsertRowid})`);
        } else {
          // 이미 존재하는 경우 ID 조회
          const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(user.username);
          if (existing) {
            userIds.push(existing.id);
            console.log(`  - User 이미 존재: ${user.username} (ID: ${existing.id})`);
          }
        }
      } catch (error) {
        console.error(`  ✗ User 추가 실패: ${user.username}`, error.message);
      }
    }

    // 첫 번째 사용자를 admin으로 설정 (이미 존재하는 경우)
    const adminUser = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
    if (adminUser) {
      userIds.unshift(adminUser.id);
    } else {
      // admin 사용자 생성
      const adminResult = userStmt.run('admin', 'ADMIN001', 'admin@example.com', hashPassword('admin123'), 'Admin', 'Administrator', getKoreaTime(), getKoreaTime());
      if (adminResult.lastInsertRowid) {
        userIds.unshift(adminResult.lastInsertRowid);
        console.log(`  ✓ Admin User 추가: admin (ID: ${adminResult.lastInsertRowid})`);
      }
    }

    const [adminId, dev1Id, dev2Id, sec1Id, sec2Id] = userIds.length >= 5 ? userIds : [userIds[0], userIds[0], userIds[0], userIds[0], userIds[0]];

    // 2. MCP Registry (mcp_servers) 추가 - 2개
    console.log('\n[2/6] MCP Registry 추가 중...');
    const mcpServers = [
      {
        name: 'github-mcp-server',
        description: 'GitHub MCP Server for repository management and code operations',
        short_description: 'GitHub integration for code management',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/github',
        connection_snippet: 'npx -y @modelcontextprotocol/server-github GITHUB_TOKEN=your_token',
        status: 'approved',
        created_by: adminId
      },
      {
        name: 'notion-mcp-server',
        description: 'Notion MCP Server for workspace and page management',
        short_description: 'Notion workspace integration',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/notion',
        connection_snippet: 'npx -y @modelcontextprotocol/server-notion NOTION_API_KEY=your_key',
        status: 'approved',
        created_by: adminId
      }
    ];

    const mcpServerStmt = db.prepare(`
      INSERT OR IGNORE INTO mcp_servers (name, description, short_description, github_link, connection_snippet, status, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const mcpServerIds = [];
    for (const server of mcpServers) {
      try {
        const result = mcpServerStmt.run(
          server.name,
          server.description,
          server.short_description,
          server.github_link,
          server.connection_snippet,
          server.status,
          server.created_by,
          getKoreaTime(),
          getKoreaTime()
        );
        if (result.lastInsertRowid) {
          mcpServerIds.push(result.lastInsertRowid);
          console.log(`  ✓ MCP Server 추가: ${server.name} (ID: ${result.lastInsertRowid})`);
        } else {
          const existing = db.prepare('SELECT id FROM mcp_servers WHERE name = ?').get(server.name);
          if (existing) {
            mcpServerIds.push(existing.id);
            console.log(`  - MCP Server 이미 존재: ${server.name} (ID: ${existing.id})`);
          }
        }
      } catch (error) {
        console.error(`  ✗ MCP Server 추가 실패: ${server.name}`, error.message);
      }
    }

    // 3. Register Board (mcp_register_requests) 추가
    console.log('\n[3/6] Register Board 추가 중...');
    const registerRequests = [
      // 승인됨 2개
      {
        title: 'Slack MCP Server',
        name: 'slack-mcp-server',
        description: 'Slack integration for team communication',
        connection_snippet: 'npx -y @modelcontextprotocol/server-slack SLACK_TOKEN=your_token',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/slack',
        status: 'approved',
        requested_by: dev1Id,
        reviewed_by: adminId,
        review_comment: '승인되었습니다.',
        reviewed_at: getKoreaTime(),
        scanned: 1
      },
      {
        title: 'PostgreSQL MCP Server',
        name: 'postgresql-mcp-server',
        description: 'PostgreSQL database integration',
        connection_snippet: 'npx -y @modelcontextprotocol/server-postgres POSTGRES_CONNECTION_STRING=your_connection',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/postgres',
        status: 'approved',
        requested_by: dev2Id,
        reviewed_by: adminId,
        review_comment: '승인되었습니다.',
        reviewed_at: getKoreaTime(),
        scanned: 1
      },
      // 대기중 2개
      {
        title: 'AWS MCP Server',
        name: 'aws-mcp-server',
        description: 'AWS cloud services integration',
        connection_snippet: 'npx -y @modelcontextprotocol/server-aws AWS_ACCESS_KEY_ID=your_key AWS_SECRET_ACCESS_KEY=your_secret',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/aws',
        status: 'pending',
        requested_by: sec1Id,
        scanned: 1
      },
      {
        title: 'Docker MCP Server',
        name: 'docker-mcp-server',
        description: 'Docker container management',
        connection_snippet: 'npx -y @modelcontextprotocol/server-docker DOCKER_HOST=your_host',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/docker',
        status: 'pending',
        requested_by: sec2Id,
        scanned: 1
      },
      // 거부됨 2개
      {
        title: 'Redis MCP Server',
        name: 'redis-mcp-server',
        description: 'Redis cache integration',
        connection_snippet: 'npx -y @modelcontextprotocol/server-redis REDIS_URL=your_url',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/redis',
        status: 'rejected',
        requested_by: dev1Id,
        reviewed_by: adminId,
        review_comment: '보안 정책에 위배됩니다.',
        reviewed_at: getKoreaTime(),
        scanned: 0
      },
      {
        title: 'MongoDB MCP Server',
        name: 'mongodb-mcp-server',
        description: 'MongoDB database integration',
        connection_snippet: 'npx -y @modelcontextprotocol/server-mongodb MONGODB_URI=your_uri',
        github_link: 'https://github.com/modelcontextprotocol/servers/tree/main/src/mongodb',
        status: 'rejected',
        requested_by: dev2Id,
        reviewed_by: adminId,
        review_comment: '라이선스 문제로 거부되었습니다.',
        reviewed_at: getKoreaTime(),
        scanned: 0
      }
    ];

    const registerRequestStmt = db.prepare(`
      INSERT OR IGNORE INTO mcp_register_requests 
      (title, name, description, connection_snippet, github_link, status, requested_by, reviewed_by, review_comment, reviewed_at, scanned, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const pendingRequestIds = [];
    for (const request of registerRequests) {
      try {
        const result = registerRequestStmt.run(
          request.title,
          request.name,
          request.description,
          request.connection_snippet,
          request.github_link,
          request.status,
          request.requested_by,
          request.reviewed_by || null,
          request.review_comment || null,
          request.reviewed_at || null,
          request.scanned || 0,
          getKoreaTime(),
          getKoreaTime()
        );
        if (result.lastInsertRowid) {
          if (request.status === 'pending') {
            pendingRequestIds.push({ id: result.lastInsertRowid, name: request.name, github_link: request.github_link });
          }
          console.log(`  ✓ Register Request 추가: ${request.title} (${request.status})`);
        } else {
          const existing = db.prepare('SELECT id, status FROM mcp_register_requests WHERE name = ?').get(request.name);
          if (existing) {
            if (existing.status === 'pending') {
              pendingRequestIds.push({ id: existing.id, name: request.name, github_link: request.github_link });
            }
            console.log(`  - Register Request 이미 존재: ${request.title} (${existing.status})`);
          }
        }
      } catch (error) {
        console.error(`  ✗ Register Request 추가 실패: ${request.title}`, error.message);
      }
    }

    // 4. Risk Assessment 데이터 추가 (대기중인 서버 2개에 대해)
    console.log('\n[4/6] Risk Assessment 데이터 추가 중...');
    const riskAssessmentStmt = {
      code: db.prepare(`
        INSERT OR IGNORE INTO code_vulnerabilities 
        (scan_id, scan_path, scan_timestamp, rule_id, vulnerability, severity, language, file, line, column, message, description, cwe, code_snippet, pattern_type, pattern, confidence, raw_finding)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `),
      oss: db.prepare(`
        INSERT OR IGNORE INTO oss_vulnerabilities 
        (scan_id, scan_path, scan_timestamp, package_name, package_version, vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity, vulnerability_title, vulnerability_description, reachable, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `),
      tool: db.prepare(`
        INSERT OR IGNORE INTO tool_validation_vulnerabilities 
        (scan_id, scan_path, scan_timestamp, tool_name, host, method, path, category_code, category_name, title, description, evidence, recommendation, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
    };

    for (const pendingRequest of pendingRequestIds.slice(0, 2)) {
      const scanPath = pendingRequest.github_link || `https://github.com/example/${pendingRequest.name}`;
      const scanId = `scan_${pendingRequest.id}_${Date.now()}`;
      const scanTime = getKoreaTime();

      // Code vulnerabilities
      const codeVulns = [
        { rule_id: 'CWE-79', vulnerability: 'XSS', severity: 'high', language: 'JavaScript', file: 'src/index.js', line: 42, message: 'Potential XSS vulnerability', description: 'User input not sanitized', cwe: 'CWE-79' },
        { rule_id: 'CWE-89', vulnerability: 'SQL Injection', severity: 'critical', language: 'JavaScript', file: 'src/db.js', line: 15, message: 'SQL injection risk', description: 'Direct SQL query with user input', cwe: 'CWE-89' }
      ];

      for (const vuln of codeVulns) {
        try {
          riskAssessmentStmt.code.run(
            scanId, scanPath, scanTime, vuln.rule_id, vuln.vulnerability, vuln.severity,
            vuln.language, vuln.file, vuln.line, vuln.column || 0, vuln.message, vuln.description,
            vuln.cwe, null, null, null, null, JSON.stringify(vuln)
          );
        } catch (error) {
          console.error(`  ✗ Code vulnerability 추가 실패:`, error.message);
        }
      }

      // OSS vulnerabilities
      const ossVulns = [
        { package_name: 'express', package_version: '4.17.1', vulnerability_id: 'CVE-2022-24999', cve: 'CVE-2022-24999', cvss: 7.5, severity: 'high', title: 'Express.js vulnerability', description: 'Prototype pollution vulnerability', reachable: 1 },
        { package_name: 'lodash', package_version: '4.17.20', vulnerability_id: 'CVE-2021-23337', cve: 'CVE-2021-23337', cvss: 8.1, severity: 'high', title: 'Lodash vulnerability', description: 'Command injection vulnerability', reachable: 0 }
      ];

      for (const vuln of ossVulns) {
        try {
          riskAssessmentStmt.oss.run(
            scanId, scanPath, scanTime, vuln.package_name, vuln.package_version,
            vuln.vulnerability_id, vuln.cve, vuln.cvss, vuln.severity, vuln.title,
            vuln.description, vuln.reachable, JSON.stringify(vuln)
          );
        } catch (error) {
          console.error(`  ✗ OSS vulnerability 추가 실패:`, error.message);
        }
      }

      // Tool validation vulnerabilities
      const toolVulns = [
        { tool_name: 'api_endpoint', host: 'api.example.com', method: 'POST', path: '/v1/data', category_code: 'AUTH', category_name: 'Authentication', title: 'Missing authentication', description: 'API endpoint lacks authentication', evidence: 'No auth headers found', recommendation: 'Add API key authentication' },
        { tool_name: 'file_upload', host: 'storage.example.com', method: 'PUT', path: '/upload', category_code: 'FILE', category_name: 'File Upload', title: 'Unrestricted file upload', description: 'No file type validation', evidence: 'Accepts any file type', recommendation: 'Implement file type whitelist' }
      ];

      for (const vuln of toolVulns) {
        try {
          riskAssessmentStmt.tool.run(
            scanId, scanPath, scanTime, vuln.tool_name, vuln.host, vuln.method, vuln.path,
            vuln.category_code, vuln.category_name, vuln.title, vuln.description,
            vuln.evidence, vuln.recommendation, JSON.stringify(vuln)
          );
        } catch (error) {
          console.error(`  ✗ Tool vulnerability 추가 실패:`, error.message);
        }
      }

      console.log(`  ✓ Risk Assessment 데이터 추가: ${pendingRequest.name} (OSS: ${ossVulns.length}, Code: ${codeVulns.length}, Tool: ${toolVulns.length})`);
    }

    // 5. DLP 데이터 추가
    console.log('\n[5/6] DLP 데이터 추가 중...');
    const dlpStmt = db.prepare(`
      INSERT INTO dlp_violation_logs 
      (user_id, username, employee_id, source_ip, action_type, violation_type, severity, original_text, masked_text, status, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const dlpLogs = [
      { user_id: dev1Id, username: 'dev1', employee_id: 'EMP001', source_ip: '192.168.1.100', action_type: 'request', violation_type: 'PII', severity: 'high', original_text: 'John Doe, SSN: 123-45-6789', masked_text: 'John Doe, SSN: ***-**-****', status: 'pending' },
      { user_id: dev2Id, username: 'dev2', employee_id: 'EMP002', source_ip: '192.168.1.101', action_type: 'response', violation_type: 'Credit Card', severity: 'critical', original_text: 'Card: 4532-1234-5678-9010', masked_text: 'Card: ****-****-****-9010', status: 'pending' },
      { user_id: sec1Id, username: 'sec1', employee_id: 'EMP003', source_ip: '192.168.1.102', action_type: 'request', violation_type: 'API Key', severity: 'high', original_text: 'API_KEY=sk_live_1234567890', masked_text: 'API_KEY=sk_live_********', status: 'resolved' },
      { user_id: sec2Id, username: 'sec2', employee_id: 'EMP004', source_ip: '192.168.1.103', action_type: 'response', violation_type: 'Password', severity: 'critical', original_text: 'password: mySecret123', masked_text: 'password: ********', status: 'pending' },
      { user_id: dev1Id, username: 'dev1', employee_id: 'EMP001', source_ip: '192.168.1.100', action_type: 'request', violation_type: 'Email', severity: 'medium', original_text: 'Contact: john.doe@example.com', masked_text: 'Contact: j***@example.com', status: 'pending' }
    ];

    for (const log of dlpLogs) {
      try {
        dlpStmt.run(
          log.user_id, log.username, log.employee_id, log.source_ip, log.action_type,
          log.violation_type, log.severity, log.original_text, log.masked_text,
          log.status, getKoreaTime()
        );
        console.log(`  ✓ DLP Log 추가: ${log.violation_type} (${log.severity})`);
      } catch (error) {
        console.error(`  ✗ DLP Log 추가 실패:`, error.message);
      }
    }

    // 6. Download Logs 추가
    console.log('\n[6/6] Download Logs 추가 중...');
    const downloadLogStmt = db.prepare(`
      INSERT INTO download_logs 
      (user_id, file_path, file_name, mcp_server_id, downloaded_at, ip_address)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const downloadLogs = [
      { user_id: dev1Id, file_path: '/uploads/github-mcp-server.zip', file_name: 'github-mcp-server.zip', mcp_server_id: mcpServerIds[0] || null, ip_address: '192.168.1.100' },
      { user_id: dev2Id, file_path: '/uploads/notion-mcp-server.zip', file_name: 'notion-mcp-server.zip', mcp_server_id: mcpServerIds[1] || null, ip_address: '192.168.1.101' },
      { user_id: sec1Id, file_path: '/uploads/security-report.pdf', file_name: 'security-report.pdf', mcp_server_id: null, ip_address: '192.168.1.102' },
      { user_id: sec2Id, file_path: '/uploads/config.json', file_name: 'config.json', mcp_server_id: mcpServerIds[0] || null, ip_address: '192.168.1.103' }
    ];

    for (const log of downloadLogs) {
      try {
        downloadLogStmt.run(
          log.user_id, log.file_path, log.file_name, log.mcp_server_id, getKoreaTime(), log.ip_address
        );
        console.log(`  ✓ Download Log 추가: ${log.file_name}`);
      } catch (error) {
        console.error(`  ✗ Download Log 추가 실패:`, error.message);
      }
    }

    console.log('\n=== 샘플 데이터 추가 완료 ===');
    console.log(`\n요약:`);
    console.log(`- Users: ${users.length}개 (팀: ${team1}, ${team2})`);
    console.log(`- MCP Registry: ${mcpServers.length}개`);
    console.log(`- Register Board: 승인됨 2개, 대기중 2개, 거부됨 2개`);
    console.log(`- Risk Assessment: 대기중 서버 2개에 대해 OSS, Code, Tool 데이터 추가`);
    console.log(`- DLP Logs: ${dlpLogs.length}개`);
    console.log(`- Download Logs: ${downloadLogs.length}개`);

  } catch (error) {
    console.error('샘플 데이터 추가 중 오류 발생:', error);
    throw error;
  }
}

// 스크립트 실행
if (require.main === module) {
  addSampleData()
    .then(() => {
      console.log('\n스크립트 실행 완료');
      process.exit(0);
    })
    .catch((error) => {
      console.error('스크립트 실행 실패:', error);
      process.exit(1);
    });
}

module.exports = { addSampleData };

