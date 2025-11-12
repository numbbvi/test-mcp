const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { getKoreaTimeSQL } = require('../utils/dateTime');

// 데이터베이스 디렉토리 경로
const dbDir = path.join(__dirname, '..', 'db');

// 데이터베이스 디렉토리가 없으면 생성
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log(`데이터베이스 디렉토리 생성: ${dbDir}`);
}

// 데이터베이스 파일 경로 (프로젝트 루트의 db 폴더에 생성)
const dbPath = path.join(dbDir, 'bomtool.db');
const db = new Database(dbPath);

// 외래 키 제약 조건 활성화
db.pragma('foreign_keys = ON');

// 한국 시간을 사용하는 CURRENT_TIMESTAMP 함수 (SQLite에서 사용)
const KOREA_TIMESTAMP = "datetime('now', '+9 hours')";

// 기존 테이블 마이그레이션 (스키마 업데이트)
const migrateTables = () => {
  try {
    // Users 테이블 마이그레이션
    const tableInfo = db.prepare("PRAGMA table_info(users)").all();
    const columnNames = tableInfo.map(col => col.name);
    
    // employee_id 컬럼 추가
    if (!columnNames.includes('employee_id')) {
      // SQLite는 ALTER TABLE ADD COLUMN에서 DEFAULT만 지원하므로, UNIQUE 제약은 별도 처리
      db.exec(`ALTER TABLE users ADD COLUMN employee_id TEXT`);
      // 기존 데이터에 기본값 할당
      const existingUsers = db.prepare('SELECT id FROM users WHERE employee_id IS NULL').all();
      if (existingUsers.length > 0) {
        const updateStmt = db.prepare('UPDATE users SET employee_id = ? WHERE id = ?');
        existingUsers.forEach(user => {
          updateStmt.run(`EMP${String(user.id).padStart(3, '0')}`, user.id);
        });
      }
      // UNIQUE 인덱스 생성
      db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_employee_id ON users(employee_id)');
      console.log('Users 테이블: employee_id 컬럼 추가 완료');
    }
    
    // team 컬럼 추가
    if (!columnNames.includes('team')) {
      db.exec('ALTER TABLE users ADD COLUMN team TEXT');
      console.log('Users 테이블: team 컬럼 추가 완료');
    }
    
    // position 컬럼 추가
    if (!columnNames.includes('position')) {
      db.exec('ALTER TABLE users ADD COLUMN position TEXT');
      console.log('Users 테이블: position 컬럼 추가 완료');
    }
    
    // is_active 컬럼 추가
    if (!columnNames.includes('is_active')) {
      db.exec('ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1');
      console.log('Users 테이블: is_active 컬럼 추가 완료');
    }
    
    // role 컬럼이 있으면 제거 (RBAC로 대체)
    if (columnNames.includes('role')) {
      // role 컬럼은 유지하되, user_roles 테이블을 우선 사용
      console.log('Users 테이블: role 컬럼은 유지 (하위 호환성)');
    }

    // MCP Register Requests 테이블 마이그레이션
    try {
      const requestTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_register_requests'
      `).get();
      
      if (requestTableExists) {
        const requestTableInfo = db.prepare("PRAGMA table_info(mcp_register_requests)").all();
        const requestColumnNames = requestTableInfo.map(col => col.name);
        
        // title 컬럼 추가
        if (!requestColumnNames.includes('title')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN title TEXT`);
          // 기존 name 값을 title로 복사
          db.exec(`UPDATE mcp_register_requests SET title = name WHERE title IS NULL`);
          console.log('MCP Register Requests 테이블: title 컬럼 추가 완료');
        }
        
        // priority 컬럼 추가
        if (!requestColumnNames.includes('priority')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN priority TEXT DEFAULT 'normal'`);
          console.log('MCP Register Requests 테이블: priority 컬럼 추가 완료');
        }
        
        // reviewed_by 컬럼 추가
        if (!requestColumnNames.includes('reviewed_by')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN reviewed_by INTEGER`);
          console.log('MCP Register Requests 테이블: reviewed_by 컬럼 추가 완료');
        }
        
        // review_comment 컬럼 추가
        if (!requestColumnNames.includes('review_comment')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN review_comment TEXT`);
          console.log('MCP Register Requests 테이블: review_comment 컬럼 추가 완료');
        }
        
        // reviewed_at 컬럼 추가
        if (!requestColumnNames.includes('reviewed_at')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN reviewed_at DATETIME`);
          console.log('MCP Register Requests 테이블: reviewed_at 컬럼 추가 완료');
        }
        
        // connection_snippet 컬럼 추가
        if (!requestColumnNames.includes('connection_snippet')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN connection_snippet TEXT`);
          console.log('MCP Register Requests 테이블: connection_snippet 컬럼 추가 완료');
        }
        
        // image_path 컬럼 추가
        if (!requestColumnNames.includes('image_path')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN image_path TEXT`);
          console.log('MCP Register Requests 테이블: image_path 컬럼 추가 완료');
        }
        
        // scanned 컬럼 추가 (스캔 완료 여부)
        if (!requestColumnNames.includes('scanned')) {
          db.exec(`ALTER TABLE mcp_register_requests ADD COLUMN scanned INTEGER DEFAULT 0`);
          console.log('MCP Register Requests 테이블: scanned 컬럼 추가 완료');
        }
      }
    } catch (requestError) {
      console.error('MCP Register Requests 테이블 마이그레이션 오류:', requestError);
    }

    // MCP Servers 테이블 마이그레이션
    try {
      const serverTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='mcp_servers'
      `).get();
      
      if (serverTableExists) {
        const serverTableInfo = db.prepare("PRAGMA table_info(mcp_servers)").all();
        const serverColumnNames = serverTableInfo.map(col => col.name);
        
        // short_description 컬럼 추가 (카드 표지용)
        if (!serverColumnNames.includes('short_description')) {
          db.exec(`ALTER TABLE mcp_servers ADD COLUMN short_description TEXT`);
          console.log('MCP Servers 테이블: short_description 컬럼 추가 완료');
        }
        
        // 기존 데이터의 short_description이 NULL인 경우 description과 동일하게 설정
        db.exec(`UPDATE mcp_servers SET short_description = description WHERE short_description IS NULL AND description IS NOT NULL`);
        console.log('기존 MCP 서버 데이터의 short_description 업데이트 완료');
        
        // allowed_teams 컬럼 추가 (팀별 접근 권한)
        if (!serverColumnNames.includes('allowed_teams')) {
          db.exec(`ALTER TABLE mcp_servers ADD COLUMN allowed_teams TEXT`);
          console.log('MCP Servers 테이블: allowed_teams 컬럼 추가 완료');
          // 기존 데이터는 모든 팀이 접근 가능하도록 NULL 유지 (NULL = 모든 팀 접근 가능)
        }
      }
    } catch (serverError) {
      console.error('MCP Servers 테이블 마이그레이션 오류:', serverError);
    }

    // DLP Violation Logs 테이블 마이그레이션
    try {
      const dlpTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='dlp_violation_logs'
      `).get();
      
      if (dlpTableExists) {
        const dlpTableInfo = db.prepare("PRAGMA table_info(dlp_violation_logs)").all();
        const dlpColumnNames = dlpTableInfo.map(col => col.name);
        
        // original_text, masked_text, original_json 컬럼 추가
        if (!dlpColumnNames.includes('original_text')) {
          db.exec(`ALTER TABLE dlp_violation_logs ADD COLUMN original_text TEXT`);
          console.log('DLP Violation Logs 테이블: original_text 컬럼 추가 완료');
        }
        if (!dlpColumnNames.includes('masked_text')) {
          db.exec(`ALTER TABLE dlp_violation_logs ADD COLUMN masked_text TEXT`);
          console.log('DLP Violation Logs 테이블: masked_text 컬럼 추가 완료');
        }
        if (!dlpColumnNames.includes('original_json')) {
          db.exec(`ALTER TABLE dlp_violation_logs ADD COLUMN original_json TEXT`);
          console.log('DLP Violation Logs 테이블: original_json 컬럼 추가 완료');
        }
      }
    } catch (dlpError) {
      console.error('DLP Violation Logs 테이블 마이그레이션 오류:', dlpError);
    }

    // IP User Mappings 테이블 마이그레이션 (테이블 생성 확인만, 컬럼 추가는 불필요)
    try {
      const ipMappingTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='ip_user_mappings'
      `).get();
      
      if (!ipMappingTableExists) {
        db.exec(`
          CREATE TABLE ip_user_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            username TEXT,
            employee_id TEXT,
            description TEXT,
            created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            FOREIGN KEY (username) REFERENCES users(username),
            FOREIGN KEY (employee_id) REFERENCES users(employee_id)
          )
        `);
        console.log('IP User Mappings 테이블 생성 완료');
      }
    } catch (ipMappingError) {
      console.error('IP User Mappings 테이블 마이그레이션 오류:', ipMappingError);
    }

    // Users 테이블에 ip_address 컬럼 추가 마이그레이션
    try {
      const usersTableExists = db.prepare(`
        SELECT name FROM sqlite_master WHERE type='table' AND name='users'
      `).get();
      
      if (usersTableExists) {
        const usersTableInfo = db.prepare("PRAGMA table_info(users)").all();
        const usersColumnNames = usersTableInfo.map(col => col.name);
        
        if (!usersColumnNames.includes('ip_address')) {
          db.exec(`ALTER TABLE users ADD COLUMN ip_address TEXT`);
          console.log('Users 테이블: ip_address 컬럼 추가 완료');
        }
      }
    } catch (usersError) {
      console.error('Users 테이블 마이그레이션 오류:', usersError);
    }

    // ==================== Tool 권한 관리 마이그레이션 ====================
    try {
      // mcp_servers 테이블에 tools 컬럼 추가
      const serverColumnInfo = db.prepare(`PRAGMA table_info(mcp_servers)`).all();
      const serverColumnNames = serverColumnInfo.map(col => col.name);
      
      if (!serverColumnNames.includes('tools')) {
        db.exec(`ALTER TABLE mcp_servers ADD COLUMN tools TEXT`);
        console.log('MCP Servers 테이블: tools 컬럼 추가 완료');
        // 기존 데이터는 NULL로 유지 (Tool 정보 없음 = 서버 전체 권한으로 처리)
      }

      // ==================== MCP Proxy 연동용 스키마 확장 ====================
      // server_type: 서버 연결 타입 (local, ssh, http, sse)
      if (!serverColumnNames.includes('server_type')) {
        db.exec(`ALTER TABLE mcp_servers ADD COLUMN server_type TEXT DEFAULT 'local'`);
        console.log('MCP Servers 테이블: server_type 컬럼 추가 완료');
      }

      // connection_config: 서버 연결 설정 (JSON 형식)
      if (!serverColumnNames.includes('connection_config')) {
        db.exec(`ALTER TABLE mcp_servers ADD COLUMN connection_config TEXT`);
        console.log('MCP Servers 테이블: connection_config 컬럼 추가 완료');
      }

      // mcp_tool_permissions 테이블에 tool_name 컬럼 추가
      const toolPermTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='mcp_tool_permissions'
      `).get();
      
      if (toolPermTableExists) {
        const toolPermColumnInfo = db.prepare(`PRAGMA table_info(mcp_tool_permissions)`).all();
        const toolPermColumnNames = toolPermColumnInfo.map(col => col.name);
        
        if (!toolPermColumnNames.includes('tool_name')) {
          // tool_name 컬럼 추가
          db.exec(`ALTER TABLE mcp_tool_permissions ADD COLUMN tool_name TEXT`);
          console.log('MCP Tool Permissions 테이블: tool_name 컬럼 추가 완료');
          
          // 기존 UNIQUE 제약조건 제거 (수동으로 처리 필요)
          // SQLite는 ALTER TABLE로 UNIQUE 제약조건을 직접 제거할 수 없으므로
          // 새 인덱스 생성으로 대체 (기존 UNIQUE 제약조건은 유지하고 tool_name NULL 허용)
          
          // 새로운 복합 인덱스 생성 (tool_name 포함)
          try {
            db.exec(`
              CREATE UNIQUE INDEX IF NOT EXISTS idx_user_server_tool 
              ON mcp_tool_permissions(user_id, mcp_server_id, tool_name)
            `);
            console.log('MCP Tool Permissions 테이블: 복합 인덱스 생성 완료');
          } catch (indexError) {
            // 인덱스가 이미 존재하면 무시
            console.log('인덱스 생성 건너뜀 (이미 존재 또는 기존 UNIQUE 제약조건과 충돌 가능)');
          }
        }
      }

      // mcp_tool_team_permissions 테이블 생성
      const toolTeamPermTableExists = db.prepare(`
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='mcp_tool_team_permissions'
      `).get();
      
      if (!toolTeamPermTableExists) {
        db.exec(`
          CREATE TABLE mcp_tool_team_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mcp_server_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            team TEXT NOT NULL,
            permission_type TEXT DEFAULT 'allow',
            created_by INTEGER,
            created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
            FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id),
            UNIQUE(mcp_server_id, tool_name, team)
          )
        `);
        console.log('MCP Tool Team Permissions 테이블 생성 완료');
      }
    } catch (toolError) {
      console.error('Tool 권한 관리 마이그레이션 오류:', toolError);
    }
    
  } catch (error) {
    console.error('마이그레이션 오류:', error);
  }
};

// 테이블 초기화
const initializeTables = () => {
  // ==================== RBAC 구조 ====================
  
  // Users 테이블 (확장)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      employee_id TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      team TEXT,
      position TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // Roles 테이블 (역할 정의)
  db.exec(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // Permissions 테이블 (권한 정의)
  db.exec(`
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      resource TEXT,
      action TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // User_Roles 테이블 (사용자-역할 매핑, 다대다)
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      assigned_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      UNIQUE(user_id, role_id)
    )
  `);

  // Role_Permissions 테이블 (역할-권한 매핑, 다대다)
  db.exec(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
      UNIQUE(role_id, permission_id)
    )
  `);

  // MCP Servers 테이블 (마켓플레이스용)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      short_description TEXT,
      github_link TEXT,
      connection_snippet TEXT,
      file_path TEXT,
      allowed_teams TEXT,
      status TEXT DEFAULT 'approved',
      created_by INTEGER,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `);

  // ==================== MCP 관련 ====================
  
  // MCP Register Requests 테이블 (게시판 기능 포함)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_register_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      connection_snippet TEXT,
      github_link TEXT,
      file_path TEXT,
      image_path TEXT,
      status TEXT DEFAULT 'pending',
      priority TEXT DEFAULT 'normal',
      requested_by INTEGER NOT NULL,
      reviewed_by INTEGER,
      review_comment TEXT,
      reviewed_at DATETIME,
      scanned INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (requested_by) REFERENCES users(id),
      FOREIGN KEY (reviewed_by) REFERENCES users(id)
    )
  `);

  // MCP Tool Access Permissions 테이블 (MCP 서버별 접근 권한)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_tool_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      mcp_server_id INTEGER NOT NULL,
      granted_by INTEGER,
      granted_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
      FOREIGN KEY (granted_by) REFERENCES users(id),
      UNIQUE(user_id, mcp_server_id)
    )
  `);

  // ==================== 추적/로그 ====================
  
  // Download Logs 테이블 (파일 다운로드 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS download_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      file_path TEXT NOT NULL,
      file_name TEXT,
      mcp_server_id INTEGER,
      downloaded_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      ip_address TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id)
    )
  `);

  // MCP Tool Usage Logs 테이블 (MCP 도구 사용 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS mcp_tool_usage_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      mcp_server_id INTEGER NOT NULL,
      action TEXT,
      details TEXT,
      used_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      ip_address TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id)
    )
  `);

  // IP 사용자 매핑 테이블 (IP → 사용자 매핑)
  db.exec(`
    CREATE TABLE IF NOT EXISTS ip_user_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT UNIQUE NOT NULL,
      username TEXT,
      employee_id TEXT,
      description TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      updated_at DATETIME DEFAULT (datetime('now', '+9 hours')),
      FOREIGN KEY (username) REFERENCES users(username),
      FOREIGN KEY (employee_id) REFERENCES users(employee_id)
    )
  `);

  // DLP Violation Logs 테이블 (DLP 위반 추적)
  db.exec(`
    CREATE TABLE IF NOT EXISTS dlp_violation_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      employee_id TEXT,
      source_ip TEXT NOT NULL,
      destination_ip TEXT,
      protocol TEXT,
      action_type TEXT NOT NULL,
      violation_type TEXT NOT NULL,
      severity TEXT DEFAULT 'medium',
      file_name TEXT,
      file_path TEXT,
      file_size INTEGER,
      file_hash TEXT,
      content_summary TEXT,
      matched_pattern TEXT,
      rule_id TEXT,
      rule_name TEXT,
      user_agent TEXT,
      timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      status TEXT DEFAULT 'pending',
      handled_by INTEGER,
      handled_at DATETIME,
      notes TEXT,
      original_text TEXT,
      masked_text TEXT,
      original_json TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (handled_by) REFERENCES users(id)
    )
  `);

  // Code Vulnerabilities 테이블 (코드 스캔 결과 저장)
  db.exec(`
    CREATE TABLE IF NOT EXISTS code_vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT,
      scan_path TEXT,
      scan_timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      rule_id TEXT,
      vulnerability TEXT,
      severity TEXT,
      language TEXT,
      file TEXT,
      line INTEGER,
      column INTEGER,
      message TEXT,
      description TEXT,
      cwe TEXT,
      code_snippet TEXT,
      pattern_type TEXT,
      pattern TEXT,
      confidence TEXT,
      raw_finding TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // OSS Vulnerabilities 테이블 생성
  db.exec(`
    CREATE TABLE IF NOT EXISTS oss_vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT,
      scan_path TEXT,
      scan_timestamp DATETIME DEFAULT (datetime('now', '+9 hours')),
      package_name TEXT NOT NULL,
      package_version TEXT,
      package_fixed_version TEXT,
      package_all_fixed_versions TEXT,
      package_affected_range TEXT,
      package_dependency_type TEXT,
      vulnerability_id TEXT,
      vulnerability_cve TEXT,
      vulnerability_cvss REAL,
      vulnerability_severity TEXT,
      vulnerability_title TEXT,
      vulnerability_description TEXT,
      vulnerability_reference_url TEXT,
      reachable INTEGER DEFAULT 0,
      functions_count INTEGER DEFAULT 0,
      reachable_functions INTEGER DEFAULT 0,
      unreachable_functions INTEGER DEFAULT 0,
      raw_data TEXT,
      created_at DATETIME DEFAULT (datetime('now', '+9 hours'))
    )
  `);

  // ==================== 기본 데이터 초기화 ====================
  
  // 기본 Roles 생성
  const roleCount = db.prepare('SELECT COUNT(*) as count FROM roles').get();
  if (roleCount.count === 0) {
    const roleStmt = db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)');
    roleStmt.run('admin', '시스템 관리자 - 모든 권한');
    roleStmt.run('manager', '팀 매니저 - 팀 관리 및 승인 권한');
    roleStmt.run('user', '일반 사용자 - 기본 접근 권한');
    console.log('기본 역할 생성 완료');
  }

  // 기본 Permissions 생성
  const permCount = db.prepare('SELECT COUNT(*) as count FROM permissions').get();
  if (permCount.count === 0) {
    const permStmt = db.prepare('INSERT INTO permissions (name, description, resource, action) VALUES (?, ?, ?, ?)');
    
    // 파일 다운로드 관련
    permStmt.run('download_file', '파일 다운로드', 'file', 'download');
    permStmt.run('view_download_log', '다운로드 로그 조회', 'log', 'view');
    
    // MCP 도구 관련
    permStmt.run('use_mcp_tool', 'MCP 도구 사용', 'mcp_tool', 'use');
    permStmt.run('manage_mcp_tool', 'MCP 도구 관리', 'mcp_tool', 'manage');
    
    // 게시판/요청 관련
    permStmt.run('create_request', 'MCP 서버 등록 요청', 'request', 'create');
    permStmt.run('view_request', '등록 요청 조회', 'request', 'view');
    permStmt.run('approve_request', '등록 요청 승인', 'request', 'approve');
    permStmt.run('reject_request', '등록 요청 거부', 'request', 'reject');
    
    // 사용자 관리
    permStmt.run('view_user', '사용자 조회', 'user', 'view');
    permStmt.run('manage_user', '사용자 관리', 'user', 'manage');
    
    // 대시보드
    permStmt.run('view_dashboard', '대시보드 조회', 'dashboard', 'view');
    
    console.log('기본 권한 생성 완료');
  }

  // Role-Permission 매핑 (관리자는 모든 권한)
  const adminRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('admin');
  const managerRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('manager');
  const userRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('user');
  
  const rolePermCount = db.prepare('SELECT COUNT(*) as count FROM role_permissions').get();
  if (rolePermCount.count === 0 && adminRole && managerRole && userRole) {
    const rolePermStmt = db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
    const allPerms = db.prepare('SELECT id FROM permissions').all();
    
    // Admin: 모든 권한
    allPerms.forEach(perm => {
      rolePermStmt.run(adminRole.id, perm.id);
    });
    
    // Manager: 관리 권한
    const managerPerms = ['view_dashboard', 'view_user', 'view_request', 'approve_request', 'reject_request', 'view_download_log', 'use_mcp_tool'];
    managerPerms.forEach(permName => {
      const perm = db.prepare('SELECT id FROM permissions WHERE name = ?').get(permName);
      if (perm) rolePermStmt.run(managerRole.id, perm.id);
    });
    
    // User: 기본 권한
    const userPerms = ['view_dashboard', 'create_request', 'view_request', 'use_mcp_tool'];
    userPerms.forEach(permName => {
      const perm = db.prepare('SELECT id FROM permissions WHERE name = ?').get(permName);
      if (perm) rolePermStmt.run(userRole.id, perm.id);
    });
    
    console.log('역할-권한 매핑 완료');
  }

  // 기본 관리자 계정 생성 또는 role 할당
  const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  const userExists = db.prepare('SELECT id FROM users WHERE username = ?').get('user');
  
  if (!adminExists) {
    // 새로 생성
    const userStmt = db.prepare('INSERT INTO users (username, employee_id, email, password, team, position) VALUES (?, ?, ?, ?, ?, ?)');
    const adminUserId = userStmt.run('admin', 'EMP001', 'admin@example.com', 'admin', 'IT', 'Administrator').lastInsertRowid;
    const userUserId = userExists 
      ? userExists.id 
      : userStmt.run('user', 'EMP002', 'user@example.com', 'user', 'Development', 'Developer').lastInsertRowid;
    
    // 관리자 역할 할당
    if (adminRole) {
      const userRoleStmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
      userRoleStmt.run(adminUserId, adminRole.id);
      if (!userExists) {
        userRoleStmt.run(userUserId, userRole.id);
      }
    }
    
    console.log('기본 사용자 계정 생성 완료');
  } else {
    // 기존 계정에 role이 없는 경우 추가
    const adminUserRoles = db.prepare('SELECT COUNT(*) as count FROM user_roles WHERE user_id = ?').get(adminExists.id);
    if (adminUserRoles.count === 0 && adminRole) {
      const userRoleStmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
      userRoleStmt.run(adminExists.id, adminRole.id);
      console.log('기존 admin 계정에 admin 역할 추가 완료');
    }
    
    // user 계정에도 role 확인 및 추가
    if (userExists) {
      const userUserRoles = db.prepare('SELECT COUNT(*) as count FROM user_roles WHERE user_id = ?').get(userExists.id);
      if (userUserRoles.count === 0 && userRole) {
        const userRoleStmt = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
        userRoleStmt.run(userExists.id, userRole.id);
        console.log('기존 user 계정에 user 역할 추가 완료');
      }
    }
  }

  // 기본 MCP 서버 데이터가 없으면 생성
  const mcpCount = db.prepare('SELECT COUNT(*) as count FROM mcp_servers WHERE status = ?').get('approved');
  if (mcpCount.count === 0) {
    const mcpStmt = db.prepare(`
      INSERT INTO mcp_servers (name, description, short_description, github_link, connection_snippet, status, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    
  }

  console.log('데이터베이스 테이블 초기화 완료');
};

// 데이터베이스 초기화 실행
migrateTables(); // 먼저 마이그레이션
initializeTables(); // 그 다음 테이블 생성 및 데이터 초기화

module.exports = db;

