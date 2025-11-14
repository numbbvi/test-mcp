#!/usr/bin/env node
/**
 * 데이터베이스의 모든 MCP 관련 데이터 삭제 스크립트
 * 
 * 주의: 이 스크립트는 모든 MCP 서버, 요청, 취약점 데이터를 삭제합니다.
 * 실행 전에 백업을 권장합니다.
 */

const Database = require('better-sqlite3');
const path = require('path');

// 데이터베이스 파일 경로
const dbPath = path.join(__dirname, '..', 'db', 'bomtool.db');
const db = new Database(dbPath);

// 외래 키 제약 조건 활성화
db.pragma('foreign_keys = ON');

console.log('데이터베이스 초기화 시작...\n');

try {
  // 트랜잭션 시작
  const transaction = db.transaction(() => {
    // 1. OSS 취약점 데이터 삭제
    console.log('OSS 취약점 데이터 삭제 중...');
    const ossVulnsDeleted = db.prepare('DELETE FROM oss_vulnerabilities').run();
    console.log(`  - 삭제된 OSS 취약점: ${ossVulnsDeleted.changes}개`);
    
    // 2. 코드 취약점 데이터 삭제
    console.log('코드 취약점 데이터 삭제 중...');
    const codeVulnsDeleted = db.prepare('DELETE FROM code_vulnerabilities').run();
    console.log(`  - 삭제된 코드 취약점: ${codeVulnsDeleted.changes}개`);
    
    // 3. Tool Validation 취약점 데이터 삭제
    try {
      console.log('Tool Validation 취약점 데이터 삭제 중...');
      const toolVulnsDeleted = db.prepare('DELETE FROM tool_validation_vulnerabilities').run();
      console.log(`  - 삭제된 Tool Validation 취약점: ${toolVulnsDeleted.changes}개`);
    } catch (e) {
      console.log('  - Tool Validation 취약점 테이블이 없습니다. 건너뜁니다.');
    }
    
    // 4. MCP 도구 사용 로그 삭제 (mcp_servers 참조)
    console.log('MCP 도구 사용 로그 삭제 중...');
    const usageLogsDeleted = db.prepare('DELETE FROM mcp_tool_usage_logs').run();
    console.log(`  - 삭제된 사용 로그: ${usageLogsDeleted.changes}개`);
    
    // 5. MCP 도구 권한 삭제 (mcp_servers 참조)
    console.log('MCP 도구 권한 삭제 중...');
    const permissionsDeleted = db.prepare('DELETE FROM mcp_tool_permissions').run();
    console.log(`  - 삭제된 도구 권한: ${permissionsDeleted.changes}개`);
    
    // 6. 파일 다운로드 로그 삭제 (mcp_servers 참조)
    try {
      console.log('파일 다운로드 로그 삭제 중...');
      const downloadLogsDeleted = db.prepare('DELETE FROM download_logs').run();
      console.log(`  - 삭제된 다운로드 로그: ${downloadLogsDeleted.changes}개`);
    } catch (e) {
      console.log('  - 파일 다운로드 로그 테이블이 없습니다. 건너뜁니다.');
    }
    
    // 7. Permission Violation 로그 삭제 (mcp_servers 참조)
    try {
      console.log('Permission Violation 로그 삭제 중...');
      const permissionLogsDeleted = db.prepare('DELETE FROM permission_violation_logs').run();
      console.log(`  - 삭제된 Permission Violation 로그: ${permissionLogsDeleted.changes}개`);
    } catch (e) {
      console.log('  - Permission Violation 로그 테이블이 없습니다. 건너뜁니다.');
    }
    
    // 8. MCP 서버 등록 요청 삭제
    console.log('MCP 서버 등록 요청 삭제 중...');
    const requestsDeleted = db.prepare('DELETE FROM mcp_register_requests').run();
    console.log(`  - 삭제된 등록 요청: ${requestsDeleted.changes}개`);
    
    // 9. MCP 서버 삭제 (다른 테이블 참조 제거 후)
    console.log('MCP 서버 삭제 중...');
    const serversDeleted = db.prepare('DELETE FROM mcp_servers').run();
    console.log(`  - 삭제된 MCP 서버: ${serversDeleted.changes}개`);
    
    // 10. DLP 위반 로그 삭제
    try {
      console.log('DLP 위반 로그 삭제 중...');
      const dlpLogsDeleted = db.prepare('DELETE FROM dlp_violation_logs').run();
      console.log(`  - 삭제된 DLP 로그: ${dlpLogsDeleted.changes}개`);
    } catch (e) {
      console.log('  - DLP 위반 로그 테이블이 없습니다. 건너뜁니다.');
    }
    
    // 11. IP-User 매핑 삭제 (user와 admin 제외)
    try {
      console.log('IP-User 매핑 삭제 중...');
      const ipMappingsDeleted = db.prepare('DELETE FROM ip_user_mappings').run();
      console.log(`  - 삭제된 IP 매핑: ${ipMappingsDeleted.changes}개`);
    } catch (e) {
      console.log('  - IP-User 매핑 테이블이 없습니다. 건너뜁니다.');
    }
  });
  
  // 트랜잭션 실행
  transaction();
  
  console.log('\n✅ 데이터베이스 초기화 완료!');
  console.log('\n주의: user와 admin 사용자 계정은 유지되었습니다.');
  
} catch (error) {
  console.error('❌ 오류 발생:', error.message);
  console.error(error.stack);
  process.exit(1);
} finally {
  db.close();
}

