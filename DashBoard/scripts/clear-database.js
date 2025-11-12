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
const dbPath = path.join(__dirname, '..', 'backend', 'db', 'bomtool.db');

// backend의 node_modules를 사용하기 위해 경로 추가
const backendPath = path.join(__dirname, '..', 'backend');
process.chdir(backendPath);

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
    
    // 3. MCP 서버 등록 요청 삭제
    console.log('MCP 서버 등록 요청 삭제 중...');
    const requestsDeleted = db.prepare('DELETE FROM mcp_register_requests').run();
    console.log(`  - 삭제된 등록 요청: ${requestsDeleted.changes}개`);
    
    // 4. MCP 서버 삭제
    console.log('MCP 서버 삭제 중...');
    const serversDeleted = db.prepare('DELETE FROM mcp_servers').run();
    console.log(`  - 삭제된 MCP 서버: ${serversDeleted.changes}개`);
    
    // 5. MCP 도구 권한 삭제
    console.log('MCP 도구 권한 삭제 중...');
    const permissionsDeleted = db.prepare('DELETE FROM mcp_tool_permissions').run();
    console.log(`  - 삭제된 도구 권한: ${permissionsDeleted.changes}개`);
    
    // 6. MCP 도구 사용 로그 삭제
    console.log('MCP 도구 사용 로그 삭제 중...');
    const usageLogsDeleted = db.prepare('DELETE FROM mcp_tool_usage_logs').run();
    console.log(`  - 삭제된 사용 로그: ${usageLogsDeleted.changes}개`);
    
    // 7. 파일 다운로드 로그 삭제
    console.log('파일 다운로드 로그 삭제 중...');
    const downloadLogsDeleted = db.prepare('DELETE FROM file_download_logs').run();
    console.log(`  - 삭제된 다운로드 로그: ${downloadLogsDeleted.changes}개`);
  });
  
  // 트랜잭션 실행
  transaction();
  
  console.log('\n✅ 데이터베이스 초기화 완료!');
  console.log('\n주의: 사용자, DLP 로그 등 다른 데이터는 유지되었습니다.');
  
} catch (error) {
  console.error('❌ 오류 발생:', error.message);
  console.error(error.stack);
  process.exit(1);
} finally {
  db.close();
}

