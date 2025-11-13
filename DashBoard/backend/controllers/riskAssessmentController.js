const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs').promises;
const db = require('../config/db');
const { v4: uuidv4 } = require('uuid');
const { getKoreaTimeSQLite } = require('../utils/dateTime');

const execAsync = promisify(exec);

// dev-server.js처럼 spawn('docker', ...) 형식으로 사용하므로
// Docker 경로를 찾는 함수가 필요 없습니다. PATH에서 자동으로 찾습니다.

// GitHub URL 유효성 검사 함수 (dev-server.js에서 가져옴)
function isValidGithubUrl(url) {
  if (typeof url !== 'string') return false;
  const trimmed = url.trim();
  const pattern = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)(?:\.git)?$/i;
  return pattern.test(trimmed);
}

// 스캐너 경로 설정 (환경 변수로 오버라이드 가능 - 클라우드 환경에서 유용)
const SCANNER_PATH = process.env.SCANNER_PATH || path.resolve(__dirname, '../../../MCP-SCAN');
const ARTIFACTS_DIR = path.join(SCANNER_PATH, 'artifacts');
const CONTAINER_NAME = process.env.DOCKER_CONTAINER_NAME || 'bomtool-scanner';

// Bomtori 분석 설정 (dev-server.js와 동일)
const BOMTORI_ROOT = process.env.BOMTORI_ROOT || path.resolve(__dirname, '../../../SBOM-SCA');
const BOMTORI_OUTPUT_DIR = process.env.BOMTORI_OUTPUT_DIR || path.join(BOMTORI_ROOT, 'output');
const BOMTORI_CONTAINER_NAME = process.env.BOMTORI_CONTAINER_NAME || 'bomtori';

// TOOL-VET 분석 설정
const TOOL_VET_ROOT = process.env.TOOL_VET_ROOT || path.resolve(__dirname, '../../../TOOL-VET');
const TOOL_VET_OUTPUT_DIR = process.env.TOOL_VET_OUTPUT_DIR || path.join(TOOL_VET_ROOT, 'output');
const TOOL_VET_CONTAINER_NAME = process.env.TOOL_VET_CONTAINER_NAME || 'mcp-vetting';

// Go 프로젝트 버전에서 "v" 접두사 제거 함수
const removeVersionPrefix = (version) => {
  if (!version || typeof version !== 'string') {
    return version;
  }
  // "v"로 시작하면 제거
  return version.startsWith('v') ? version.substring(1) : version;
};

// 진행률 추적을 위한 메모리 저장소 (스캔 세션별 진행률)
const scanProgress = new Map(); // { scanId: { bomtori: 0-100, scanner: 0-100, status: 'running'|'completed'|'failed' } }

const riskAssessmentController = {
  // 코드 스캔 실행 (도커 컨테이너 사용)
  scanCode: async (req, res) => {
    try {
      const { github_url, repository_path, mcp_server_name } = req.body;
      
      if (!github_url && !repository_path) {
        return res.status(400).json({
          success: false,
          message: 'github_url 또는 repository_path가 필요합니다.'
        });
      }

      // GitHub URL을 우선적으로 사용, 없으면 파일 경로 사용
      let scanPath = null;
      if (github_url) {
        scanPath = github_url;
      } else if (repository_path) {
        // 파일 경로를 절대 경로로 변환
        // repository_path는 /uploads/filename 형식이므로 절대 경로로 변환
        const uploadsDir = path.join(__dirname, '..', 'uploads');
        const fileName = path.basename(repository_path);
        const fullPath = path.join(uploadsDir, fileName);
        
        // 파일 존재 확인
        try {
          await fs.access(fullPath);
          scanPath = fullPath;
        } catch (e) {
          return res.status(400).json({
            success: false,
            message: `파일을 찾을 수 없습니다: ${fullPath}`
          });
        }
      }
      
      // MCP 서버 이름 결정: 명시적으로 제공되거나 GitHub URL에서 추출
      let serverName = mcp_server_name;
      if (!serverName && github_url) {
        // GitHub URL에서 repo 이름 추출: https://github.com/user/repo -> repo
        const match = github_url.match(/github\.com\/[^\/]+\/([^\/]+)/);
        if (match && match[1]) {
          serverName = match[1].replace(/\.git$/, ''); // .git 제거
        }
      }
      // 파일 경로만 있는 경우 파일명에서 추출
      if (!serverName && repository_path) {
        const fileName = path.basename(repository_path);
        // 타임스탬프_파일명 형식에서 파일명 추출
        const match = fileName.match(/^\d+_\d+_(.+)$/);
        if (match && match[1]) {
          serverName = match[1].replace(/\.[^.]*$/, ''); // 확장자 제거
        } else {
          serverName = fileName.replace(/\.[^.]*$/, ''); // 확장자 제거
        }
      }
      // 기본값: 'finding'
      if (!serverName || serverName.trim() === '') {
        serverName = 'finding';
      }

      // serverName이 숫자만 있는 경우 방지 (안전한 이름으로 변환)
      if (/^\d+$/.test(serverName)) {
        serverName = `mcp_server_${serverName}`;
      }

      // serverName을 안전한 파일명으로 변환 (공백, 특수문자 제거)
      // 공백을 언더스코어로 변환하고, 특수문자는 제거
      const safeServerName = serverName
        .replace(/\s+/g, '_')  // 공백을 언더스코어로 변환
        .replace(/[^a-zA-Z0-9_-]/g, '_')  // 알파벳, 숫자, 언더스코어, 하이픈만 허용
        .replace(/_{2,}/g, '_')  // 연속된 언더스코어를 하나로
        .replace(/^_+|_+$/g, '');  // 앞뒤 언더스코어 제거

      // scanPath가 null인 경우 에러 반환
      if (!scanPath) {
        return res.status(400).json({
          success: false,
          message: '스캔 경로를 결정할 수 없습니다.'
        });
      }

      // 도커 컨테이너가 실행 중인지 확인 (dev-server.js처럼 spawn 사용)
      try {
        const checkProcess = spawn('docker', [
          'ps',
          '--filter',
          `name=${CONTAINER_NAME}`,
          '--format',
          '{{.Names}}'
        ], {
          cwd: SCANNER_PATH
        });
        
        let stdout = '';
        let stderr = '';
        
        checkProcess.stdout.on('data', (data) => {
          stdout += data.toString();
        });
        
        checkProcess.stderr.on('data', (data) => {
          stderr += data.toString();
        });
        
        await new Promise((resolve, reject) => {
          checkProcess.on('close', (code) => {
            if (code !== 0) {
              reject(new Error(`Docker 명령 실행 실패: ${stderr || '알 수 없는 오류'}`));
          } else {
              resolve();
            }
          });
          
          checkProcess.on('error', (error) => {
            reject(error);
          });
        });
        
        if (!stdout.trim()) {
          return res.status(500).json({
            success: false,
            message: `Docker 컨테이너가 실행 중이 아닙니다: ${CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`
          });
        }
        
        console.log(`Docker 컨테이너 확인됨: ${CONTAINER_NAME}`);
      } catch (error) {
        console.error('도커 컨테이너 확인 오류:', error);
        return res.status(500).json({
          success: false,
          message: `도커 컨테이너 확인 실패: ${error.message}`
        });
      }

      // 도커 컨테이너에서 스캔 실행 (안전한 서버 이름으로 출력 파일 지정)
      // execFile을 사용하여 쉘 없이 직접 실행
      const dockerArgs = [
        'exec',
        CONTAINER_NAME,
        'python',
        '-m',
        'scanner.cli',
        '--path',
        scanPath,
        '--output',
        safeServerName
      ];
      
      console.log(`스캔 시작: ${scanPath} (서버 이름: ${serverName})`);
      console.log(`실행 명령: docker ${dockerArgs.join(' ')}`);
      console.log(`현재 작업 디렉토리: ${SCANNER_PATH}`);
      
      // 스캔 ID 미리 생성 (Bomtori와 code scanner가 동일한 scan_id 사용)
      const scanId = uuidv4();
      
      // 진행률 초기화
      const hasBomtori = github_url && isValidGithubUrl(github_url);
      const hasToolVet = github_url && isValidGithubUrl(github_url);
      scanProgress.set(scanId, {
        bomtori: hasBomtori ? 0 : null, // null이면 실행 안 함
        scanner: 0,
        toolVet: hasToolVet ? 0 : null, // null이면 실행 안 함
        status: 'running',
        bomtoriCompleted: false,
        scannerCompleted: false,
        toolVetCompleted: false
      });
      
      // 즉시 scan_id 반환 (비동기로 진행)
      if (!res.headersSent) {
        res.json({
          success: true,
          scan_id: scanId,
          message: '스캔이 시작되었습니다.'
        });
      }
      
      // Bomtori와 Scanner를 동시에 시작하기 위한 Promise 배열
      const scanPromises = [];
      
      // Bomtori 분석도 동시에 실행 (GitHub URL이 있는 경우만)
      let bomtoriProcess = null;
      if (github_url && isValidGithubUrl(github_url)) {
        try {
          // Bomtori 컨테이너가 실행 중인지 확인
          try {
            const checkBomtoriProcess = spawn('docker', [
              'ps',
              '--filter',
              `name=${BOMTORI_CONTAINER_NAME}`,
              '--format',
              '{{.Names}}'
            ], {
              cwd: BOMTORI_ROOT
            });
            
            let bomtoriStdout = '';
            let bomtoriStderr = '';
            
            checkBomtoriProcess.stdout.on('data', (data) => {
              bomtoriStdout += data.toString();
            });
            
            checkBomtoriProcess.stderr.on('data', (data) => {
              bomtoriStderr += data.toString();
            });
            
      await new Promise((resolve, reject) => {
              checkBomtoriProcess.on('close', (code) => {
                if (code !== 0) {
                  reject(new Error(`Docker 명령 실행 실패: ${bomtoriStderr || '알 수 없는 오류'}`));
                } else {
                  resolve();
                }
              });
              
              checkBomtoriProcess.on('error', (error) => {
                reject(error);
              });
            });
            
            if (!bomtoriStdout.trim()) {
              throw new Error(`Bomtori 컨테이너가 실행 중이 아닙니다: ${BOMTORI_CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`);
            } else {
              console.log(`Bomtori 컨테이너 확인됨: ${BOMTORI_CONTAINER_NAME}`);
            }
          } catch (error) {
            console.error('Bomtori 컨테이너 확인 오류:', error);
            throw error; // 컨테이너 확인 실패 시 오류 전파
          }
          
          // Bomtori 출력 디렉토리 생성
          await fs.mkdir(BOMTORI_OUTPUT_DIR, { recursive: true });
          
          // docker exec로 실행 (bomtool-scanner와 동일한 방식)
          const bomtoriArgs = [
            'exec',
            BOMTORI_CONTAINER_NAME,
            'python',
            'main.py',
            github_url,
            '--output-dir',
            '/app/output'
          ];
          
          console.log(`Bomtori 분석 시작: ${github_url}`);
          console.log(`Bomtori 실행 명령: docker ${bomtoriArgs.join(' ')}`);
          
          // Bomtori를 Promise로 감싸서 동시 실행
          const bomtoriPromise = new Promise((resolve, reject) => {
            // Bomtori 시작 시 즉시 진행률 업데이트
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.bomtori = 1; // 시작됨을 표시
              scanProgress.set(scanId, currentProgress);
            }
            
            bomtoriProcess = spawn('docker', bomtoriArgs, { cwd: BOMTORI_ROOT });
          
          // Bomtori 진행률 추적
          let bomtoriStartTime = Date.now();
          const bomtoriEstimatedDuration = 120000; // 2분 예상
          
          // 시간 기반 진행률 업데이트를 위한 인터벌 설정
          const bomtoriProgressInterval = setInterval(() => {
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress && currentProgress.bomtori !== null && currentProgress.bomtori < 100 && !currentProgress.bomtoriCompleted) {
              const elapsed = Date.now() - bomtoriStartTime;
              const estimatedProgress = Math.min(Math.floor((elapsed / bomtoriEstimatedDuration) * 100), 99);
              // 최소 1%씩 증가하도록 보장
              if (estimatedProgress > currentProgress.bomtori) {
                currentProgress.bomtori = estimatedProgress;
                scanProgress.set(scanId, currentProgress);
              }
            }
          }, 2000); // 2초마다 업데이트
          
          bomtoriProcess.stdout.on('data', (data) => {
            const output = data.toString().trim();
            console.log('[Bomtori]', output);
            
            // 진행률 파싱 시도 (예: "Progress: 50%" 또는 "50%")
            const progressMatch = output.match(/(\d+)%/);
            if (progressMatch) {
              const progress = parseInt(progressMatch[1]);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress && !currentProgress.bomtoriCompleted) {
                currentProgress.bomtori = Math.min(progress, 99);
                scanProgress.set(scanId, currentProgress);
              }
            }
          });
          
          bomtoriProcess.stderr.on('data', (data) => {
            console.error('[Bomtori Error]', data.toString().trim());
          });
          
          bomtoriProcess.on('close', async (code) => {
              // 진행률 업데이트 인터벌 정리
              clearInterval(bomtoriProgressInterval);
              
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.bomtori = 100;
                currentProgress.bomtoriCompleted = true;
                scanProgress.set(scanId, currentProgress);
              }
              
              if (code === 0) {
                console.log('Bomtori 분석 완료 (종료 코드: 0)');
                
                // Bomtori 결과 파일 읽기 및 저장
                try {
                  // repo_name 추출 (GitHub URL에서 - Bomtori와 동일한 방식)
                  // Bomtori는 github_url.split('/')[-1].replace('.git', '')를 사용
                  const repoName = github_url.split('/').pop().replace('.git', '').replace(/[^a-zA-Z0-9_-]/g, '_');
                  
                  console.log(`Bomtori 결과 파일 확인 중 (repoName: ${repoName})`);
                  console.log(`BOMTORI_OUTPUT_DIR: ${BOMTORI_OUTPUT_DIR}`);
                  
                  // 출력 디렉토리의 모든 파일 확인 (디버깅용)
                  let allFiles = [];
                  try {
                    allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
                    console.log(`BOMTORI_OUTPUT_DIR의 파일 목록:`, allFiles);
                    
                    // dashboard.json 파일 찾기 (repoName으로 시작하는 파일)
                    const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                    console.log(`발견된 dashboard.json 파일들:`, dashboardFiles);
                  } catch (dirError) {
                    console.error('BOMTORI_OUTPUT_DIR 읽기 실패:', dirError);
                  }
                  
                  // 예상 파일명
                  const dashboardFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-dashboard.json`);
                  console.log(`예상 파일 경로: ${dashboardFile}`);
                  
                  // 파일 존재 확인 (최대 60초 대기, 컨테이너 종료 후 파일이 완전히 쓰여질 때까지 대기)
                  let fileExists = false;
                  let foundDashboardFile = null;
                  
                  for (let i = 0; i < 120; i++) {
                    // 먼저 예상 파일명 확인
                    try {
                      await fs.access(dashboardFile);
                      const stats = await fs.stat(dashboardFile);
                      if (stats.size > 0) {
                        fileExists = true;
                        foundDashboardFile = dashboardFile;
                        console.log(`Bomtori 결과 파일 확인됨: ${dashboardFile} (크기: ${stats.size} bytes)`);
                        break;
                      }
                    } catch (e) {
                      // 예상 파일명이 없으면 모든 dashboard.json 파일 확인
                      if (i % 5 === 0 && allFiles.length > 0) {
                        const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                        // 파일을 수정 시간순으로 정렬 (가장 최근 파일 우선)
                        const dashboardFilesWithStats = [];
                        for (const file of dashboardFiles) {
                          const filePath = path.join(BOMTORI_OUTPUT_DIR, file);
                          try {
                            const stats = await fs.stat(filePath);
                            if (stats.size > 0) {
                              dashboardFilesWithStats.push({ file, filePath, mtime: stats.mtime });
                            }
                          } catch (fileError) {
                            // 파일 접근 실패, 무시
                          }
                        }
                        // 수정 시간순으로 정렬 (최신 파일이 먼저)
                        dashboardFilesWithStats.sort((a, b) => b.mtime - a.mtime);
                        
                        // 가장 최근 파일 사용 (파일명 매칭보다 최신 파일 우선)
                        if (dashboardFilesWithStats.length > 0) {
                          const latestFile = dashboardFilesWithStats[0];
                          fileExists = true;
                          foundDashboardFile = latestFile.filePath;
                          console.log(`가장 최근 dashboard.json 파일 사용: ${latestFile.file} (크기: ${(await fs.stat(latestFile.filePath)).size} bytes, 수정 시간: ${latestFile.mtime})`);
                          break;
                        }
                      }
                      
                      if (i % 10 === 0) {
                        console.log(`Bomtori 결과 파일 대기 중... (${i + 1}/120): ${dashboardFile}`);
                      }
                    }
                    await new Promise(resolve => setTimeout(resolve, 500));
                  }
                  
                  if (fileExists && foundDashboardFile) {
                    console.log(`Bomtori 결과 파일 읽기: ${foundDashboardFile}`);
                    const dashboardData = JSON.parse(await fs.readFile(foundDashboardFile, 'utf-8'));
                    const vulnerabilities = dashboardData.vulnerabilities || [];
                    
                    if (vulnerabilities.length > 0) {
                      // 기존 OSS 취약점 데이터 삭제 (같은 scan_path의 이전 스캔 결과)
                      try {
                        const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                        deleteOssStmt.run(scanPath);
                        console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scanPath}`);
                      } catch (deleteError) {
                        console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                      }
                      
                      // code scanner와 동일한 scan_id 사용
                      
                      const insertOssStmt = db.prepare(`
                        INSERT INTO oss_vulnerabilities (
                          scan_id, scan_path, scan_timestamp,
                          package_name, package_version, package_fixed_version, package_all_fixed_versions,
                          package_affected_range, package_dependency_type,
                          vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                          vulnerability_title, vulnerability_description, vulnerability_reference_url,
                          reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `);
                      
                      for (const vuln of vulnerabilities) {
                        try {
                          const pkg = vuln.package || {};
                          const vulnInfo = vuln.vulnerability || {};
                          
                          // Go 프로젝트와 npm 프로젝트 모두 지원
                          const packageName = pkg.name || null;
                          // Go 프로젝트 버전에서 "v" 접두사 제거
                          const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                          const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                          const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                            ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                            : [];
                          const affectedRange = pkg.affected_range || null;
                          const dependencyType = pkg.dependency_type || null;
                          
                          const vulnId = vulnInfo.id || null;
                          const cve = vulnInfo.cve || null;
                          const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null;
                          const severity = vulnInfo.severity || null;
                          const title = vulnInfo.title || null;
                          const description = vulnInfo.description || null;
                          const referenceUrl = vulnInfo.reference_url || null;
                          
                          const reachable = vuln.reachable === true ? 1 : 0;
                          const functionsCount = vuln.functions_count || 0;
                          const reachableFunctions = vuln.reachable_functions || 0;
                          const unreachableFunctions = vuln.unreachable_functions || 0;
                          
                          insertOssStmt.run(
                            scanId,
                            scanPath,
                            getKoreaTimeSQLite(),
                            packageName,
                            currentVersion,
                            fixedVersion,
                            JSON.stringify(allFixedVersions),
                            affectedRange,
                            dependencyType,
                            vulnId,
                            cve,
                            cvss,
                            severity,
                            title,
                            description,
                            referenceUrl,
                            reachable,
                            functionsCount,
                            reachableFunctions,
                            unreachableFunctions,
                            JSON.stringify(vuln)
                          );
                        } catch (insertError) {
                          console.error('OSS 취약점 저장 오류:', insertError);
                        }
                      }
                      
                      console.log(`OSS 취약점 ${vulnerabilities.length}개 저장 완료`);
                    } else {
                      console.log('Bomtori dashboard 파일에는 취약점이 없습니다.');
                    }
                  } else {
                    console.error(`Bomtori 결과 파일을 찾을 수 없습니다: ${dashboardFile}`);
                    console.error(`대기 시간 초과 (60초)`);
                    console.error(`발견된 dashboard.json 파일들:`, allFiles.filter(f => f.includes('dashboard.json')));
                    
                    // 파일을 찾지 못했지만 dashboard.json 파일이 있으면 가장 최근 파일 사용
                    const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                    if (dashboardFiles.length > 0) {
                      console.log(`예상 파일명을 찾지 못했지만 dashboard.json 파일이 있습니다. 가장 최근 파일을 사용합니다.`);
                      const dashboardFilesWithStats = [];
                      for (const file of dashboardFiles) {
                        const filePath = path.join(BOMTORI_OUTPUT_DIR, file);
                        try {
                          const stats = await fs.stat(filePath);
                          if (stats.size > 0) {
                            dashboardFilesWithStats.push({ file, filePath, mtime: stats.mtime });
                          }
                        } catch (fileError) {
                          // 파일 접근 실패, 무시
                        }
                      }
                      if (dashboardFilesWithStats.length > 0) {
                        dashboardFilesWithStats.sort((a, b) => b.mtime - a.mtime);
                        const latestFile = dashboardFilesWithStats[0];
                        foundDashboardFile = latestFile.filePath;
                        fileExists = true;
                        console.log(`가장 최근 dashboard.json 파일 사용: ${latestFile.file}`);
                        
                        // 파일을 찾았으므로 다시 읽기 시도
                        const dashboardData = JSON.parse(await fs.readFile(foundDashboardFile, 'utf-8'));
                        const vulnerabilities = dashboardData.vulnerabilities || [];
                        
                        if (vulnerabilities.length > 0) {
                          // 기존 OSS 취약점 데이터 삭제 (같은 scan_path의 이전 스캔 결과)
                          try {
                            const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                            deleteOssStmt.run(scanPath);
                            console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scanPath}`);
                          } catch (deleteError) {
                            console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                          }
                          
                          const insertOssStmt = db.prepare(`
                            INSERT INTO oss_vulnerabilities (
                              scan_id, scan_path, scan_timestamp,
                              package_name, package_version, package_fixed_version, package_all_fixed_versions,
                              package_affected_range, package_dependency_type,
                              vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                              vulnerability_title, vulnerability_description, vulnerability_reference_url,
                              reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          `);
                          
                          for (const vuln of vulnerabilities) {
                            try {
                              const pkg = vuln.package || {};
                              const vulnInfo = vuln.vulnerability || {};
                              
                              // Go 프로젝트와 npm 프로젝트 모두 지원
                              const packageName = pkg.name || null;
                              // Go 프로젝트 버전에서 "v" 접두사 제거
                              const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                              const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                              const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                                ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                                : [];
                              const affectedRange = pkg.affected_range || null;
                              const dependencyType = pkg.dependency_type || null;
                              
                              const vulnId = vulnInfo.id || null;
                              const cve = vulnInfo.cve || null;
                              const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null;
                              const severity = vulnInfo.severity || null;
                              const title = vulnInfo.title || null;
                              const description = vulnInfo.description || null;
                              const referenceUrl = vulnInfo.reference_url || null;
                              
                              const reachable = vuln.reachable === true ? 1 : 0;
                              const functionsCount = vuln.functions_count || 0;
                              const reachableFunctions = vuln.reachable_functions || 0;
                              const unreachableFunctions = vuln.unreachable_functions || 0;
                              
                              insertOssStmt.run(
                                scanId,
                                scanPath,
                                getKoreaTimeSQLite(),
                                packageName,
                                currentVersion,
                                fixedVersion,
                                JSON.stringify(allFixedVersions),
                                affectedRange,
                                dependencyType,
                                vulnId,
                                cve,
                                cvss,
                                severity,
                                title,
                                description,
                                referenceUrl,
                                reachable,
                                functionsCount,
                                reachableFunctions,
                                unreachableFunctions,
                                JSON.stringify(vuln)
                              );
                            } catch (insertError) {
                              console.error('OSS 취약점 저장 오류:', insertError);
                              console.error('저장 실패한 취약점:', JSON.stringify(vuln, null, 2));
                            }
                          }
                          
                          console.log(`OSS 취약점 ${vulnerabilities.length}개 저장 완료 (대체 파일 사용)`);
                        }
                      }
                    }
                    
                    // dashboard.json 파일이 없는 경우, summary.json을 확인하여 실패 원인 로깅
                    if (!fileExists) {
                      const summaryFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-summary.json`);
                      try {
                        const summaryExists = await fs.access(summaryFile).then(() => true).catch(() => false);
                        if (summaryExists) {
                          const summaryData = JSON.parse(await fs.readFile(summaryFile, 'utf-8'));
                          const vulnStatus = summaryData.vulnerability?.status || 'unknown';
                          console.log(`Bomtori summary 파일 확인됨: ${summaryFile}`);
                          console.log(`Vulnerability 분석 상태: ${vulnStatus}`);
                          if (vulnStatus === 'Skipped or Failed') {
                            console.log('Vulnerability 분석이 실패하여 dashboard.json이 생성되지 않았습니다.');
                          }
                        } else {
                          console.error(`Bomtori summary 파일도 찾을 수 없습니다: ${summaryFile}`);
                          console.error('가능한 원인: 컨테이너가 종료되기 전에 파일이 완전히 쓰여지지 않았거나, 볼륨 마운트 문제일 수 있습니다.');
                        }
                      } catch (error) {
                        console.error('Bomtori summary 파일 확인 중 오류:', error);
                      }
                    }
                  }
                } catch (error) {
                  console.error('Bomtori 결과 저장 오류:', error);
                  // 오류가 발생해도 계속 진행
                }
                resolve();
              } else {
                console.error(`Bomtori 분석 실패 (종료 코드: ${code})`);
                const currentProgress = scanProgress.get(scanId);
                if (currentProgress) {
                  currentProgress.bomtori = 100; // 실패해도 100%로 표시
                  currentProgress.bomtoriCompleted = true;
                  currentProgress.bomtoriError = `Bomtori 분석 실패 (종료 코드: ${code}). 프로젝트 타입을 감지할 수 없거나 지원되지 않는 프로젝트입니다.`;
                  scanProgress.set(scanId, currentProgress);
                }
                resolve(); // 실패해도 resolve (오류는 무시하지만 오류 정보는 저장)
              }
            });
            
            bomtoriProcess.on('error', (error) => {
              // 진행률 업데이트 인터벌 정리
              clearInterval(bomtoriProgressInterval);
              
              console.error('Bomtori 실행 오류:', error.message);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.bomtori = 100;
                currentProgress.bomtoriCompleted = true;
                currentProgress.bomtoriError = `Bomtori 실행 오류: ${error.message}`;
                scanProgress.set(scanId, currentProgress);
              }
              resolve(); // 오류는 무시하고 resolve (오류 정보는 저장)
            });
          });
          
          scanPromises.push(bomtoriPromise);
        } catch (error) {
          console.error('Bomtori 분석 시작 실패:', error.message);
          // Bomtori 시작 실패 시에도 진행률 업데이트
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.bomtori = 100;
            currentProgress.bomtoriCompleted = true;
            currentProgress.bomtoriError = `Bomtori 시작 실패: ${error.message}`;
            scanProgress.set(scanId, currentProgress);
          }
        }
      }
      
      // Code Scanner도 Promise로 감싸서 동시 실행
      const scannerPromise = new Promise((resolve, reject) => {
        const scanProcess = spawn('docker', dockerArgs, {
          cwd: SCANNER_PATH
        });
        
        // 타임아웃 설정
        const timeout = setTimeout(() => {
          scanProcess.kill();
          reject(new Error('스캔 타임아웃 (5분 초과)'));
        }, 300000); // 5분

        let stdout = '';
        let stderr = '';

        // Scanner 진행률 추적
        let scannerStartTime = Date.now();
        const scannerEstimatedDuration = 180000; // 3분 예상

        scanProcess.stdout.on('data', (data) => {
          const output = data.toString();
          stdout += output;
          const trimmed = output.trim();
          console.log('[Scanner]', trimmed);
          
          // 진행률 파싱 시도 (예: "Progress: 50%" 또는 "50%")
          const progressMatch = trimmed.match(/(\d+)%/);
          if (progressMatch) {
            const progress = parseInt(progressMatch[1]);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scanner = Math.min(progress, 99);
              scanProgress.set(scanId, currentProgress);
            }
          } else {
            // 시간 기반 진행률 추정
            const elapsed = Date.now() - scannerStartTime;
            const estimatedProgress = Math.min(Math.floor((elapsed / scannerEstimatedDuration) * 100), 99);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scanner = estimatedProgress;
              scanProgress.set(scanId, currentProgress);
            }
          }
        });

        scanProcess.stderr.on('data', (data) => {
          stderr += data.toString();
          console.error('[Scanner Error]', data.toString().trim());
        });

        scanProcess.on('close', async (code) => {
          clearTimeout(timeout);
          
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.scanner = 100;
            currentProgress.scannerCompleted = true;
            scanProgress.set(scanId, currentProgress);
          }
          
          if (code !== 0) {
            console.error(`스캔 프로세스 종료 코드: ${code}`);
            console.error(`stderr: ${stderr}`);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scanner = 100;
              currentProgress.scannerCompleted = true;
              currentProgress.scannerError = `Code Scanner 실패 (종료 코드: ${code}): ${stderr || '알 수 없는 오류'}`;
              scanProgress.set(scanId, currentProgress);
            }
            if (!res.headersSent) {
            res.status(500).json({
              success: false,
              message: `스캔 실패: ${stderr || '알 수 없는 오류'}`
            });
            }
            return reject(new Error(`스캔 실패: ${stderr || '알 수 없는 오류'}`));
          }

          try {
            // 결과 파일 읽기 (안전한 서버 이름으로 저장된 파일)
            const resultFile = path.join(ARTIFACTS_DIR, `${safeServerName}.json`);
            
            // 파일 존재 확인 (최대 5초 대기)
            let fileExists = false;
            for (let i = 0; i < 10; i++) {
              try {
                await fs.access(resultFile);
                fileExists = true;
                break;
              } catch (e) {
                await new Promise(resolve => setTimeout(resolve, 500));
              }
            }

            if (!fileExists) {
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.scannerError = `스캔 결과 파일을 찾을 수 없습니다: ${resultFile}`;
                scanProgress.set(scanId, currentProgress);
              }
              if (!res.headersSent) {
              res.status(500).json({
                success: false,
                message: `스캔 결과 파일을 찾을 수 없습니다: ${resultFile}`
              });
              }
              return reject(new Error(`스캔 결과 파일을 찾을 수 없습니다: ${resultFile}`));
            }

            const resultData = await fs.readFile(resultFile, 'utf-8');
            const scanResult = JSON.parse(resultData);

            // 결과 형식: { scan_info: {...}, findings: [...], summary: {...} }
            const findings = scanResult.findings || (Array.isArray(scanResult) ? scanResult : []);

            // scanId는 이미 생성되어 있음 (Bomtori와 동일한 ID 사용)

            // 기존 코드 취약점 데이터 삭제 (같은 scan_path의 이전 스캔 결과)
            try {
              const deleteStmt = db.prepare('DELETE FROM code_vulnerabilities WHERE scan_path = ?');
              deleteStmt.run(scanPath);
              console.log(`기존 코드 취약점 데이터 삭제 완료: ${scanPath}`);
            } catch (deleteError) {
              console.error('기존 코드 취약점 데이터 삭제 오류:', deleteError);
            }

            // 데이터베이스에 저장
            const insertStmt = db.prepare(`
              INSERT INTO code_vulnerabilities (
                scan_id, scan_path, scan_timestamp, rule_id, vulnerability, severity,
                language, file, line, column, message, description, cwe,
                code_snippet, pattern_type, pattern, confidence, raw_finding
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            for (const finding of findings) {
              try {
                insertStmt.run(
                  scanId,
                  scanPath,
                  getKoreaTimeSQLite(),
                  finding.rule_id || null,
                  finding.vulnerability || finding.message || null,
                  finding.severity || null,
                  finding.language || null,
                  finding.file || null,
                  finding.line || null,
                  finding.column || null,
                  finding.message || null,
                  finding.description || null,
                  finding.cwe || null,
                  finding.code_snippet || null,
                  finding.pattern_type || null,
                  finding.pattern || null,
                  finding.confidence || null,
                  JSON.stringify(finding)
                );
              } catch (insertError) {
                console.error('취약점 저장 오류:', insertError);
              }
            }

            // Scanner 완료 처리
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.scannerCompleted = true;
            }
            
            resolve();
          } catch (error) {
            console.error('결과 파싱 오류:', error);
            if (!res.headersSent) {
            res.status(500).json({
              success: false,
              message: `결과 파싱 실패: ${error.message}`
            });
            }
            reject(error);
          }
        });

        scanProcess.on('error', (error) => {
          clearTimeout(timeout);
          console.error('스캐너 실행 오류:', error);
          console.error('오류 코드:', error.code);
          console.error('오류 메시지:', error.message);
          
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.scanner = 100;
            currentProgress.scannerCompleted = true;
            // 더 자세한 오류 메시지 제공
            let errorMessage = `스캐너 실행 실패: ${error.message}`;
            if (error.code === 'ENOENT') {
              errorMessage = `Docker를 찾을 수 없습니다. PATH에 docker가 설정되어 있는지 확인해주세요.`;
            }
            currentProgress.scannerError = errorMessage;
            scanProgress.set(scanId, currentProgress);
          }
          
          reject(error);
        });
      });
      
      scanPromises.push(scannerPromise);
      
      // TOOL-VET 분석도 동시에 실행 (GitHub URL이 있는 경우만)
      if (github_url && isValidGithubUrl(github_url)) {
        try {
          // TOOL-VET 컨테이너가 실행 중인지 확인
          try {
            const checkToolVetProcess = spawn('docker', [
              'ps',
              '--filter',
              `name=${TOOL_VET_CONTAINER_NAME}`,
              '--format',
              '{{.Names}}'
            ], {
              cwd: TOOL_VET_ROOT
            });
            
            let toolVetStdout = '';
            let toolVetStderr = '';
            
            checkToolVetProcess.stdout.on('data', (data) => {
              toolVetStdout += data.toString();
            });
            
            checkToolVetProcess.stderr.on('data', (data) => {
              toolVetStderr += data.toString();
            });
            
            await new Promise((resolve, reject) => {
              checkToolVetProcess.on('close', (code) => {
                if (code !== 0) {
                  reject(new Error(`Docker 명령 실행 실패: ${toolVetStderr || '알 수 없는 오류'}`));
                } else {
                  resolve();
                }
              });
              
              checkToolVetProcess.on('error', (error) => {
                reject(error);
              });
            });
            
            if (!toolVetStdout.trim()) {
              throw new Error(`Docker 컨테이너가 실행 중이 아닙니다: ${TOOL_VET_CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`);
            }
          } catch (error) {
            console.error(`TOOL-VET 컨테이너 확인 실패: ${error.message}`);
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.toolVet = 100;
              currentProgress.toolVetCompleted = true;
              currentProgress.toolVetError = `TOOL-VET 시작 실패: TOOL-VET 컨테이너가 실행 중이 아닙니다: ${TOOL_VET_CONTAINER_NAME}. 컨테이너를 먼저 시작해주세요.`;
              scanProgress.set(scanId, currentProgress);
            }
            // 컨테이너가 없어도 계속 진행 (오류만 기록)
          }
          
          // docker exec로 실행
          const toolVetArgs = [
            'exec',
            TOOL_VET_CONTAINER_NAME,
            'python',
            'main.py',
            '--git-url',
            github_url,
            '--output-dir',
            '/app/output'
          ];
          
          console.log(`TOOL-VET 실행 명령: docker ${toolVetArgs.join(' ')}`);
          
          const toolVetPromise = new Promise((resolve, reject) => {
            const toolVetProcess = spawn('docker', toolVetArgs, { cwd: TOOL_VET_ROOT });
            
            const currentProgress = scanProgress.get(scanId);
            if (currentProgress) {
              currentProgress.toolVet = 1; // 시작됨을 표시
              scanProgress.set(scanId, currentProgress);
            }
            
            let toolVetStartTime = Date.now();
            const toolVetEstimatedDuration = 300000; // 5분 예상
            
            // 시간 기반 진행률 업데이트를 위한 인터벌 설정
            const toolVetProgressInterval = setInterval(() => {
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress && currentProgress.toolVet !== null && currentProgress.toolVet < 100 && !currentProgress.toolVetCompleted) {
                const elapsed = Date.now() - toolVetStartTime;
                const estimatedProgress = Math.min(Math.floor((elapsed / toolVetEstimatedDuration) * 100), 99);
                if (estimatedProgress > currentProgress.toolVet) {
                  currentProgress.toolVet = estimatedProgress;
                  scanProgress.set(scanId, currentProgress);
                }
              }
            }, 2000); // 2초마다 업데이트
            
            toolVetProcess.stdout.on('data', (data) => {
              const output = data.toString().trim();
              console.log('[TOOL-VET]', output);
              
              // 진행률 파싱 시도
              const progressMatch = output.match(/(\d+)%/);
              if (progressMatch) {
                const progress = parseInt(progressMatch[1]);
                const currentProgress = scanProgress.get(scanId);
                if (currentProgress && !currentProgress.toolVetCompleted) {
                  currentProgress.toolVet = Math.min(progress, 99);
                  scanProgress.set(scanId, currentProgress);
                }
              }
            });
            
            toolVetProcess.stderr.on('data', (data) => {
              console.error('[TOOL-VET Error]', data.toString().trim());
            });
            
            toolVetProcess.on('close', async (code) => {
              clearInterval(toolVetProgressInterval);
              
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.toolVet = 100;
                currentProgress.toolVetCompleted = true;
                scanProgress.set(scanId, currentProgress);
              }
              
              if (code === 0) {
                console.log('TOOL-VET 분석 완료');
                resolve();
              } else {
                console.error(`TOOL-VET 분석 실패 (종료 코드: ${code})`);
                const currentProgress = scanProgress.get(scanId);
                if (currentProgress) {
                  currentProgress.toolVet = 100;
                  currentProgress.toolVetCompleted = true;
                  currentProgress.toolVetError = `TOOL-VET 분석 실패 (종료 코드: ${code}). 프로젝트 타입을 감지할 수 없거나 지원되지 않는 프로젝트입니다.`;
                  scanProgress.set(scanId, currentProgress);
                }
                resolve(); // 실패해도 resolve (오류는 무시하지만 오류 정보는 저장)
              }
            });
            
            toolVetProcess.on('error', (error) => {
              clearInterval(toolVetProgressInterval);
              
              console.error('TOOL-VET 실행 오류:', error);
              const currentProgress = scanProgress.get(scanId);
              if (currentProgress) {
                currentProgress.toolVet = 100;
                currentProgress.toolVetCompleted = true;
                currentProgress.toolVetError = `TOOL-VET 실행 오류: ${error.message}`;
                scanProgress.set(scanId, currentProgress);
              }
              resolve(); // 오류는 무시하고 resolve (오류 정보는 저장)
            });
          });
          
          scanPromises.push(toolVetPromise);
        } catch (error) {
          console.error('TOOL-VET 분석 시작 실패:', error.message);
          const currentProgress = scanProgress.get(scanId);
          if (currentProgress) {
            currentProgress.toolVet = 100;
            currentProgress.toolVetCompleted = true;
            currentProgress.toolVetError = `TOOL-VET 시작 실패: ${error.message}`;
            scanProgress.set(scanId, currentProgress);
          }
        }
      }
      
      // 모든 스캔을 동시에 시작하고 완료될 때까지 대기
      try {
        await Promise.all(scanPromises);
        
        // 모든 스캔이 완료되었는지 최종 확인
        const finalProgress = scanProgress.get(scanId);
        if (finalProgress) {
          // Bomtori, Code Scanner, TOOL-VET 중 하나라도 오류가 있으면 'failed'로 설정
          if (finalProgress.bomtoriError || finalProgress.scannerError || finalProgress.toolVetError) {
            finalProgress.status = 'failed';
            const errorMessages = [];
            if (finalProgress.bomtoriError) {
              errorMessages.push(finalProgress.bomtoriError);
            }
            if (finalProgress.scannerError) {
              errorMessages.push(finalProgress.scannerError);
            }
            if (finalProgress.toolVetError) {
              errorMessages.push(finalProgress.toolVetError);
            }
            finalProgress.error = errorMessages.join(' / ');
          } else {
            finalProgress.status = 'completed';
            
            // 스캔 완료 시 mcp_register_requests 테이블의 scanned 필드와 analysis_timestamp 업데이트
            if (serverName) {
              try {
                // pending 상태인 경우 업데이트
                let updateStmt = db.prepare('UPDATE mcp_register_requests SET scanned = 1, analysis_timestamp = datetime("now") WHERE name = ? AND status = ?');
                let result = updateStmt.run(serverName, 'pending');
                
                // pending 상태에서 업데이트되지 않았다면 approved 상태에서도 시도
                if (result.changes === 0) {
                  updateStmt = db.prepare('UPDATE mcp_register_requests SET scanned = 1, analysis_timestamp = datetime("now") WHERE name = ? AND status = ?');
                  result = updateStmt.run(serverName, 'approved');
                }
                
                if (result.changes > 0) {
                  console.log(`스캔 완료: ${serverName} 요청의 scanned 필드 및 analysis_timestamp 업데이트 완료`);
                } else {
                  console.log(`스캔 완료: ${serverName} 요청을 찾을 수 없거나 이미 거부됨`);
                }
              } catch (updateError) {
                console.error('스캔 완료 상태 업데이트 오류:', updateError);
                // 오류가 발생해도 스캔 결과는 정상적으로 저장되므로 계속 진행
              }
            }
          }
          scanProgress.set(scanId, finalProgress);
        }
      } catch (error) {
        // 오류 발생 시 상태를 'failed'로 설정
        console.error('스캔 프로세스 오류:', error);
        const finalProgress = scanProgress.get(scanId);
        if (finalProgress) {
          finalProgress.status = 'failed';
          finalProgress.error = error.message || '스캔 중 오류가 발생했습니다.';
          scanProgress.set(scanId, finalProgress);
        }
      }

    } catch (error) {
      console.error('코드 스캔 오류:', error);
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: '코드 스캔 중 오류가 발생했습니다.'
        });
      }
    }
  },

  // 진행률 조회 API
  getScanProgress: async (req, res) => {
    try {
      const { scan_id } = req.query;
      
      if (!scan_id) {
        return res.status(400).json({
          success: false,
          message: 'scan_id가 필요합니다.'
        });
      }
      
      const progress = scanProgress.get(scan_id);
      
      if (!progress) {
        return res.status(404).json({
          success: false,
          message: '진행률 정보를 찾을 수 없습니다.'
        });
      }
      
      res.json({
        success: true,
        data: progress
      });
    } catch (error) {
      console.error('진행률 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '진행률 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // OSS 취약점 조회 (데이터베이스에서 조회)
  getOssVulnerabilities: async (req, res) => {
    try {
      const { scan_id, scan_path } = req.query;
      
      let vulnerabilities = [];
      
      if (scan_id) {
        // scan_id로 조회
        vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id);
      } else if (scan_path) {
        // scan_path로 최신 스캔 결과 조회
        const latestScan = db.prepare('SELECT DISTINCT scan_id FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').get(scan_path);
        if (latestScan && latestScan.scan_id) {
          vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id);
        } else {
          // scan_path로 직접 조회 시도 (scan_id가 없는 경우)
          vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
        }
        
        // 데이터베이스에 데이터가 없고 scan_path가 GitHub URL인 경우, dashboard.json 파일에서 직접 로드 시도
        if (vulnerabilities.length === 0 && scan_path && isValidGithubUrl(scan_path)) {
          try {
            // repo_name 추출 (GitHub URL에서)
            // 예: https://github.com/github/github-mcp-server -> github-mcp-server
            // 예: https://github.com/github/github-mcp-server.git -> github-mcp-server
            let repoName = scan_path.split('/').pop().replace('.git', '');
            // GitHub URL 형식: https://github.com/owner/repo
            const urlParts = scan_path.split('/');
            if (urlParts.length >= 2 && urlParts[urlParts.length - 2] && urlParts[urlParts.length - 1]) {
              // owner/repo 형식으로 추출
              repoName = `${urlParts[urlParts.length - 2]}-${urlParts[urlParts.length - 1]}`.replace('.git', '');
            }
            repoName = repoName.replace(/[^a-zA-Z0-9_-]/g, '_');
            
            const dashboardFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-dashboard.json`);
            
            console.log(`데이터베이스에 OSS 취약점이 없어 dashboard.json 파일에서 로드 시도`);
            console.log(`scan_path: ${scan_path}`);
            console.log(`추출된 repoName: ${repoName}`);
            console.log(`예상 파일 경로: ${dashboardFile}`);
            
            // 파일 존재 확인
            try {
              await fs.access(dashboardFile);
              const dashboardData = JSON.parse(await fs.readFile(dashboardFile, 'utf-8'));
              const dashboardVulnerabilities = dashboardData.vulnerabilities || [];
              
              console.log(`dashboard.json에서 발견된 취약점 개수: ${dashboardVulnerabilities.length}`);
              
              if (dashboardVulnerabilities.length > 0) {
                // scan_id 생성 (없으면 새로 생성)
                const scanId = uuidv4();
                
                // 기존 OSS 취약점 데이터 삭제 (같은 scan_path의 이전 스캔 결과)
                try {
                  const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                  deleteOssStmt.run(scan_path);
                  console.log(`기존 OSS 취약점 데이터 삭제 완료: ${scan_path}`);
                } catch (deleteError) {
                  console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                }
                
                // 데이터베이스에 저장
                const insertOssStmt = db.prepare(`
                  INSERT INTO oss_vulnerabilities (
                    scan_id, scan_path, scan_timestamp,
                    package_name, package_version, package_fixed_version, package_all_fixed_versions,
                    package_affected_range, package_dependency_type,
                    vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                    vulnerability_title, vulnerability_description, vulnerability_reference_url,
                    reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `);
                
                let successCount = 0;
                let errorCount = 0;
                
                for (const vuln of dashboardVulnerabilities) {
                  try {
                    const pkg = vuln.package || {};
                    const vulnInfo = vuln.vulnerability || {};
                    
                    // Go 프로젝트의 경우 module 필드가 있을 수 있음
                    // npm 프로젝트와 Go 프로젝트 모두 동일한 필드명 사용
                    const packageName = pkg.name || null;
                    // Go 프로젝트 버전에서 "v" 접두사 제거
                    const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                    const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                    const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                      ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                      : [];
                    const affectedRange = pkg.affected_range || null;
                    const dependencyType = pkg.dependency_type || null;
                    
                    // vulnerability 정보
                    const vulnId = vulnInfo.id || null;
                    const cve = vulnInfo.cve || null;
                    const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null; // 0도 유효한 값
                    const severity = vulnInfo.severity || null;
                    const title = vulnInfo.title || null;
                    const description = vulnInfo.description || null;
                    const referenceUrl = vulnInfo.reference_url || null;
                    
                    // reachability 정보
                    const reachable = vuln.reachable === true ? 1 : 0;
                    const functionsCount = vuln.functions_count || 0;
                    const reachableFunctions = vuln.reachable_functions || 0;
                    const unreachableFunctions = vuln.unreachable_functions || 0;
                    
                    insertOssStmt.run(
                      scanId,
                      scan_path,
                      getKoreaTimeSQLite(),
                      packageName,
                      currentVersion,
                      fixedVersion,
                      JSON.stringify(allFixedVersions),
                      affectedRange,
                      dependencyType,
                      vulnId,
                      cve,
                      cvss,
                      severity,
                      title,
                      description,
                      referenceUrl,
                      reachable,
                      functionsCount,
                      reachableFunctions,
                      unreachableFunctions,
                      JSON.stringify(vuln)
                    );
                    successCount++;
                  } catch (insertError) {
                    errorCount++;
                    console.error('OSS 취약점 저장 오류:', insertError);
                    console.error('에러 메시지:', insertError.message);
                    console.error('에러 스택:', insertError.stack);
                    console.error('저장 실패한 취약점:', JSON.stringify(vuln, null, 2));
                  }
                }
                
                console.log(`OSS 취약점 저장 완료: 성공 ${successCount}개, 실패 ${errorCount}개 (총 ${dashboardVulnerabilities.length}개)`);
                
                // 저장한 데이터 다시 조회
                vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
                console.log(`데이터베이스에서 조회된 취약점 개수: ${vulnerabilities.length}`);
              } else {
                console.log(`dashboard.json에 취약점이 없습니다 (vulnerabilities 배열이 비어있음)`);
              }
            } catch (fileError) {
              console.log(`dashboard.json 파일을 찾을 수 없거나 읽을 수 없습니다: ${dashboardFile}`);
              console.log(`파일 에러:`, fileError.message);
              
              // 파일을 찾지 못한 경우, output 디렉토리의 모든 dashboard.json 파일 확인
              try {
                const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
                const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
                console.log(`발견된 dashboard.json 파일들:`, dashboardFiles);
                
                // 파일명에 repoName이 포함된 파일 찾기
                const matchingFiles = dashboardFiles.filter(f => {
                  const fileLower = f.toLowerCase();
                  const repoNameLower = repoName.toLowerCase();
                  return fileLower.includes(repoNameLower) || repoNameLower.includes(fileLower.replace('-dashboard.json', ''));
                });
                
                if (matchingFiles.length > 0) {
                  console.log(`매칭되는 파일 발견: ${matchingFiles.join(', ')}`);
                  // 가장 최근 파일 사용 시도
                  const latestFile = path.join(BOMTORI_OUTPUT_DIR, matchingFiles[0]);
                  try {
                    const dashboardData = JSON.parse(await fs.readFile(latestFile, 'utf-8'));
                    const dashboardVulnerabilities = dashboardData.vulnerabilities || [];
                    console.log(`대체 파일에서 발견된 취약점 개수: ${dashboardVulnerabilities.length}`);
                    
                    if (dashboardVulnerabilities.length > 0) {
                      const scanId = uuidv4();
                      // 기존 데이터 삭제
                      try {
                        const deleteOssStmt = db.prepare('DELETE FROM oss_vulnerabilities WHERE scan_path = ?');
                        deleteOssStmt.run(scan_path);
                      } catch (deleteError) {
                        console.error('기존 OSS 취약점 데이터 삭제 오류:', deleteError);
                      }
                      
                      // 저장 로직 (위와 동일)
                      const insertOssStmt = db.prepare(`
                        INSERT INTO oss_vulnerabilities (
                          scan_id, scan_path, scan_timestamp,
                          package_name, package_version, package_fixed_version, package_all_fixed_versions,
                          package_affected_range, package_dependency_type,
                          vulnerability_id, vulnerability_cve, vulnerability_cvss, vulnerability_severity,
                          vulnerability_title, vulnerability_description, vulnerability_reference_url,
                          reachable, functions_count, reachable_functions, unreachable_functions, raw_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                      `);
                      
                      let successCount = 0;
                      let errorCount = 0;
                      
                      for (const vuln of dashboardVulnerabilities) {
                        try {
                          const pkg = vuln.package || {};
                          const vulnInfo = vuln.vulnerability || {};
                          
                          const packageName = pkg.name || null;
                          // Go 프로젝트 버전에서 "v" 접두사 제거
                          const currentVersion = removeVersionPrefix(pkg.current_version) || null;
                          const fixedVersion = removeVersionPrefix(pkg.fixed_version) || null;
                          const allFixedVersions = Array.isArray(pkg.all_fixed_versions) 
                            ? pkg.all_fixed_versions.map(v => removeVersionPrefix(v))
                            : [];
                          const affectedRange = pkg.affected_range || null;
                          const dependencyType = pkg.dependency_type || null;
                          
                          const vulnId = vulnInfo.id || null;
                          const cve = vulnInfo.cve || null;
                          const cvss = vulnInfo.cvss != null ? vulnInfo.cvss : null;
                          const severity = vulnInfo.severity || null;
                          const title = vulnInfo.title || null;
                          const description = vulnInfo.description || null;
                          const referenceUrl = vulnInfo.reference_url || null;
                          
                          const reachable = vuln.reachable === true ? 1 : 0;
                          const functionsCount = vuln.functions_count || 0;
                          const reachableFunctions = vuln.reachable_functions || 0;
                          const unreachableFunctions = vuln.unreachable_functions || 0;
                          
                          insertOssStmt.run(
                            scanId,
                            scan_path,
                            getKoreaTimeSQLite(),
                            packageName,
                            currentVersion,
                            fixedVersion,
                            JSON.stringify(allFixedVersions),
                            affectedRange,
                            dependencyType,
                            vulnId,
                            cve,
                            cvss,
                            severity,
                            title,
                            description,
                            referenceUrl,
                            reachable,
                            functionsCount,
                            reachableFunctions,
                            unreachableFunctions,
                            JSON.stringify(vuln)
                          );
                          successCount++;
                        } catch (insertError) {
                          errorCount++;
                          console.error('OSS 취약점 저장 오류:', insertError);
                          console.error('저장 실패한 취약점:', JSON.stringify(vuln, null, 2));
                        }
                      }
                      
                      console.log(`대체 파일에서 OSS 취약점 저장 완료: 성공 ${successCount}개, 실패 ${errorCount}개`);
                      vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
                      console.log(`데이터베이스에서 조회된 취약점 개수: ${vulnerabilities.length}`);
                    }
                  } catch (readError) {
                    console.error('대체 파일 읽기 실패:', readError);
                  }
                }
              } catch (dirError) {
                console.error('output 디렉토리 읽기 실패:', dirError);
              }
            }
          } catch (loadError) {
            console.error('dashboard.json 파일에서 OSS 취약점 로드 오류:', loadError);
          }
        }
      } else {
        // 모든 취약점 조회
        vulnerabilities = db.prepare('SELECT * FROM oss_vulnerabilities ORDER BY scan_timestamp DESC, id DESC').all();
      }
      
      // raw_data JSON 파싱
      const findings = vulnerabilities.map(v => {
        const finding = {
          package: {
            name: v.package_name,
            current_version: v.package_version,
            fixed_version: v.package_fixed_version,
            all_fixed_versions: v.package_all_fixed_versions ? JSON.parse(v.package_all_fixed_versions) : [],
            affected_range: v.package_affected_range,
            dependency_type: v.package_dependency_type
          },
          vulnerability: {
            id: v.vulnerability_id,
            cve: v.vulnerability_cve,
            cvss: v.vulnerability_cvss,
            severity: v.vulnerability_severity,
            title: v.vulnerability_title,
            description: v.vulnerability_description,
            reference_url: v.vulnerability_reference_url
          },
          reachable: v.reachable === 1,
          functions_count: v.functions_count,
          reachable_functions: v.reachable_functions,
          unreachable_functions: v.unreachable_functions
        };
        
        // raw_data가 있으면 파싱하여 추가
        if (v.raw_data) {
          try {
            const rawData = JSON.parse(v.raw_data);
            // rawData에 functions 배열이 있으면 finding에 포함
            if (rawData.functions && Array.isArray(rawData.functions)) {
              finding.functions = rawData.functions;
            }
            return { ...finding, rawData };
          } catch (e) {
            return { ...finding, rawData: v.raw_data };
          }
        }
        
        return finding;
      });
      
      // packages 배열도 함께 반환 (license 정보 포함)
      // scan_id로 조회한 경우에도 scan_path를 가져와서 packages를 로드해야 함
      let packages = [];
      let actualScanPath = scan_path;
      
      // scan_id로 조회한 경우 scan_path를 가져오기 (모든 경로에서 동일하게 처리)
      if (!actualScanPath && vulnerabilities.length > 0) {
        actualScanPath = vulnerabilities[0].scan_path;
        console.log(`scan_id로 조회: scan_path 추출됨 - ${actualScanPath}`);
      }
      
      // scan_path가 여전히 없으면 scan_id로 조회한 경우에도 scan_path를 다시 시도
      if (!actualScanPath && scan_id) {
        const scanPathFromDb = db.prepare('SELECT DISTINCT scan_path FROM oss_vulnerabilities WHERE scan_id = ? LIMIT 1').get(scan_id);
        if (scanPathFromDb && scanPathFromDb.scan_path) {
          actualScanPath = scanPathFromDb.scan_path;
          console.log(`scan_id로 scan_path 재조회: ${actualScanPath}`);
        }
      }
      
      if (actualScanPath && isValidGithubUrl(actualScanPath)) {
        try {
          // repo_name 추출 (실제 파일명은 repo-dashboard.json 형식)
          // GitHub URL 형식: https://github.com/owner/repo
          let repoName = actualScanPath.split('/').pop().replace('.git', '');
          // owner-repo 형식이 아니라 repo만 사용
          repoName = repoName.replace(/[^a-zA-Z0-9_-]/g, '_');
          
          const dashboardFile = path.join(BOMTORI_OUTPUT_DIR, `${repoName}-dashboard.json`);
          
          try {
            await fs.access(dashboardFile);
            const dashboardData = JSON.parse(await fs.readFile(dashboardFile, 'utf-8'));
            packages = dashboardData.packages || [];
            console.log(`packages 배열 로드 완료: ${packages.length}개 패키지 (scan_path: ${actualScanPath}, repoName: ${repoName})`);
          } catch (fileError) {
            console.log(`dashboard.json 파일을 찾을 수 없거나 읽을 수 없습니다: ${dashboardFile}`, fileError.message);
            
            // 파일을 찾지 못한 경우, output 디렉토리의 모든 dashboard.json 파일 확인
            try {
              const allFiles = await fs.readdir(BOMTORI_OUTPUT_DIR);
              const dashboardFiles = allFiles.filter(f => f.includes('dashboard.json'));
              
              // 파일명에 repoName이 포함된 파일 찾기
              const matchingFiles = dashboardFiles.filter(f => {
                const fileLower = f.toLowerCase();
                const repoNameLower = repoName.toLowerCase();
                return fileLower.includes(repoNameLower) || repoNameLower.includes(fileLower.replace('-dashboard.json', ''));
              });
              
              if (matchingFiles.length > 0) {
                // 가장 최근 파일 사용
                const latestFile = path.join(BOMTORI_OUTPUT_DIR, matchingFiles[0]);
                try {
                  const dashboardData = JSON.parse(await fs.readFile(latestFile, 'utf-8'));
                  packages = dashboardData.packages || [];
                  console.log(`대체 파일에서 packages 배열 로드 완료: ${packages.length}개 패키지 (파일: ${matchingFiles[0]})`);
                } catch (readError) {
                  console.error('대체 파일 읽기 실패:', readError);
                }
              }
            } catch (dirError) {
              console.error('output 디렉토리 읽기 실패:', dirError);
            }
          }
        } catch (loadError) {
          console.error('dashboard.json 파일에서 packages 로드 오류:', loadError);
        }
      }
      
      res.json({
        success: true,
        data: findings,
        packages: packages
      });
    } catch (error) {
      console.error('OSS 취약점 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: 'OSS 취약점 조회 중 오류가 발생했습니다.'
      });
    }
  },

  // 스캔 결과 조회 (데이터베이스에서 조회)
  getCodeVulnerabilities: async (req, res) => {
    try {
      const { scan_id, scan_path } = req.query;
      
      let vulnerabilities = [];
      
      if (scan_id) {
        // scan_id로 조회
        vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_id);
      } else if (scan_path) {
        // scan_path로 최신 스캔 결과 조회
        // 먼저 최신 scan_id 가져오기
        const latestScan = db.prepare('SELECT DISTINCT scan_id FROM code_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC LIMIT 1').get(scan_path);
        if (latestScan && latestScan.scan_id) {
          // 해당 scan_id의 모든 취약점 조회
          vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_id = ? ORDER BY scan_timestamp DESC, id DESC').all(latestScan.scan_id);
        } else {
          // scan_path로 직접 조회 시도 (scan_id가 없는 경우)
          vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities WHERE scan_path = ? ORDER BY scan_timestamp DESC, id DESC').all(scan_path);
        }
      } else {
        // 모든 취약점 조회
        vulnerabilities = db.prepare('SELECT * FROM code_vulnerabilities ORDER BY scan_timestamp DESC, id DESC').all();
      }
      
      // raw_finding JSON 파싱
      const findings = vulnerabilities.map(v => {
        const finding = {
          rule_id: v.rule_id,
          vulnerability: v.vulnerability,
          severity: v.severity,
          language: v.language,
          file: v.file,
          line: v.line,
          column: v.column,
          message: v.message,
          description: v.description,
          cwe: v.cwe,
          code_snippet: v.code_snippet,
          pattern_type: v.pattern_type,
          pattern: v.pattern,
          confidence: v.confidence
        };
        
        // raw_finding이 있으면 파싱하여 추가
        if (v.raw_finding) {
          try {
            const rawData = JSON.parse(v.raw_finding);
            return { ...finding, ...rawData, rawFinding: rawData };
          } catch (e) {
            return { ...finding, rawFinding: v.raw_finding };
          }
        }
        
        return finding;
      });
      
      res.json({
        success: true,
        data: findings
      });
    } catch (error) {
      console.error('스캔 결과 조회 오류:', error);
      res.status(500).json({
        success: false,
        message: '스캔 결과 조회 중 오류가 발생했습니다.'
      });
    }
  }
};

module.exports = riskAssessmentController;

