/**
 * 모든 요청 로깅 미들웨어 (디버깅용)
 * MCP Proxy 요청 추적을 위해 사용
 */

function requestLogger(req, res, next) {
  // MCP Proxy 또는 DLP 관련 요청 로깅
  const isMCPRequest = req.path.includes('/api/mcp') || req.headers['x-mcp-proxy-request'] === 'true';
  const isDLPRequest = req.path.includes('/dlp/violation') || req.path === '/api/dlp/violation';
  
  // 모든 POST 요청 로깅 (디버깅용)
  if (req.method === 'POST') {
    console.log(`\n📥 === ${req.method} 요청 ===`);
    console.log('Path:', req.path);
    console.log('Headers:', {
      'content-type': req.headers['content-type'],
      'x-api-key': req.headers['x-api-key'] ? '***설정됨***' : '없음',
    });
    if (req.body && Object.keys(req.body).length > 0) {
      console.log('Body:', JSON.stringify(req.body, null, 2));
    }
    console.log('===============================\n');
  }
  
  if (isMCPRequest || isDLPRequest) {
    const requestType = isDLPRequest ? 'DLP 위반 로그' : 'MCP Proxy';
    console.log(`\n📥 === ${requestType} 요청 수신 ===`);
    console.log('시간:', new Date().toISOString());
    console.log('Method:', req.method);
    console.log('Path:', req.path);
    console.log('Query:', req.query);
    console.log('Headers:', {
      'content-type': req.headers['content-type'],
      'x-original-client-ip': req.headers['x-original-client-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-mcp-proxy-request': req.headers['x-mcp-proxy-request'],
      'x-api-key': req.headers['x-api-key'] ? '***설정됨***' : '없음',
      'user-agent': req.headers['user-agent']
    });
    console.log('Remote Address:', req.socket.remoteAddress);
    
    // Body 로깅 (JSON인 경우)
    if (req.body && Object.keys(req.body).length > 0) {
      console.log('Body:', JSON.stringify(req.body, null, 2));
    }
    console.log('===============================\n');
  }
  
  next();
}

module.exports = requestLogger;


