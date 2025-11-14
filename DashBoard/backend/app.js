const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const errorHandler = require('./middleware/errorHandler');

dotenv.config();

// Initialize Database (테이블 자동 생성)
require('./config/db');

// Routes
const authRoutes = require('./routes/auth');
const marketplaceRoutes = require('./routes/marketplace');
const fileRoutes = require('./routes/file');
const userRoutes = require('./routes/user');
const dlpRoutes = require('./routes/dlp');
const mcpRoutes = require('./routes/mcp');
const dashboardRoutes = require('./routes/dashboard');
const riskAssessmentRoutes = require('./routes/riskAssessment');
const permissionViolationRoutes = require('./routes/permissionViolation');
const debugRoutes = require('./routes/debug'); // 개발용
const dbTablesRoutes = require('./routes/dbTables'); // DB 테이블 조회
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: '*', // 모든 origin 허용 (프로덕션에서는 특정 도메인으로 제한)
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-MCP-Proxy-Request', 'X-Original-Client-IP', 'X-Forwarded-For']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 요청 로깅 (디버깅용 - MCP Proxy 요청 추적)
const requestLogger = require('./middleware/requestLogger');
app.use(requestLogger);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/marketplace', marketplaceRoutes);
app.use('/api/file', fileRoutes);
app.use('/api/users', userRoutes);
app.use('/api/dlp', dlpRoutes);
app.use('/api/mcp', mcpRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/risk-assessment', riskAssessmentRoutes);
app.use('/api/permission-violation', permissionViolationRoutes);
console.log('[Server] Risk Assessment 라우트 등록됨: /api/risk-assessment');
console.log('[Server] Permission Violation 라우트 등록됨: /api/permission-violation');
app.use('/api/debug', debugRoutes); // 개발용: DB 확인 (프로덕션에서는 제거 권장)
app.use('/api/db-tables', dbTablesRoutes); // DB 테이블 조회

// 정적 파일 제공 (업로드된 파일)
app.use('/uploads', express.static('uploads'));

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'MCP Safer API Server', status: 'ok' });
});

// Error handler (마지막에 위치)
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`[${new Date().toISOString()}] 서버 시작됨 - Risk Assessment 라우트 포함`);
});

module.exports = app;
