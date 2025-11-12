const express = require('express');
const router = express.Router();
const dashboardController = require('../controllers/dashboardController');
const { jwtAuth } = require('../middleware/jwtAuth');

// 모든 엔드포인트는 인증 필요
router.use(jwtAuth);

// MCP 서버 트래픽 통계 (앱별)
router.get('/traffic/app', dashboardController.getMcpTrafficByApp);

// Host별 사용량
router.get('/traffic/host', dashboardController.getMcpTrafficByHost);

// 실시간 탐지 결과
router.get('/detections', dashboardController.getDetectionResults);

// 사용자 통계
router.get('/statistics', dashboardController.getUserStatistics);

// MCP 서버별 사용자 분포
router.get('/user-distribution', dashboardController.getMcpUserDistribution);

// MCP 서버 통계 (개수 및 카테고리별 분포)
router.get('/mcp-server-stats', dashboardController.getMcpServerStats);

module.exports = router;

