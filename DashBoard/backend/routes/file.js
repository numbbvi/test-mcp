const express = require('express');
const router = express.Router();
const fileController = require('../controllers/fileController');
const upload = require('../middleware/upload');

// 파일 다운로드
router.get('/download/:id', fileController.downloadFile);

// 파일 업로드 (단일 파일)
router.post('/upload', upload.single('file'), fileController.uploadFile);

// 다운로드 로그 조회 (관리자용)
router.get('/download-logs', fileController.getDownloadLogs);

// 다운로드 로그에서 팀 목록 가져오기
router.get('/download-logs/teams', fileController.getTeams);

module.exports = router;

