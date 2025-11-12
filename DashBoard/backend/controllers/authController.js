const userModel = require('../models/user');
const { generateToken } = require('../utils/jwt');

const authController = {
  login: (req, res) => {
    try {
      const { username, employee_id, password } = req.body;

      // 필수 필드 검증
      if (!username || !employee_id || !password) {
        return res.status(400).json({
          success: false,
          message: '사용자명, 사원번호, 비밀번호를 모두 입력해주세요.'
        });
      }

      // DB에서 사용자 조회 (사용자명과 사원번호 모두 일치해야 함)
      const user = userModel.findByUsername(username);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: '사용자명 또는 비밀번호가 잘못되었습니다.'
        });
      }

      // 사원번호 일치 확인
      if (user.employee_id !== employee_id) {
        return res.status(401).json({
          success: false,
          message: '사용자명 또는 비밀번호가 잘못되었습니다.'
        });
      }

      // 비밀번호 확인 (현재는 평문 비교, 추후 bcrypt 등으로 암호화 권장)
      if (user.password !== password) {
        return res.status(401).json({
          success: false,
          message: '사용자명 또는 비밀번호가 잘못되었습니다.'
        });
      }

      // 사용자 활성화 상태 확인
      if (!user.is_active) {
        return res.status(403).json({
          success: false,
          message: '비활성화된 계정입니다.'
        });
      }

      // 역할을 배열로 변환 (role 이름만 추출)
      const roleNames = (user.roles || []).map(role => role.name || role);

      // JWT 토큰 발급
      const token = generateToken({
        id: user.id,
        username: user.username,
        employee_id: user.employee_id,
        email: user.email,
        team: user.team,
        roles: roleNames
      });

      res.json({
        success: true,
        message: '로그인 성공',
        token: token,
        user: {
          id: user.id,
          username: user.username,
          employee_id: user.employee_id,
          email: user.email,
          team: user.team,
          roles: roleNames
        }
      });
    } catch (error) {
      console.error('로그인 오류:', error);
      res.status(500).json({
        success: false,
        message: '로그인 중 오류가 발생했습니다.'
      });
    }
  },

  logout: (req, res) => {
    // 추후 세션/토큰 무효화 로직 추가
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  },

  register: (req, res) => {
    const { username, password, email } = req.body;

    // 필수 필드 검증
    if (!username || !password || !email) {
      return res.status(400).json({
        success: false,
        message: '모든 필드를 입력해주세요.'
      });
    }

    // 중복 사용자 확인
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: '이미 존재하는 사용자명 또는 이메일입니다.'
      });
    }

    // 비밀번호 길이 검증
    if (password.length < 4) {
      return res.status(400).json({
        success: false,
        message: '비밀번호는 최소 4자 이상이어야 합니다.'
      });
    }

    // 새 사용자 생성 (일반 사용자로 자동 설정)
    const newUser = {
      id: users.length + 1,
      username,
      password, // 추후 암호화 필요
      email,
      role: 'user' // 기본값은 일반 사용자
    };

    users.push(newUser);

    res.json({
      success: true,
      message: '회원가입이 완료되었습니다.',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  }
};

module.exports = authController;

