import React, { useState, useEffect } from 'react';
import { apiGet, apiPut } from '../../utils/api';
import './Settings.css';

const Settings = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('profile'); // 'profile' or 'password'
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [message, setMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    fetchUserInfo();
  }, []);

  const fetchUserInfo = async () => {
    try {
      setLoading(true);
      const savedUser = localStorage.getItem('user');
      if (savedUser) {
        const userData = JSON.parse(savedUser);
        setUser(userData);
      }
      
      // 서버에서 최신 정보 가져오기
      try {
        const res = await apiGet(`/users/me`);
        if (res.success && res.data) {
          setUser(res.data);
        } else {
          console.warn('사용자 정보 응답 형식 오류:', res);
        }
      } catch (apiError) {
        console.error('API 호출 오류:', apiError);
        // API 실패해도 localStorage의 사용자 정보는 표시
        if (!savedUser) {
          setMessage({ type: 'error', text: '사용자 정보를 불러오는데 실패했습니다.' });
        }
      }
    } catch (error) {
      console.error('사용자 정보 로드 실패:', error);
      setMessage({ type: 'error', text: '사용자 정보를 불러오는데 실패했습니다.' });
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });

    // 유효성 검사
    if (!passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword) {
      setMessage({ type: 'error', text: '모든 필드를 입력해주세요.' });
      return;
    }

    if (passwordForm.newPassword.length < 4) {
      setMessage({ type: 'error', text: '새 비밀번호는 최소 4자 이상이어야 합니다.' });
      return;
    }

    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setMessage({ type: 'error', text: '새 비밀번호와 확인 비밀번호가 일치하지 않습니다.' });
      return;
    }

    if (passwordForm.currentPassword === passwordForm.newPassword) {
      setMessage({ type: 'error', text: '현재 비밀번호와 새 비밀번호가 같습니다.' });
      return;
    }

    try {
      const res = await apiPut(`/users/me/password`, {
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword
      });

      if (res.success) {
        setMessage({ type: 'success', text: '비밀번호가 성공적으로 변경되었습니다.' });
        setPasswordForm({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
      } else {
        setMessage({ type: 'error', text: res.message || '비밀번호 변경에 실패했습니다.' });
      }
    } catch (error) {
      console.error('비밀번호 변경 실패:', error);
      setMessage({ type: 'error', text: '비밀번호 변경 중 오류가 발생했습니다.' });
    }
  };

  if (loading) {
    return (
      <section className="settings">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>로딩 중...</p>
        </div>
      </section>
    );
  }

  if (!user) {
    return (
      <section className="settings">
        <div className="error-message">사용자 정보를 불러올 수 없습니다.</div>
      </section>
    );
  }

  return (
    <section className="settings">
      <h1>Settings</h1>
      
      <div className="settings-container">
        <div className="settings-tabs">
          <button
            className={`settings-tab ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            내 정보
          </button>
          <button
            className={`settings-tab ${activeTab === 'password' ? 'active' : ''}`}
            onClick={() => setActiveTab('password')}
          >
            비밀번호 변경
          </button>
        </div>

        <div className="settings-content">
          {activeTab === 'profile' && (
            <div className="profile-section">
              <h2>내 정보</h2>
              <div className="info-card">
                <div className="info-row">
                  <span className="info-label">사용자명</span>
                  <span className="info-value">{user.username || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">사원번호</span>
                  <span className="info-value">{user.employee_id || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">이메일</span>
                  <span className="info-value">{user.email || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">팀</span>
                  <span className="info-value">{user.team || '미지정'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">직책</span>
                  <span className="info-value">{user.position || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">역할</span>
                  <span className="info-value">
                    {user.roles && user.roles.length > 0 ? (
                      <div className="role-badges">
                        {user.roles.map((role, index) => (
                          <span key={index} className={`role-badge ${role === 'admin' ? 'admin' : ''}`}>
                            {role}
                          </span>
                        ))}
                      </div>
                    ) : (
                      '-'
                    )}
                  </span>
                </div>
                <div className="info-row">
                  <span className="info-label">IP 주소</span>
                  <span className="info-value">{user.ip_address || '-'}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">계정 상태</span>
                  <span className={`status-badge ${user.is_active ? 'status-active' : 'status-inactive'}`}>
                    {user.is_active ? '활성' : '비활성'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'password' && (
            <div className="password-section">
              <h2>비밀번호 변경</h2>
              <form onSubmit={handlePasswordChange} className="password-form">
                {message.text && (
                  <div className={`message ${message.type}`}>
                    {message.text}
                  </div>
                )}
                <div className="form-group">
                  <label htmlFor="currentPassword">현재 비밀번호</label>
                  <input
                    type="password"
                    id="currentPassword"
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                    placeholder="현재 비밀번호를 입력하세요"
                    required
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="newPassword">새 비밀번호</label>
                  <input
                    type="password"
                    id="newPassword"
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                    placeholder="새 비밀번호를 입력하세요"
                    required
                    minLength={4}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="confirmPassword">새 비밀번호 확인</label>
                  <input
                    type="password"
                    id="confirmPassword"
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                    placeholder="새 비밀번호를 다시 입력하세요"
                    required
                    minLength={4}
                  />
                </div>
                <div className="form-actions">
                  <button type="submit" className="btn-save">비밀번호 변경</button>
                </div>
              </form>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};

export default Settings;

