import React, { useState, useEffect } from 'react';
import { apiPost, API_BASE_URL } from '../../utils/api';
import './ServerRequest.css';

const ServerRequest = () => {
  const [form, setForm] = useState({ 
    name: '', 
    description: '', 
    connection: '', 
    github: '', 
    file: null,
    image: null,
    auth_token: ''
  });
  const [imagePreview, setImagePreview] = useState(null);
  const [showRequestForm, setShowRequestForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // ESC 키로 모달 닫기
  useEffect(() => {
    if (!showRequestForm) return;

    const handleEscape = (e) => {
      if (e.key === 'Escape' && !submitting) {
        setShowRequestForm(false);
      }
    };

    window.addEventListener('keydown', handleEscape);
    return () => {
      window.removeEventListener('keydown', handleEscape);
    };
  }, [showRequestForm, submitting]);

  const onChange = (e) => {
    const { name, value, files } = e.target;
    if (name === 'image' && files && files[0]) {
      const file = files[0];
      setForm((prev) => ({ ...prev, [name]: file }));
      // 이미지 미리보기 생성
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result);
      };
      reader.readAsDataURL(file);
    } else {
      setForm((prev) => ({ ...prev, [name]: files ? files[0] : value }));
    }
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    
    // 유효성 검사
    if (!form.name.trim()) {
      alert('MCP Server Name은 필수입니다.');
      return;
    }
    
    if (!form.description.trim()) {
      alert('MCP Server Description은 필수입니다.');
      return;
    }
    
    if (!form.connection.trim()) {
      alert('Connection은 필수입니다.');
      return;
    }
    
    // GitHub 링크나 파일 중 하나는 반드시 있어야 함
    if (!form.github.trim() && !form.file) {
      alert('Github Link 또는 File 중 하나는 반드시 입력해야 합니다.');
      return;
    }
    
    try {
      // localStorage에서 사용자 정보 가져오기
      const savedUser = localStorage.getItem('user');
      if (!savedUser) {
        alert('로그인이 필요합니다.');
        return;
      }
      const user = JSON.parse(savedUser);

      setSubmitting(true);

      const formData = new FormData();
      formData.append('name', form.name);
      formData.append('description', form.description);
      formData.append('connection', form.connection || '');
      formData.append('github', form.github);
      formData.append('user_id', user.id);
      if (form.auth_token) {
        formData.append('auth_token', form.auth_token);
      }
      if (form.file) {
        formData.append('file', form.file);
      }
      if (form.image) {
        formData.append('image', form.image);
      }

      const res = await fetch(`${API_BASE_URL}/marketplace/request`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: formData
      });

      // 응답이 JSON인지 확인
      const contentType = res.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await res.text();
        throw new Error(`서버 오류 (${res.status}): ${text.substring(0, 200)}`);
      }

      const data = await res.json();
      if (data.success) {
        alert(data.message || '등록 요청이 접수되었습니다.');
        setShowRequestForm(false);
        setForm({ name: '', description: '', connection: '', github: '', file: null, image: null, auth_token: '' });
        setImagePreview(null);
      } else {
        alert(data.message || '등록 요청 실패');
      }
    } catch (error) {
      console.error('등록 요청 오류:', error);
      // 네트워크 오류인 경우
      if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        alert('서버에 연결할 수 없습니다. 네트워크 연결을 확인해주세요.');
      } else {
        alert(`등록 요청 중 오류가 발생했습니다: ${error.message || error.toString()}`);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="server-request-section">
      <div className="server-request-header">
        <h1>MCP Server Request</h1>
        <button 
          className="btn-primary request-button"
          onClick={() => setShowRequestForm(true)}
        >
          + New Server Request
        </button>
      </div>

      <div className="server-request-info">
        <div className="info-card">
          <h3>서버 신청 안내</h3>
          <ul>
            <li>새로운 MCP 서버를 등록하고 싶으시면 아래 "New Server Request" 버튼을 클릭하세요.</li>
            <li>서버 이름, 설명, 연결 방법, GitHub 링크 등을 입력해주세요.</li>
            <li>관리자 검토 후 승인되면 MCP Registry에 등록됩니다.</li>
            <li>신청 상태는 "Register Board"에서 확인할 수 있습니다.</li>
          </ul>
        </div>
      </div>

      {/* Bottom Sheet Modal */}
      {showRequestForm && (
        <div className="sheet-overlay" onClick={() => !submitting && setShowRequestForm(false)}>
          <div className="sheet" onClick={(e) => e.stopPropagation()}>
            <form className="request-form" onSubmit={onSubmit}>
              <h2>MCP Server Request</h2>
              <label className="file-field image-field">
                <span>Server Image (선택사항)</span>
                <input 
                  type="file" 
                  name="image" 
                  accept="image/*"
                  onChange={onChange}
                  disabled={submitting}
                />
                {imagePreview && (
                  <div className="image-preview">
                    <img src={imagePreview} alt="Preview" />
                    <button 
                      type="button" 
                      className="remove-image"
                      onClick={() => {
                        setForm(prev => ({ ...prev, image: null }));
                        setImagePreview(null);
                      }}
                      disabled={submitting}
                    >
                      ×
                    </button>
                  </div>
                )}
              </label>
              <label>
                <span>MCP Server Name</span>
                <input 
                  name="name" 
                  value={form.name} 
                  onChange={onChange} 
                  placeholder="ex) Github MCP Server" 
                  required 
                  disabled={submitting}
                />
              </label>
              <label>
                <span>MCP Server Description</span>
                <textarea 
                  name="description" 
                  value={form.description} 
                  onChange={onChange} 
                  placeholder="서버에 대한 간단한 설명을 입력해주세요" 
                  rows={5} 
                  required 
                  disabled={submitting}
                />
              </label>
              <label>
                <span>Connection</span>
                <textarea 
                  name="connection" 
                  value={form.connection} 
                  onChange={onChange} 
                  placeholder="mcp.json 연결 방법" 
                  rows={5}
                  required
                  disabled={submitting}
                />
              </label>
              <label>
                <span>Github Link</span>
                <input 
                  name="github" 
                  value={form.github} 
                  onChange={onChange} 
                  placeholder="https://github.com/..." 
                  disabled={submitting}
                />
                <small style={{ display: 'block', marginTop: '4px', color: '#666', fontSize: '0.85rem' }}>
                  Github Link 또는 File Upload 중 하나는 필수입니다.
                </small>
              </label>
              <label className="file-field">
                <span>File Upload</span>
                <input 
                  type="file" 
                  name="file" 
                  onChange={onChange}
                  disabled={submitting}
                />
                <small style={{ display: 'block', marginTop: '4px', color: '#666', fontSize: '0.85rem' }}>
                  Github Link 또는 File Upload 중 하나는 필수입니다.
                </small>
              </label>
              <label>
                <span>Authentication Token (Optional)</span>
                <input
                  type="password"
                  name="auth_token"
                  value={form.auth_token}
                  onChange={onChange}
                  placeholder="서버 인증에 필요한 토큰 (예: GITHUB_PERSONAL_ACCESS_TOKEN, SLACK_MCP_XOXP_TOKEN 등)"
                  disabled={submitting}
                />
                <small style={{ color: '#666', fontSize: '0.85em', marginTop: '4px', display: 'block' }}>
                  토큰이 필요한 서버의 경우, tool 스캔을 위해 토큰을 입력해주세요.
                </small>
              </label>
              <div className="request-actions">
                <button 
                  type="button" 
                  className="btn-secondary" 
                  onClick={() => setShowRequestForm(false)}
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  className="btn-primary"
                  disabled={submitting}
                >
                  {submitting ? 'Submitting...' : 'Submit'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
};

export default ServerRequest;

