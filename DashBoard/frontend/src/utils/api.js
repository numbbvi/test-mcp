/**
 * API 요청 유틸리티 함수
 * JWT 토큰을 자동으로 포함하여 요청합니다.
 */

const API_BASE_URL = 'http://localhost:3001/api';

/**
 * localStorage에서 토큰 가져오기
 */
function getToken() {
  return localStorage.getItem('token');
}

/**
 * 토큰이 포함된 headers 생성
 */
function getHeaders(additionalHeaders = {}) {
  const token = getToken();
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` }),
    ...additionalHeaders
  };
}

/**
 * API 요청 래퍼 함수
 */
async function apiRequest(url, options = {}) {
  const fullUrl = url.startsWith('http') ? url : `${API_BASE_URL}${url}`;
  
  try {
  const response = await fetch(fullUrl, {
    ...options,
    headers: getHeaders(options.headers)
  });

  // 401 Unauthorized: 토큰 만료 또는 유효하지 않음
  if (response.status === 401) {
    // 토큰 제거 및 로그인 페이지로 리다이렉트
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/';
    throw new Error('인증이 만료되었습니다. 다시 로그인해주세요.');
  }

  return response;
  } catch (error) {
    // 네트워크 오류 또는 서버 연결 실패
    if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
      throw new Error('서버에 연결할 수 없습니다. 다시 접속해주세요.');
    }
    throw error;
  }
}

/**
 * GET 요청
 */
export async function apiGet(url, options = {}) {
  const response = await apiRequest(url, {
    method: 'GET',
    ...options
  });
  return response.json();
}

/**
 * POST 요청
 */
export async function apiPost(url, data, options = {}) {
  const response = await apiRequest(url, {
    method: 'POST',
    body: JSON.stringify(data),
    ...options
  });
  
  // 응답이 JSON인지 확인
  const contentType = response.headers.get('content-type');
  if (!contentType || !contentType.includes('application/json')) {
    const text = await response.text();
    throw new Error(`서버 응답 오류: ${text.substring(0, 200)}`);
  }
  
  return response.json();
}

/**
 * PUT 요청
 */
export async function apiPut(url, data, options = {}) {
  const response = await apiRequest(url, {
    method: 'PUT',
    body: JSON.stringify(data),
    ...options
  });
  return response.json();
}

/**
 * DELETE 요청
 */
export async function apiDelete(url, options = {}) {
  const response = await apiRequest(url, {
    method: 'DELETE',
    ...options
  });
  return response.json();
}

// 내부 함수 export (필요시 사용)
export { getToken, getHeaders };






