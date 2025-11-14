import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, Navigate, useNavigate } from 'react-router-dom';
import { apiGet } from './utils/api';
import './App.css';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import UserManagement from './pages/UserManagement';
import RequestBoard from './pages/RequestBoard';
import DownloadLogs from './pages/DownloadLogs';
import RiskAssessment from './pages/RiskAssessment';
import AnomalyDetection from './pages/AnomalyDetection';
import PermissionViolation from './pages/PermissionViolation';
import MCPRegistry from './pages/MCPRegistry';
import MCPRegistryDetail from './pages/MCPRegistry/MCPRegistryDetail';
import ServerRequest from './pages/ServerRequest/ServerRequest';
import Settings from './pages/Settings';
import DbTables from './pages/DbTables';

// 아이콘 import
import dashboardIcon from './assets/tab/dashboard.png';
import marketplaceIcon from './assets/tab/marketplace.png';
import requestServerIcon from './assets/tab/request_server.png';
import userIcon from './assets/tab/user.png';
import registerBoardIcon from './assets/tab/register_board.png';
import downloadLogsIcon from './assets/tab/download_logs.png';
import riskAssessmentIcon from './assets/tab/risk_assessment.png';
import dlpIcon from './assets/tab/dlp.png';
import settingIcon from './assets/tab/setting.png';

function Header() {
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('user');
    window.location.href = '/';
  };

  const handleLogoClick = () => {
    if (user) {
      const isAdmin = (Array.isArray(user.roles) && user.roles.includes('admin')) || user.role === 'admin';
      navigate(isAdmin ? '/dashboard' : '/marketplace');
    }
  };

  return (
    <header className="header">
      <div className="header-logo" onClick={handleLogoClick}>
        <span className="workspace">MCP Safer</span>
      </div>
      {user && (
        <div className="header-user">
          <span>{user.username}</span>
          <button onClick={handleLogout} className="logout-button">Logout</button>
        </div>
      )}
    </header>
  );
}

function Sidebar() {
  const [user, setUser] = useState(null);
  const [permissionViolationCount, setPermissionViolationCount] = useState(0);
  const [dlpViolationCount, setDlpViolationCount] = useState(0);
  const [registerRequestCount, setRegisterRequestCount] = useState(0);

  // 디버깅: 상태 변경 추적
  useEffect(() => {
    console.log('📊 사이드바 알림 상태:', {
      permissionViolation: permissionViolationCount,
      dlp: dlpViolationCount,
      register: registerRequestCount
    });
  }, [permissionViolationCount, dlpViolationCount, registerRequestCount]);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  // 알림 개수 조회 (관리자만) - 3가지 모두
  useEffect(() => {
    if (!user) return; // user가 없으면 실행하지 않음
    
    const isAdmin = (Array.isArray(user.roles) && user.roles.includes('admin')) || user.role === 'admin';
    
    if (!isAdmin) return; // 관리자가 아니면 실행하지 않음
    
    const fetchAllNotificationCounts = async () => {
      try {
        console.log('🔔 알림 개수 조회 시작...', { user: user.username });
        
        // 3가지 알림 개수 동시 조회 (apiGet 사용 - 자동으로 토큰 포함)
        const [permissionData, dlpData, registerData] = await Promise.all([
          apiGet('/permission-violation/logs/pending-count').catch(() => {
            console.warn('⚠️ 권한 위반 개수 조회 실패');
            return { success: false, count: 0 };
          }),
          apiGet('/dlp/logs/pending-count').catch(() => {
            console.warn('⚠️ DLP 위반 개수 조회 실패');
            return { success: false, count: 0 };
          }),
          apiGet('/marketplace/requests/pending-count').catch(() => {
            console.warn('⚠️ 등록 요청 개수 조회 실패');
            return { success: false, count: 0 };
          })
        ]);

        console.log('🔔 알림 개수 응답:', {
          permission: permissionData,
          dlp: dlpData,
          register: registerData
        });

        // 권한 위반 개수 업데이트 (항상 업데이트 - React가 자동으로 최적화)
        if (permissionData.success) {
          const newCount = permissionData.count || 0;
          console.log('✅ 권한 위반 개수:', newCount);
          setPermissionViolationCount(newCount);
        } else {
          console.warn('⚠️ 권한 위반 개수 조회 실패:', permissionData);
          setPermissionViolationCount(0);
        }
        
        // DLP 위반 개수 업데이트
        if (dlpData.success) {
          console.log('✅ DLP 위반 개수:', dlpData.count);
          setDlpViolationCount(dlpData.count || 0);
        } else {
          console.warn('⚠️ DLP 위반 개수 조회 실패:', dlpData);
          setDlpViolationCount(0);
        }
        
        // 등록 요청 개수 업데이트
        if (registerData.success) {
          console.log('✅ 등록 요청 개수:', registerData.count);
          setRegisterRequestCount(registerData.count || 0);
        } else {
          console.warn('⚠️ 등록 요청 개수 조회 실패:', registerData);
          setRegisterRequestCount(0);
        }
      } catch (error) {
        console.error('❌ 알림 개수 조회 실패:', error);
      }
    };

    // 즉시 한 번 호출
    fetchAllNotificationCounts();
    // 5초마다 업데이트 (실시간 갱신)
    const interval = setInterval(fetchAllNotificationCounts, 5000);
    return () => clearInterval(interval);
  }, [user]);  

  // 일반 사용자는 Dashboard 접근 불가
  const menuItems = [
    { path: '/dashboard', label: 'Dashboard', icon: dashboardIcon, adminOnly: true },
    { path: '/marketplace', label: 'MCP Registry', icon: marketplaceIcon, adminOnly: false },
    { path: '/server-request', label: 'Server Request', icon: requestServerIcon, adminOnly: false },
    { path: '/request-board', label: 'Register Board', icon: registerBoardIcon, adminOnly: false },
    { path: '/risk-assessment', label: 'Risk Assessment', icon: riskAssessmentIcon, adminOnly: true },
    { path: '/anomaly-detection', label: 'Anomaly Detection', icon: dlpIcon, adminOnly: true },
    { path: '/permission-violation', label: 'Permission Violation', icon: dlpIcon, adminOnly: true },
    { path: '/download-logs', label: 'Download Logs', icon: downloadLogsIcon, adminOnly: true }
  ];

  const userManagementItem = { path: '/user-management', label: 'User Management', icon: userIcon, adminOnly: true };
  const settingsItem = { path: '/settings', label: 'Settings', icon: settingIcon, adminOnly: false };

  // roles 배열에 'admin'이 포함되어 있는지 확인
  // user.roles가 배열이면 includes로 확인, 아니면 user.role로 확인 (하위 호환성)
  const isAdmin = user && (
    (Array.isArray(user.roles) && user.roles.includes('admin')) || 
    user.role === 'admin'
  );
  
  // 관리자는 모든 메뉴, 일반 사용자는 MarketPlace, Server Request, Register Board만
  const visibleItems = isAdmin 
    ? menuItems 
    : menuItems.filter(item => !item.adminOnly && (item.path === '/marketplace' || item.path === '/server-request' || item.path === '/request-board'));

  // Settings는 항상 표시
  const showSettings = true;

  return (
    <aside className="sidebar">
      <nav className="sidebar-menu">
        <div className="sidebar-menu-top">
        {visibleItems.map(item => {
          // 각 메뉴 아이템에 대한 알림 개수 결정
          let notificationCount = 0;
          if (item.path === '/permission-violation') {
            notificationCount = permissionViolationCount;
            // 디버깅: 권한 위반 배지 표시 여부 확인
            if (notificationCount > 0) {
              console.log('🔔 권한 위반 배지 표시:', { path: item.path, count: notificationCount });
            }
          } else if (item.path === '/dlp') {
            notificationCount = dlpViolationCount;
          } else if (item.path === '/request-board') {
            notificationCount = registerRequestCount;
          }

          return (
            <NavLink 
              key={item.path} 
              to={item.path} 
              className={({ isActive }) => isActive ? 'active' : ''}
              title={item.label}
            >
              <div className="menu-item-wrapper">
                <img src={item.icon} alt={item.label} className="menu-icon" />
                <span className="menu-label">{item.label}</span>
                {notificationCount > 0 && (
                  <span 
                    className="notification-badge" 
                    data-count={notificationCount}
                    style={{ display: 'flex' }}
                  >
                    {notificationCount > 99 ? '99+' : notificationCount}
                  </span>
                )}
              </div>
            </NavLink>
          );
        })}
        </div>
        <div className="sidebar-menu-bottom">
          {isAdmin && (
            <NavLink 
              to={userManagementItem.path} 
              className={({ isActive }) => isActive ? 'active' : ''}
              title={userManagementItem.label}
            >
              <img src={userManagementItem.icon} alt={userManagementItem.label} className="menu-icon" />
              <span className="menu-label">{userManagementItem.label}</span>
            </NavLink>
          )}
          {showSettings && (
            <NavLink 
              to={settingsItem.path} 
              className={({ isActive }) => isActive ? 'active' : ''}
              title={settingsItem.label}
            >
              <img src={settingsItem.icon} alt={settingsItem.label} className="menu-icon" />
              <span className="menu-label">{settingsItem.label}</span>
            </NavLink>
          )}
        </div>
      </nav>
    </aside>
  );
}

function ProtectedRoute({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function AdminRoute({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  
  // roles 배열에 'admin'이 포함되어 있는지 확인 (하위 호환성: user.role도 체크)
  const isAdmin = user.roles?.includes('admin') || user.role === 'admin';
  if (!isAdmin) return <Navigate to="/marketplace" replace />;
  return children;
}

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  if (loading) return null;

  if (!user) {
    return (
      <Router>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="*" element={<Login onLogin={handleLogin} />} />
        </Routes>
      </Router>
    );
  }

  return (
    <Router>
      <div className="app-layout">
        <Header />
        <div className="content-row">
          <Sidebar />
          <div className="main-content">
            <Routes>
              <Route 
                path="/dashboard" 
                element={
                  <AdminRoute>
                    <Dashboard />
                  </AdminRoute>
                } 
              />
              <Route 
                path="/user-management" 
                element={
                  <AdminRoute>
                    <UserManagement />
                  </AdminRoute>
                } 
              />
              <Route 
                path="/server-request" 
                element={
                  <ProtectedRoute>
                    <ServerRequest />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/request-board" 
                element={
                  <ProtectedRoute>
                    <RequestBoard />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/download-logs" 
                element={
                  <AdminRoute>
                    <DownloadLogs />
                  </AdminRoute>
                } 
              />
              <Route path="/risk-assessment" element={<ProtectedRoute><RiskAssessment /></ProtectedRoute>} />
              <Route path="/sbom-sca" element={<Navigate to="/risk-assessment" replace />} />
              <Route path="/scanner" element={<Navigate to="/risk-assessment" replace />} />
              <Route path="/anomaly-detection" element={<ProtectedRoute><AnomalyDetection /></ProtectedRoute>} />
              <Route path="/permission-violation" element={<ProtectedRoute><PermissionViolation /></ProtectedRoute>} />
              <Route path="/marketplace" element={<ProtectedRoute><MCPRegistry /></ProtectedRoute>} />
              <Route path="/marketplace/:id" element={<ProtectedRoute><MCPRegistryDetail /></ProtectedRoute>} />
              <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
              <Route path="/db-tables" element={<ProtectedRoute><DbTables /></ProtectedRoute>} />
              <Route path="/login" element={<Navigate to="/dashboard" replace />} />
              <Route path="/register" element={<Navigate to="/dashboard" replace />} />
              <Route path="*" element={<Navigate to={(user.roles?.includes('admin') || user.role === 'admin') ? '/dashboard' : '/marketplace'} replace />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}

export default App;
