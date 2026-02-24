
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import ErrorBoundary from './components/ErrorBoundary';
import ProtectedRoute from './components/ProtectedRoute';
import MainLayout from './layouts/MainLayout';
import WelcomePage from './pages/WelcomePage';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import ProjectsDashboard from './pages/ProjectsDashboard';
import UsersPage from './pages/UsersPage';
import ProfilePage from './pages/ProfilePage';
import AdminDashboardPage from './pages/AdminDashboardPage';
import UpdatePasswordPage from './pages/UpdatePasswordPage';
import ReportsPage from './pages/ReportsPage';

function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ThemeProvider>
          <Router>
            <Routes>
              {/* Public routes */}
              <Route path="/login" element={<LoginPage />} />
              
              {/* Public routes with MainLayout */}
              <Route path="/" element={
                <MainLayout>
                  <WelcomePage />
                </MainLayout>
              } />
              
              {/* Protected routes */}
              <Route path="/projects" element={
                <ProtectedRoute requiredRoles={['admin', 'manager', 'employee']}>
                  <MainLayout>
                    <ProjectsDashboard />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/dashboard/:projectId" element={
                <ProtectedRoute requiredRoles={['admin', 'manager', 'employee']}>
                  <MainLayout>
                    <DashboardPage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/dashboard" element={
                <ProtectedRoute requiredRoles={['admin', 'manager', 'employee']}>
                  <MainLayout>
                    <DashboardPage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/users" element={
                <ProtectedRoute requiredRoles={['admin', 'manager']}>
                  <MainLayout>
                    <UsersPage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/admin-dashboard" element={
                <ProtectedRoute requiredRoles={['admin']}>
                  <MainLayout>
                    <AdminDashboardPage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/profile" element={
                <ProtectedRoute>
                  <MainLayout>
                    <ProfilePage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/reports" element={
                <ProtectedRoute requiredRoles={['manager']}>
                  <MainLayout>
                    <ReportsPage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="/update-password" element={
                <ProtectedRoute>
                  <MainLayout>
                    <UpdatePasswordPage />
                  </MainLayout>
                </ProtectedRoute>
              } />
              
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Router>
        </ThemeProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
