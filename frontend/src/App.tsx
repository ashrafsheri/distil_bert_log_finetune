
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import ErrorBoundary from './components/ErrorBoundary';
import MainLayout from './layouts/MainLayout';
import WelcomePage from './pages/WelcomePage';
import DashboardPage from './pages/DashboardPage';

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <Router>
          <MainLayout>
            <Routes>
              <Route path="/" element={<WelcomePage />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </MainLayout>
        </Router>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
