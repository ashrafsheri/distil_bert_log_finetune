import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const location = useLocation();
  const { currentUser } = useAuth();

  return (
    <div className="min-h-screen text-vt-light">
      {/* Navigation Header */}
      <nav className="glass-strong sticky top-0 z-50 border-b border-vt-primary/20 animate-slide-down">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Link to="/" className="flex items-center space-x-3 group">
                <div className="w-10 h-10 bg-gradient-to-br from-vt-primary to-vt-success rounded-lg flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform duration-300">
                  <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div>
                  <span className="text-xl font-bold gradient-text">LogGuard</span>
                  <p className="text-xs text-vt-muted">AI-Powered Security</p>
                </div>
              </Link>
            </div>
            
            <div className="flex items-center space-x-2">
              <Link
                to="/"
                className={`group relative px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 ${
                  location.pathname === '/'
                    ? 'text-vt-primary'
                    : 'text-vt-muted hover:text-vt-light'
                }`}
              >
                {location.pathname === '/' && (
                  <div className="absolute inset-0 bg-vt-primary/10 rounded-lg border border-vt-primary/30"></div>
                )}
                <div className="relative flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                  </svg>
                  Home
                </div>
              </Link>
              
              {currentUser && (
                <>
                  <Link
                    to="/dashboard"
                    className={`group relative px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 ${
                      location.pathname === '/dashboard'
                        ? 'text-vt-primary'
                        : 'text-vt-muted hover:text-vt-light'
                    }`}
                  >
                    {location.pathname === '/dashboard' && (
                      <div className="absolute inset-0 bg-vt-primary/10 rounded-lg border border-vt-primary/30"></div>
                    )}
                    <div className="relative flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                      </svg>
                      Dashboard
                    </div>
                  </Link>
                  <Link
                    to="/users"
                    className={`group relative px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 ${
                      location.pathname === '/users'
                        ? 'text-vt-primary'
                        : 'text-vt-muted hover:text-vt-light'
                    }`}
                  >
                    {location.pathname === '/users' && (
                      <div className="absolute inset-0 bg-vt-primary/10 rounded-lg border border-vt-primary/30"></div>
                    )}
                    <div className="relative flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                      </svg>
                      Users
                    </div>
                  </Link>
                </>
              )}

              {currentUser ? (
                <div className="flex items-center gap-3 ml-4 pl-4 border-l border-vt-muted/30">
                  <Link
                    to="/profile"
                    className={`flex items-center gap-2 text-sm transition-all duration-300 group ${
                      location.pathname === '/profile'
                        ? 'text-vt-primary'
                        : 'text-vt-muted hover:text-vt-light'
                    }`}
                  >
                    <div className={`w-8 h-8 rounded-full bg-gradient-to-br from-vt-primary to-vt-success flex items-center justify-center transition-transform duration-300 ${
                      location.pathname === '/profile' ? 'ring-2 ring-vt-primary ring-offset-2 ring-offset-vt-dark' : 'group-hover:scale-110'
                    }`}>
                      <span className="text-xs font-bold text-white">
                        {currentUser.email?.charAt(0).toUpperCase() || 'U'}
                      </span>
                    </div>
                    <span className="font-medium">
                      {currentUser.email?.split('@')[0] || 'User'}
                    </span>
                  </Link>
                </div>
              ) : (
                <div className="flex items-center gap-2 ml-4">
                  <Link
                    to="/login"
                    className="px-4 py-2 rounded-lg text-sm font-medium text-vt-muted hover:text-vt-light transition-colors"
                  >
                    Sign In
                  </Link>
                </div>
              )}
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1">
        {children}
      </main>

      {/* Footer */}
      <footer className="glass border-t border-vt-muted/20 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="text-sm text-vt-muted">
              © 2025 LogGuard. Powered by Ensemble AI Detection.
            </div>
            <div className="flex items-center gap-6 text-sm text-vt-muted">
              <a href="#" className="hover:text-vt-primary transition-colors">Documentation</a>
              <a href="#" className="hover:text-vt-primary transition-colors">API</a>
              <a href="#" className="hover:text-vt-primary transition-colors">Support</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default MainLayout;
