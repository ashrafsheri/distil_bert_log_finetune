import React from 'react';
import { Link, useLocation } from 'react-router-dom';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-vt-dark text-vt-light">
      {/* Navigation Header */}
      <nav className="bg-vt-blue border-b border-vt-muted/20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Link to="/" className="flex items-center space-x-3">
                <span className="text-xl font-semibold text-vt-light">LogGuard</span>
              </Link>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-4">
                <Link
                  to="/"
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    location.pathname === '/'
                      ? 'text-vt-primary bg-vt-primary/10'
                      : 'text-vt-muted hover:text-vt-light hover:bg-vt-primary/5'
                  }`}
                >
                  Welcome
                </Link>
                <Link
                  to="/dashboard"
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    location.pathname === '/dashboard'
                      ? 'text-vt-primary bg-vt-primary/10'
                      : 'text-vt-muted hover:text-vt-light hover:bg-vt-primary/5'
                  }`}
                >
                  Dashboard
                </Link>
              </div>
              
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1">
        {children}
      </main>
    </div>
  );
};

export default MainLayout;
