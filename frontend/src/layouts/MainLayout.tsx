import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface MainLayoutProps {
  children: React.ReactNode;
}

type NavItem = {
  to: string;
  label: string;
  visible: boolean;
  active: (pathname: string) => boolean;
  icon: React.ReactNode;
};

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const location = useLocation();
  const { currentUser, userInfo } = useAuth();

  const canAccessUsers = userInfo?.role === 'admin' || userInfo?.role === 'manager';
  const isAdmin = userInfo?.role === 'admin';
  const isManager = userInfo?.role === 'manager';

  const navItems: NavItem[] = [
    {
      to: '/',
      label: 'Home',
      visible: true,
      active: pathname => pathname === '/',
      icon: (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
        </svg>
      ),
    },
    {
      to: '/projects',
      label: 'Projects',
      visible: !!currentUser,
      active: pathname => pathname === '/projects' || pathname.startsWith('/dashboard') || pathname.startsWith('/projects/'),
      icon: (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
      ),
    },
    {
      to: '/users',
      label: 'Users',
      visible: canAccessUsers,
      active: pathname => pathname.startsWith('/users'),
      icon: (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-1a4 4 0 00-5.356-3.77M9 20H4v-1a4 4 0 015.356-3.77M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
        </svg>
      ),
    },
    {
      to: '/admin-dashboard',
      label: 'Admin',
      visible: isAdmin,
      active: pathname => pathname.startsWith('/admin-dashboard'),
      icon: (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      ),
    },
    {
      to: '/reports',
      label: 'Reports',
      visible: isManager,
      active: pathname => pathname.startsWith('/reports'),
      icon: (
        <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
    },
  ];

  const visibleItems = navItems.filter(item => item.visible);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-50 border-b border-white/6 bg-[rgba(7,12,24,0.94)] backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
          <Link to="/" className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-sky-400/20 bg-gradient-to-br from-sky-500/20 to-cyan-400/10 text-sky-300 shadow-[0_12px_32px_rgba(59,130,246,0.18)]">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <div className="text-xl font-semibold tracking-tight text-slate-50">LogGuard</div>
              <div className="text-xs uppercase tracking-[0.18em] text-slate-500">AI Security Operations</div>
            </div>
          </Link>

          <nav className="flex flex-1 flex-wrap items-center justify-center gap-2">
            <div className="flex flex-wrap items-center gap-2 rounded-full border border-white/6 bg-white/[0.03] p-1">
              {visibleItems.map(item => {
                const active = item.active(location.pathname);
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    className={`inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium transition ${
                      active
                        ? 'border border-sky-400/25 bg-sky-500/12 text-sky-200 shadow-[0_0_0_1px_rgba(56,189,248,0.08)]'
                        : 'text-slate-400 hover:bg-white/[0.05] hover:text-slate-100'
                    }`}
                  >
                    {item.icon}
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </nav>

          <div className="flex items-center gap-3">
            {currentUser ? (
              <>
                <Link
                  to="/profile"
                  className="flex items-center gap-3 rounded-full border border-white/6 bg-white/[0.03] px-3 py-2 transition hover:border-white/10 hover:bg-white/[0.05]"
                >
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-sky-500 to-cyan-400 text-sm font-bold text-white">
                    {currentUser.email?.charAt(0).toUpperCase() || 'U'}
                  </div>
                  <div className="hidden sm:block">
                    <div className="text-sm font-medium text-slate-100">{currentUser.email?.split('@')[0] || 'User'}</div>
                    <div className="text-xs uppercase tracking-[0.16em] text-slate-500">{userInfo?.role || 'member'}</div>
                  </div>
                </Link>
              </>
            ) : (
              <Link
                to="/login"
                className="inline-flex items-center rounded-full border border-sky-400/25 bg-sky-500/10 px-4 py-2 text-sm font-medium text-sky-200 transition hover:bg-sky-500/18"
              >
                Sign In
              </Link>
            )}
          </div>
        </div>
      </header>

      <main>{children}</main>
    </div>
  );
};

export default MainLayout;
