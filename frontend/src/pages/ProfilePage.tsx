import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import LoadingSpinner from '../components/LoadingSpinner';
import { adminService } from '../services/adminService';

const ProfilePage: React.FC = () => {
  const { currentUser, userInfo, logout, loading } = useAuth();
  const navigate = useNavigate();
  const [logoutLoading, setLogoutLoading] = React.useState(false);
  const [logType, setLogType] = React.useState<'apache' | 'nginx'>('apache');
  const [logTypeLoading, setLogTypeLoading] = React.useState(false);
  const [logTypeSaving, setLogTypeSaving] = React.useState(false);
  const [logTypeMessage, setLogTypeMessage] = React.useState<{ type: 'success' | 'error', text: string } | null>(null);

  // Fetch log type if user is manager or admin
  React.useEffect(() => {
    const fetchLogType = async () => {
      if (!userInfo?.org_id || (userInfo.role !== 'manager' && userInfo.role !== 'admin')) {
        return;
      }

      try {
        setLogTypeLoading(true);
        const response = await adminService.getOrgLogType(userInfo.org_id);
        setLogType(response.log_type);
      } catch (error) {
        console.error('Failed to fetch log type:', error);
      } finally {
        setLogTypeLoading(false);
      }
    };

    fetchLogType();
  }, [userInfo?.org_id, userInfo?.role]);

  const handleLogTypeUpdate = async () => {
    if (!userInfo?.org_id) {
      return;
    }

    try {
      setLogTypeSaving(true);
      setLogTypeMessage(null);
      await adminService.updateOrgLogType({
        org_id: userInfo.org_id,
        log_type: logType
      });
      setLogTypeMessage({ type: 'success', text: 'Log type updated successfully!' });
    } catch (error) {
      setLogTypeMessage({ 
        type: 'error', 
        text: error instanceof Error ? error.message : 'Failed to update log type' 
      });
    } finally {
      setLogTypeSaving(false);
    }
  };

  const handleLogout = async () => {
    try {
      setLogoutLoading(true);
      await logout();
      navigate('/login');
    } catch {
      // Error during logout - silently fail
    } finally {
      setLogoutLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner text="Loading profile..." />
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 animate-slide-down text-center">
          <h1 className="text-4xl font-bold gradient-text mb-2">User Profile</h1>
          <p className="text-vt-muted text-lg">Manage your account information and preferences</p>
        </div>

        {/* User Info Card */}
        <div className="glass-strong rounded-2xl border border-vt-primary/20 p-8 mb-6 animate-scale-in">
          <div className="flex items-start gap-6">
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-vt-primary to-vt-success flex items-center justify-center shadow-lg">
              <span className="text-3xl font-bold text-white">
                {currentUser?.email?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-vt-light mb-2">Account Information</h2>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  <div>
                    <p className="text-xs text-vt-muted uppercase tracking-wider">Email</p>
                    <p className="text-vt-light font-medium">{currentUser?.email || 'N/A'}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <p className="text-xs text-vt-muted uppercase tracking-wider">Account Created</p>
                    <p className="text-vt-light font-medium">
                      {currentUser?.metadata?.creationTime 
                        ? new Date(currentUser.metadata.creationTime).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric'
                          })
                        : 'N/A'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  <div>
                    <p className="text-xs text-vt-muted uppercase tracking-wider">Role</p>
                    <p className="text-vt-light font-medium capitalize">
                      {userInfo?.role || 'N/A'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Change Password Card */}
        <div className="glass-strong rounded-2xl border border-vt-warning/20 p-6 mb-6 animate-scale-in">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-vt-warning/30 to-vt-warning/10 rounded-xl flex items-center justify-center">
                <svg className="w-6 h-6 text-vt-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-bold text-vt-light">Change Password</h3>
                <p className="text-sm text-vt-muted">Update your account password</p>
              </div>
            </div>
            <Link
              to="/update-password"
              className="px-6 py-3 bg-gradient-to-r from-vt-warning to-vt-warning/80 text-white font-semibold rounded-lg hover:from-vt-warning/90 hover:to-vt-warning/70 focus:outline-none focus:ring-2 focus:ring-vt-warning focus:ring-offset-2 focus:ring-offset-vt-dark transition-all duration-300 flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span>Change Password</span>
            </Link>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="glass-strong rounded-2xl border border-vt-muted/20 p-6 mb-6 animate-slide-up">
          <h3 className="text-xl font-bold text-vt-light mb-4">Quick Actions</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Link
              to="/dashboard"
              className="glass rounded-xl border border-vt-primary/20 p-4 hover:border-vt-primary/40 hover:bg-vt-primary/10 transition-all duration-300 group"
            >
              <div className="flex items-center gap-3 mb-2">
                <svg className="w-5 h-5 text-vt-primary group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                <span className="font-medium text-vt-light">Dashboard</span>
              </div>
              <p className="text-xs text-vt-muted">View security analytics</p>
            </Link>
            <Link
              to="/"
              className="glass rounded-xl border border-vt-success/20 p-4 hover:border-vt-success/40 hover:bg-vt-success/10 transition-all duration-300 group"
            >
              <div className="flex items-center gap-3 mb-2">
                <svg className="w-5 h-5 text-vt-success group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
                <span className="font-medium text-vt-light">Home</span>
              </div>
              <p className="text-xs text-vt-muted">Return to homepage</p>
            </Link>
          </div>
        </div>

        {/* Log Type Settings - Only show for managers and admins with org_id */}
        {userInfo?.org_id && (userInfo.role === 'manager' || userInfo.role === 'admin') && (
          <div className="glass-strong rounded-2xl border border-vt-primary/20 p-6 mb-6 animate-scale-in">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-gradient-to-br from-vt-primary/30 to-vt-primary/10 rounded-xl flex items-center justify-center">
                <svg className="w-6 h-6 text-vt-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-bold text-vt-light">Log Type Configuration</h3>
                <p className="text-sm text-vt-muted">Select your organization's web server log format</p>
              </div>
            </div>
            
            {logTypeLoading ? (
              <div className="flex items-center justify-center py-4">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Log Format Type
                  </label>
                  <select
                    value={logType}
                    onChange={(e) => setLogType(e.target.value as 'apache' | 'nginx')}
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary"
                  >
                    <option value="apache">Apache</option>
                    <option value="nginx">Nginx</option>
                  </select>
                  <p className="text-xs text-slate-400 mt-2">
                    This setting determines how logs are parsed for your organization
                  </p>
                </div>

                {logTypeMessage && (
                  <div className={`p-3 rounded-lg ${
                    logTypeMessage.type === 'success' 
                      ? 'bg-green-500/20 border border-green-500/50 text-green-300' 
                      : 'bg-red-500/20 border border-red-500/50 text-red-300'
                  }`}>
                    {logTypeMessage.text}
                  </div>
                )}

                <button
                  onClick={handleLogTypeUpdate}
                  disabled={logTypeSaving}
                  className="w-full px-6 py-3 bg-gradient-to-r from-vt-primary to-vt-primary/80 text-white font-semibold rounded-lg hover:from-vt-primary/90 hover:to-vt-primary/70 focus:outline-none focus:ring-2 focus:ring-vt-primary focus:ring-offset-2 focus:ring-offset-vt-dark transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {logTypeSaving ? (
                    <>
                      <LoadingSpinner />
                      <span>Saving...</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      <span>Save Log Type</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Logout Section */}
        <div className="glass-strong rounded-2xl border border-vt-error/20 p-6 animate-slide-up stagger-1">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <h3 className="text-xl font-bold text-vt-light mb-2">Sign Out</h3>
              <p className="text-sm text-vt-muted">
                Sign out of your account. You will need to log in again to access protected pages.
              </p>
            </div>
            <button
              onClick={handleLogout}
              disabled={logoutLoading}
              className="px-6 py-3 bg-gradient-to-r from-vt-error to-vt-error/80 text-white font-semibold rounded-lg hover:from-vt-error/90 hover:to-vt-error/70 focus:outline-none focus:ring-2 focus:ring-vt-error focus:ring-offset-2 focus:ring-offset-vt-dark transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {logoutLoading ? (
                <>
                  <LoadingSpinner />
                  <span>Signing out...</span>
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  <span>Sign Out</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;

