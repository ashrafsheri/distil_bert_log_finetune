import React, { useState, useEffect } from 'react';
import { userService, User } from '../services/userService';
import Button from '../components/Button';
import Card from '../components/Card';
import UserPage from './UserPage';

const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [showRoleModal, setShowRoleModal] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<'admin' | 'manager' | 'employee'>('employee');

  // Fetch all users
  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      setError(null);
      const allUsers = await userService.getAllUsers();
      setUsers(allUsers);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch users');
      console.error('Error fetching users:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleEnable = async (uid: string) => {
    try {
      setActionLoading(uid);
      await userService.enableUser(uid);
      setSuccessMessage('User enabled successfully');
      await fetchUsers();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to enable user');
      setTimeout(() => setError(null), 5000);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDisable = async (uid: string) => {
    try {
      setActionLoading(uid);
      await userService.disableUser(uid);
      setSuccessMessage('User disabled successfully');
      await fetchUsers();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to disable user');
      setTimeout(() => setError(null), 5000);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (uid: string, email: string) => {
    if (!window.confirm(`Are you sure you want to delete user ${email}? This action cannot be undone.`)) {
      return;
    }

    try {
      setActionLoading(uid);
      await userService.deleteUser(uid);
      setSuccessMessage(`User ${email} deleted successfully`);
      await fetchUsers();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
      setTimeout(() => setError(null), 5000);
    } finally {
      setActionLoading(null);
    }
  };

  const handleUserCreated = () => {
    setShowCreateModal(false);
    fetchUsers();
    setSuccessMessage('User created successfully');
    setTimeout(() => setSuccessMessage(null), 3000);
  };

  const handleUpdateRole = async (uid: string) => {
    try {
      setActionLoading(uid);
      await userService.updateUserRole(uid, selectedRole);
      setSuccessMessage('User role updated successfully');
      await fetchUsers();
      setShowRoleModal(null);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update user role');
      setTimeout(() => setError(null), 5000);
    } finally {
      setActionLoading(null);
    }
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleString();
    } catch {
      return dateString;
    }
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'manager':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'employee':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-vt-muted/20 text-vt-muted border-vt-muted/30';
    }
  };

  if (showCreateModal) {
    return (
      <div className="min-h-screen">
        <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="mb-6">
            <Button
              variant="secondary"
              onClick={() => setShowCreateModal(false)}
              className="mb-4"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              Back to Users
            </Button>
          </div>
          <UserPage onUserCreated={handleUserCreated} />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 animate-slide-down">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              </div>
              <div>
                <h1 className="text-4xl font-bold gradient-text mb-2">Users Management</h1>
                <p className="text-vt-muted text-lg">Manage all system users</p>
              </div>
            </div>
            <Button
              variant="primary"
              onClick={() => setShowCreateModal(true)}
              size="lg"
            >
              <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
              </svg>
              Create User
            </Button>
          </div>
        </div>

        {/* Success Message */}
        {successMessage && (
          <Card variant="strong" className="mb-6 border-vt-success/30 bg-vt-success/10 p-4 animate-slide-up">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-vt-success flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-vt-success font-medium">{successMessage}</p>
            </div>
          </Card>
        )}

        {/* Error Message */}
        {error && (
          <Card variant="strong" className="mb-6 border-vt-error/30 bg-vt-error/10 p-4 animate-slide-up">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-vt-error flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-vt-error font-medium">{error}</p>
            </div>
          </Card>
        )}

        {/* Users Table */}
        <Card variant="strong" className="p-6 animate-slide-up">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-vt-primary"></div>
              <span className="ml-3 text-vt-muted">Loading users...</span>
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-12">
              <svg className="w-16 h-16 text-vt-muted mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
              <p className="text-vt-muted text-lg">No users found</p>
              <Button
                variant="primary"
                onClick={() => setShowCreateModal(true)}
                className="mt-4"
              >
                Create First User
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-vt-muted/20">
                    <th className="text-left py-3 px-4 text-sm font-semibold text-vt-light">Email</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-vt-light">Role</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-vt-light">Status</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-vt-light">Created At</th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-vt-light">Updated At</th>
                    <th className="text-right py-3 px-4 text-sm font-semibold text-vt-light">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.uid} className="border-b border-vt-muted/10 hover:bg-vt-muted/5 transition-colors">
                      <td className="py-4 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-vt-primary to-vt-success flex items-center justify-center">
                            <span className="text-xs font-bold text-white">
                              {user.email.charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <span className="text-vt-light font-medium">{user.email}</span>
                        </div>
                      </td>
                      <td className="py-4 px-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getRoleBadgeColor(user.role)}`}>
                          {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        {user.enabled ? (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">
                            Enabled
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                            Disabled
                          </span>
                        )}
                      </td>
                      <td className="py-4 px-4 text-sm text-vt-muted">
                        {formatDate(user.created_at)}
                      </td>
                      <td className="py-4 px-4 text-sm text-vt-muted">
                        {formatDate(user.updated_at)}
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => {
                              setShowRoleModal(user.uid);
                              setSelectedRole(user.role);
                            }}
                            isLoading={actionLoading === user.uid}
                            disabled={actionLoading !== null}
                          >
                            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                            Role
                          </Button>
                          {user.enabled ? (
                            <Button
                              variant="warning"
                              size="sm"
                              onClick={() => handleDisable(user.uid)}
                              isLoading={actionLoading === user.uid}
                              disabled={actionLoading !== null}
                            >
                              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                              </svg>
                              Disable
                            </Button>
                          ) : (
                            <Button
                              variant="success"
                              size="sm"
                              onClick={() => handleEnable(user.uid)}
                              isLoading={actionLoading === user.uid}
                              disabled={actionLoading !== null}
                            >
                              <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                              Enable
                            </Button>
                          )}
                          <Button
                            variant="error"
                            size="sm"
                            onClick={() => handleDelete(user.uid, user.email)}
                            isLoading={actionLoading === user.uid}
                            disabled={actionLoading !== null}
                          >
                            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Role Update Modal */}
        {showRoleModal && (
          <div className="fixed inset-0 bg-black bg-opacity-70 flex items-center justify-center z-50 p-4">
            <Card variant="strong" className="relative w-full max-w-md p-6">
              <Button
                onClick={() => setShowRoleModal(null)}
                variant="secondary"
                size="sm"
                className="absolute top-4 right-4"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </Button>
              
              <h3 className="text-2xl font-bold gradient-text mb-4">Update User Role</h3>
              
              <div className="mb-6">
                <label className="block text-sm font-medium text-vt-light mb-2">
                  Select Role
                </label>
                <select
                  value={selectedRole}
                  onChange={(e) => setSelectedRole(e.target.value as 'admin' | 'manager' | 'employee')}
                  className="w-full px-4 py-3 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent"
                >
                  <option value="employee">Employee</option>
                  <option value="manager">Manager</option>
                  <option value="admin">Admin</option>
                </select>
              </div>

              <div className="flex gap-3">
                <Button
                  variant="secondary"
                  onClick={() => setShowRoleModal(null)}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={() => handleUpdateRole(showRoleModal)}
                  isLoading={actionLoading === showRoleModal}
                  className="flex-1"
                >
                  Update Role
                </Button>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default UsersPage;

