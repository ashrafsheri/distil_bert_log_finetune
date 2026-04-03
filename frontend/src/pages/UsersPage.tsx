import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Select from '../components/Select';
import { useAuth } from '../context/AuthContext';
import { userService, User } from '../services/userService';
import UserPage from './UserPage';

const roleBadgeClass = (role: User['role']) => {
  if (role === 'admin') return 'border-rose-400/20 bg-rose-500/10 text-rose-200';
  if (role === 'manager') return 'border-sky-400/20 bg-sky-500/10 text-sky-200';
  return 'border-emerald-400/20 bg-emerald-500/10 text-emerald-200';
};

const UsersPage: React.FC = () => {
  const { userInfo } = useAuth();
  const navigate = useNavigate();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [showRoleModal, setShowRoleModal] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<'admin' | 'manager' | 'employee'>('employee');
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const updateRoleSelectId = 'update-user-role';

  const isAdmin = userInfo?.role === 'admin';
  const isManager = userInfo?.role === 'manager';
  const canAccess = isAdmin || isManager;

  const fetchUsers = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const allUsers = await userService.getAllUsers();
      setUsers(allUsers);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (userInfo && !canAccess) {
      navigate('/dashboard');
      return;
    }

    if (canAccess) {
      fetchUsers();
    }
  }, [canAccess, fetchUsers, navigate, userInfo]);

  const filteredUsers = useMemo(() => {
    return users.filter(user => {
      const query = searchTerm.trim().toLowerCase();
      const matchesSearch = !query
        || user.email.toLowerCase().includes(query)
        || (user.org_name || user.org_id || '').toLowerCase().includes(query);
      const matchesRole = !roleFilter || user.role === roleFilter;
      const matchesStatus = !statusFilter || (statusFilter === 'enabled' ? user.enabled : !user.enabled);
      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [roleFilter, searchTerm, statusFilter, users]);

  const metrics = useMemo(() => {
    const enabled = users.filter(user => user.enabled).length;
    const admins = users.filter(user => user.role === 'admin').length;
    const managers = users.filter(user => user.role === 'manager').length;
    return { enabled, admins, managers };
  }, [users]);

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
    if (!globalThis.confirm(`Delete user ${email}? This action cannot be undone.`)) return;

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

  if (!userInfo || !canAccess) return null;

  if (showCreateModal) {
    return (
      <div className="mx-auto max-w-[1200px] px-4 py-8 sm:px-6 lg:px-8">
        <button
          type="button"
          onClick={() => setShowCreateModal(false)}
          className="mb-6 inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-white/[0.05]"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to users
        </button>
        <UserPage onUserCreated={handleUserCreated} />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1600px] px-4 py-8 sm:px-6 lg:px-8">
      <section className="rounded-[32px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,29,0.94))] p-8 shadow-[0_28px_80px_rgba(2,8,23,0.45)]">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">Identity and access</p>
            <h1 className="mt-3 text-4xl font-semibold tracking-tight text-slate-50">Users Management</h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-400">
              Search accounts, adjust roles, and enforce access state across the LogGuard workspace.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="inline-flex items-center justify-center rounded-2xl border border-sky-400/20 bg-sky-500/10 px-5 py-3 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/16"
          >
            Create User
          </button>
        </div>

        <div className="mt-8 grid gap-4 xl:grid-cols-4">
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Total users</p>
            <p className="mt-4 text-4xl font-semibold text-slate-50">{users.length}</p>
            <p className="mt-2 text-sm text-slate-400">All provisioned platform accounts.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Enabled</p>
            <p className="mt-4 text-4xl font-semibold text-emerald-300">{metrics.enabled}</p>
            <p className="mt-2 text-sm text-slate-400">Accounts currently able to authenticate.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Admins</p>
            <p className="mt-4 text-4xl font-semibold text-rose-300">{metrics.admins}</p>
            <p className="mt-2 text-sm text-slate-400">Platform-level administrative access.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Managers</p>
            <p className="mt-4 text-4xl font-semibold text-sky-300">{metrics.managers}</p>
            <p className="mt-2 text-sm text-slate-400">Operational managers across organizations.</p>
          </div>
        </div>

        <div className="mt-8 grid gap-4 lg:grid-cols-[minmax(0,1fr)_180px_180px]">
          <label className="grid gap-2 text-sm text-slate-300">
            <span>Search users</span>
            <input
              value={searchTerm}
              onChange={event => setSearchTerm(event.target.value)}
              placeholder="Email or organization"
              className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
            />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">
            <span>Role</span>
            <Select
              value={roleFilter}
              onChange={value => setRoleFilter(value as string)}
              options={[
                { label: 'All roles', value: '' },
                { label: 'Admin', value: 'admin' },
                { label: 'Manager', value: 'manager' },
                { label: 'Employee', value: 'employee' },
              ]}
              density="sm"
            />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">
            <span>Status</span>
            <Select
              value={statusFilter}
              onChange={value => setStatusFilter(value as string)}
              options={[
                { label: 'All statuses', value: '' },
                { label: 'Enabled', value: 'enabled' },
                { label: 'Disabled', value: 'disabled' },
              ]}
              density="sm"
            />
          </label>
        </div>

        {successMessage && (
          <div className="mt-6 rounded-3xl border border-emerald-400/18 bg-emerald-500/10 px-5 py-4 text-sm text-emerald-200">
            {successMessage}
          </div>
        )}

        {error && (
          <div className="mt-6 rounded-3xl border border-rose-400/18 bg-rose-500/10 px-5 py-4 text-sm text-rose-200">
            {error}
          </div>
        )}

        <div className="mt-8 overflow-hidden rounded-[28px] border border-white/6 bg-white/[0.025]">
          {loading ? (
            <div className="flex items-center justify-center px-6 py-16">
              <div className="flex items-center gap-3 text-slate-400">
                <div className="h-8 w-8 animate-spin rounded-full border-b-2 border-sky-400" />
                Loading users...
              </div>
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="px-6 py-16 text-center text-slate-400">No users match the current filters.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[980px]">
                <thead className="bg-white/[0.02]">
                  <tr className="border-b border-white/6 text-left">
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">User</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Role</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Organization</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Status</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map(user => (
                    <tr key={user.uid} className="border-b border-white/6 last:border-b-0">
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-4">
                          <div className="flex h-11 w-11 items-center justify-center rounded-full bg-gradient-to-br from-sky-500 to-cyan-400 text-sm font-bold text-white">
                            {user.email.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-medium text-slate-100">{user.email}</div>
                            <div className="mt-1 text-xs font-mono text-slate-500">{user.uid}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-medium ${roleBadgeClass(user.role)}`}>
                          {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                        </span>
                      </td>
                      <td className="px-6 py-5 text-sm text-slate-300">{user.org_name || user.org_id || 'Platform-wide'}</td>
                      <td className="px-6 py-5">
                        <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-medium ${user.enabled ? 'border-emerald-400/18 bg-emerald-500/10 text-emerald-200' : 'border-amber-400/18 bg-amber-500/10 text-amber-200'}`}>
                          {user.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                      <td className="px-6 py-5">
                        <div className="flex flex-wrap gap-2">
                          {isAdmin && (
                            <button
                              type="button"
                              onClick={() => {
                                setShowRoleModal(user.uid);
                                setSelectedRole(user.role);
                              }}
                              disabled={actionLoading !== null}
                              className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-white/[0.05] disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              Role
                            </button>
                          )}
                          {user.enabled ? (
                            <button
                              type="button"
                              onClick={() => handleDisable(user.uid)}
                              disabled={actionLoading !== null}
                              className="rounded-2xl border border-amber-400/18 bg-amber-500/10 px-4 py-2 text-sm font-medium text-amber-200 transition hover:bg-amber-500/16 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              {actionLoading === user.uid ? 'Working...' : 'Disable'}
                            </button>
                          ) : (
                            <button
                              type="button"
                              onClick={() => handleEnable(user.uid)}
                              disabled={actionLoading !== null}
                              className="rounded-2xl border border-emerald-400/18 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-200 transition hover:bg-emerald-500/16 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              {actionLoading === user.uid ? 'Working...' : 'Enable'}
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => handleDelete(user.uid, user.email)}
                            disabled={actionLoading !== null}
                            className="rounded-2xl border border-rose-400/18 bg-rose-500/10 px-4 py-2 text-sm font-medium text-rose-200 transition hover:bg-rose-500/16 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {actionLoading === user.uid ? 'Working...' : 'Delete'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {showRoleModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-md">
            <div className="w-full max-w-md rounded-[28px] border border-white/8 bg-[linear-gradient(180deg,rgba(15,23,42,0.98),rgba(8,15,29,0.95))] p-6 shadow-[0_28px_80px_rgba(2,8,23,0.55)]">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h3 className="text-2xl font-semibold text-slate-50">Update User Role</h3>
                  <p className="mt-1 text-sm text-slate-400">Adjust access level for the selected account.</p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowRoleModal(null)}
                  className="rounded-full border border-white/10 p-2 text-slate-400 transition hover:bg-white/[0.05] hover:text-slate-100"
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className="mt-6">
                <label htmlFor={updateRoleSelectId} className="mb-2 block text-sm font-medium text-slate-300">
                  Select role
                </label>
                <Select
                  id={updateRoleSelectId}
                  value={selectedRole}
                  onChange={value => setSelectedRole(value as 'admin' | 'manager' | 'employee')}
                  options={[
                    { label: 'Employee', value: 'employee' },
                    { label: 'Manager', value: 'manager' },
                    { label: 'Admin', value: 'admin' },
                  ]}
                />
              </div>

              <div className="mt-6 flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowRoleModal(null)}
                  className="flex-1 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.05]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => handleUpdateRole(showRoleModal)}
                  disabled={actionLoading === showRoleModal}
                  className="flex-1 rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-400 px-4 py-3 text-sm font-semibold text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] transition hover:translate-y-[-1px] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {actionLoading === showRoleModal ? 'Updating...' : 'Update role'}
                </button>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};

export default UsersPage;
