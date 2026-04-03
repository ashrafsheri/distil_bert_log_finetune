import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { adminService, CreateOrgRequest, CreateOrgResponse } from '../services/adminService';
import { organizationService, OrganizationSummary } from '../services/organizationService';
import LoadingSpinner from '../components/LoadingSpinner';
import Modal from '../components/Modal';
import OrgCreationResult from '../components/OrgCreationResult';

interface CreateOrgFormData {
  name: string;
  email: string;
}

const AdminDashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [orgs, setOrgs] = useState<OrganizationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [createFormData, setCreateFormData] = useState<CreateOrgFormData>({ name: '', email: '' });
  const [createLoading, setCreateLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [orgCreationResult, setOrgCreationResult] = useState<CreateOrgResponse | null>(null);

  const fetchOrgs = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await organizationService.getAllOrganizations();
      setOrgs(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch organizations');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrgs();
  }, []);

  const handleCreateOrg = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!createFormData.name.trim() || !createFormData.email.trim()) return;

    try {
      setCreateLoading(true);
      const request: CreateOrgRequest = {
        name: createFormData.name.trim(),
        manager_email: createFormData.email.trim(),
      };

      const response = await adminService.createOrg(request);
      setOrgCreationResult(response);
      setCreateFormData({ name: '', email: '' });
      setShowCreateForm(false);
      await fetchOrgs();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create organization');
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDeleteOrg = async (orgId: string) => {
    if (!globalThis.confirm(`Delete organization "${orgId}"? This cannot be undone.`)) return;

    try {
      setActionLoading(orgId);
      await adminService.deleteOrg(orgId);
      await fetchOrgs();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete organization');
    } finally {
      setActionLoading(null);
    }
  };

  const totals = useMemo(() => {
    const totalUsers = orgs.reduce((sum, org) => sum + (org.user_count || 0), 0);
    const totalProjects = orgs.reduce((sum, org) => sum + (org.project_count || 0), 0);
    const avgUsers = orgs.length ? totalUsers / orgs.length : 0;
    return { totalUsers, totalProjects, avgUsers };
  }, [orgs]);

  if (loading) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1600px] px-4 py-8 sm:px-6 lg:px-8">
      <section className="rounded-[32px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,29,0.94))] p-8 shadow-[0_28px_80px_rgba(2,8,23,0.45)]">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">System overview</p>
            <h1 className="mt-3 text-4xl font-semibold tracking-tight text-slate-50">Admin Dashboard</h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-400">
              Manage organizations, provision managers, and keep project ownership visible across the platform.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setShowCreateForm(current => !current)}
            className="inline-flex items-center justify-center rounded-2xl border border-sky-400/20 bg-sky-500/10 px-5 py-3 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/16"
          >
            {showCreateForm ? 'Close form' : '+ Add organization'}
          </button>
        </div>

        <div className="mt-8 grid gap-4 xl:grid-cols-4">
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Organizations</p>
            <p className="mt-4 text-4xl font-semibold text-slate-50">{orgs.length}</p>
            <p className="mt-2 text-sm text-slate-400">Active tenants managed in this workspace.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Projects</p>
            <p className="mt-4 text-4xl font-semibold text-sky-300">{totals.totalProjects}</p>
            <p className="mt-2 text-sm text-slate-400">Total monitored services across organizations.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Users</p>
            <p className="mt-4 text-4xl font-semibold text-emerald-300">{totals.totalUsers}</p>
            <p className="mt-2 text-sm text-slate-400">Provisioned platform accounts and managers.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Avg users / org</p>
            <p className="mt-4 text-4xl font-semibold text-fuchsia-300">{totals.avgUsers.toFixed(1)}</p>
            <p className="mt-2 text-sm text-slate-400">Distribution of ownership across tenants.</p>
          </div>
        </div>

        {showCreateForm && (
          <form onSubmit={handleCreateOrg} className="mt-8 rounded-[28px] border border-white/6 bg-white/[0.025] p-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-slate-50">Create organization</h2>
                <p className="mt-1 text-sm text-slate-400">Provision a tenant and generate an initial manager credential.</p>
              </div>
            </div>
            <div className="mt-6 grid gap-4 lg:grid-cols-2">
              <label className="grid gap-2 text-sm text-slate-300">
                <span>Organization name</span>
                <input
                  type="text"
                  value={createFormData.name}
                  onChange={event => setCreateFormData(prev => ({ ...prev, name: event.target.value }))}
                  className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
                  placeholder="Acme Corporation"
                  required
                />
              </label>
              <label className="grid gap-2 text-sm text-slate-300">
                <span>Manager email</span>
                <input
                  type="email"
                  value={createFormData.email}
                  onChange={event => setCreateFormData(prev => ({ ...prev, email: event.target.value }))}
                  className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
                  placeholder="manager@company.com"
                  required
                />
              </label>
            </div>
            <div className="mt-6 flex flex-wrap gap-3">
              <button
                type="submit"
                disabled={createLoading}
                className="inline-flex items-center justify-center rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-400 px-5 py-3 text-sm font-semibold text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] transition hover:translate-y-[-1px] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {createLoading ? 'Creating...' : 'Create organization'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreateForm(false)}
                className="inline-flex items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.05]"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {error && (
          <div className="mt-8 rounded-3xl border border-rose-400/18 bg-rose-500/10 px-5 py-4 text-sm text-rose-200">
            {error}
          </div>
        )}

        <div className="mt-8 overflow-hidden rounded-[28px] border border-white/6 bg-white/[0.025]">
          <div className="flex items-center justify-between border-b border-white/6 px-6 py-5">
            <div>
              <h2 className="text-2xl font-semibold text-slate-50">Organizations</h2>
              <p className="mt-1 text-sm text-slate-400">Current tenant roster with project and user counts.</p>
            </div>
          </div>

          {orgs.length === 0 ? (
            <div className="px-6 py-16 text-center text-slate-400">No organizations found.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[860px]">
                <thead className="bg-white/[0.02]">
                  <tr className="border-b border-white/6 text-left">
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Organization</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Org ID</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Projects</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Users</th>
                    <th className="px-6 py-4 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {orgs.map(org => (
                    <tr key={org.id} className="border-b border-white/6 last:border-b-0">
                      <td className="px-6 py-5">
                        <div className="font-medium text-slate-100">{org.name}</div>
                        <div className="mt-1 text-sm text-slate-500">Tenant workspace</div>
                      </td>
                      <td className="px-6 py-5 font-mono text-sm text-slate-400">{org.id}</td>
                      <td className="px-6 py-5">
                        <span className="inline-flex rounded-full border border-sky-400/15 bg-sky-500/10 px-3 py-1 text-sm font-medium text-sky-200">
                          {org.project_count} project{org.project_count === 1 ? '' : 's'}
                        </span>
                      </td>
                      <td className="px-6 py-5">
                        <span className="inline-flex rounded-full border border-emerald-400/15 bg-emerald-500/10 px-3 py-1 text-sm font-medium text-emerald-200">
                          {org.user_count} user{org.user_count === 1 ? '' : 's'}
                        </span>
                      </td>
                      <td className="px-6 py-5">
                        <div className="flex flex-wrap gap-3">
                          <button
                            type="button"
                            onClick={() => navigate(`/projects?org=${org.id}`)}
                            className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-white/[0.05]"
                          >
                            View Projects
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteOrg(org.id)}
                            disabled={actionLoading === org.id}
                            className="rounded-2xl border border-rose-400/18 bg-rose-500/10 px-4 py-2 text-sm font-medium text-rose-200 transition hover:bg-rose-500/16 disabled:cursor-not-allowed disabled:opacity-60"
                          >
                            {actionLoading === org.id ? 'Deleting...' : 'Delete'}
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

        <Modal isOpen={!!orgCreationResult} onClose={() => setOrgCreationResult(null)} title="Organization Created">
          {orgCreationResult && (
            <OrgCreationResult
              orgId={orgCreationResult.org_id}
              orgName={orgCreationResult.name}
              managerEmail={orgCreationResult.manager_email}
              managerPassword={orgCreationResult.manager_password}
              onClose={() => setOrgCreationResult(null)}
            />
          )}
        </Modal>
      </section>
    </div>
  );
};

export default AdminDashboardPage;
