import React, { useState, useEffect } from 'react';
import { adminService, OrgSummary, CreateOrgRequest, CreateOrgResponse, RegenerateApiKeyResponse } from '../services/adminService';
import LoadingSpinner from '../components/LoadingSpinner';
import Button from '../components/Button';
import Card from '../components/Card';
import Modal from '../components/Modal';
import OrgCreationResult from '../components/OrgCreationResult';
import ApiKeyRegenerationResult from '../components/ApiKeyRegenerationResult';

interface CreateOrgFormData {
  name: string;
  email: string;
}

const AdminDashboardPage: React.FC = () => {
  const [orgs, setOrgs] = useState<OrgSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [createFormData, setCreateFormData] = useState<CreateOrgFormData>({
    name: '',
    email: ''
  });
  const [createLoading, setCreateLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Modal states
  const [orgCreationResult, setOrgCreationResult] = useState<CreateOrgResponse | null>(null);
  const [apiKeyRegenerationResult, setApiKeyRegenerationResult] = useState<RegenerateApiKeyResponse | null>(null);

  const fetchOrgs = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await adminService.getAllOrgs();
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

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createFormData.name.trim() || !createFormData.email.trim()) {
      return;
    }

    try {
      setCreateLoading(true);
      const request: CreateOrgRequest = {
        name: createFormData.name.trim(),
        manager_email: createFormData.email.trim()
      };

      const response = await adminService.createOrg(request);
      setOrgCreationResult(response);

      setCreateFormData({ name: '', email: '' });
      setShowCreateForm(false);
      fetchOrgs(); // Refresh the list
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to create organization');
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDeleteOrg = async (orgId: string) => {
    if (!confirm(`Are you sure you want to delete organization "${orgId}"? This action cannot be undone.`)) {
      return;
    }

    try {
      setActionLoading(orgId);
      await adminService.deleteOrg(orgId);
      alert('Organization deleted successfully');
      fetchOrgs(); // Refresh the list
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete organization');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRegenerateApiKey = async (orgId: string) => {
    if (!confirm(`Are you sure you want to regenerate the API key for organization "${orgId}"? The old key will no longer work.`)) {
      return;
    }

    try {
      setActionLoading(orgId);
      const response = await adminService.regenerateApiKey({ org_id: orgId });
      setApiKeyRegenerationResult(response);
      fetchOrgs(); // Refresh the list (though it won't change the display)
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to regenerate API key');
    } finally {
      setActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="mb-10">
          <h1 className="text-4xl font-bold text-white mb-3">Admin Dashboard</h1>
          <p className="text-slate-400 text-lg">Manage organizations and their API keys</p>
        </div>

        <div className="mb-8">
          <Button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="bg-vt-primary hover:bg-vt-primary/80 px-6 py-3 text-lg"
          >
            {showCreateForm ? 'Cancel' : '+ Add New Organization'}
          </Button>
        </div>

        {showCreateForm && (
          <Card className="mb-8 p-8">
            <h2 className="text-2xl font-semibold text-white mb-6">Create New Organization</h2>
            <form onSubmit={handleCreateOrg} className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-3">
                  Organization Name
                </label>
                <input
                  type="text"
                  value={createFormData.name}
                  onChange={(e) => setCreateFormData(prev => ({ ...prev, name: e.target.value }))}
                  className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-vt-primary text-lg"
                  placeholder="Enter organization name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-3">
                  Manager Email
                </label>
                <input
                  type="email"
                  value={createFormData.email}
                  onChange={(e) => setCreateFormData(prev => ({ ...prev, email: e.target.value }))}
                  className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-vt-primary text-lg"
                  placeholder="Enter manager email"
                  required
                />
              </div>
              <div className="flex gap-4 pt-4">
                <Button
                  type="submit"
                  disabled={createLoading}
                  className="bg-vt-success hover:bg-vt-success/80 px-6 py-3 text-lg"
                >
                  {createLoading ? 'Creating...' : 'Create Organization'}
                </Button>
                <Button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  variant="secondary"
                  className="px-6 py-3 text-lg"
                >
                  Cancel
                </Button>
              </div>
            </form>
          </Card>
        )}

        {error && (
          <Card className="mb-8 border-red-500/50 p-6">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-red-500 rounded-full flex items-center justify-center">
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div>
                <p className="text-red-400 font-medium">Error</p>
                <p className="text-red-300 text-sm">{error}</p>
              </div>
            </div>
            <Button onClick={fetchOrgs} className="mt-4">
              Retry
            </Button>
          </Card>
        )}

        <Card className="p-8">
          <h2 className="text-2xl font-semibold text-white mb-6">Organizations</h2>
          {orgs.length === 0 ? (
            <div className="text-center py-12">
              <svg className="w-16 h-16 text-slate-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
              <p className="text-slate-400 text-lg">No organizations found.</p>
              <p className="text-slate-500 text-sm mt-2">Create your first organization to get started.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="pb-4 text-slate-300 font-medium text-lg">ID</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Name</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Users</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {orgs.map((org) => (
                    <tr key={org.id} className="border-b border-slate-800">
                      <td className="py-4 text-slate-300 font-mono text-sm">{org.id}</td>
                      <td className="py-4 text-white font-medium">{org.name}</td>
                      <td className="py-4 text-slate-300">
                        <span className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-slate-700 text-slate-300">
                          {org.user_count} user{org.user_count !== 1 ? 's' : ''}
                        </span>
                      </td>
                      <td className="py-4">
                        <div className="flex gap-3">
                          <Button
                            size="sm"
                            onClick={() => handleRegenerateApiKey(org.id)}
                            disabled={actionLoading === org.id}
                            className="bg-vt-primary hover:bg-vt-primary/80 px-4 py-2"
                          >
                            {actionLoading === org.id ? '...' : '🔑 Regenerate Key'}
                          </Button>
                          <Button
                            size="sm"
                            onClick={() => handleDeleteOrg(org.id)}
                            disabled={actionLoading === org.id}
                            variant="danger"
                            className="px-4 py-2"
                          >
                            {actionLoading === org.id ? '...' : '🗑️ Delete'}
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

        {/* Modals */}
        <Modal
          isOpen={!!orgCreationResult}
          onClose={() => setOrgCreationResult(null)}
          title="Organization Created"
        >
          {orgCreationResult && (
            <OrgCreationResult
              orgId={orgCreationResult.org_id}
              apiKey={orgCreationResult.api_key}
              managerEmail={orgCreationResult.manager_email}
              managerPassword={orgCreationResult.manager_password}
              onClose={() => setOrgCreationResult(null)}
            />
          )}
        </Modal>

        <Modal
          isOpen={!!apiKeyRegenerationResult}
          onClose={() => setApiKeyRegenerationResult(null)}
          title="API Key Regenerated"
        >
          {apiKeyRegenerationResult && (
            <ApiKeyRegenerationResult
              orgId={apiKeyRegenerationResult.org_id}
              newApiKey={apiKeyRegenerationResult.new_api_key}
              onClose={() => setApiKeyRegenerationResult(null)}
            />
          )}
        </Modal>
      </div>
    </div>
  );
};

export default AdminDashboardPage;