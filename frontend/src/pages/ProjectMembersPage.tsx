/**
 * Project Members Page
 * Manage project members - add, remove, update roles
 * Only ProjectAdmin and Owner can manage members
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  projectService,
  ProjectMemberDetail,
  ProjectSummary,
  AvailableMember,
} from '../services/projectService';
import Button from '../components/Button';
import Card from '../components/Card';
import Modal from '../components/Modal';
import Select from '../components/Select';
import LoadingSpinner from '../components/LoadingSpinner';

const ProjectMembersPage: React.FC = () => {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const { userInfo } = useAuth();

  // Data state
  const [project, setProject] = useState<ProjectSummary | null>(null);
  const [members, setMembers] = useState<ProjectMemberDetail[]>([]);
  const [availableMembers, setAvailableMembers] = useState<AvailableMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Add member modal state
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedUserEmail, setSelectedUserEmail] = useState<string>('');
  const [addRole, setAddRole] = useState<'project_staff' | 'project_admin'>('project_staff');
  const [isAdding, setIsAdding] = useState(false);

  // Role update modal state
  const [showRoleModal, setShowRoleModal] = useState<string | null>(null);
  const [roleModalUser, setRoleModalUser] = useState<ProjectMemberDetail | null>(null);
  const [newRole, setNewRole] = useState<'project_staff' | 'project_admin'>('project_staff');
  const [isUpdatingRole, setIsUpdatingRole] = useState(false);

  // Action loading state
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Determine current user's permissions
  const isSystemAdmin = userInfo?.role === 'admin';
  const isOrgManager = userInfo?.role === 'manager';
  const currentMember = members.find((m) => m.user_id === userInfo?.uid);
  const canManageMembers =
    isSystemAdmin ||
    isOrgManager ||
    currentMember?.role === 'owner' ||
    currentMember?.role === 'project_admin';

  /** Fetch project info, members, and available org members */
  const fetchData = useCallback(async () => {
    if (!projectId) return;

    try {
      setLoading(true);
      setError(null);

      const [projectData, membersData] = await Promise.all([
        projectService.getProject(projectId),
        projectService.getProjectMembers(projectId),
      ]);

      setProject(projectData);
      setMembers(membersData);

      // Fetch available members (may fail if user lacks permission)
      try {
        const available = await projectService.getAvailableMembers(projectId);
        setAvailableMembers(available);
      } catch {
        console.log('Could not load available members - user may not have management permissions');
        setAvailableMembers([]);
      }
    } catch (err) {
      console.error('Error loading project members:', err);
      setError(err instanceof Error ? err.message : 'Failed to load project members');
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  /** Add a member to the project */
  const handleAddMember = async () => {
    if (!projectId || !selectedUserEmail) return;

    try {
      setIsAdding(true);
      setError(null);

      await projectService.addProjectMember({
        project_id: projectId,
        user_email: selectedUserEmail,
        role: addRole,
      });

      setSuccessMessage('Member added successfully');
      setShowAddModal(false);
      setSelectedUserEmail('');
      setAddRole('project_staff');
      await fetchData();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error adding member:', err);
      setError(err instanceof Error ? err.message : 'Failed to add member');
      setTimeout(() => setError(null), 5000);
    } finally {
      setIsAdding(false);
    }
  };

  /** Remove a member from the project */
  const handleRemoveMember = async (userId: string, email: string) => {
    if (!projectId) return;
    if (!window.confirm(`Are you sure you want to remove ${email} from this project?`)) return;

    try {
      setActionLoading(userId);
      setError(null);

      await projectService.removeProjectMember(projectId, userId);

      setSuccessMessage(`${email} removed from project`);
      await fetchData();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error removing member:', err);
      setError(err instanceof Error ? err.message : 'Failed to remove member');
      setTimeout(() => setError(null), 5000);
    } finally {
      setActionLoading(null);
    }
  };

  /** Open role update modal */
  const openRoleModal = (member: ProjectMemberDetail) => {
    setRoleModalUser(member);
    setNewRole(
      member.role === 'owner'
        ? 'project_admin'
        : (member.role as 'project_staff' | 'project_admin')
    );
    setShowRoleModal(member.user_id);
  };

  /** Update a member's role */
  const handleUpdateRole = async () => {
    if (!projectId || !showRoleModal) return;

    try {
      setIsUpdatingRole(true);
      setError(null);

      await projectService.updateProjectMemberRole(projectId, showRoleModal, newRole);

      setSuccessMessage('Member role updated successfully');
      setShowRoleModal(null);
      setRoleModalUser(null);
      await fetchData();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      console.error('Error updating role:', err);
      setError(err instanceof Error ? err.message : 'Failed to update role');
      setTimeout(() => setError(null), 5000);
    } finally {
      setIsUpdatingRole(false);
    }
  };

  /** Get badge color for project role */
  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'owner':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'project_admin':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'project_staff':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-vt-muted/20 text-vt-muted border-vt-muted/30';
    }
  };

  /** Format role display name */
  const formatRoleName = (role: string) => {
    switch (role) {
      case 'owner':
        return 'Owner';
      case 'project_admin':
        return 'Project Admin';
      case 'project_staff':
        return 'Project Staff';
      default:
        return role;
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
    <div className="min-h-screen">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 animate-slide-down">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button
                variant="secondary"
                onClick={() => navigate('/projects')}
                size="sm"
              >
                <svg
                  className="w-4 h-4 mr-1"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M10 19l-7-7m0 0l7-7m-7 7h18"
                  />
                </svg>
                Back
              </Button>
              <div className="w-12 h-12 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-lg">
                <svg
                  className="w-6 h-6 text-white"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                  />
                </svg>
              </div>
              <div>
                <h1 className="text-4xl font-bold gradient-text mb-2">Project Members</h1>
                <p className="text-vt-muted text-lg">
                  {project?.name || projectId}
                  <span className="text-sm ml-2 font-mono text-vt-muted/60">
                    ({projectId})
                  </span>
                </p>
              </div>
            </div>
            {canManageMembers && (
              <Button variant="primary" onClick={() => setShowAddModal(true)} size="lg">
                <svg
                  className="w-5 h-5 mr-2"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"
                  />
                </svg>
                Add Member
              </Button>
            )}
          </div>
        </div>

        {/* Success Message */}
        {successMessage && (
          <Card
            variant="strong"
            className="mb-6 border-vt-success/30 bg-vt-success/10 p-4 animate-slide-up"
          >
            <div className="flex items-center gap-3">
              <svg
                className="w-5 h-5 text-vt-success flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <p className="text-vt-success font-medium">{successMessage}</p>
            </div>
          </Card>
        )}

        {/* Error Message */}
        {error && (
          <Card
            variant="strong"
            className="mb-6 border-vt-error/30 bg-vt-error/10 p-4 animate-slide-up"
          >
            <div className="flex items-center gap-3">
              <svg
                className="w-5 h-5 text-vt-error flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <p className="text-vt-error font-medium">{error}</p>
            </div>
          </Card>
        )}

        {/* Members Table */}
        <Card variant="strong" className="p-6 animate-slide-up">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-semibold text-white">
              Members ({members.length})
            </h2>
          </div>

          {members.length === 0 ? (
            <div className="text-center py-12">
              <svg
                className="w-16 h-16 text-vt-muted mx-auto mb-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                />
              </svg>
              <p className="text-vt-muted text-lg">No members found</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-vt-muted/20">
                    <th className="text-center py-3 px-4 text-sm font-semibold text-vt-light">
                      Email
                    </th>
                    <th className="text-center py-3 px-4 text-sm font-semibold text-vt-light">
                      Role
                    </th>
                    <th className="text-center py-3 px-4 text-sm font-semibold text-vt-light">
                      Added
                    </th>
                    {canManageMembers && (
                      <th className="text-center py-3 px-4 text-sm font-semibold text-vt-light">
                        Actions
                      </th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {members.map((member) => (
                    <tr
                      key={member.id}
                      className="border-b border-vt-muted/10 hover:bg-vt-muted/5 transition-colors"
                    >
                      <td className="py-4 px-4">
                        <div className="flex items-center justify-center gap-2">
                          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-vt-primary to-vt-success flex items-center justify-center">
                            <span className="text-xs font-bold text-white">
                              {member.user_email.charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <span className="text-vt-light font-medium">
                            {member.user_email}
                          </span>
                        </div>
                      </td>
                      <td className="py-4 px-4 text-center">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getRoleBadgeColor(member.role)}`}
                        >
                          {formatRoleName(member.role)}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-center text-vt-muted text-sm">
                        {new Date(member.created_at).toLocaleDateString()}
                      </td>
                      {canManageMembers && (
                        <td className="py-4 px-4">
                          <div className="flex items-center justify-center gap-2">
                            {member.role !== 'owner' ? (
                              <>
                                <Button
                                  variant="secondary"
                                  size="sm"
                                  onClick={() => openRoleModal(member)}
                                  disabled={actionLoading !== null}
                                >
                                  <svg
                                    className="w-4 h-4 mr-1"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                  >
                                    <path
                                      strokeLinecap="round"
                                      strokeLinejoin="round"
                                      strokeWidth={2}
                                      d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                                    />
                                  </svg>
                                  Role
                                </Button>
                                <Button
                                  variant="error"
                                  size="sm"
                                  onClick={() =>
                                    handleRemoveMember(member.user_id, member.user_email)
                                  }
                                  isLoading={actionLoading === member.user_id}
                                  disabled={actionLoading !== null}
                                >
                                  <svg
                                    className="w-4 h-4 mr-1"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                  >
                                    <path
                                      strokeLinecap="round"
                                      strokeLinejoin="round"
                                      strokeWidth={2}
                                      d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                                    />
                                  </svg>
                                  Remove
                                </Button>
                              </>
                            ) : (
                              <span className="text-vt-muted text-xs italic">
                                Project owner
                              </span>
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Add Member Modal */}
        <Modal
          isOpen={showAddModal}
          onClose={() => {
            setShowAddModal(false);
            setSelectedUserEmail('');
            setAddRole('project_staff');
          }}
          title="Add Member to Project"
        >
          <div className="space-y-4">
            <p className="text-slate-400 text-sm">
              Add an organization member to this project. Only members of the same organization can
              be added.
            </p>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Select Organization Member
              </label>
              {availableMembers.length === 0 ? (
                <p className="text-vt-muted text-sm py-2">
                  No available organization members to add.
                </p>
              ) : (
                <Select
                  value={selectedUserEmail}
                  onChange={(val) => setSelectedUserEmail(val)}
                  options={availableMembers.map((m) => ({
                    label: `${m.email} (${m.org_role})`,
                    value: m.email,
                  }))}
                  placeholder="Select a member..."
                />
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Project Role
              </label>
              <Select
                value={addRole}
                onChange={(val) => setAddRole(val as 'project_staff' | 'project_admin')}
                options={[
                  { label: 'Project Staff', value: 'project_staff' },
                  { label: 'Project Admin', value: 'project_admin' },
                ]}
              />
              <p className="text-xs text-slate-400 mt-2">
                <strong>Project Staff:</strong> Can view and access project data.{' '}
                <strong>Project Admin:</strong> Can also manage project members.
              </p>
            </div>

            <div className="flex gap-3 pt-4">
              <Button
                variant="secondary"
                onClick={() => {
                  setShowAddModal(false);
                  setSelectedUserEmail('');
                  setAddRole('project_staff');
                }}
                className="flex-1"
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleAddMember}
                isLoading={isAdding}
                disabled={!selectedUserEmail || isAdding}
                className="flex-1"
              >
                Add Member
              </Button>
            </div>
          </div>
        </Modal>

        {/* Update Role Modal */}
        {showRoleModal && roleModalUser && (
          <div className="fixed inset-0 bg-vt-dark/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <Card variant="strong" className="relative w-full max-w-md p-6">
              <Button
                onClick={() => {
                  setShowRoleModal(null);
                  setRoleModalUser(null);
                }}
                variant="secondary"
                size="sm"
                className="absolute top-4 right-4"
              >
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </Button>

              <h3 className="text-2xl font-bold gradient-text mb-4">Update Member Role</h3>
              <p className="text-vt-muted mb-4">
                Updating role for{' '}
                <span className="text-vt-light font-medium">{roleModalUser.user_email}</span>
              </p>

              <div className="mb-6">
                <label className="block text-sm font-medium text-vt-light mb-2">
                  Select Role
                </label>
                <Select
                  value={newRole}
                  onChange={(val) => setNewRole(val as 'project_staff' | 'project_admin')}
                  options={[
                    { label: 'Project Staff', value: 'project_staff' },
                    { label: 'Project Admin', value: 'project_admin' },
                  ]}
                />
              </div>

              <div className="flex gap-3">
                <Button
                  variant="secondary"
                  onClick={() => {
                    setShowRoleModal(null);
                    setRoleModalUser(null);
                  }}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleUpdateRole}
                  isLoading={isUpdatingRole}
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

export default ProjectMembersPage;
