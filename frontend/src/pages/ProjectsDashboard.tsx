import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { projectService, ProjectSummary, ProjectHealthSummary, CreateProjectResponse } from '../services/projectService';
import { organizationService, OrganizationSummary } from '../services/organizationService';
import LoadingSpinner from '../components/LoadingSpinner';
import Button from '../components/Button';
import Card from '../components/Card';
import Modal from '../components/Modal';
import ProjectCreationResult from '../components/ProjectCreationResult';
import { useAuth } from '../context/AuthContext';

const ProjectsDashboard: React.FC = () => {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [projectHealth, setProjectHealth] = useState<Record<string, ProjectHealthSummary>>({});
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [selectedOrg, setSelectedOrg] = useState('');
  const [logType, setLogType] = useState<'apache' | 'nginx'>('apache');
  const [trafficProfile, setTrafficProfile] = useState<'standard' | 'low_traffic'>('standard');
  const [isCreating, setIsCreating] = useState(false);
  const [projectCreationResult, setProjectCreationResult] = useState<CreateProjectResponse | null>(null);
  const [regeneratingKeyFor, setRegeneratingKeyFor] = useState<string | null>(null);
  const [showLogTypeModal, setShowLogTypeModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<ProjectSummary | null>(null);
  const [newLogType, setNewLogType] = useState<'apache' | 'nginx'>('apache');
  const [isUpdatingLogType, setIsUpdatingLogType] = useState(false);
  const [logTypeMessage, setLogTypeMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const selectedOrgId = searchParams.get('org');
  const { userInfo } = useAuth();
  const isAdmin = userInfo?.role === 'admin';
  const isManager = userInfo?.role === 'manager';
  const canCreateProject = isAdmin || isManager;
  const projectNameInputId = 'create-project-name';
  const organizationSelectId = 'create-project-organization';
  const organizationDisplayId = 'selected-organization';
  const createLogTypeSelectId = 'create-project-log-type';
  const createTrafficProfileSelectId = 'create-project-traffic-profile';
  const updateLogTypeSelectId = 'update-project-log-type';

  useEffect(() => {
    loadData();
  }, [selectedOrgId]);

  const loadData = async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Load projects
      let projectsData: ProjectSummary[];
      if (selectedOrgId) {
        projectsData = await projectService.getProjectsByOrganization(selectedOrgId);
      } else {
        projectsData = await projectService.getMyProjects();
      }
      setProjects(projectsData);
      const healthEntries = await Promise.all(
        projectsData.map(async (project) => {
          try {
            const health = await projectService.getProjectHealth(project.id);
            return [project.id, health] as const;
          } catch {
            return null;
          }
        })
      );
      setProjectHealth(
        healthEntries.reduce<Record<string, ProjectHealthSummary>>((acc, entry) => {
          if (entry) {
            acc[entry[0]] = entry[1];
          }
          return acc;
        }, {})
      );
      
      // Load organizations for dropdown (only for admins)
      if (isAdmin) {
        const orgsData = await organizationService.getAllOrganizations();
        setOrganizations(orgsData);
      }
    } catch (err) {
      console.error('Error loading data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load projects');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!projectName.trim()) {
      setError('Project name is required');
      return;
    }

    const orgId = selectedOrgId || selectedOrg;
    if (!orgId && isAdmin) {
      setError('Organization is required');
      return;
    }

    try {
      setIsCreating(true);
      setError(null);
      
      const result = await projectService.createProject({
        name: projectName.trim(),
        org_id: orgId,
        log_type: logType,
        traffic_profile: trafficProfile,
      });
      
      // Show API key modal
      setProjectCreationResult(result);
      
      // Reset form
      setProjectName('');
      setSelectedOrg('');
      setLogType('apache');
      setTrafficProfile('standard');
      setShowCreateForm(false);
      
      // Reload projects
      await loadData();
    } catch (err) {
      console.error('Error creating project:', err);
      setError(err instanceof Error ? err.message : 'Failed to create project');
    } finally {
      setIsCreating(false);
    }
  };

  const handleRegenerateApiKey = async (projectId: string, projectName: string) => {
    if (!globalThis.confirm(`Are you sure you want to regenerate the API key for "${projectName}"? The old key will no longer work.`)) {
      return;
    }

    try {
      setRegeneratingKeyFor(projectId);
      setError(null);
      
      const result = await projectService.regenerateApiKey({ project_id: projectId });
      
      // Show API key modal with regenerated key
      setProjectCreationResult({
        project_id: projectId,
        name: projectName,
        api_key: result.new_api_key,
        org_id: '',
        log_type: 'apache',
        warmup_threshold: projectHealth[projectId]?.warmup_threshold ?? 10000,
        traffic_profile: projectHealth[projectId]?.traffic_profile === 'low_traffic' ? 'low_traffic' : 'standard',
      });
      
    } catch (err) {
      console.error('Error regenerating API key:', err);
      setError(err instanceof Error ? err.message : 'Failed to regenerate API key');
    } finally {
      setRegeneratingKeyFor(null);
    }
  };

  const handleViewProject = (projectId: string) => {
    navigate(`/dashboard/${projectId}`);
  };

  const handleChangeLogType = (project: ProjectSummary) => {
    setSelectedProject(project);
    setNewLogType(project.log_type);
    setLogTypeMessage(null);
    setShowLogTypeModal(true);
  };

  const handleUpdateLogType = async () => {
    if (!selectedProject) return;

    try {
      setIsUpdatingLogType(true);
      setLogTypeMessage(null);
      
      await projectService.updateProjectLogType({
        project_id: selectedProject.id,
        log_type: newLogType
      });
      
      setLogTypeMessage({ type: 'success', text: 'Log type updated successfully!' });
      
      // Update the project in the list
      setProjects(projects.map(p => 
        p.id === selectedProject.id 
          ? { ...p, log_type: newLogType }
          : p
      ));
      
      // Close modal after a short delay to show success message
      setTimeout(() => {
        setShowLogTypeModal(false);
        setSelectedProject(null);
        setLogTypeMessage(null);
      }, 1500);
    } catch (err) {
      console.error('Error updating log type:', err);
      setLogTypeMessage({ 
        type: 'error', 
        text: err instanceof Error ? err.message : 'Failed to update log type' 
      });
    } finally {
      setIsUpdatingLogType(false);
    }
  };

  const getStatusBadgeClass = (status?: string) => {
    switch (status) {
      case 'ready':
        return 'bg-green-500/20 text-green-400 border border-green-500/30';
      case 'training':
        return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
      case 'warmup':
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border border-red-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border border-slate-500/30';
    }
  };

  if (isLoading) {
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
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold text-white mb-3">
                {selectedOrgId ? 'Organization Projects' : 'Projects'}
              </h1>
              <p className="text-slate-400 text-lg">
                {selectedOrgId 
                  ? `Viewing projects for organization ${selectedOrgId}`
                  : 'Select a project to view its log monitoring dashboard'}
              </p>
            </div>
            {selectedOrgId && (
              <Button
                onClick={() => navigate('/projects')}
                variant="secondary"
                className="px-4 py-2"
              >
                ← Back to All Projects
              </Button>
            )}
          </div>
        </div>

        {canCreateProject && (
          <div className="mb-8">
            <Button
              onClick={() => setShowCreateForm(!showCreateForm)}
              className="bg-vt-primary hover:bg-vt-primary/80 px-6 py-3 text-lg"
            >
              {showCreateForm ? 'Cancel' : 'Create New Project'}
            </Button>
          </div>
        )}

        {showCreateForm && (
          <Card className="mb-8 p-8">
            <h2 className="text-2xl font-semibold text-white mb-6">Create New Project</h2>
            <form className="space-y-6" onSubmit={handleCreateProject}>
              <div>
                <label htmlFor={projectNameInputId} className="block text-sm font-medium text-slate-300 mb-3">
                  Project Name
                </label>
                <input
                  id={projectNameInputId}
                  type="text"
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-vt-primary text-lg"
                  placeholder="Enter project name"
                  required
                  disabled={isCreating}
                />
              </div>
              {!selectedOrgId && isAdmin && (
                <div>
                  <label htmlFor={organizationSelectId} className="block text-sm font-medium text-slate-300 mb-3">
                    Organization
                  </label>
                  <select
                    id={organizationSelectId}
                    value={selectedOrg}
                    onChange={(e) => setSelectedOrg(e.target.value)}
                    className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary text-lg"
                    required
                    disabled={isCreating}
                  >
                    <option value="">Select an organization</option>
                    {organizations.map(org => (
                      <option key={org.id} value={org.id}>{org.name}</option>
                    ))}
                  </select>
                </div>
              )}
              {selectedOrgId && (
                <div>
                  <label htmlFor={organizationDisplayId} className="block text-sm font-medium text-slate-300 mb-3">
                    Organization
                  </label>
                  <input
                    id={organizationDisplayId}
                    type="text"
                    value={selectedOrgId}
                    disabled
                    className="w-full px-4 py-3 bg-slate-600 border border-slate-500 rounded-lg text-slate-300 text-lg cursor-not-allowed"
                  />
                </div>
              )}
              <div>
                <label htmlFor={createLogTypeSelectId} className="block text-sm font-medium text-slate-300 mb-3">
                  Log Type
                </label>
                <select
                  id={createLogTypeSelectId}
                  value={logType}
                  onChange={(e) => setLogType(e.target.value as 'apache' | 'nginx')}
                  className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary text-lg"
                  disabled={isCreating}
                >
                  <option value="apache">Apache</option>
                  <option value="nginx">Nginx</option>
                </select>
              </div>
              <div>
                <label htmlFor={createTrafficProfileSelectId} className="block text-sm font-medium text-slate-300 mb-3">
                  Traffic Profile
                </label>
                <select
                  id={createTrafficProfileSelectId}
                  value={trafficProfile}
                  onChange={(e) => setTrafficProfile(e.target.value as 'standard' | 'low_traffic')}
                  className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary text-lg"
                  disabled={isCreating}
                >
                  <option value="standard">Standard</option>
                  <option value="low_traffic">Low Traffic</option>
                </select>
                <p className="mt-2 text-sm text-slate-400">
                  {trafficProfile === 'low_traffic'
                    ? 'Uses a 1,000-log warmup target with lower sequence and calibration requirements for quieter live projects.'
                    : 'Uses the standard 10,000-log warmup target and stricter activation thresholds.'}
                </p>
              </div>
              <div className="flex gap-4 pt-4">
                <Button
                  type="submit"
                  className="bg-vt-success hover:bg-vt-success/80 px-6 py-3 text-lg"
                  disabled={isCreating}
                >
                  {isCreating ? 'Creating...' : 'Create Project'}
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
            <Button onClick={loadData} className="mt-4">
              Retry
            </Button>
          </Card>
        )}

        <Card className="p-8">
          <h2 className="text-2xl font-semibold text-white mb-6">My Projects</h2>
          {projects.length === 0 ? (
            <div className="text-center py-12">
              <svg className="w-16 h-16 text-slate-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
              </svg>
              <p className="text-slate-400 text-lg">No projects available.</p>
              <p className="text-slate-500 text-sm mt-2">
                {isAdmin
                  ? 'Create your first project to get started.'
                  : 'Ask your administrator to add you to a project.'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="pb-4 text-slate-300 font-medium text-lg">Project Name</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Log Type</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Status</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Members</th>
                    <th className="pb-4 text-slate-300 font-medium text-lg">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {projects.map((project) => (
                    <tr key={project.id} className="border-b border-slate-800 align-top">
                      <td className="py-4 text-white">
                        <div className="font-medium">{project.name}</div>
                        <div className="text-sm text-slate-400 font-mono">{project.id}</div>
                        {projectHealth[project.id] && (
                          <div className="mt-2 space-y-1 text-xs text-slate-400">
                            <div>
                              Phase: <span className="text-slate-200 font-medium">{projectHealth[project.id].phase}</span>
                              {' '}• Warmup {projectHealth[project.id].warmup_progress.toFixed(1)}%
                              {' '}• Profile <span className="text-slate-200 font-medium">{projectHealth[project.id].traffic_profile || 'standard'}</span>
                            </div>
                            <div>
                              Baseline eligible: <span className="text-slate-200 font-medium">{projectHealth[project.id].baseline_eligible_count.toLocaleString()}</span>
                              {' '}• Parse failure rate: <span className="text-slate-200 font-medium">{(projectHealth[project.id].parse_failure_rate * 100).toFixed(1)}%</span>
                            </div>
                            {projectHealth[project.id].low_sample_calibration && (
                              <div className="text-yellow-300">
                                Calibration is running in low-sample mode for this low-traffic project.
                              </div>
                            )}
                            {projectHealth[project.id].student_training_blockers.length > 0 && (
                              <div className="text-vt-warning">
                                Blockers: {projectHealth[project.id].student_training_blockers.join(', ')}
                              </div>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="py-4">
                        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          {project.log_type}
                        </span>
                      </td>
                      <td className="py-4">
                        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${getStatusBadgeClass(project.model_status)}`}>
                          {project.model_status || 'warmup'}
                        </span>
                        {projectHealth[project.id]?.has_student_model && (
                          <div className="mt-2 text-xs text-vt-success">Student model active</div>
                        )}
                      </td>
                      <td className="py-4 text-slate-300">
                        <span className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-slate-700 text-slate-300">
                          {project.member_count} member{project.member_count === 1 ? '' : 's'}
                        </span>
                      </td>
                      <td className="py-4">
                        <div className="flex gap-3">
                          <Button
                            onClick={() => handleViewProject(project.id)}
                            size="sm"
                            className="bg-vt-primary hover:bg-vt-primary/80 px-4 py-2"
                          >
                            View Dashboard
                          </Button>
                          {(isAdmin || isManager) && (
                            <Button
                              onClick={() => navigate(`/projects/${project.id}/members`)}
                              size="sm"
                              variant="secondary"
                              className="px-4 py-2"
                            >
                              Manage Members
                            </Button>
                          )}
                          {(isAdmin || isManager) && (
                            <Button
                              onClick={() => handleChangeLogType(project)}
                              size="sm"
                              className="bg-vt-warning hover:bg-vt-warning/80 px-4 py-2"
                            >
                              Change Log Type
                            </Button>
                          )}
                          {(isAdmin || isManager) && (
                            <Button
                              onClick={() => handleRegenerateApiKey(project.id, project.name)}
                              size="sm"
                              disabled={regeneratingKeyFor === project.id}
                              className="bg-vt-success hover:bg-vt-success/80 px-4 py-2"
                            >
                              {regeneratingKeyFor === project.id ? 'Regenerating...' : 'Regenerate Key'}
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* API Key Modal */}
        <Modal
          isOpen={!!projectCreationResult}
          onClose={() => setProjectCreationResult(null)}
          title="API Key Generated"
        >
          {projectCreationResult && (
            <ProjectCreationResult
              projectId={projectCreationResult.project_id}
              projectName={projectCreationResult.name}
              apiKey={projectCreationResult.api_key}
              onClose={() => setProjectCreationResult(null)}
            />
          )}
        </Modal>

        {/* Change Log Type Modal */}
        <Modal
          isOpen={showLogTypeModal}
          onClose={() => {
            setShowLogTypeModal(false);
            setSelectedProject(null);
            setLogTypeMessage(null);
          }}
          title="Change Log Type"
        >
          {selectedProject && (
            <div className="space-y-4">
              <div>
                <p className="text-slate-300 mb-4">
                  Change the log format type for <span className="font-semibold text-white">{selectedProject.name}</span>
                </p>
                <label htmlFor={updateLogTypeSelectId} className="block text-sm font-medium text-slate-300 mb-2">
                  Log Format Type
                </label>
                <select
                  id={updateLogTypeSelectId}
                  value={newLogType}
                  onChange={(e) => setNewLogType(e.target.value as 'apache' | 'nginx')}
                  disabled={isUpdatingLogType}
                  className="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-vt-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <option value="apache">Apache</option>
                  <option value="nginx">Nginx</option>
                </select>
                <p className="text-xs text-slate-400 mt-2">
                  This setting determines how logs are parsed for this project
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

              <div className="flex gap-3 pt-4">
                <Button
                  onClick={handleUpdateLogType}
                  disabled={isUpdatingLogType || newLogType === selectedProject.log_type}
                  className="flex-1 bg-vt-primary hover:bg-vt-primary/80 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isUpdatingLogType ? (
                    <div className="flex items-center justify-center gap-2">
                      <LoadingSpinner />
                      <span>Updating...</span>
                    </div>
                  ) : (
                    'Update Log Type'
                  )}
                </Button>
                <Button
                  onClick={() => {
                    setShowLogTypeModal(false);
                    setSelectedProject(null);
                    setLogTypeMessage(null);
                  }}
                  disabled={isUpdatingLogType}
                  variant="secondary"
                  className="px-6"
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </Modal>
      </div>
    </div>
  );
};

export default ProjectsDashboard;
