import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { organizationService, OrganizationSummary } from '../services/organizationService';
import { projectService, CreateProjectResponse, ProjectHealthSummary, ProjectSummary } from '../services/projectService';
import LoadingSpinner from '../components/LoadingSpinner';
import Modal from '../components/Modal';
import ProjectCreationResult from '../components/ProjectCreationResult';
import { useAuth } from '../context/AuthContext';

const phaseBadgeClass = (phase?: string) => {
  if (!phase) return 'border-slate-400/12 bg-slate-500/10 text-slate-300';
  if (phase === 'warmup') return 'border-amber-400/18 bg-amber-500/10 text-amber-200';
  if (phase === 'ready' || phase === 'active') return 'border-emerald-400/18 bg-emerald-500/10 text-emerald-200';
  return 'border-sky-400/18 bg-sky-500/10 text-sky-200';
};

const ProjectsDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const selectedOrgId = searchParams.get('org');
  const { userInfo } = useAuth();
  const isAdmin = userInfo?.role === 'admin';
  const isManager = userInfo?.role === 'manager';
  const canCreateProject = isAdmin || isManager;

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
  const [optimizingWarmupFor, setOptimizingWarmupFor] = useState<string | null>(null);
  const [showLogTypeModal, setShowLogTypeModal] = useState(false);
  const [selectedProject, setSelectedProject] = useState<ProjectSummary | null>(null);
  const [newLogType, setNewLogType] = useState<'apache' | 'nginx'>('apache');
  const [isUpdatingLogType, setIsUpdatingLogType] = useState(false);
  const [logTypeMessage, setLogTypeMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  useEffect(() => {
    loadData();
  }, [selectedOrgId, userInfo?.uid]);

  const loadData = async () => {
    try {
      setIsLoading(true);
      setError(null);

      const [projectsData, organizationsData] = await Promise.all([
        selectedOrgId ? projectService.getProjectsByOrganization(selectedOrgId) : projectService.getMyProjects(),
        isAdmin ? organizationService.getAllOrganizations() : organizationService.getMyOrganizations(),
      ]);

      setProjects(projectsData);
      setOrganizations(organizationsData);

      const healthEntries = await Promise.all(
        projectsData.map(async project => {
          try {
            const health = await projectService.getProjectHealth(project.id);
            return [project.id, health] as const;
          } catch {
            return null;
          }
        }),
      );

      setProjectHealth(
        healthEntries.reduce<Record<string, ProjectHealthSummary>>((acc, entry) => {
          if (entry) acc[entry[0]] = entry[1];
          return acc;
        }, {}),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load projects');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateProject = async (event: React.FormEvent) => {
    event.preventDefault();
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

      setProjectCreationResult(result);
      setProjectName('');
      setSelectedOrg('');
      setLogType('apache');
      setTrafficProfile('standard');
      setShowCreateForm(false);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create project');
    } finally {
      setIsCreating(false);
    }
  };

  const handleRegenerateApiKey = async (projectId: string, projectName: string) => {
    if (!globalThis.confirm(`Regenerate the API key for "${projectName}"? The old key will stop working.`)) return;

    try {
      setRegeneratingKeyFor(projectId);
      setError(null);
      const result = await projectService.regenerateApiKey({ project_id: projectId });
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
      setError(err instanceof Error ? err.message : 'Failed to regenerate API key');
    } finally {
      setRegeneratingKeyFor(null);
    }
  };

  const handleOptimizeWarmup = async (project: ProjectSummary) => {
    const health = projectHealth[project.id];
    if (!health) return;

    try {
      setOptimizingWarmupFor(project.id);
      setError(null);
      await projectService.updateProject(project.id, {
        traffic_profile: 'low_traffic',
        warmup_threshold: Math.min(health.warmup_threshold || 1000, 1000),
      });
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to optimize project warmup');
    } finally {
      setOptimizingWarmupFor(null);
    }
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
      await projectService.updateProjectLogType({ project_id: selectedProject.id, log_type: newLogType });
      setProjects(current =>
        current.map(project => (project.id === selectedProject.id ? { ...project, log_type: newLogType } : project)),
      );
      setLogTypeMessage({ type: 'success', text: 'Log type updated successfully.' });
      setTimeout(() => {
        setShowLogTypeModal(false);
        setSelectedProject(null);
        setLogTypeMessage(null);
      }, 1200);
    } catch (err) {
      setLogTypeMessage({ type: 'error', text: err instanceof Error ? err.message : 'Failed to update log type' });
    } finally {
      setIsUpdatingLogType(false);
    }
  };

  const organizationMap = useMemo(() => {
    return new Map(organizations.map(org => [org.id, org.name]));
  }, [organizations]);

  const filteredProjects = useMemo(() => {
    return projects.filter(project => {
      const health = projectHealth[project.id];
      const phase = health?.phase || project.model_status || 'warmup';
      const query = searchTerm.trim().toLowerCase();
      const orgLabel = organizationMap.get(project.org_id) || project.org_id;
      const matchesQuery = !query
        || project.name.toLowerCase().includes(query)
        || orgLabel.toLowerCase().includes(query)
        || project.id.toLowerCase().includes(query);
      const matchesStatus =
        !statusFilter
        || (statusFilter === 'student' && !!health?.has_student_model)
        || (statusFilter === 'warmup' && phase === 'warmup')
        || (statusFilter === 'active' && phase !== 'warmup');

      return matchesQuery && matchesStatus;
    });
  }, [organizationMap, projectHealth, projects, searchTerm, statusFilter]);

  const metrics = useMemo(() => {
    const activeProtection = projects.filter(project => {
      const phase = projectHealth[project.id]?.phase || project.model_status;
      return phase && phase !== 'warmup';
    }).length;
    const warmup = projects.filter(project => (projectHealth[project.id]?.phase || project.model_status || 'warmup') === 'warmup').length;
    const studentModels = projects.filter(project => projectHealth[project.id]?.has_student_model).length;
    const lowTraffic = projects.filter(project => (projectHealth[project.id]?.traffic_profile || project.traffic_profile) === 'low_traffic').length;
    return { activeProtection, warmup, studentModels, lowTraffic };
  }, [projectHealth, projects]);

  if (isLoading) {
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
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
              {selectedOrgId ? 'Organization scope' : 'Project command center'}
            </p>
            <h1 className="mt-3 text-4xl font-semibold tracking-tight text-slate-50">
              {selectedOrgId ? 'Organization Projects' : 'Projects'}
            </h1>
            <p className="mt-3 max-w-2xl text-base leading-7 text-slate-400">
              {selectedOrgId
                ? `Monitoring projects belonging to ${organizationMap.get(selectedOrgId) || selectedOrgId}.`
                : 'Manage protected services, warmup state, model readiness, and project-level access from one place.'}
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            {selectedOrgId && (
              <button
                type="button"
                onClick={() => navigate('/projects')}
                className="inline-flex items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.05]"
              >
                Back to all projects
              </button>
            )}
            {canCreateProject && (
              <button
                type="button"
                onClick={() => setShowCreateForm(current => !current)}
                className="inline-flex items-center justify-center rounded-2xl border border-sky-400/20 bg-sky-500/10 px-5 py-3 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/16"
              >
                {showCreateForm ? 'Close form' : 'Create project'}
              </button>
            )}
          </div>
        </div>

        <div className="mt-8 grid gap-4 xl:grid-cols-4">
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Total projects</p>
            <p className="mt-4 text-4xl font-semibold text-slate-50">{projects.length}</p>
            <p className="mt-2 text-sm text-slate-400">Protected services visible in this scope.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Active protection</p>
            <p className="mt-4 text-4xl font-semibold text-emerald-300">{metrics.activeProtection}</p>
            <p className="mt-2 text-sm text-slate-400">Projects beyond initial warmup.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Student models</p>
            <p className="mt-4 text-4xl font-semibold text-sky-300">{metrics.studentModels}</p>
            <p className="mt-2 text-sm text-slate-400">Projects currently running the student path.</p>
          </div>
          <div className="rounded-3xl border border-white/6 bg-white/[0.03] p-6">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Low traffic profile</p>
            <p className="mt-4 text-4xl font-semibold text-fuchsia-300">{metrics.lowTraffic}</p>
            <p className="mt-2 text-sm text-slate-400">Projects tuned for lower event volume.</p>
          </div>
        </div>

        <div className="mt-8 grid gap-4 lg:grid-cols-[minmax(0,1fr)_220px]">
          <label className="grid gap-2 text-sm text-slate-300">
            <span>Search projects</span>
            <input
              value={searchTerm}
              onChange={event => setSearchTerm(event.target.value)}
              placeholder="Name, org, or project ID"
              className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
            />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">
            <span>Status</span>
            <select
              value={statusFilter}
              onChange={event => setStatusFilter(event.target.value)}
              className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
            >
              <option value="">All states</option>
              <option value="active">Active</option>
              <option value="warmup">Warmup</option>
              <option value="student">Student model ready</option>
            </select>
          </label>
        </div>

        {canCreateProject && showCreateForm && (
          <form onSubmit={handleCreateProject} className="mt-8 rounded-[28px] border border-white/6 bg-white/[0.025] p-6">
            <div>
              <h2 className="text-xl font-semibold text-slate-50">Create project</h2>
              <p className="mt-1 text-sm text-slate-400">Provision a monitored application with warmup and log parsing defaults.</p>
            </div>

            <div className="mt-6 grid gap-4 lg:grid-cols-2">
              <label className="grid gap-2 text-sm text-slate-300">
                <span>Project name</span>
                <input
                  value={projectName}
                  onChange={event => setProjectName(event.target.value)}
                  className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
                  placeholder="Production API Gateway"
                  required
                  disabled={isCreating}
                />
              </label>

              {!selectedOrgId && isAdmin ? (
                <label className="grid gap-2 text-sm text-slate-300">
                  <span>Organization</span>
                  <select
                    value={selectedOrg}
                    onChange={event => setSelectedOrg(event.target.value)}
                    className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
                    required
                    disabled={isCreating}
                  >
                    <option value="">Select organization</option>
                    {organizations.map(org => (
                      <option key={org.id} value={org.id}>
                        {org.name}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <label className="grid gap-2 text-sm text-slate-300">
                  <span>Organization</span>
                  <input
                    value={selectedOrgId ? organizationMap.get(selectedOrgId) || selectedOrgId : 'Current organization'}
                    disabled
                    className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-400 outline-none"
                  />
                </label>
              )}

              <label className="grid gap-2 text-sm text-slate-300">
                <span>Log type</span>
                <select
                  value={logType}
                  onChange={event => setLogType(event.target.value as 'apache' | 'nginx')}
                  className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
                  disabled={isCreating}
                >
                  <option value="apache">Apache</option>
                  <option value="nginx">Nginx</option>
                </select>
              </label>

              <label className="grid gap-2 text-sm text-slate-300">
                <span>Traffic profile</span>
                <select
                  value={trafficProfile}
                  onChange={event => setTrafficProfile(event.target.value as 'standard' | 'low_traffic')}
                  className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30"
                  disabled={isCreating}
                >
                  <option value="standard">Standard</option>
                  <option value="low_traffic">Low traffic</option>
                </select>
              </label>
            </div>

            <p className="mt-4 text-sm text-slate-400">
              {trafficProfile === 'low_traffic'
                ? 'Low traffic reduces warmup targets and activation gates for quieter projects.'
                : 'Standard traffic keeps the full warmup threshold and stricter activation criteria.'}
            </p>

            <div className="mt-6 flex flex-wrap gap-3">
              <button
                type="submit"
                disabled={isCreating}
                className="inline-flex items-center justify-center rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-400 px-5 py-3 text-sm font-semibold text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] transition hover:translate-y-[-1px] disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isCreating ? 'Creating...' : 'Create project'}
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

        <div className="mt-8">
          {filteredProjects.length === 0 ? (
            <div className="rounded-[28px] border border-white/6 bg-white/[0.025] px-6 py-16 text-center text-slate-400">
              No projects match the current view.
            </div>
          ) : (
            <div className="grid gap-5 xl:grid-cols-2">
              {filteredProjects.map(project => {
                const health = projectHealth[project.id];
                const phase = health?.phase || project.model_status || 'warmup';
                const orgLabel = organizationMap.get(project.org_id) || project.org_id;
                const blockers = health?.student_training_blockers || [];

                return (
                  <article
                    key={project.id}
                    className="rounded-[28px] border border-white/6 bg-[linear-gradient(180deg,rgba(12,20,38,0.96),rgba(8,15,29,0.94))] p-6 shadow-[0_20px_48px_rgba(2,8,23,0.38)]"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="flex flex-wrap items-center gap-3">
                          <h2 className="text-xl font-semibold text-slate-50">{project.name}</h2>
                          <span className={`inline-flex rounded-full border px-3 py-1 text-sm font-medium ${phaseBadgeClass(phase)}`}>
                            {phase}
                          </span>
                          {health?.has_student_model && (
                            <span className="inline-flex rounded-full border border-emerald-400/18 bg-emerald-500/10 px-3 py-1 text-sm font-medium text-emerald-200">
                              Student model active
                            </span>
                          )}
                        </div>
                        <div className="mt-3 flex flex-wrap gap-3 text-sm text-slate-400">
                          <span>{orgLabel}</span>
                          <span>•</span>
                          <span className="font-mono">{project.id}</span>
                        </div>
                      </div>
                    </div>

                    <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-2xl border border-white/6 bg-white/[0.03] p-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Log type</div>
                        <div className="mt-2 text-sm font-semibold text-slate-100">{project.log_type}</div>
                      </div>
                      <div className="rounded-2xl border border-white/6 bg-white/[0.03] p-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Traffic</div>
                        <div className="mt-2 text-sm font-semibold text-slate-100">{health?.traffic_profile || project.traffic_profile || 'standard'}</div>
                      </div>
                      <div className="rounded-2xl border border-white/6 bg-white/[0.03] p-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Warmup</div>
                        <div className="mt-2 text-sm font-semibold text-slate-100">
                          {health ? `${health.warmup_progress.toFixed(1)}%` : 'N/A'}
                        </div>
                      </div>
                      <div className="rounded-2xl border border-white/6 bg-white/[0.03] p-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Members</div>
                        <div className="mt-2 text-sm font-semibold text-slate-100">
                          {project.member_count} member{project.member_count === 1 ? '' : 's'}
                        </div>
                      </div>
                    </div>

                    {health && (
                      <div className="mt-4 rounded-2xl border border-white/6 bg-white/[0.02] p-4 text-sm text-slate-300">
                        <div className="flex flex-wrap gap-4">
                          <span>Baseline eligible: <strong className="text-slate-100">{health.baseline_eligible_count.toLocaleString()}</strong></span>
                          <span>Parse failure rate: <strong className="text-slate-100">{(health.parse_failure_rate * 100).toFixed(1)}%</strong></span>
                          {health.calibration_sample_count !== undefined && (
                            <span>Calibration samples: <strong className="text-slate-100">{health.calibration_sample_count}</strong></span>
                          )}
                        </div>
                        {blockers.length > 0 && (
                          <div className="mt-3 text-amber-200">Blockers: {blockers.join(', ')}</div>
                        )}
                      </div>
                    )}

                    <div className="mt-6 flex flex-wrap gap-3">
                      <button
                        type="button"
                        onClick={() => navigate(`/dashboard/${project.id}`)}
                        className="rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-400 px-4 py-2.5 text-sm font-semibold text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] transition hover:translate-y-[-1px]"
                      >
                        View Dashboard
                      </button>
                      {(isAdmin || isManager) && (
                        <button
                          type="button"
                          onClick={() => navigate(`/projects/${project.id}/members`)}
                          className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.05]"
                        >
                          Manage Members
                        </button>
                      )}
                      {(isAdmin || isManager) && (
                        <button
                          type="button"
                          onClick={() => handleChangeLogType(project)}
                          className="rounded-2xl border border-amber-400/18 bg-amber-500/10 px-4 py-2.5 text-sm font-semibold text-amber-200 transition hover:bg-amber-500/16"
                        >
                          Change Log Type
                        </button>
                      )}
                      {(isAdmin || isManager) && health && health.phase === 'warmup' && !health.has_student_model && (
                        <button
                          type="button"
                          onClick={() => handleOptimizeWarmup(project)}
                          disabled={optimizingWarmupFor === project.id}
                          className="rounded-2xl border border-sky-400/18 bg-sky-500/10 px-4 py-2.5 text-sm font-semibold text-sky-200 transition hover:bg-sky-500/16 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {optimizingWarmupFor === project.id ? 'Optimizing...' : 'Optimize Warmup'}
                        </button>
                      )}
                      {(isAdmin || isManager) && (
                        <button
                          type="button"
                          onClick={() => handleRegenerateApiKey(project.id, project.name)}
                          disabled={regeneratingKeyFor === project.id}
                          className="rounded-2xl border border-emerald-400/18 bg-emerald-500/10 px-4 py-2.5 text-sm font-semibold text-emerald-200 transition hover:bg-emerald-500/16 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {regeneratingKeyFor === project.id ? 'Regenerating...' : 'Regenerate Key'}
                        </button>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </div>

        <Modal isOpen={!!projectCreationResult} onClose={() => setProjectCreationResult(null)} title="API Key Generated">
          {projectCreationResult && (
            <ProjectCreationResult
              projectId={projectCreationResult.project_id}
              projectName={projectCreationResult.name}
              apiKey={projectCreationResult.api_key}
              onClose={() => setProjectCreationResult(null)}
            />
          )}
        </Modal>

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
                <p className="mb-4 text-slate-300">
                  Change the log format type for <span className="font-semibold text-white">{selectedProject.name}</span>
                </p>
                <label className="mb-2 block text-sm font-medium text-slate-300">Log format type</label>
                <select
                  value={newLogType}
                  onChange={event => setNewLogType(event.target.value as 'apache' | 'nginx')}
                  disabled={isUpdatingLogType}
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-slate-100 outline-none transition focus:border-sky-400/30 disabled:opacity-50"
                >
                  <option value="apache">Apache</option>
                  <option value="nginx">Nginx</option>
                </select>
                <p className="mt-2 text-xs text-slate-400">This controls how the service parses incoming logs for this project.</p>
              </div>

              {logTypeMessage && (
                <div className={`rounded-2xl p-3 ${logTypeMessage.type === 'success' ? 'bg-emerald-500/10 text-emerald-200' : 'bg-rose-500/10 text-rose-200'}`}>
                  {logTypeMessage.text}
                </div>
              )}

              <div className="flex gap-3 pt-4">
                <button
                  type="button"
                  onClick={handleUpdateLogType}
                  disabled={isUpdatingLogType || newLogType === selectedProject.log_type}
                  className="flex-1 rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-400 px-4 py-3 text-sm font-semibold text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] transition hover:translate-y-[-1px] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {isUpdatingLogType ? 'Updating...' : 'Update Log Type'}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowLogTypeModal(false);
                    setSelectedProject(null);
                    setLogTypeMessage(null);
                  }}
                  disabled={isUpdatingLogType}
                  className="rounded-2xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.05]"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </Modal>
      </section>
    </div>
  );
};

export default ProjectsDashboard;
