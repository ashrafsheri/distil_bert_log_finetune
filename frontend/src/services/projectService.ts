/**
 * Project Service
 * Provides methods for project operations
 */

import { apiService } from './apiService';

export interface ProjectSummary {
  id: string;
  name: string;
  org_id: string;
  log_type: 'apache' | 'nginx';
  member_count: number;
  model_status?: string;
}

export interface CreateProjectRequest {
  name: string;
  org_id: string;
  log_type?: 'apache' | 'nginx';
}

export interface CreateProjectResponse {
  project_id: string;
  api_key: string;
  name: string;
  org_id: string;
  log_type: 'apache' | 'nginx';
}

export interface UpdateProjectRequest {
  name?: string;
  log_type?: 'apache' | 'nginx';
}

export interface RegenerateApiKeyRequest {
  project_id: string;
}

export interface RegenerateApiKeyResponse {
  project_id: string;
  new_api_key: string;
}

export interface UpdateLogTypeRequest {
  project_id: string;
  log_type: 'apache' | 'nginx';
}

export interface UpdateLogTypeResponse {
  project_id: string;
  log_type: 'apache' | 'nginx';
  message: string;
}

export interface ProjectMemberDetail {
  id: string;
  project_id: string;
  user_id: string;
  user_email: string;
  role: 'viewer' | 'editor' | 'admin' | 'owner';
  created_at: string;
}

export interface AddProjectMemberRequest {
  project_id: string;
  user_email: string;
  role: 'viewer' | 'editor' | 'admin' | 'owner';
}

export interface AddProjectMemberResponse {
  project_id: string;
  user_email: string;
  user_id: string;
  role: string;
  message: string;
}

export class ProjectService {
  /**
   * Get all projects for the current user
   */
  async getMyProjects(): Promise<ProjectSummary[]> {
    const response = await apiService.get<ProjectSummary[]>('/api/v1/projects/my-projects');
    return response.data;
  }

  /**
   * Get all projects in an organization
   */
  async getProjectsByOrganization(orgId: string): Promise<ProjectSummary[]> {
    const response = await apiService.get<ProjectSummary[]>(`/api/v1/projects/organization/${orgId}`);
    return response.data;
  }

  /**
   * Get a specific project by ID
   */
  async getProject(projectId: string): Promise<ProjectSummary> {
    const response = await apiService.get<ProjectSummary>(`/api/v1/projects/${projectId}`);
    return response.data;
  }

  /**
   * Create a new project
   */
  async createProject(data: CreateProjectRequest): Promise<CreateProjectResponse> {
    const response = await apiService.post<CreateProjectResponse>('/api/v1/projects/create', data);
    return response.data;
  }

  /**
   * Update a project
   */
  async updateProject(projectId: string, data: UpdateProjectRequest): Promise<{ message: string }> {
    const response = await apiService.put<{ message: string }>(`/api/v1/projects/${projectId}`, data);
    return response.data;
  }

  /**
   * Delete a project
   */
  async deleteProject(projectId: string): Promise<void> {
    await apiService.delete(`/api/v1/projects/${projectId}`);
  }

  /**
   * Regenerate API key for a project
   */
  async regenerateApiKey(data: RegenerateApiKeyRequest): Promise<RegenerateApiKeyResponse> {
    const response = await apiService.post<RegenerateApiKeyResponse>('/api/v1/projects/regenerate-api-key', data);
    return response.data;
  }

  /**
   * Get log type for a project
   */
  async getProjectLogType(projectId: string): Promise<{ project_id: string; log_type: string }> {
    const response = await apiService.get<{ project_id: string; log_type: string }>(`/api/v1/projects/${projectId}/log-type`);
    return response.data;
  }

  /**
   * Update log type for a project
   */
  async updateProjectLogType(data: UpdateLogTypeRequest): Promise<UpdateLogTypeResponse> {
    const response = await apiService.put<UpdateLogTypeResponse>('/api/v1/projects/log-type', data);
    return response.data;
  }

  /**
   * Get all members of a project
   */
  async getProjectMembers(projectId: string): Promise<ProjectMemberDetail[]> {
    const response = await apiService.get<ProjectMemberDetail[]>(`/api/v1/projects/${projectId}/members`);
    return response.data;
  }

  /**
   * Add a member to a project
   */
  async addProjectMember(data: AddProjectMemberRequest): Promise<AddProjectMemberResponse> {
    const response = await apiService.post<AddProjectMemberResponse>('/api/v1/projects/members/add', data);
    return response.data;
  }

  /**
   * Remove a member from a project
   */
  async removeProjectMember(projectId: string, userId: string): Promise<void> {
    await apiService.delete(`/api/v1/projects/members/${projectId}/${userId}`);
  }

  /**
   * Update a project member's role
   */
  async updateProjectMemberRole(
    projectId: string, 
    userId: string, 
    role: 'viewer' | 'editor' | 'admin' | 'owner'
  ): Promise<{ message: string }> {
    const response = await apiService.put<{ message: string }>(
      `/api/v1/projects/members/${projectId}/${userId}/role`,
      { role }
    );
    return response.data;
  }
}

export const projectService = new ProjectService();
