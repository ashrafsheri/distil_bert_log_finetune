/**
 * Admin Service
 * Provides methods for admin operations like organization management
 * Updated to use new hierarchy: Organizations → Projects
 */

import { apiService } from './apiService';
import { organizationService, OrganizationSummary } from './organizationService';

// Legacy interface for backward compatibility
export interface OrgSummary {
  id: string;
  name: string;
  user_count: number;
}

export interface CreateOrgRequest {
  name: string;
  manager_email: string;
  log_type?: 'apache' | 'nginx';
}

export interface CreateOrgResponse {
  org_id: string;
  name: string;
  message: string;
  manager_email: string;
  manager_password: string;
}

export interface DeleteOrgRequest {
  org_id: string;
}

export interface RegenerateApiKeyRequest {
  org_id: string;
}

export interface RegenerateApiKeyResponse {
  org_id: string;
  new_api_key: string;
}

export interface UpdateLogTypeRequest {
  org_id: string;
  log_type: 'apache' | 'nginx';
}

export interface UpdateLogTypeResponse {
  org_id: string;
  log_type: 'apache' | 'nginx';
  message: string;
}

export interface GetLogTypeResponse {
  org_id: string;
  log_type: 'apache' | 'nginx';
}

export class AdminService {
  /**
   * Get all organizations with user counts
   * Now uses the new /api/v1/organizations/all endpoint
   */
  async getAllOrgs(): Promise<OrgSummary[]> {
    const response = await apiService.get<OrganizationSummary[]>('/api/v1/organizations/all');
    // Map to legacy format for backward compatibility
    return response.data.map(org => ({
      id: org.id,
      name: org.name,
      user_count: org.user_count || 0
    }));
  }

  /**
   * Create a new organization
   * Now uses the new /api/v1/organizations endpoint
   */
  async createOrg(data: CreateOrgRequest): Promise<CreateOrgResponse> {
    // Create organization with manager
    const orgResponse = await organizationService.createOrganization({ 
      name: data.name,
      manager_email: data.manager_email 
    });
    
    // Return the complete response
    return orgResponse;
  }

  /**
   * Delete an organization
   * Now uses the new /api/v1/organizations/{id} endpoint
   */
  async deleteOrg(orgId: string): Promise<void> {
    await organizationService.deleteOrganization(orgId);
  }

  /**
   * Regenerate API key for an organization
   * Note: API keys are now at the project level, not organization level
   * This method will need a projectId instead
   */
  async regenerateApiKey(_data: RegenerateApiKeyRequest): Promise<RegenerateApiKeyResponse> {
    // This needs to be updated to work with projects
    // For now, throw an error indicating projects should be used
    throw new Error('API keys are now managed at the project level. Please use projectService.regenerateApiKey(projectId)');
  }

  /**
   * Get log type for an organization
   * Note: Log types are now at the project level, not organization level
   */
  async getOrgLogType(_orgId: string): Promise<GetLogTypeResponse> {
    // Log types are now per-project
    throw new Error('Log types are now managed at the project level. Please use the project details endpoint.');
  }

  /**
   * Update log type for an organization
   * Note: Log types are now at the project level, not organization level
   */
  async updateOrgLogType(_data: UpdateLogTypeRequest): Promise<UpdateLogTypeResponse> {
    // Log types are now per-project
    throw new Error('Log types are now managed at the project level. Please use projectService.updateProject(projectId, { log_type })');
  }
}

export const adminService = new AdminService();