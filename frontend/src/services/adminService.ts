/**
 * Admin Service
 * Provides methods for admin operations like organization management
 */

import { apiService } from './apiService';

export interface OrgSummary {
  id: string;
  name: string;
  user_count: number;
}

export interface CreateOrgRequest {
  name: string;
  manager_email: string;
}

export interface CreateOrgResponse {
  org_id: string;
  api_key: string;
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

export class AdminService {
  /**
   * Get all organizations with user counts
   */
  async getAllOrgs(): Promise<OrgSummary[]> {
    const response = await apiService.get<OrgSummary[]>('/api/v1/admin/orgs');
    return response.data;
  }

  /**
   * Create a new organization
   */
  async createOrg(data: CreateOrgRequest): Promise<CreateOrgResponse> {
    const response = await apiService.post<CreateOrgResponse>('/api/v1/admin/create-org', data);
    return response.data;
  }

  /**
   * Delete an organization
   */
  async deleteOrg(orgId: string): Promise<void> {
    await apiService.delete(`/api/v1/admin/delete-org/${orgId}`);
  }


  /**
   * Regenerate API key for an organization
   */
  async regenerateApiKey(data: RegenerateApiKeyRequest): Promise<RegenerateApiKeyResponse> {
    const response = await apiService.post<RegenerateApiKeyResponse>('/api/v1/admin/regenerate-api-key', data);
    return response.data;
  }
}

export const adminService = new AdminService();