/**
 * Organization Service  
 * Provides methods for organization operations
 */

import { apiService } from './apiService';

export interface OrganizationSummary {
  id: string;
  name: string;
  project_count: number;
  user_count: number;
}

export interface CreateOrganizationRequest {
  name: string;
  manager_email: string;
}

export interface CreateOrganizationResponse {
  org_id: string;
  name: string;
  message: string;
  manager_email: string;
  manager_password: string;
}

export interface UpdateOrganizationRequest {
  name?: string;
}

export class OrganizationService {
  /**
   * Get all organizations (admin only)
   */
  async getAllOrganizations(): Promise<OrganizationSummary[]> {
    const response = await apiService.get<OrganizationSummary[]>('/api/v1/organizations/all');
    return response.data;
  }

  /**
   * Get organizations the current user has access to
   */
  async getMyOrganizations(): Promise<OrganizationSummary[]> {
    const response = await apiService.get<OrganizationSummary[]>('/api/v1/organizations/my-organizations');
    return response.data;
  }

  /**
   * Get a specific organization by ID
   */
  async getOrganization(orgId: string): Promise<OrganizationSummary> {
    const response = await apiService.get<OrganizationSummary>(`/api/v1/organizations/${orgId}`);
    return response.data;
  }

  /**
   * Create a new organization
   */
  async createOrganization(data: CreateOrganizationRequest): Promise<CreateOrganizationResponse> {
    const response = await apiService.post<CreateOrganizationResponse>('/api/v1/organizations/create', data);
    return response.data;
  }

  /**
   * Update an organization
   */
  async updateOrganization(orgId: string, data: UpdateOrganizationRequest): Promise<{ message: string }> {
    const response = await apiService.put<{ message: string }>(`/api/v1/organizations/${orgId}`, data);
    return response.data;
  }

  /**
   * Delete an organization
   */
  async deleteOrganization(orgId: string): Promise<void> {
    await apiService.delete(`/api/v1/organizations/${orgId}`);
  }
}

export const organizationService = new OrganizationService();
