/**
 * User Service
 * Handles user management API calls
 */

import { apiService } from './apiService';

export interface User {
  uid: string;
  email: string;
  role: 'admin' | 'manager' | 'employee';
  enabled: boolean;
  org_id?: string;
  created_at: string;
  updated_at: string;
}

export interface UserUpdate {
  enabled: boolean;
}

export interface PasswordUpdate {
  new_password: string;
  current_password?: string;
}

export const userService = {
  /**
   * Get all users
   */
  async getAllUsers(): Promise<User[]> {
    const response = await apiService.get<User[]>('/api/v1/users');
    return response.data;
  },

  /**
   * Get current user's data
   */
  async getCurrentUser(): Promise<User> {
    const response = await apiService.get<User>('/api/v1/users/uid');
    return response.data;
  },

  /**
   * Update user enabled status
   */
  async updateUserEnabled(uid: string, enabled: boolean): Promise<User> {
    const response = await apiService.put<User>(`/api/v1/users/uid/${uid}/enabled`, { enabled });
    return response.data;
  },

  /**
   * Delete a user
   */
  async deleteUser(uid: string): Promise<void> {
    await apiService.delete(`/api/v1/users/uid/${uid}`);
  },

  /**
   * Enable a user
   */
  async enableUser(uid: string): Promise<User> {
    return this.updateUserEnabled(uid, true);
  },

  /**
   * Disable a user
   */
  async disableUser(uid: string): Promise<User> {
    return this.updateUserEnabled(uid, false);
  },

  /**
   * Update user role
   */
  async updateUserRole(uid: string, role: 'admin' | 'manager' | 'employee'): Promise<User> {
    const response = await apiService.patch<User>(`/api/v1/users/uid/${uid}/role`, { role });
    return response.data;
  },

  /**
   * Update user password
   */
  async updateUserPassword(uid: string, passwordData: PasswordUpdate): Promise<void> {
    await apiService.put(`/api/v1/users/uid/${uid}/password`, passwordData);
  },
};

