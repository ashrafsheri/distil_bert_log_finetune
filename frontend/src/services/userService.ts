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
  created_at: string;
  updated_at: string;
}

export interface UserUpdate {
  email?: string;
  role?: 'admin' | 'manager' | 'employee';
  enabled?: boolean;
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
   * Get a user by UID
   */
  async getUser(uid: string): Promise<User> {
    const response = await apiService.get<User>(`/api/v1/users/uid/${uid}`);
    return response.data;
  },

  /**
   * Update a user
   */
  async updateUser(uid: string, userData: UserUpdate): Promise<User> {
    const response = await apiService.put<User>(`/api/v1/users/uid/${uid}`, userData);
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
    return this.updateUser(uid, { enabled: true });
  },

  /**
   * Disable a user
   */
  async disableUser(uid: string): Promise<User> {
    return this.updateUser(uid, { enabled: false });
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

