import { 
  signInWithEmailAndPassword, 
  signOut,
  User,
  onAuthStateChanged
} from 'firebase/auth';
import { auth } from '../config/firebase';

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface SignupCredentials {
  email: string;
  password: string;
  role: 'admin' | 'manager' | 'employee'; // Required, not optional
}

export interface AuthService {
  login: (credentials: LoginCredentials) => Promise<User>;
  createUser: (credentials: SignupCredentials) => Promise<void>;
  logout: () => Promise<void>;
  getCurrentUser: () => User | null;
  getIdToken: () => Promise<string | null>;
  onAuthStateChange: (callback: (user: User | null) => void) => () => void;
}

class AuthServiceImpl implements AuthService {
  /**
   * Login with email and password
   * @param credentials - Email and password
   * @returns Promise that resolves with the authenticated user
   * @throws Error if login fails
   */
  async login(credentials: LoginCredentials): Promise<User> {
    if (!auth) {
      throw new Error('Firebase auth is not initialized. Please check your configuration.');
    }
    try {
      const userCredential = await signInWithEmailAndPassword(
        auth,
        credentials.email,
        credentials.password
      );
      return userCredential.user;
    } catch (error: unknown) {
      const errorCode = (error as { code?: string })?.code;
      if (errorCode) {
        throw new Error(this.getErrorMessage(errorCode));
      }
      throw new Error('Login failed. Please try again.');
    }
  }

  /**
   * Create a new user account (complete creation in backend)
   * @param credentials - Email, password, and role (role is required)
   * @returns Promise that resolves when user is created
   * @throws Error if user creation fails
   */
  async createUser(credentials: SignupCredentials): Promise<void> {
    try {
      // Import apiService here to avoid circular dependency
      const { apiService } = await import('./apiService');
      
      // Call backend endpoint that handles complete user creation (Firebase + Database)
      await apiService.post('/api/v1/users/create', {
        email: credentials.email,
        password: credentials.password,
        role: credentials.role
      });
      
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      
      // Handle specific error cases
      if (errorMessage.includes('already exists')) {
        throw new Error('An account with this email already exists. Please use a different email.');
      } else if (errorMessage.includes('invalid')) {
        throw new Error('Invalid input. Please check your email and password.');
      } else if (errorMessage.includes('network') || errorMessage.includes('fetch')) {
        throw new Error('Network error. Please check your internet connection and try again.');
      } else if (errorMessage.includes('Forbidden') || errorMessage.includes('admin')) {
        throw new Error('Only administrators can create new users.');
      }
      
      throw new Error(errorMessage || 'Failed to create user account');
    }
  }

  /**
   * Logout the current user
   * @returns Promise that resolves when logout is complete
   * @throws Error if logout fails
   */
  async logout(): Promise<void> {
    if (!auth) {
      return;
    }
    try {
      await signOut(auth);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to log out: ${errorMessage}`);
    }
  }

  /**
   * Get the current authenticated user
   * @returns Current user or null if not authenticated
   */
  getCurrentUser(): User | null {
    if (!auth) {
      return null;
    }
    return auth.currentUser;
  }

  /**
   * Get Firebase ID token for the current user
   * @returns Promise that resolves with the ID token or null if not authenticated
   */
  async getIdToken(): Promise<string | null> {
    if (!auth) {
      return null;
    }
    
    const currentUser = auth.currentUser;
    if (!currentUser) {
      return null;
    }
    
    try {
      const token = await currentUser.getIdToken();
      return token;
    } catch {
      return null;
    }
  }

  /**
   * Subscribe to authentication state changes
   * @param callback - Function called when auth state changes
   * @returns Unsubscribe function
   */
  onAuthStateChange(callback: (user: User | null) => void): () => void {
    if (!auth) {
      // Return a no-op unsubscribe function and immediately call callback with null
      callback(null);
      return () => {};
    }
    return onAuthStateChanged(auth, callback);
  }

  /**
   * Convert Firebase error codes to user-friendly messages
   */
  private getErrorMessage(errorCode: string): string {
    const errorMessages: Record<string, string> = {
      'auth/user-not-found': 'No account found with this email address.',
      'auth/wrong-password': 'Incorrect password. Please try again.',
      'auth/invalid-email': 'Invalid email address.',
      'auth/user-disabled': 'This account has been disabled.',
      'auth/too-many-requests': 'Too many failed attempts. Please try again later.',
      'auth/network-request-failed': 'Network error. Please check your connection.',
      'auth/invalid-credential': 'Invalid email or password.',
    };

    return errorMessages[errorCode] || 'An error occurred during login. Please try again.';
  }
}

// Export singleton instance
export const authService: AuthService = new AuthServiceImpl();

