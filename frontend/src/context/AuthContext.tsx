import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User } from 'firebase/auth';
import { authService } from '../services/authService';
import { LoginCredentials, SignupCredentials } from '../services/authService';
import { userService, User as BackendUser } from '../services/userService';
import LoadingSpinner from '../components/LoadingSpinner';

interface AuthContextType {
  currentUser: User | null;
  userInfo: BackendUser | null;
  loading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  createUser: (credentials: SignupCredentials) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [userInfo, setUserInfo] = useState<BackendUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Fetch user info from backend when Firebase user changes
  useEffect(() => {
    const fetchUserInfo = async (firebaseUser: User | null) => {
      if (!firebaseUser) {
        setUserInfo(null);
        return;
      }

      try {
        const userInfoData = await userService.getCurrentUser();
        setUserInfo(userInfoData);
      } catch (error) {
        console.error('Error fetching user info:', error);
        // If fetching user info fails, logout the user
        try {
          await authService.logout();
        } catch (logoutError) {
          console.error('Error during logout:', logoutError);
        }
        setUserInfo(null);
        setCurrentUser(null);
      }
    };

    let mounted = true;
    
    // Set a timeout to ensure loading doesn't hang forever
    const timeoutId = setTimeout(() => {
      if (mounted) {
        console.warn('Auth initialization taking longer than expected');
        setLoading(false);
      }
    }, 5000); // 5 second timeout

    try {
      const unsubscribe = authService.onAuthStateChange(async (user) => {
        if (mounted) {
          setCurrentUser(user);
          await fetchUserInfo(user);
          setLoading(false);
          clearTimeout(timeoutId);
        }
      });

      return () => {
        mounted = false;
        clearTimeout(timeoutId);
        unsubscribe();
      };
    } catch (error) {
      console.error('Error initializing auth:', error);
      if (mounted) {
        setLoading(false);
      }
      clearTimeout(timeoutId);
    }
  }, []); // Empty dependency array - only run once on mount

  const login = async (credentials: LoginCredentials) => {
    await authService.login(credentials);
    // After successful Firebase login, fetch user info from backend
    try {
      const userInfoData = await userService.getCurrentUser();
      setUserInfo(userInfoData);
      // State will update automatically via onAuthStateChange
    } catch (error) {
      console.error('Error fetching user info after login:', error);
      // If fetching user info fails, logout and throw error
      try {
        await authService.logout();
      } catch (logoutError) {
        console.error('Error during logout:', logoutError);
      }
      setUserInfo(null);
      setCurrentUser(null);
      throw new Error('Failed to fetch user information. Your account may not be properly configured.');
    }
  };

  const createUser = async (credentials: SignupCredentials) => {
    await authService.createUser(credentials);
    // Note: The new user will be created but the current session won't change
    // The admin creating the user will remain logged in
  };

  const logout = async () => {
    await authService.logout();
    setUserInfo(null);
    // State will update automatically via onAuthStateChange
  };

  const value: AuthContextType = {
    currentUser,
    userInfo,
    loading,
    login,
    createUser,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {loading ? (
        <div className="min-h-screen flex items-center justify-center">
          <LoadingSpinner text="Initializing..." />
        </div>
      ) : (
        children
      )}
    </AuthContext.Provider>
  );
};

