import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User } from 'firebase/auth';
import { authService } from '../services/authService';
import { LoginCredentials, SignupCredentials } from '../services/authService';
import LoadingSpinner from '../components/LoadingSpinner';

interface AuthContextType {
  currentUser: User | null;
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
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let timeoutId: NodeJS.Timeout;
    let mounted = true;
    
    // Set a timeout to ensure loading doesn't hang forever
    timeoutId = setTimeout(() => {
      if (mounted) {
        console.warn('Auth initialization taking longer than expected');
        setLoading(false);
      }
    }, 5000); // 5 second timeout

    try {
      const unsubscribe = authService.onAuthStateChange((user) => {
        if (mounted) {
          setCurrentUser(user);
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
    // State will update automatically via onAuthStateChange
  };

  const createUser = async (credentials: SignupCredentials) => {
    await authService.createUser(credentials);
    // Note: The new user will be created but the current session won't change
    // The admin creating the user will remain logged in
  };

  const logout = async () => {
    await authService.logout();
    // State will update automatically via onAuthStateChange
  };

  const value: AuthContextType = {
    currentUser,
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

