import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import LoadingSpinner from './LoadingSpinner';

interface ProtectedRouteProps {
  children: React.ReactElement;
  requiredRoles?: ('admin' | 'manager' | 'employee')[];
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, requiredRoles }) => {
  const { currentUser, userInfo, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner />;
  }

  if (!currentUser || !userInfo) {
    return <Navigate to="/login" replace />;
  }

  // Check role-based access if requiredRoles is specified
  if (requiredRoles && requiredRoles.length > 0) {


    if (!requiredRoles.includes(userInfo.role)) {
      // Redirect to dashboard if user doesn't have required role
      if (userInfo.role === 'admin') {
        return <Navigate to="/admin-dashboard" replace />;
      }
      return <Navigate to="/dashboard" replace />;
    }
  }

  return children;
};

export default ProtectedRoute;

