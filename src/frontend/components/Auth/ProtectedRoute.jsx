import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { checkAuth, hasUserPermission, hasUserAllPermissions, hasUserAnyPermission } from '../../services/AuthService';

/**
 * ProtectedRoute Component
 * Protects routes that require authentication and specific permissions
 * 
 * @param {Object} props - Component props
 * @param {JSX.Element} props.children - Child component to render if authorized
 * @param {string|string[]} [props.requiredPermission] - Required permission(s) to access the route
 * @param {boolean} [props.requireAll=false] - If true, user must have all permissions in the array
 * @returns {JSX.Element} - The protected component or redirect
 */
const ProtectedRoute = ({ 
  children, 
  requiredPermission, 
  requireAll = false,
  redirectPath = '/login'
}) => {
  const location = useLocation();
  const isAuthenticated = checkAuth();

  // Not authenticated, redirect to login
  if (!isAuthenticated) {
    return <Navigate to={redirectPath} state={{ from: location }} replace />;
  }

  // If no permission required, render children
  if (!requiredPermission) {
    return children;
  }

  // Check permissions based on type and requirements
  let hasRequiredPermission = false;
  
  if (Array.isArray(requiredPermission)) {
    // Array of permissions
    if (requireAll) {
      // Require all permissions
      hasRequiredPermission = hasUserAllPermissions(requiredPermission);
    } else {
      // Require any permission
      hasRequiredPermission = hasUserAnyPermission(requiredPermission);
    }
  } else {
    // Single permission
    hasRequiredPermission = hasUserPermission(requiredPermission);
  }

  // If user doesn't have required permissions, redirect to unauthorized page
  if (!hasRequiredPermission) {
    return <Navigate to="/unauthorized" state={{ from: location }} replace />;
  }

  // User is authenticated and has required permissions
  return children;
};

export default ProtectedRoute; 