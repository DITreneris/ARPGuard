import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import AnalyticsDashboard from './components/Dashboard/AnalyticsDashboard';
import AlertDashboard from './components/Alerts/AlertDashboard';
import Login from './components/Auth/Login';
import ProtectedRoute from './components/Auth/ProtectedRoute';
import Unauthorized from './components/Auth/Unauthorized';
import UserManagement from './components/Admin/UserManagement';
import NotFound from './components/common/NotFound';
import { PERMISSIONS } from './services/RoleService';

/**
 * Main routing component for the application
 * Defines all available routes and their components
 */
const AppRoutes = () => {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/unauthorized" element={<Unauthorized />} />
      
      {/* Protected routes */}
      <Route 
        path="/dashboard" 
        element={
          <ProtectedRoute requiredPermission={PERMISSIONS.DASHBOARD_VIEW}>
            <AnalyticsDashboard />
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path="/alerts" 
        element={
          <ProtectedRoute requiredPermission={PERMISSIONS.ALERTS_VIEW}>
            <AlertDashboard />
          </ProtectedRoute>
        } 
      />

      {/* Admin routes */}
      <Route 
        path="/admin/users" 
        element={
          <ProtectedRoute 
            requiredPermission={PERMISSIONS.USERS_MANAGE}
            redirectPath="/unauthorized"
          >
            <UserManagement />
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/system/settings" 
        element={
          <ProtectedRoute 
            requiredPermission={[PERMISSIONS.SYSTEM_VIEW, PERMISSIONS.SYSTEM_CONFIGURE]}
            requireAll={true}
            redirectPath="/unauthorized"
          >
            {/* System settings component would go here */}
            <div>System Settings</div>
          </ProtectedRoute>
        } 
      />

      <Route 
        path="/discovery" 
        element={
          <ProtectedRoute 
            requiredPermission={[
              PERMISSIONS.DISCOVERY_VIEW, 
              PERMISSIONS.DISCOVERY_RUN
            ]}
            requireAll={false}
          >
            {/* Discovery component would go here */}
            <div>Network Discovery</div>
          </ProtectedRoute>
        } 
      />
      
      {/* Redirect root to dashboard */}
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      
      {/* 404 route */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
};

export default AppRoutes; 