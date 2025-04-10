/**
 * Role Service
 * Defines user roles and permissions for the system
 */

/**
 * Role definitions with associated permissions
 */
export const ROLES = {
  ADMIN: 'admin',
  OPERATOR: 'operator',
  VIEWER: 'viewer'
};

/**
 * Permission definitions
 */
export const PERMISSIONS = {
  // Dashboard permissions
  DASHBOARD_VIEW: 'dashboard:view',
  DASHBOARD_EDIT: 'dashboard:edit',
  
  // Analytics permissions
  ANALYTICS_VIEW: 'analytics:view',
  ANALYTICS_EXPORT: 'analytics:export',
  
  // Alert permissions
  ALERTS_VIEW: 'alerts:view',
  ALERTS_MANAGE: 'alerts:manage',
  ALERTS_CONFIGURE: 'alerts:configure',
  
  // User management permissions
  USERS_VIEW: 'users:view',
  USERS_MANAGE: 'users:manage',
  
  // System permissions
  SYSTEM_VIEW: 'system:view',
  SYSTEM_CONFIGURE: 'system:configure',
  
  // Discovery permissions
  DISCOVERY_VIEW: 'discovery:view',
  DISCOVERY_RUN: 'discovery:run',
  DISCOVERY_CONFIGURE: 'discovery:configure'
};

/**
 * Role to permissions mapping
 */
export const ROLE_PERMISSIONS = {
  [ROLES.ADMIN]: [
    PERMISSIONS.DASHBOARD_VIEW,
    PERMISSIONS.DASHBOARD_EDIT,
    PERMISSIONS.ANALYTICS_VIEW,
    PERMISSIONS.ANALYTICS_EXPORT,
    PERMISSIONS.ALERTS_VIEW,
    PERMISSIONS.ALERTS_MANAGE,
    PERMISSIONS.ALERTS_CONFIGURE,
    PERMISSIONS.USERS_VIEW,
    PERMISSIONS.USERS_MANAGE,
    PERMISSIONS.SYSTEM_VIEW,
    PERMISSIONS.SYSTEM_CONFIGURE,
    PERMISSIONS.DISCOVERY_VIEW,
    PERMISSIONS.DISCOVERY_RUN,
    PERMISSIONS.DISCOVERY_CONFIGURE
  ],
  [ROLES.OPERATOR]: [
    PERMISSIONS.DASHBOARD_VIEW,
    PERMISSIONS.ANALYTICS_VIEW,
    PERMISSIONS.ANALYTICS_EXPORT,
    PERMISSIONS.ALERTS_VIEW,
    PERMISSIONS.ALERTS_MANAGE,
    PERMISSIONS.SYSTEM_VIEW,
    PERMISSIONS.DISCOVERY_VIEW,
    PERMISSIONS.DISCOVERY_RUN
  ],
  [ROLES.VIEWER]: [
    PERMISSIONS.DASHBOARD_VIEW,
    PERMISSIONS.ANALYTICS_VIEW,
    PERMISSIONS.ALERTS_VIEW,
    PERMISSIONS.DISCOVERY_VIEW
  ]
};

/**
 * Check if a role has a specific permission
 * @param {string} role - User role
 * @param {string} permission - Permission to check
 * @returns {boolean} - Whether the role has the permission
 */
export const hasPermission = (role, permission) => {
  if (!role || !permission) {
    return false;
  }
  
  return ROLE_PERMISSIONS[role]?.includes(permission) || false;
};

/**
 * Get all permissions for a role
 * @param {string} role - User role
 * @returns {Array} - List of permissions for the role
 */
export const getRolePermissions = (role) => {
  return ROLE_PERMISSIONS[role] || [];
};

/**
 * Check if a role has multiple permissions (requires all)
 * @param {string} role - User role
 * @param {Array} permissions - List of permissions to check
 * @returns {boolean} - Whether the role has all permissions
 */
export const hasAllPermissions = (role, permissions) => {
  if (!role || !permissions || !permissions.length) {
    return false;
  }
  
  const rolePermissions = ROLE_PERMISSIONS[role] || [];
  return permissions.every(permission => rolePermissions.includes(permission));
};

/**
 * Check if a role has any of the permissions
 * @param {string} role - User role
 * @param {Array} permissions - List of permissions to check
 * @returns {boolean} - Whether the role has any of the permissions
 */
export const hasAnyPermission = (role, permissions) => {
  if (!role || !permissions || !permissions.length) {
    return false;
  }
  
  const rolePermissions = ROLE_PERMISSIONS[role] || [];
  return permissions.some(permission => rolePermissions.includes(permission));
};

export default {
  ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  hasPermission,
  getRolePermissions,
  hasAllPermissions,
  hasAnyPermission
}; 