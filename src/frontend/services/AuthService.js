/**
 * Authentication Service
 * Handles authentication for the Analytics Dashboard
 */

import axios from 'axios';
import { hasPermission, hasAllPermissions, hasAnyPermission } from './RoleService';

const API_BASE_URL = '/api/auth';
const TOKEN_KEY = 'arp_guard_auth_token';
const USER_KEY = 'arp_guard_user';

/**
 * Login to the system
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @returns {Promise} Promise resolving to login result
 */
export const login = async (username, password) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/login`, { username, password });
    
    // Store token and user in localStorage
    localStorage.setItem(TOKEN_KEY, response.data.access_token);
    localStorage.setItem(USER_KEY, JSON.stringify(response.data.user));
    
    // Set Authorization header for future requests
    setAuthHeader(response.data.access_token);
    
    return response.data;
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
};

/**
 * Logout from the system
 * @returns {Promise} Promise resolving to logout result
 */
export const logout = async () => {
  try {
    // Only call API if we have a token
    const token = getToken();
    if (token) {
      await axios.post(`${API_BASE_URL}/logout`);
    }
    
    // Clear local storage and auth header
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    axios.defaults.headers.common['Authorization'] = '';
    
    return { success: true };
  } catch (error) {
    console.error('Logout error:', error);
    
    // Still clear local storage and auth header on error
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    axios.defaults.headers.common['Authorization'] = '';
    
    throw error;
  }
};

/**
 * Check if user is authenticated
 * @returns {Promise<boolean>} Promise resolving to authentication status
 */
export const checkAuth = async () => {
  try {
    // Get token from localStorage
    const token = getToken();
    if (!token) {
      return false;
    }
    
    // Set token in header and make request
    setAuthHeader(token);
    const response = await axios.get(`${API_BASE_URL}/check`);
    
    return response.data.authenticated === true;
  } catch (error) {
    console.error('Auth check error:', error);
    return false;
  }
};

/**
 * Get the current user from localStorage
 * @returns {Object|null} User object or null if not logged in
 */
export const getCurrentUser = () => {
  try {
    const userStr = localStorage.getItem(USER_KEY);
    if (userStr) {
      return JSON.parse(userStr);
    }
    return null;
  } catch (error) {
    console.error('Error getting current user:', error);
    return null;
  }
};

/**
 * Get authentication token from localStorage
 * @returns {string|null} Authentication token or null if not available
 */
export const getToken = () => {
  return localStorage.getItem(TOKEN_KEY);
};

/**
 * Set the Authorization header for axios requests
 * @param {string} token - JWT token
 */
export const setAuthHeader = (token) => {
  if (token) {
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    axios.defaults.headers.common['Authorization'] = '';
  }
};

/**
 * Check if the current user has a specific permission
 * @param {string} permission - Permission to check
 * @returns {boolean} Whether the user has the permission
 */
export const hasUserPermission = (permission) => {
  const user = getCurrentUser();
  if (!user || !user.role) {
    return false;
  }
  
  return hasPermission(user.role, permission);
};

/**
 * Check if the current user has all the specified permissions
 * @param {Array} permissions - Array of permissions to check
 * @returns {boolean} Whether the user has all the permissions
 */
export const hasUserAllPermissions = (permissions) => {
  const user = getCurrentUser();
  if (!user || !user.role) {
    return false;
  }
  
  return hasAllPermissions(user.role, permissions);
};

/**
 * Check if the current user has any of the specified permissions
 * @param {Array} permissions - Array of permissions to check
 * @returns {boolean} Whether the user has any of the permissions
 */
export const hasUserAnyPermission = (permissions) => {
  const user = getCurrentUser();
  if (!user || !user.role) {
    return false;
  }
  
  return hasAnyPermission(user.role, permissions);
};

/**
 * Get the user's role
 * @returns {string|null} User's role or null if not available
 */
export const getUserRole = () => {
  const user = getCurrentUser();
  return user?.role || null;
};

// Initialize auth header from localStorage on service load
const token = getToken();
if (token) {
  setAuthHeader(token);
}

export default {
  login,
  logout,
  checkAuth,
  getCurrentUser,
  getToken,
  setAuthHeader,
  hasUserPermission,
  hasUserAllPermissions,
  hasUserAnyPermission,
  getUserRole
}; 