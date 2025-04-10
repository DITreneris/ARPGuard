/**
 * Analytics Service
 * Provides functions to interact with the analytics API endpoints
 */

import axios from 'axios';

const API_BASE_URL = '/api/analytics';
const AUTH_BASE_URL = '/api/auth';

// Create axios instance with interceptors for authentication
const axiosInstance = axios.create({
  baseURL: '/',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add request interceptor to include authentication token
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Add response interceptor to handle authentication errors
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    // If unauthorized, redirect to login
    if (error.response && error.response.status === 401) {
      // Clear token and redirect to login page
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

/**
 * Login user and store authentication token
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @returns {Promise} Promise resolving to authentication result
 */
export const login = async (username, password) => {
  try {
    const response = await axios.post(`${AUTH_BASE_URL}/login`, { username, password });
    
    // Store token in localStorage
    if (response.data.access_token) {
      localStorage.setItem('auth_token', response.data.access_token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    
    return response.data;
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
};

/**
 * Logout user and clear authentication data
 * @returns {Promise} Promise resolving to logout result
 */
export const logout = async () => {
  try {
    // Call logout endpoint
    await axiosInstance.post(`${AUTH_BASE_URL}/logout`);
    
    // Clear local storage
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    
    return { success: true };
  } catch (error) {
    console.error('Logout failed:', error);
    // Still clear token even if server call fails
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user');
    throw error;
  }
};

/**
 * Check if user is currently authenticated
 * @returns {boolean} True if user is authenticated
 */
export const isAuthenticated = () => {
  const token = localStorage.getItem('auth_token');
  return !!token;
};

/**
 * Get current user data
 * @returns {Object|null} User data or null if not authenticated
 */
export const getCurrentUser = () => {
  try {
    const userJson = localStorage.getItem('user');
    return userJson ? JSON.parse(userJson) : null;
  } catch (error) {
    console.error('Error getting current user:', error);
    return null;
  }
};

/**
 * Verify token validity
 * @returns {Promise} Promise resolving to token verification result
 */
export const verifyToken = async () => {
  try {
    const response = await axiosInstance.get(`${AUTH_BASE_URL}/verify`);
    return response.data;
  } catch (error) {
    console.error('Token verification failed:', error);
    throw error;
  }
};

/**
 * Get user permissions
 * @returns {Promise} Promise resolving to user permissions
 */
export const getUserPermissions = async () => {
  try {
    const response = await axiosInstance.get(`${AUTH_BASE_URL}/permissions`);
    return response.data.permissions || [];
  } catch (error) {
    console.error('Error fetching permissions:', error);
    return [];
  }
};

/**
 * Check if user has a specific permission
 * @param {string} permission - Permission to check
 * @returns {Promise<boolean>} Promise resolving to true if user has permission
 */
export const hasPermission = async (permission) => {
  try {
    const permissions = await getUserPermissions();
    return permissions.includes(permission);
  } catch (error) {
    console.error('Error checking permission:', error);
    return false;
  }
};

/**
 * Fetches dashboard data for the specified time period
 * @param {string} period - Time period for data (today, week, month, custom)
 * @param {Object} dateRange - Optional date range for custom period
 * @returns {Promise} Promise resolving to dashboard data
 */
export const fetchDashboardData = async (period = 'week', dateRange = null) => {
  try {
    const params = { period };
    
    // Add date range params for custom period
    if (period === 'custom' && dateRange) {
      params.startDate = dateRange.startDate;
      params.endDate = dateRange.endDate;
    }
    
    const response = await axiosInstance.get(`/api/dashboard`, { params });
    return response.data;
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    throw error;
  }
};

/**
 * Export dashboard data as CSV
 * @param {string} period - Time period for data
 * @param {Object} dateRange - Optional date range for custom period
 * @returns {Promise} Promise resolving to CSV data
 */
export const exportDashboardCSV = async (period = 'week', dateRange = null) => {
  try {
    const params = { period, format: 'csv' };
    
    if (period === 'custom' && dateRange) {
      params.startDate = dateRange.startDate;
      params.endDate = dateRange.endDate;
    }
    
    const response = await axiosInstance.get('/api/export/csv', { 
      params,
      responseType: 'blob'
    });
    
    return response.data;
  } catch (error) {
    console.error('Error exporting CSV:', error);
    throw error;
  }
};

/**
 * Export dashboard data as JSON
 * @param {string} period - Time period for data
 * @param {Object} dateRange - Optional date range for custom period
 * @returns {Promise} Promise resolving to JSON data
 */
export const exportDashboardJSON = async (period = 'week', dateRange = null) => {
  try {
    const params = { period, format: 'json' };
    
    if (period === 'custom' && dateRange) {
      params.startDate = dateRange.startDate;
      params.endDate = dateRange.endDate;
    }
    
    const response = await axiosInstance.get('/api/export/json', { 
      params,
      responseType: 'blob'
    });
    
    return response.data;
  } catch (error) {
    console.error('Error exporting JSON:', error);
    throw error;
  }
};

/**
 * Downloads a blob as a file
 * @param {Blob} blob - File data
 * @param {string} filename - Name for the downloaded file
 */
export const downloadFile = (blob, filename) => {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
};

/**
 * Get system performance metrics
 * @returns {Promise} Promise resolving to system performance data
 */
export const getSystemPerformance = async () => {
  try {
    const response = await axiosInstance.get('/api/system/performance');
    return response.data;
  } catch (error) {
    console.error('Error fetching system performance:', error);
    throw error;
  }
};

/**
 * Fetches detailed alert history with optional filters
 * @param {Object} filters - Filter options
 * @param {string} filters.period - Time period ('1h', '24h', '7d', '30d')
 * @param {string} filters.severity - Alert severity level
 * @param {number} filters.page - Page number for pagination
 * @param {number} filters.limit - Number of results per page
 * @returns {Promise<Object>} Alert history with pagination metadata
 */
export const fetchAlertHistory = async (filters = {}) => {
  try {
    const queryParams = new URLSearchParams();
    
    if (filters.period) queryParams.append('period', filters.period);
    if (filters.severity) queryParams.append('severity', filters.severity);
    if (filters.page) queryParams.append('page', filters.page);
    if (filters.limit) queryParams.append('limit', filters.limit || 10);
    
    const response = await fetch(`${API_BASE_URL}/analytics/alerts?${queryParams.toString()}`);
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Failed to fetch alert history: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching alert history:', error);
    throw error;
  }
};

/**
 * Fetches network activity metrics
 * @param {string} period - Time period for data ('1h', '24h', '7d', '30d')
 * @returns {Promise<Object>} Network activity data
 */
export const fetchNetworkActivity = async (period = '24h') => {
  try {
    const response = await fetch(`${API_BASE_URL}/analytics/network?period=${period}`);
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Failed to fetch network activity: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching network activity:', error);
    throw error;
  }
};

/**
 * Fetches alert details by ID
 * @param {string} alertId - Alert identifier
 * @returns {Promise<Object>} Detailed alert information
 */
export const fetchAlertDetails = async (alertId) => {
  try {
    const response = await fetch(`${API_BASE_URL}/analytics/alerts/${alertId}`);
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Failed to fetch alert details: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching alert details:', error);
    throw error;
  }
}; 