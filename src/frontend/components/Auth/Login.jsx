import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { login, isAuthenticated } from '../../services/AnalyticsService';
import './Login.css';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // Check if user is already authenticated, redirect if so
  useEffect(() => {
    if (isAuthenticated()) {
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    }
  }, [navigate, location]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validate inputs
    if (!username.trim() || !password.trim()) {
      setError('Username and password are required');
      return;
    }
    
    try {
      setLoading(true);
      setError('');
      
      // Call login service
      await login(username, password);
      
      // Redirect to dashboard or original destination
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
      
    } catch (err) {
      console.error('Login error:', err);
      setError(
        err.response?.data?.error || 
        'Login failed. Please check your credentials and try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h2>ARP Guard Analytics</h2>
          <p>Sign in to access the dashboard</p>
        </div>
        
        {error && (
          <div className="login-error">
            {error}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              disabled={loading}
              autoFocus
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              disabled={loading}
            />
          </div>
          
          <button 
            type="submit" 
            className="login-button"
            disabled={loading}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        
        <div className="login-footer">
          <p>Demo credentials: admin / admin</p>
          <p className="version-info">ARP Guard Analytics v2.1.0</p>
        </div>
      </div>
    </div>
  );
};

export default Login; 