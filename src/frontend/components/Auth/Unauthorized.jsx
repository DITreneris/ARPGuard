import React from 'react';
import { useNavigate } from 'react-router-dom';
import { getUserRole } from '../../services/AuthService';
import './Unauthorized.css';

/**
 * Unauthorized Component
 * Displays when a user tries to access a route they don't have permission for
 */
const Unauthorized = () => {
  const navigate = useNavigate();
  const userRole = getUserRole();

  const handleGoBack = () => {
    navigate(-1);
  };

  const handleGoToDashboard = () => {
    navigate('/dashboard');
  };

  return (
    <div className="unauthorized-container">
      <div className="unauthorized-card">
        <div className="unauthorized-icon">
          <i className="fas fa-lock"></i>
        </div>
        
        <h1>Access Denied</h1>
        
        <p className="unauthorized-message">
          You don't have permission to access this page.
        </p>
        
        {userRole && (
          <p className="unauthorized-role">
            Your current role is: <strong>{userRole}</strong>
          </p>
        )}
        
        <div className="unauthorized-actions">
          <button 
            className="unauthorized-button back"
            onClick={handleGoBack}
          >
            Go Back
          </button>
          
          <button 
            className="unauthorized-button dashboard"
            onClick={handleGoToDashboard}
          >
            Go to Dashboard
          </button>
        </div>
        
        <p className="unauthorized-help">
          If you believe you should have access to this page, 
          please contact your system administrator.
        </p>
      </div>
    </div>
  );
};

export default Unauthorized; 