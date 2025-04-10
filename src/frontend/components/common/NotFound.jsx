import React from 'react';
import { Link } from 'react-router-dom';
import './NotFound.css';

/**
 * 404 Not Found component
 * Displayed when a route doesn't match any defined routes
 */
const NotFound = () => {
  return (
    <div className="not-found-container">
      <div className="not-found-content">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you are looking for doesn't exist or has been moved.</p>
        <div className="not-found-actions">
          <Link to="/dashboard" className="back-home-button">
            Back to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
};

export default NotFound; 