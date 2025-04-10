import React from 'react';
import './Spinner.css';

/**
 * Loading spinner component
 * @param {Object} props - Component props
 * @param {string} [props.size='medium'] - Size of the spinner (small, medium, large)
 * @returns {React.ReactNode} Rendered component
 */
const Spinner = ({ size = 'medium' }) => {
  return (
    <div className={`spinner spinner-${size}`}>
      <div className="spinner-circle"></div>
    </div>
  );
};

export default Spinner; 