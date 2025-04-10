import React, { useState, useEffect } from 'react';
import { getUserRole, hasUserPermission } from '../../services/AuthService';
import { PERMISSIONS, ROLES } from '../../services/RoleService';
import './UserManagement.css';

/**
 * UserManagement Component
 * Allows administrators to manage users and their roles
 */
const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [newUser, setNewUser] = useState({ username: '', email: '', role: ROLES.VIEWER });
  const currentUserRole = getUserRole();
  const canManageUsers = hasUserPermission(PERMISSIONS.USERS_MANAGE);

  // Mock data for demonstration
  const mockUsers = [
    { id: 1, username: 'admin', email: 'admin@arpguard.com', role: ROLES.ADMIN, lastLogin: '2023-08-15T14:22:31Z' },
    { id: 2, username: 'operator1', email: 'operator1@arpguard.com', role: ROLES.OPERATOR, lastLogin: '2023-08-14T09:45:12Z' },
    { id: 3, username: 'viewer1', email: 'viewer1@arpguard.com', role: ROLES.VIEWER, lastLogin: '2023-08-10T16:30:45Z' },
    { id: 4, username: 'analyst', email: 'analyst@arpguard.com', role: ROLES.OPERATOR, lastLogin: '2023-08-12T11:15:22Z' },
    { id: 5, username: 'guest', email: 'guest@arpguard.com', role: ROLES.VIEWER, lastLogin: '2023-08-01T08:20:10Z' },
  ];

  useEffect(() => {
    // Simulate API call
    const fetchUsers = async () => {
      try {
        setLoading(true);
        // In a real app, this would be an API call
        // const response = await axios.get('/api/users');
        // setUsers(response.data);
        
        // Using mock data for demonstration
        setTimeout(() => {
          setUsers(mockUsers);
          setLoading(false);
        }, 800);
      } catch (err) {
        setError('Failed to load users. Please try again.');
        setLoading(false);
      }
    };

    fetchUsers();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewUser(prev => ({ ...prev, [name]: value }));
  };

  const handleAddUser = (e) => {
    e.preventDefault();
    if (!newUser.username || !newUser.email) {
      setError('Username and email are required');
      return;
    }

    // In a real app, this would be an API call
    // axios.post('/api/users', newUser)
    //   .then(response => {
    //     setUsers(prev => [...prev, response.data]);
    //     setNewUser({ username: '', email: '', role: ROLES.VIEWER });
    //   })
    //   .catch(err => setError('Failed to add user'));

    // For demonstration
    const id = users.length + 1;
    const newUserWithId = { 
      ...newUser, 
      id, 
      lastLogin: 'Never' 
    };
    
    setUsers(prev => [...prev, newUserWithId]);
    setNewUser({ username: '', email: '', role: ROLES.VIEWER });
    setError(null);
  };

  const handleDeleteUser = (userId) => {
    // In a real app, this would be an API call
    // axios.delete(`/api/users/${userId}`)
    //   .then(() => {
    //     setUsers(prev => prev.filter(user => user.id !== userId));
    //   })
    //   .catch(err => setError('Failed to delete user'));

    // For demonstration
    setUsers(prev => prev.filter(user => user.id !== userId));
  };

  const handleChangeRole = (userId, newRole) => {
    // In a real app, this would be an API call
    // axios.patch(`/api/users/${userId}`, { role: newRole })
    //   .then(response => {
    //     setUsers(prev => prev.map(user => 
    //       user.id === userId ? { ...user, role: newRole } : user
    //     ));
    //   })
    //   .catch(err => setError('Failed to update user role'));

    // For demonstration
    setUsers(prev => prev.map(user => 
      user.id === userId ? { ...user, role: newRole } : user
    ));
  };

  if (loading) {
    return <div className="loading">Loading users...</div>;
  }

  return (
    <div className="user-management">
      <h1>User Management</h1>
      
      {error && <div className="error-message">{error}</div>}
      
      {canManageUsers && (
        <div className="add-user-form">
          <h2>Add New User</h2>
          <form onSubmit={handleAddUser}>
            <div className="form-group">
              <label htmlFor="username">Username</label>
              <input
                type="text"
                id="username"
                name="username"
                value={newUser.username}
                onChange={handleInputChange}
                placeholder="Enter username"
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="email">Email</label>
              <input
                type="email"
                id="email"
                name="email"
                value={newUser.email}
                onChange={handleInputChange}
                placeholder="Enter email"
              />
            </div>
            
            <div className="form-group">
              <label htmlFor="role">Role</label>
              <select
                id="role"
                name="role"
                value={newUser.role}
                onChange={handleInputChange}
              >
                <option value={ROLES.ADMIN}>Admin</option>
                <option value={ROLES.OPERATOR}>Operator</option>
                <option value={ROLES.VIEWER}>Viewer</option>
              </select>
            </div>
            
            <button type="submit" className="add-user-button">
              Add User
            </button>
          </form>
        </div>
      )}
      
      <div className="users-table-container">
        <h2>Current Users</h2>
        <table className="users-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Last Login</th>
              {canManageUsers && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id}>
                <td>{user.username}</td>
                <td>{user.email}</td>
                <td>
                  {canManageUsers ? (
                    <select
                      value={user.role}
                      onChange={(e) => handleChangeRole(user.id, e.target.value)}
                      disabled={user.username === 'admin'} // Prevent changing admin role
                    >
                      <option value={ROLES.ADMIN}>Admin</option>
                      <option value={ROLES.OPERATOR}>Operator</option>
                      <option value={ROLES.VIEWER}>Viewer</option>
                    </select>
                  ) : (
                    <span className={`role-badge ${user.role}`}>
                      {user.role}
                    </span>
                  )}
                </td>
                <td>{new Date(user.lastLogin).toLocaleString()}</td>
                {canManageUsers && (
                  <td>
                    <button
                      className="delete-button"
                      onClick={() => handleDeleteUser(user.id)}
                      disabled={user.username === 'admin' || user.username === currentUserRole} // Can't delete self or admin
                    >
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default UserManagement; 