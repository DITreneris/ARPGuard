# Access Control System Documentation

## Overview
The access control system implements a role-based access control (RBAC) model with JWT-based authentication. It provides granular control over user permissions and secure access to system resources.

## Components

### 1. Role Service
Located in `src/frontend/services/RoleService.js`
- Defines available roles: Admin, Viewer, Operator
- Maps roles to specific permissions
- Provides permission checking utilities

### 2. Authentication Service
Located in `src/frontend/services/AuthService.js`
- Handles JWT token management
- Manages user sessions
- Integrates with RoleService for permission validation

### 3. Protected Route Component
Located in `src/frontend/components/ProtectedRoute.jsx`
- Wraps protected routes
- Validates user permissions
- Handles unauthorized access

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user info

### User Management
- `GET /api/users` - List users (Admin only)
- `POST /api/users` - Create user (Admin only)
- `PUT /api/users/{id}` - Update user (Admin only)
- `DELETE /api/users/{id}` - Delete user (Admin only)

## Permission Levels

### Admin
- Full system access
- User management
- System configuration
- License management

### Operator
- Network monitoring
- Device management
- Alert handling
- Limited configuration access

### Viewer
- Read-only access
- View dashboards
- View reports
- No configuration access

## Implementation Details

### JWT Token Structure
```json
{
  "sub": "user_id",
  "roles": ["role1", "role2"],
  "permissions": ["permission1", "permission2"],
  "exp": "expiration_timestamp"
}
```

### Permission Checking
```javascript
// Example permission check
if (hasPermission('network:monitor')) {
  // Allow access to network monitoring
}
```

## Security Considerations
- Tokens expire after 24 hours
- Refresh tokens available for extended sessions
- All sensitive endpoints require authentication
- Role-based access control enforced at API level
- Session management includes automatic logout 