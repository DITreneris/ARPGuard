# Session Management

## Overview

The ARPGuard application implements a robust session management system that allows for secure user authentication, session tracking, and multi-factor authentication (MFA). This document outlines the session management capabilities, API endpoints, and best practices for integrating with the session management system.

## Core Features

- **Secure Authentication**: JWT-based authentication with configurable expiration times
- **Session Tracking**: Monitor active sessions with IP address and user agent information
- **Session Activity Logging**: Comprehensive logs of session activities for security auditing
- **Multi-Factor Authentication (MFA)**: TOTP-based MFA with backup codes
- **Session Revocation**: Ability to terminate suspicious or unwanted sessions
- **Automatic Session Cleanup**: Expired sessions are automatically removed

## Session Lifecycle

1. **Creation**: A new session is created upon successful authentication
2. **Validation**: Sessions are validated on each API request
3. **Activity Updates**: Session activity is updated with each user action
4. **Expiration**: Sessions automatically expire after the configured timeout
5. **Revocation**: Sessions can be manually revoked by users or administrators

## API Endpoints

### Authentication

#### Login

```
POST /api/v1/auth/login
```

**Request Body:**
```json
{
  "username": "user@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "mfa_required": true
}
```

#### Verify MFA

```
POST /api/v1/auth/mfa/verify
```

**Request Body:**
```json
{
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "code": "123456"
}
```

**Response:**
```json
{
  "verified": true,
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
}
```

### Session Management

#### List User Sessions

```
GET /api/v1/auth/sessions
```

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "created_at": "2023-06-01T12:00:00Z",
      "last_activity": "2023-06-01T12:30:00Z",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "status": "active",
      "current": true
    },
    {
      "session_id": "a1b2c3d4-e5f6-4321-a567-0e02b2c3d479",
      "created_at": "2023-05-30T10:00:00Z",
      "last_activity": "2023-05-30T11:00:00Z",
      "ip_address": "192.168.1.101",
      "user_agent": "Mozilla/5.0...",
      "status": "active",
      "current": false
    }
  ]
}
```

#### Revoke Session

```
POST /api/v1/auth/sessions/{session_id}/revoke
```

**Response:**
```json
{
  "success": true,
  "message": "Session revoked successfully"
}
```

#### Get Session Activity

```
GET /api/v1/auth/sessions/{session_id}/activity
```

**Response:**
```json
{
  "activities": [
    {
      "timestamp": "2023-06-01T12:00:00Z",
      "action": "session_created",
      "ip_address": "192.168.1.100"
    },
    {
      "timestamp": "2023-06-01T12:10:00Z",
      "action": "mfa_verified",
      "ip_address": "192.168.1.100"
    },
    {
      "timestamp": "2023-06-01T12:20:00Z",
      "action": "configuration_updated",
      "ip_address": "192.168.1.100"
    }
  ]
}
```

### MFA Management

#### Setup MFA

```
POST /api/v1/auth/mfa/setup
```

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KGgo...",
  "backup_codes": [
    "ABCD1234",
    "EFGH5678",
    ...
  ]
}
```

#### Disable MFA

```
POST /api/v1/auth/mfa/disable
```

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "message": "MFA disabled successfully"
}
```

## Client Integration Examples

### JavaScript Client Example

```javascript
class ARPGuardAuthClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.token = localStorage.getItem('auth_token');
    this.sessionId = localStorage.getItem('session_id');
  }

  async login(username, password) {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      this.token = data.access_token;
      this.sessionId = data.session_id;
      
      localStorage.setItem('auth_token', this.token);
      localStorage.setItem('session_id', this.sessionId);
      
      return {
        success: true,
        mfaRequired: data.mfa_required
      };
    }
    
    return {
      success: false,
      error: data.detail
    };
  }

  async verifyMfa(code) {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/mfa/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify({
        session_id: this.sessionId,
        code
      })
    });
    
    const data = await response.json();
    
    return {
      success: response.ok,
      verified: data.verified
    };
  }

  async getSessions() {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/sessions`, {
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });
    
    const data = await response.json();
    
    return data.sessions;
  }

  async revokeSession(sessionId) {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/sessions/${sessionId}/revoke`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });
    
    return response.ok;
  }

  async setupMfa() {
    const response = await fetch(`${this.baseUrl}/api/v1/auth/mfa/setup`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });
    
    return await response.json();
  }

  async logout() {
    if (this.sessionId) {
      await this.revokeSession(this.sessionId);
    }
    
    localStorage.removeItem('auth_token');
    localStorage.removeItem('session_id');
    
    this.token = null;
    this.sessionId = null;
  }
}
```

## Security Considerations

### Token Security
- Store JWT tokens securely using HTTP-only cookies or secure storage
- Keep token expiration times short (30 minutes recommended)
- Implement token refresh mechanisms for extended sessions

### Session Monitoring
- Monitor for unusual session activities (multiple logins from different locations)
- Implement rate limiting for authentication attempts
- Log failed authentication attempts and suspicious activities

### MFA Best Practices
- Encourage MFA for all users, especially administrators
- Securely store MFA secrets and backup codes
- Provide clear recovery paths for lost MFA devices

## Session Timeout Configuration

The ARPGuard application allows configuring session timeouts to meet your organization's security requirements:

- **Access Token Expiry**: Controls how long the JWT token is valid (default: 30 minutes)
- **Session Inactivity Timeout**: Controls how long a session can be inactive before requiring re-authentication (default: 1 hour)
- **Session Maximum Duration**: Controls the maximum lifetime of a session regardless of activity (default: 7 days)

These settings can be configured in the application settings or environment variables.

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check username and password
   - Verify that the account is not locked or disabled

2. **MFA Issues**
   - Ensure device time is synchronized
   - Try using backup codes if TOTP fails

3. **Session Not Found**
   - Session may have expired
   - Session may have been revoked from another device

4. **Multiple Sessions Warning**
   - User may be logged in from multiple devices
   - Check for unauthorized access

## Conclusion

The ARPGuard session management system provides a secure and flexible authentication framework. By following the guidelines in this document, you can ensure that your implementation is both secure and user-friendly. 