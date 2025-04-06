from typing import Dict, List, Set
from enum import Enum
from dataclasses import dataclass
from app.utils.logger import get_logger

# Module logger
logger = get_logger('components.rbac')

class Role(Enum):
    """User roles in the system."""
    ADMIN = 'admin'
    OPERATOR = 'operator'
    VIEWER = 'viewer'

class Permission(Enum):
    """Available permissions in the system."""
    # Site management
    MANAGE_SITES = 'manage_sites'
    VIEW_SITES = 'view_sites'
    
    # Network operations
    SCAN_NETWORK = 'scan_network'
    START_DETECTION = 'start_detection'
    STOP_DETECTION = 'stop_detection'
    START_SPOOFING = 'start_spoofing'
    STOP_SPOOFING = 'stop_spoofing'
    
    # Configuration
    MANAGE_CONFIG = 'manage_config'
    VIEW_CONFIG = 'view_config'
    
    # Reports
    GENERATE_REPORTS = 'generate_reports'
    VIEW_REPORTS = 'view_reports'

@dataclass
class User:
    """User information."""
    username: str
    role: Role
    sites: List[str]  # List of site IDs the user has access to

class RBAC:
    """Role-Based Access Control system."""
    
    # Role to permissions mapping
    ROLE_PERMISSIONS = {
        Role.ADMIN: {
            Permission.MANAGE_SITES,
            Permission.VIEW_SITES,
            Permission.SCAN_NETWORK,
            Permission.START_DETECTION,
            Permission.STOP_DETECTION,
            Permission.START_SPOOFING,
            Permission.STOP_SPOOFING,
            Permission.MANAGE_CONFIG,
            Permission.VIEW_CONFIG,
            Permission.GENERATE_REPORTS,
            Permission.VIEW_REPORTS
        },
        Role.OPERATOR: {
            Permission.VIEW_SITES,
            Permission.SCAN_NETWORK,
            Permission.START_DETECTION,
            Permission.STOP_DETECTION,
            Permission.VIEW_CONFIG,
            Permission.GENERATE_REPORTS,
            Permission.VIEW_REPORTS
        },
        Role.VIEWER: {
            Permission.VIEW_SITES,
            Permission.VIEW_CONFIG,
            Permission.VIEW_REPORTS
        }
    }
    
    def __init__(self):
        """Initialize the RBAC system."""
        self.users: Dict[str, User] = {}
        self._load_default_users()
    
    def _load_default_users(self):
        """Load default users into the system."""
        # Create default admin user
        self.add_user('admin', Role.ADMIN, ['*'])  # '*' means access to all sites
    
    def add_user(self, username: str, role: Role, sites: List[str]) -> bool:
        """Add a new user to the system.
        
        Args:
            username: Username
            role: User role
            sites: List of site IDs the user has access to
            
        Returns:
            bool: True if user was added successfully
        """
        if username in self.users:
            logger.warning(f"User {username} already exists")
            return False
        
        self.users[username] = User(username, role, sites)
        logger.info(f"Added user {username} with role {role.value}")
        return True
    
    def remove_user(self, username: str) -> bool:
        """Remove a user from the system.
        
        Args:
            username: Username to remove
            
        Returns:
            bool: True if user was removed successfully
        """
        if username not in self.users:
            logger.warning(f"User {username} does not exist")
            return False
        
        del self.users[username]
        logger.info(f"Removed user {username}")
        return True
    
    def update_user_role(self, username: str, role: Role) -> bool:
        """Update a user's role.
        
        Args:
            username: Username
            role: New role
            
        Returns:
            bool: True if role was updated successfully
        """
        if username not in self.users:
            logger.warning(f"User {username} does not exist")
            return False
        
        self.users[username].role = role
        logger.info(f"Updated user {username} role to {role.value}")
        return True
    
    def update_user_sites(self, username: str, sites: List[str]) -> bool:
        """Update a user's site access.
        
        Args:
            username: Username
            sites: New list of site IDs
            
        Returns:
            bool: True if sites were updated successfully
        """
        if username not in self.users:
            logger.warning(f"User {username} does not exist")
            return False
        
        self.users[username].sites = sites
        logger.info(f"Updated user {username} site access")
        return True
    
    def has_permission(self, username: str, permission: Permission, site_id: str = None) -> bool:
        """Check if a user has a specific permission.
        
        Args:
            username: Username
            permission: Permission to check
            site_id: Optional site ID to check access for
            
        Returns:
            bool: True if user has the permission
        """
        if username not in self.users:
            logger.warning(f"User {username} does not exist")
            return False
        
        user = self.users[username]
        
        # Check if user has access to the site
        if site_id and '*' not in user.sites and site_id not in user.sites:
            logger.warning(f"User {username} does not have access to site {site_id}")
            return False
        
        # Check if user's role has the permission
        has_perm = permission in self.ROLE_PERMISSIONS[user.role]
        
        if not has_perm:
            logger.warning(f"User {username} does not have permission {permission.value}")
        
        return has_perm
    
    def get_user_permissions(self, username: str) -> Set[Permission]:
        """Get all permissions for a user.
        
        Args:
            username: Username
            
        Returns:
            Set[Permission]: Set of permissions the user has
        """
        if username not in self.users:
            logger.warning(f"User {username} does not exist")
            return set()
        
        return self.ROLE_PERMISSIONS[self.users[username].role]
    
    def get_user_sites(self, username: str) -> List[str]:
        """Get all sites a user has access to.
        
        Args:
            username: Username
            
        Returns:
            List[str]: List of site IDs
        """
        if username not in self.users:
            logger.warning(f"User {username} does not exist")
            return []
        
        return self.users[username].sites 