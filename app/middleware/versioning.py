from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Dict, List, Tuple, Optional, Set, Callable
import re
import json
import yaml
from datetime import datetime, timedelta
import os
from pathlib import Path

# Version related constants
CURRENT_API_VERSION = "1.0.0"
SUPPORTED_VERSIONS = ["0.9.0", "1.0.0"]
DEPRECATED_VERSIONS = ["0.9.0"]
SUNSET_DATES = {
    "0.9.0": (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
}

# Migration paths define how to migrate from one version to another
# Each entry is a tuple of (from_version, to_version, migration_function)
VERSION_MIGRATIONS = []

# Path to store version migration configurations
MIGRATIONS_DIR = Path("app/middleware/migrations")


class VersionError(Exception):
    """Exception raised for version-related errors."""
    pass


def extract_version_from_accept(accept_header: str) -> Optional[str]:
    """Extract API version from Accept header."""
    if not accept_header:
        return None
    
    version_match = re.search(r'version=(\d+\.\d+(?:\.\d+)?)', accept_header)
    if version_match:
        return version_match.group(1)
    return None


def extract_version_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """Extract API version from headers."""
    # Try X-API-Version header first
    if "x-api-version" in headers:
        return headers["x-api-version"]
    
    # Then try Accept header with version parameter
    if "accept" in headers:
        version = extract_version_from_accept(headers["accept"])
        if version:
            return version
    
    return None


def get_highest_accepted_version(accept_header: str) -> Optional[str]:
    """Get highest accepted version based on quality values."""
    if not accept_header:
        return None
    
    version_pattern = r'version=(\d+\.\d+(?:\.\d+)?);?\s*(?:q=(\d+\.\d+))?'
    versions = re.findall(version_pattern, accept_header)
    
    if not versions:
        return None
    
    # Sort by quality value (default to 1.0 if not specified)
    versions_with_q = [(v, float(q) if q else 1.0) for v, q in versions]
    versions_with_q.sort(key=lambda x: x[1], reverse=True)
    
    # Return highest quality version that is supported
    for version, _ in versions_with_q:
        if version in SUPPORTED_VERSIONS:
            return version
    
    return None


class APIVersionMiddleware(BaseHTTPMiddleware):
    """Middleware to handle API versioning and migrations."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self._load_migrations()
    
    def _load_migrations(self):
        """Load migration configurations from files."""
        global VERSION_MIGRATIONS
        
        if not MIGRATIONS_DIR.exists():
            MIGRATIONS_DIR.mkdir(parents=True, exist_ok=True)
            return
        
        for migration_file in MIGRATIONS_DIR.glob("*.yaml"):
            try:
                with open(migration_file, "r") as f:
                    migration_config = yaml.safe_load(f)
                
                from_version = migration_config.get("from_version")
                to_version = migration_config.get("to_version")
                
                if not from_version or not to_version:
                    continue
                
                migration_function = self._create_migration_function(migration_config)
                VERSION_MIGRATIONS.append((from_version, to_version, migration_function))
            except Exception as e:
                print(f"Error loading migration file {migration_file}: {e}")
    
    def _create_migration_function(self, config: Dict) -> Callable:
        """Create a migration function from configuration."""
        transforms = config.get("transforms", [])
        
        def migration_function(data: Dict) -> Dict:
            result = data.copy()
            
            for transform in transforms:
                transform_type = transform.get("type")
                
                if transform_type == "rename_field":
                    old_path = transform.get("old_path")
                    new_path = transform.get("new_path")
                    if old_path and new_path:
                        self._rename_field(result, old_path, new_path)
                
                elif transform_type == "convert_type":
                    path = transform.get("path")
                    to_type = transform.get("to_type")
                    if path and to_type:
                        self._convert_type(result, path, to_type)
                
                elif transform_type == "add_field":
                    path = transform.get("path")
                    value = transform.get("value")
                    if path:
                        self._add_field(result, path, value)
                
                elif transform_type == "remove_field":
                    path = transform.get("path")
                    if path:
                        self._remove_field(result, path)
                
                elif transform_type == "map_value":
                    path = transform.get("path")
                    mapping = transform.get("mapping", {})
                    if path and mapping:
                        self._map_value(result, path, mapping)
            
            return result
        
        return migration_function
    
    def _get_nested_value(self, data: Dict, path: str) -> Optional[any]:
        """Get a nested value from a dictionary using dot notation."""
        keys = path.split(".")
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def _set_nested_value(self, data: Dict, path: str, value: any) -> None:
        """Set a nested value in a dictionary using dot notation."""
        keys = path.split(".")
        current = data
        
        for i, key in enumerate(keys[:-1]):
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _remove_nested_value(self, data: Dict, path: str) -> None:
        """Remove a nested value from a dictionary using dot notation."""
        keys = path.split(".")
        current = data
        
        for i, key in enumerate(keys[:-1]):
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return
        
        if keys[-1] in current:
            del current[keys[-1]]
    
    def _rename_field(self, data: Dict, old_path: str, new_path: str) -> None:
        """Rename a field in the data."""
        value = self._get_nested_value(data, old_path)
        if value is not None:
            self._set_nested_value(data, new_path, value)
            self._remove_nested_value(data, old_path)
    
    def _convert_type(self, data: Dict, path: str, to_type: str) -> None:
        """Convert a field to a different type."""
        value = self._get_nested_value(data, path)
        if value is not None:
            if to_type == "string":
                self._set_nested_value(data, path, str(value))
            elif to_type == "integer":
                try:
                    self._set_nested_value(data, path, int(value))
                except (ValueError, TypeError):
                    pass
            elif to_type == "float":
                try:
                    self._set_nested_value(data, path, float(value))
                except (ValueError, TypeError):
                    pass
            elif to_type == "boolean":
                if isinstance(value, str):
                    self._set_nested_value(data, path, value.lower() == "true")
                else:
                    self._set_nested_value(data, path, bool(value))
            elif to_type == "array" and not isinstance(value, list):
                self._set_nested_value(data, path, [value])
    
    def _add_field(self, data: Dict, path: str, value: any) -> None:
        """Add a field to the data."""
        self._set_nested_value(data, path, value)
    
    def _remove_field(self, data: Dict, path: str) -> None:
        """Remove a field from the data."""
        self._remove_nested_value(data, path)
    
    def _map_value(self, data: Dict, path: str, mapping: Dict) -> None:
        """Map a value based on a mapping dictionary."""
        value = self._get_nested_value(data, path)
        if value is not None and str(value) in mapping:
            self._set_nested_value(data, path, mapping[str(value)])
    
    def find_migration_path(
        self, from_version: str, to_version: str
    ) -> List[Tuple[str, str, Callable]]:
        """Find a migration path from one version to another."""
        if from_version == to_version:
            return []
        
        # Simple direct migration
        for v_from, v_to, func in VERSION_MIGRATIONS:
            if v_from == from_version and v_to == to_version:
                return [(v_from, v_to, func)]
        
        # TODO: Implement more complex path finding if needed
        return []
    
    def migrate_data(self, data: Dict, from_version: str, to_version: str) -> Dict:
        """Migrate data from one version to another."""
        if from_version == to_version:
            return data
        
        migration_path = self.find_migration_path(from_version, to_version)
        if not migration_path:
            raise VersionError(f"No migration path from {from_version} to {to_version}")
        
        result = data
        for v_from, v_to, func in migration_path:
            result = func(result)
        
        return result
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Process the request and handle versioning."""
        # Extract version from request
        requested_version = extract_version_from_headers(dict(request.headers))
        
        # If no version specified, use current version
        if not requested_version:
            requested_version = CURRENT_API_VERSION
        
        # Check if version is supported
        if requested_version not in SUPPORTED_VERSIONS:
            return Response(
                content=json.dumps({
                    "error": "Unsupported API version",
                    "current_version": CURRENT_API_VERSION,
                    "supported_versions": SUPPORTED_VERSIONS
                }),
                status_code=400,
                media_type="application/json"
            )
        
        # Set request state for access in endpoints
        request.state.api_version = requested_version
        
        # Get path to check for deprecated endpoints
        path = request.url.path
        
        # Check for deprecated version endpoints (v0)
        if "/api/v0/" in path and requested_version in DEPRECATED_VERSIONS:
            sunset_date = SUNSET_DATES.get(requested_version, "")
            return Response(
                content=json.dumps({
                    "error": "This API version is deprecated",
                    "sunset_date": sunset_date,
                    "current_version": CURRENT_API_VERSION
                }),
                status_code=410,
                headers={
                    "X-API-Deprecated": "true",
                    "X-API-Sunset-Date": sunset_date
                },
                media_type="application/json"
            )
        
        # Process the request
        response = await call_next(request)
        
        # Add version headers to response
        response.headers["X-API-Version"] = requested_version
        
        # Add deprecation warning if using deprecated version
        if requested_version in DEPRECATED_VERSIONS:
            sunset_date = SUNSET_DATES.get(requested_version, "")
            response.headers["X-API-Deprecation-Warning"] = (
                f"API version {requested_version} is deprecated and will be "
                f"removed after {sunset_date}. Please migrate to version {CURRENT_API_VERSION}."
            )
        
        return response


# Helper function to register a new migration
def register_migration(
    from_version: str, to_version: str, migration_config: Dict
) -> None:
    """Register a new migration between API versions."""
    # Create migrations directory if it doesn't exist
    MIGRATIONS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save migration config to file
    file_path = MIGRATIONS_DIR / f"migrate_{from_version}_to_{to_version}.yaml"
    
    # Add metadata
    migration_config.update({
        "from_version": from_version,
        "to_version": to_version,
        "created_at": datetime.now().isoformat()
    })
    
    with open(file_path, "w") as f:
        yaml.dump(migration_config, f, default_flow_style=False)
    
    print(f"Migration from {from_version} to {to_version} registered") 