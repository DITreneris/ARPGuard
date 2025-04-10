from typing import Dict, Any, Optional, Callable, TypeVar, List
import functools
from fastapi import Request, Depends, HTTPException, status

# Type variables for type hinting
T = TypeVar('T')
ResponseT = TypeVar('ResponseT')

# Version compatibility functions
def get_api_version(request: Request) -> str:
    """Get the API version from the request."""
    return getattr(request.state, "api_version", "1.0.0")

def requires_version(min_version: str, max_version: Optional[str] = None):
    """
    Dependency to check if the request's API version is within the required range.
    
    Args:
        min_version: Minimum API version required (inclusive)
        max_version: Maximum API version allowed (inclusive), or None for no upper limit
    
    Returns:
        Dependency function that validates the API version
    """
    def validate_version(request: Request) -> str:
        version = get_api_version(request)
        
        # Simple version comparison for now - assumes format like "1.0.0"
        if version_to_tuple(version) < version_to_tuple(min_version):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API version {version} is too old. Minimum required: {min_version}"
            )
        
        if max_version and version_to_tuple(version) > version_to_tuple(max_version):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API version {version} is too new. Maximum supported: {max_version}"
            )
        
        return version
    
    return validate_version

def version_to_tuple(version: str) -> tuple:
    """Convert a version string to a tuple for comparison."""
    return tuple(int(x) for x in version.split('.'))

def versioned_response(
    request: Request,
    response_data: Dict[str, Any],
    transformers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Transform the response data based on the requested API version.
    
    Args:
        request: The FastAPI request object
        response_data: The original response data
        transformers: A dictionary mapping version strings to transformation functions
    
    Returns:
        The transformed response data
    """
    version = get_api_version(request)
    
    if not transformers or version not in transformers:
        return response_data
    
    transformer = transformers[version]
    return transformer(response_data)

def deprecated_since(version: str, use_instead: Optional[str] = None):
    """
    Decorator to mark an endpoint as deprecated since a specific version.
    
    Args:
        version: The API version since which this endpoint is deprecated
        use_instead: Alternative endpoint to use, if any
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the request object
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                for _, value in kwargs.items():
                    if isinstance(value, Request):
                        request = value
                        break
            
            # Get current API version
            current_version = get_api_version(request) if request else "1.0.0"
            
            # Execute the function
            result = await func(*args, **kwargs)
            
            # If response is a Response object, add deprecation headers
            if hasattr(result, "headers"):
                result.headers["X-API-Deprecated-Since"] = version
                if use_instead:
                    result.headers["X-API-Alternative"] = use_instead
            
            return result
        
        return wrapper
    
    return decorator

def migrate_request_data(
    request_data: Dict[str, Any],
    from_version: str,
    to_version: str,
    migrations: Dict[str, List[Callable[[Dict[str, Any]], Dict[str, Any]]]]
) -> Dict[str, Any]:
    """
    Migrate request data from one version to another.
    
    Args:
        request_data: The original request data
        from_version: Source version
        to_version: Target version
        migrations: Dictionary mapping version pairs to lists of migration functions
    
    Returns:
        The migrated request data
    """
    key = f"{from_version}_to_{to_version}"
    
    if key not in migrations:
        # No direct migration path, try to find a chain
        # (This is a simplified approach; a real implementation might use a graph)
        return request_data
    
    result = request_data.copy()
    for migration_func in migrations[key]:
        result = migration_func(result)
    
    return result

# Example usage in an endpoint:
"""
@app.get("/api/v1/some_endpoint")
async def get_some_data(
    request: Request,
    version: str = Depends(requires_version("0.9.0", "1.0.0"))
):
    # Process request
    data = {"result": "some data"}
    
    # Transform response based on version
    return versioned_response(
        request,
        data,
        {
            "0.9.0": lambda d: {"data": d["result"], "version": "0.9.0"},
            "1.0.0": lambda d: {"result": d["result"], "api_version": "1.0.0"}
        }
    )
""" 