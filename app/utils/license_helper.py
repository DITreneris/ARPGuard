"""
License key generation and validation utilities.
"""
import uuid
import hmac
import hashlib
import random
import string
import time
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional, List

from app.config import settings

# License key format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
LICENSE_KEY_PATTERN = r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$'

def generate_license_key(org_name: str, license_type: str = "standard", expiry_days: int = 365) -> Dict[str, Any]:
    """
    Generate a new license key with metadata.
    
    Args:
        org_name: Organization name for the license
        license_type: Type of license (standard, professional, enterprise)
        expiry_days: Number of days until license expires
    
    Returns:
        Dictionary containing license key and metadata
    """
    # Create a unique identifier
    uid = uuid.uuid4().hex
    
    # Add a timestamp
    timestamp = int(time.time())
    
    # Generate a seed based on org name, uid, and timestamp
    seed = f"{org_name}:{uid}:{timestamp}:{settings.SECRET_KEY}"
    seed_hash = hashlib.sha256(seed.encode()).hexdigest()
    
    # Create the license segments from the hash
    segments = []
    for i in range(5):
        start = i * 5
        segment = seed_hash[start:start+5].upper()
        segment = ''.join([c if c in string.ascii_uppercase else str(ord(c) % 10) for c in segment])
        segments.append(segment)
    
    # Format the license key
    license_key = '-'.join(segments)
    
    # Calculate expiry date
    expiry_date = (datetime.utcnow() + timedelta(days=expiry_days)).isoformat()
    
    # Define default features based on license type
    features = _get_features_for_license_type(license_type)
    
    # Create license metadata
    license_data = {
        "license_key": license_key,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expiry_date,
        "license_type": license_type,
        "features": features,
        "metadata": {
            "uid": uid,
            "timestamp": timestamp
        }
    }
    
    # Create verification signature
    license_data["signature"] = _create_signature(license_data)
    
    return license_data

def validate_license_key(license_key: str) -> Tuple[bool, str]:
    """
    Validate a license key format.
    
    Args:
        license_key: The license key to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check the format
    if not re.match(LICENSE_KEY_PATTERN, license_key):
        return False, "Invalid license key format"
    
    return True, ""

def validate_license_data(license_data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate license data including signature.
    
    Args:
        license_data: The license data to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check required fields
    required_fields = ["license_key", "created_at", "license_type", "signature"]
    for field in required_fields:
        if field not in license_data:
            return False, f"Missing required field: {field}"
    
    # Verify signature
    original_signature = license_data.get("signature")
    license_copy = {k: v for k, v in license_data.items() if k != "signature"}
    computed_signature = _create_signature(license_copy)
    
    if original_signature != computed_signature:
        return False, "Invalid license signature"
    
    # Check expiration
    if "expires_at" in license_data:
        expiry_date = datetime.fromisoformat(license_data["expires_at"])
        if datetime.utcnow() > expiry_date:
            return False, "License has expired"
    
    return True, ""

def get_hardware_fingerprint() -> str:
    """
    Generate a hardware fingerprint for the current system.
    This helps prevent license sharing across multiple systems.
    
    Returns:
        A string representing the hardware fingerprint
    """
    import platform
    import uuid
    import hashlib
    
    system_info = {
        "system": platform.system(),
        "node": platform.node(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "mac_address": hex(uuid.getnode())
    }
    
    # Create a consistent string representation of the system info
    info_str = ":".join(f"{k}={v}" for k, v in sorted(system_info.items()))
    
    # Create a hash of the system info
    return hashlib.sha256(info_str.encode()).hexdigest()

def _create_signature(data: Dict[str, Any]) -> str:
    """
    Create a HMAC signature for license data.
    
    Args:
        data: Dictionary of license data
    
    Returns:
        Signature string
    """
    # Serialize the data to a consistent string
    data_str = _serialize_data(data)
    
    # Create HMAC signature
    signature = hmac.new(
        settings.SECRET_KEY.encode(),
        data_str.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return signature

def _serialize_data(data: Dict[str, Any]) -> str:
    """
    Serialize dictionary data to a consistent string format.
    
    Args:
        data: Dictionary to serialize
    
    Returns:
        Serialized string
    """
    if isinstance(data, dict):
        return ":".join(f"{k}={_serialize_data(v)}" for k, v in sorted(data.items()))
    elif isinstance(data, list):
        return ",".join(_serialize_data(item) for item in data)
    else:
        return str(data)

def _get_features_for_license_type(license_type: str) -> Dict[str, List[str]]:
    """
    Get the features included in a specific license type.
    
    Args:
        license_type: The type of license
    
    Returns:
        Dictionary of features
    """
    # Base features for all license types
    base_features = [
        "basic_monitoring",
        "arp_attack_detection",
        "email_alerts",
        "dashboard_access"
    ]
    
    # Define features by license type
    if license_type == "standard":
        enabled_features = base_features + [
            "basic_reporting",
            "network_visualization"
        ]
        restricted_features = [
            "advanced_analytics",
            "api_access",
            "automated_response",
            "custom_rules",
            "role_based_access"
        ]
    elif license_type == "professional":
        enabled_features = base_features + [
            "basic_reporting",
            "network_visualization",
            "advanced_analytics",
            "api_access",
            "scheduled_scans"
        ]
        restricted_features = [
            "automated_response",
            "custom_rules",
            "role_based_access",
            "white_labeling"
        ]
    elif license_type == "enterprise":
        enabled_features = base_features + [
            "basic_reporting",
            "network_visualization",
            "advanced_analytics",
            "api_access",
            "scheduled_scans",
            "automated_response",
            "custom_rules",
            "role_based_access",
            "white_labeling",
            "priority_support"
        ]
        restricted_features = []
    else:  # trial or unknown
        enabled_features = base_features
        restricted_features = [
            "advanced_analytics",
            "api_access",
            "automated_response",
            "custom_rules"
        ]
    
    return {
        "enabled_features": enabled_features,
        "restricted_features": restricted_features
    } 