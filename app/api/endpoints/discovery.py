"""
API endpoints for network device discovery.
"""
import asyncio
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
import uuid

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.core.auth import get_current_user
from app.components.device_discovery import DeviceDiscovery

# Initialize router
router = APIRouter(
    prefix="/discovery",
    tags=["discovery"],
    responses={404: {"description": "Not found"}},
)

# Initialize the device discovery component
discovery = DeviceDiscovery()

# Track active WebSocket connections
active_ws_clients: Set[WebSocket] = set()

# Store scan status information
scan_statuses = {}

# Models
class ScanOptions(BaseModel):
    """Options for network scan."""
    ip_range: Optional[str] = Field(None, description="IP range to scan (e.g., 192.168.1.0/24)")
    timeout: int = Field(5, description="Scan timeout in seconds", ge=1, le=30)
    deep_scan: bool = Field(False, description="Perform a deep scan (port scanning, OS detection)")
    include_hostnames: bool = Field(True, description="Attempt to resolve hostnames")

class ScanResponse(BaseModel):
    """Response model for scan requests."""
    scan_id: str = Field(..., description="Unique scan ID")
    status: str = Field(..., description="Current scan status")
    message: str = Field(None, description="Optional status message")

class ScanStatus(BaseModel):
    """Status model for ongoing scans."""
    scan_id: str = Field(..., description="Unique scan ID")
    status: str = Field(..., description="Current scan status")
    start_time: str = Field(..., description="Scan start time in ISO format")
    progress: float = Field(0.0, description="Scan progress percentage", ge=0.0, le=100.0)
    device_count: int = Field(0, description="Number of devices discovered so far")
    message: str = Field(None, description="Optional status message")

class ScheduleOptions(BaseModel):
    """Options for scheduling recurring scans."""
    frequency: str = Field(..., description="Scan frequency (hourly, daily, weekly)")
    time_of_day: Optional[str] = Field(None, description="Time of day for the scan (HH:MM)")
    days_of_week: Optional[List[str]] = Field(None, description="Days of the week for the scan")
    scan_options: ScanOptions = Field(..., description="Options for the scheduled scan")

class ScheduleResponse(BaseModel):
    """Response model for schedule requests."""
    schedule_id: str = Field(..., description="Unique schedule ID")
    status: str = Field(..., description="Schedule status")
    next_run: Optional[str] = Field(None, description="Next scheduled run time")

class Device(BaseModel):
    """Device model."""
    ip: str = Field(..., description="IP address")
    mac: str = Field(..., description="MAC address")
    hostname: Optional[str] = Field(None, description="Hostname if resolved")
    vendor: Optional[str] = Field(None, description="Device vendor")
    is_gateway: bool = Field(False, description="Whether this is a gateway device")
    last_seen: str = Field(..., description="Last time the device was seen")
    first_seen: str = Field(..., description="First time the device was discovered")
    ports: Optional[List[int]] = Field(None, description="Open ports if scanned")
    os_info: Optional[Dict[str, Any]] = Field(None, description="OS information if available")
    device_type: Optional[str] = Field(None, description="Detected device type")

class DeviceList(BaseModel):
    """List of devices with metadata."""
    devices: List[Device] = Field(..., description="List of discovered devices")
    total: int = Field(..., description="Total number of devices")
    scan_id: Optional[str] = Field(None, description="ID of the scan that discovered these devices")
    scan_time: Optional[str] = Field(None, description="Time when the scan was performed")

# Helper function for scan progress updates
async def update_scan_progress(scan_id: str, devices: List[Dict[str, Any]], status_message: str):
    """Update scan progress and notify WebSocket clients."""
    # Update scan status
    progress = 0.0
    if "complete" in status_message.lower():
        progress = 100.0
    elif "progress" in status_message.lower():
        # Extract progress percentage if available
        try:
            progress_str = status_message.split(':')[1].split('%')[0].strip()
            progress = float(progress_str)
        except (IndexError, ValueError):
            # Calculate based on expected devices (rough estimate)
            expected_devices = 25  # Default expectation
            progress = min(95.0, (len(devices) / expected_devices) * 100)
    
    scan_statuses[scan_id] = {
        "scan_id": scan_id,
        "status": "completed" if progress >= 100 else "in_progress",
        "start_time": scan_statuses.get(scan_id, {}).get("start_time", datetime.now().isoformat()),
        "progress": progress,
        "device_count": len(devices),
        "message": status_message
    }
    
    # Notify all connected WebSocket clients
    if active_ws_clients:
        message = {
            "type": "scan_update",
            "data": scan_statuses[scan_id]
        }
        
        for client in list(active_ws_clients):
            try:
                await client.send_json(message)
            except Exception:
                active_ws_clients.discard(client)

# API routes
@router.post("/scan", response_model=ScanResponse)
async def start_network_scan(
    options: ScanOptions,
    background_tasks: BackgroundTasks,
    current_user = Depends(get_current_user)
):
    """Start a network discovery scan."""
    if discovery.discovery_in_progress:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A scan is already in progress"
        )
    
    # Generate a scan ID
    scan_id = f"scan_{uuid.uuid4().hex[:8]}"
    
    # Initialize scan status
    scan_statuses[scan_id] = {
        "scan_id": scan_id,
        "status": "starting",
        "start_time": datetime.now().isoformat(),
        "progress": 0.0,
        "device_count": 0,
        "message": "Scan is starting"
    }
    
    # Define the progress callback
    async def progress_callback(devices_count, status_message):
        await update_scan_progress(scan_id, discovery.devices, status_message)
    
    # Start the scan in the background
    def run_scan():
        # Create an event loop for the background task
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Setup the progress callback to run in the background
        async def async_progress_callback(devices_count, status_message):
            await update_scan_progress(scan_id, discovery.devices, status_message)
        
        # Create a synchronous wrapper for the callback
        def sync_callback(devices_count, status_message):
            loop.run_until_complete(async_progress_callback(devices_count, status_message))
        
        # Run the scan
        result_scan_id, devices = discovery.discover_devices(
            subnet=options.ip_range,
            timeout=options.timeout,
            progress_callback=sync_callback
        )
        
        # Update final status
        final_status = {
            "scan_id": scan_id,
            "status": "completed",
            "start_time": scan_statuses[scan_id]["start_time"],
            "progress": 100.0,
            "device_count": len(devices),
            "message": f"Scan completed, found {len(devices)} devices"
        }
        scan_statuses[scan_id] = final_status
        
        # Send final notification
        loop.run_until_complete(notify_clients_of_scan_completion(scan_id, devices))
        
        # Close the event loop
        loop.close()
    
    # Schedule the background task
    background_tasks.add_task(run_scan)
    
    return {
        "scan_id": scan_id,
        "status": "starting",
        "message": "Scan has been started"
    }

async def notify_clients_of_scan_completion(scan_id: str, devices: List[Dict[str, Any]]):
    """Notify WebSocket clients when a scan completes."""
    if active_ws_clients:
        message = {
            "type": "scan_completed",
            "data": {
                "scan_id": scan_id,
                "device_count": len(devices),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        for client in list(active_ws_clients):
            try:
                await client.send_json(message)
            except Exception:
                active_ws_clients.discard(client)

@router.get("/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str, current_user = Depends(get_current_user)):
    """Get the status of a network scan."""
    if scan_id not in scan_statuses:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )
    
    return scan_statuses[scan_id]

@router.delete("/scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(scan_id: str, current_user = Depends(get_current_user)):
    """Cancel an ongoing network scan."""
    if scan_id not in scan_statuses:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )
    
    # Only try to stop if it's in progress
    if scan_statuses[scan_id]["status"] in ["starting", "in_progress"]:
        success = discovery.stop_discovery()
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to cancel the scan"
            )
        
        # Update the scan status
        scan_statuses[scan_id]["status"] = "cancelled"
        scan_statuses[scan_id]["message"] = "Scan was cancelled by user"
        
        # Notify WebSocket clients
        if active_ws_clients:
            message = {
                "type": "scan_cancelled",
                "data": {
                    "scan_id": scan_id,
                    "timestamp": datetime.now().isoformat()
                }
            }
            
            for client in list(active_ws_clients):
                try:
                    await client.send_json(message)
                except Exception:
                    active_ws_clients.discard(client)

@router.get("/devices", response_model=DeviceList)
async def get_discovered_devices(
    current_user = Depends(get_current_user),
    scan_id: Optional[str] = None
):
    """Get all discovered devices."""
    if scan_id:
        # Get devices from a specific scan
        scan_details = discovery.get_discovery_details(scan_id)
        if "error" in scan_details:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=scan_details["error"]
            )
        
        return {
            "devices": scan_details["devices"],
            "total": scan_details["device_count"],
            "scan_id": scan_id,
            "scan_time": scan_details["timestamp"]
        }
    else:
        # Get devices from the most recent scan
        devices = discovery.get_last_discovery()
        return {
            "devices": devices,
            "total": len(devices),
            "scan_id": discovery.current_scan_id,
            "scan_time": (discovery.last_scan_timestamp.isoformat() 
                          if discovery.last_scan_timestamp else None)
        }

@router.post("/schedule", response_model=ScheduleResponse)
async def schedule_scan(
    options: ScheduleOptions,
    current_user = Depends(get_current_user)
):
    """Schedule a recurring network scan."""
    # Generate a schedule ID
    schedule_id = f"schedule_{uuid.uuid4().hex[:8]}"
    
    # TODO: Implement actual scheduling logic
    # This would integrate with a job scheduler like APScheduler
    
    return {
        "schedule_id": schedule_id,
        "status": "scheduled",
        "next_run": (datetime.now().replace(hour=int(options.time_of_day.split(':')[0]),
                    minute=int(options.time_of_day.split(':')[1])).isoformat()
                    if options.time_of_day else None)
    }

@router.get("/schedules")
async def get_scheduled_scans(current_user = Depends(get_current_user)):
    """Get all scheduled scans."""
    # TODO: Implement retrieval of scheduled scans
    # This would retrieve from a database or scheduler
    
    return {
        "schedules": []
    }

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time discovery updates."""
    await websocket.accept()
    active_ws_clients.add(websocket)
    
    try:
        # Send initial data about any ongoing scans
        for scan_id, status in scan_statuses.items():
            if status["status"] in ["starting", "in_progress"]:
                await websocket.send_json({
                    "type": "scan_update",
                    "data": status
                })
        
        # Wait for messages
        while True:
            data = await websocket.receive_text()
            # Handle client messages if needed
            await websocket.send_json({
                "type": "acknowledgement",
                "message": f"Received: {data}"
            })
    except WebSocketDisconnect:
        active_ws_clients.discard(websocket) 