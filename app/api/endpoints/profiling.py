from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Query, WebSocket, WebSocketDisconnect
import logging
from datetime import datetime

from app.utils.global_state import get_memory_profiler, get_performance_monitor, get_cpu_profiler
from app.utils.memory_profiler import MemoryProfiler
from app.utils.cpu_profiler import CPUProfiler
from app.core.security import get_current_active_user
from app.core.dependencies import get_admin_user

router = APIRouter()
logger = logging.getLogger("arp_guard.api.profiling")

@router.post("/memory/snapshot", response_model=Dict[str, Any])
async def create_memory_snapshot(
    label: Optional[str] = None,
    user=Depends(get_current_active_user)
):
    """
    Take a memory snapshot and return the results.
    
    Args:
        label: Optional label for the snapshot
    
    Returns:
        Dict containing the snapshot data
    """
    profiler = get_memory_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="Memory profiler not available")
    
    snapshot_id = profiler.take_snapshot(label=label or f"api_snapshot_{datetime.now().isoformat()}")
    snapshot = profiler.get_snapshot(snapshot_id)
    
    if not snapshot:
        raise HTTPException(status_code=500, detail="Failed to create memory snapshot")
    
    return {
        "snapshot_id": snapshot_id,
        "timestamp": snapshot.timestamp,
        "label": snapshot.label,
        "rss": snapshot.rss,
        "vms": snapshot.vms,
        "uss": snapshot.uss,
        "pss": snapshot.pss,
        "cpu_percent": snapshot.cpu_percent,
        "object_counts": dict(snapshot.object_counts)
    }

@router.get("/memory/snapshots", response_model=List[Dict[str, Any]])
async def list_memory_snapshots(
    limit: int = Query(10, ge=1, le=100),
    user=Depends(get_current_active_user)
):
    """
    List all memory snapshots.
    
    Args:
        limit: Maximum number of snapshots to return
    
    Returns:
        List of snapshot summaries
    """
    profiler = get_memory_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="Memory profiler not available")
    
    snapshots = profiler.get_all_snapshots()
    result = []
    
    # Sort by timestamp, newest first
    sorted_snapshots = sorted(
        snapshots.items(), 
        key=lambda x: x[1].timestamp, 
        reverse=True
    )
    
    for snapshot_id, snapshot in sorted_snapshots[:limit]:
        result.append({
            "snapshot_id": snapshot_id,
            "timestamp": snapshot.timestamp,
            "label": snapshot.label,
            "rss": snapshot.rss,
            "vms": snapshot.vms
        })
    
    return result

@router.get("/memory/snapshots/{snapshot_id}", response_model=Dict[str, Any])
async def get_memory_snapshot(
    snapshot_id: str,
    user=Depends(get_current_active_user)
):
    """
    Get a specific memory snapshot.
    
    Args:
        snapshot_id: ID of the snapshot to retrieve
    
    Returns:
        Dict containing the snapshot data
    """
    profiler = get_memory_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="Memory profiler not available")
    
    snapshot = profiler.get_snapshot(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Memory snapshot {snapshot_id} not found")
    
    return {
        "snapshot_id": snapshot_id,
        "timestamp": snapshot.timestamp,
        "label": snapshot.label,
        "rss": snapshot.rss,
        "vms": snapshot.vms,
        "uss": snapshot.uss,
        "pss": snapshot.pss,
        "cpu_percent": snapshot.cpu_percent,
        "object_counts": dict(snapshot.object_counts)
    }

@router.get("/memory/analysis", response_model=Dict[str, Any])
async def analyze_memory(
    user=Depends(get_current_active_user)
):
    """
    Analyze memory usage and return a comprehensive report.
    
    Returns:
        Dict containing memory analysis data
    """
    profiler = get_memory_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="Memory profiler not available")
    
    # Take a new snapshot for the latest data
    snapshot_id = profiler.take_snapshot(label=f"analysis_{datetime.now().isoformat()}")
    
    # Get memory summary
    summary = profiler.get_summary()
    
    # Find potential leaks
    leaks = profiler.find_leaks()
    
    # Get growth by type
    growth_by_type = profiler.get_growth_by_type()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "current_snapshot_id": snapshot_id,
        "summary": summary,
        "potential_leaks": leaks,
        "growth_by_type": growth_by_type,
        "health_score": profiler.calculate_health_score()
    }

@router.post("/memory/clear", response_model=Dict[str, str])
async def clear_memory_snapshots(
    user=Depends(get_admin_user)
):
    """
    Clear all memory snapshots (admin only).
    
    Returns:
        Dict containing success message
    """
    profiler = get_memory_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="Memory profiler not available")
    
    profiler.clear_snapshots()
    return {"message": "All memory snapshots cleared successfully"}

@router.post("/memory/gc", response_model=Dict[str, Any])
async def trigger_garbage_collection(
    user=Depends(get_admin_user)
):
    """
    Manually trigger garbage collection (admin only).
    
    Returns:
        Dict containing garbage collection results
    """
    profiler = get_memory_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="Memory profiler not available")
    
    # Take snapshot before GC
    before_snapshot_id = profiler.take_snapshot(label="before_gc")
    
    # Trigger garbage collection
    collected = profiler.force_garbage_collection()
    
    # Take snapshot after GC
    after_snapshot_id = profiler.take_snapshot(label="after_gc")
    
    # Compare snapshots
    diff = profiler.compare_snapshots(before_snapshot_id, after_snapshot_id)
    
    return {
        "collected_objects": collected,
        "before_snapshot_id": before_snapshot_id,
        "after_snapshot_id": after_snapshot_id,
        "memory_diff": diff
    }

@router.websocket("/ws/memory")
async def memory_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time memory updates.
    """
    await websocket.accept()
    
    profiler = get_memory_profiler()
    if not profiler:
        await websocket.close(code=1011, reason="Memory profiler not available")
        return
    
    try:
        # Take initial snapshot
        snapshot_id = profiler.take_snapshot(label="websocket_initial")
        snapshot = profiler.get_snapshot(snapshot_id)
        
        # Send initial data
        await websocket.send_json({
            "type": "snapshot",
            "data": {
                "snapshot_id": snapshot_id,
                "timestamp": snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime) else snapshot.timestamp,
                "rss": snapshot.rss,
                "vms": snapshot.vms,
                "uss": snapshot.uss,
                "pss": snapshot.pss,
                "cpu_percent": snapshot.cpu_percent
            }
        })
        
        # Send health score
        await websocket.send_json({
            "type": "health",
            "data": {
                "health_score": profiler.calculate_health_score()
            }
        })
        
        # Process messages from client
        while True:
            data = await websocket.receive_json()
            cmd = data.get("command")
            
            if cmd == "snapshot":
                # Take new snapshot on demand
                snapshot_id = profiler.take_snapshot(label=data.get("label", "websocket_snapshot"))
                snapshot = profiler.get_snapshot(snapshot_id)
                
                await websocket.send_json({
                    "type": "snapshot",
                    "data": {
                        "snapshot_id": snapshot_id,
                        "timestamp": snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime) else snapshot.timestamp,
                        "rss": snapshot.rss,
                        "vms": snapshot.vms,
                        "uss": snapshot.uss,
                        "pss": snapshot.pss,
                        "cpu_percent": snapshot.cpu_percent
                    }
                })
            
            elif cmd == "analyze":
                # Perform memory analysis
                summary = profiler.get_summary()
                leaks = profiler.find_leaks()
                
                await websocket.send_json({
                    "type": "analysis",
                    "data": {
                        "summary": summary,
                        "potential_leaks": leaks,
                        "health_score": profiler.calculate_health_score()
                    }
                })
            
            elif cmd == "ping":
                # Simple ping response
                await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    
    except WebSocketDisconnect:
        logger.info("Memory WebSocket client disconnected")
    except Exception as e:
        logger.error(f"Error in memory WebSocket: {str(e)}")
        await websocket.close(code=1011, reason=f"Internal error: {str(e)}")

@router.post("/cpu/snapshot", response_model=Dict[str, Any])
async def create_cpu_snapshot(
    label: Optional[str] = None,
    user=Depends(get_current_active_user)
):
    """
    Take a CPU snapshot and return the results.
    
    Args:
        label: Optional label for the snapshot
    
    Returns:
        Dict containing the snapshot data
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    snapshot_id = profiler.take_snapshot(label=label or f"api_snapshot_{datetime.now().isoformat()}")
    snapshot = profiler.get_snapshot(snapshot_id)
    
    if not snapshot:
        raise HTTPException(status_code=500, detail="Failed to create CPU snapshot")
    
    return {
        "snapshot_id": snapshot_id,
        "timestamp": snapshot.timestamp,
        "label": snapshot.label,
        "process_cpu_percent": snapshot.process_cpu_percent,
        "total_cpu_percent": snapshot.total_cpu_percent,
        "per_cpu_percent": snapshot.per_cpu_percent
    }

@router.get("/cpu/snapshots", response_model=List[Dict[str, Any]])
async def list_cpu_snapshots(
    limit: int = Query(10, ge=1, le=100),
    user=Depends(get_current_active_user)
):
    """
    List all CPU snapshots.
    
    Args:
        limit: Maximum number of snapshots to return
    
    Returns:
        List of snapshot summaries
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    snapshots = profiler.get_all_snapshots()
    result = []
    
    # Sort by timestamp, newest first
    sorted_snapshots = sorted(
        snapshots.items(), 
        key=lambda x: x[1].timestamp, 
        reverse=True
    )
    
    for snapshot_id, snapshot in sorted_snapshots[:limit]:
        result.append({
            "snapshot_id": snapshot_id,
            "timestamp": snapshot.timestamp,
            "label": snapshot.label,
            "process_cpu_percent": snapshot.process_cpu_percent,
            "total_cpu_percent": snapshot.total_cpu_percent
        })
    
    return result

@router.get("/cpu/snapshots/{snapshot_id}", response_model=Dict[str, Any])
async def get_cpu_snapshot(
    snapshot_id: str,
    user=Depends(get_current_active_user)
):
    """
    Get a specific CPU snapshot.
    
    Args:
        snapshot_id: ID of the snapshot to retrieve
    
    Returns:
        Dict containing the snapshot data
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    snapshot = profiler.get_snapshot(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"CPU snapshot {snapshot_id} not found")
    
    return {
        "snapshot_id": snapshot_id,
        "timestamp": snapshot.timestamp,
        "label": snapshot.label,
        "process_cpu_percent": snapshot.process_cpu_percent,
        "total_cpu_percent": snapshot.total_cpu_percent,
        "per_cpu_percent": snapshot.per_cpu_percent,
        "top_processes": snapshot.top_processes,
        "system_stats": snapshot.system_stats
    }

@router.post("/cpu/start-profiling", response_model=Dict[str, Any])
async def start_cpu_profiling(
    user=Depends(get_admin_user)
):
    """
    Start CPU profiling (admin only).
    
    Returns:
        Dict containing success status
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    success = profiler.start_profiling()
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to start CPU profiling")
    
    return {
        "status": "success",
        "message": "CPU profiling started"
    }

@router.post("/cpu/stop-profiling", response_model=Dict[str, Any])
async def stop_cpu_profiling(
    user=Depends(get_admin_user)
):
    """
    Stop CPU profiling and get hotspots (admin only).
    
    Returns:
        Dict containing profiling results and hotspots
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    success = profiler.stop_profiling()
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to stop CPU profiling")
    
    hotspots = profiler.identify_hotspots()
    
    return {
        "status": "success",
        "message": "CPU profiling stopped",
        "hotspots": hotspots
    }

@router.get("/cpu/analysis", response_model=Dict[str, Any])
async def analyze_cpu(
    user=Depends(get_current_active_user)
):
    """
    Analyze CPU usage and return a comprehensive report.
    
    Returns:
        Dict containing CPU analysis data
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    # Take a new snapshot for the latest data
    snapshot_id = profiler.take_snapshot(label=f"analysis_{datetime.now().isoformat()}")
    
    # Get CPU summary
    summary = profiler.get_summary()
    
    # Get optimization recommendations
    recommendations = profiler.get_optimization_recommendations()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "current_snapshot_id": snapshot_id,
        "summary": summary,
        "recommendations": recommendations,
        "health_score": profiler.calculate_health_score()
    }

@router.post("/cpu/clear", response_model=Dict[str, str])
async def clear_cpu_snapshots(
    user=Depends(get_admin_user)
):
    """
    Clear all CPU snapshots (admin only).
    
    Returns:
        Dict containing success message
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    profiler.clear_snapshots()
    return {"message": "All CPU snapshots cleared successfully"}

@router.post("/cpu/set-baseline", response_model=Dict[str, Any])
async def set_cpu_baseline(
    snapshot_id: Optional[str] = None,
    user=Depends(get_admin_user)
):
    """
    Set a baseline for CPU usage comparisons (admin only).
    
    Args:
        snapshot_id: Optional ID of snapshot to use as baseline
                    (if None, a new snapshot will be taken)
    
    Returns:
        Dict containing baseline information
    """
    profiler = get_cpu_profiler()
    if not profiler:
        raise HTTPException(status_code=503, detail="CPU profiler not available")
    
    baseline_id = profiler.set_baseline(snapshot_id)
    
    if not baseline_id:
        raise HTTPException(status_code=500, detail="Failed to set CPU baseline")
    
    baseline = profiler.get_snapshot(baseline_id)
    
    return {
        "message": "CPU baseline set successfully",
        "baseline_id": baseline_id,
        "timestamp": baseline.timestamp,
        "label": baseline.label,
        "process_cpu_percent": baseline.process_cpu_percent
    }

@router.websocket("/ws/cpu")
async def cpu_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time CPU updates.
    """
    await websocket.accept()
    
    profiler = get_cpu_profiler()
    if not profiler:
        await websocket.close(code=1011, reason="CPU profiler not available")
        return
    
    try:
        # Take initial snapshot
        snapshot_id = profiler.take_snapshot(label="websocket_initial")
        snapshot = profiler.get_snapshot(snapshot_id)
        
        # Send initial data
        await websocket.send_json({
            "type": "snapshot",
            "data": {
                "snapshot_id": snapshot_id,
                "timestamp": snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime) else snapshot.timestamp,
                "process_cpu_percent": snapshot.process_cpu_percent,
                "total_cpu_percent": snapshot.total_cpu_percent,
                "per_cpu_percent": snapshot.per_cpu_percent
            }
        })
        
        # Send health score
        await websocket.send_json({
            "type": "health",
            "data": {
                "health_score": profiler.calculate_health_score()
            }
        })
        
        # Start monitoring if not already active
        was_monitoring = profiler.monitoring_active
        if not was_monitoring:
            profiler.start_monitoring(interval=1.0)
        
        # Process messages from client
        while True:
            data = await websocket.receive_json()
            cmd = data.get("command")
            
            if cmd == "snapshot":
                # Take new snapshot on demand
                snapshot_id = profiler.take_snapshot(label=data.get("label", "websocket_snapshot"))
                snapshot = profiler.get_snapshot(snapshot_id)
                
                await websocket.send_json({
                    "type": "snapshot",
                    "data": {
                        "snapshot_id": snapshot_id,
                        "timestamp": snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime) else snapshot.timestamp,
                        "process_cpu_percent": snapshot.process_cpu_percent,
                        "total_cpu_percent": snapshot.total_cpu_percent,
                        "per_cpu_percent": snapshot.per_cpu_percent
                    }
                })
            
            elif cmd == "analyze":
                # Perform CPU analysis
                summary = profiler.get_summary()
                recommendations = profiler.get_optimization_recommendations()
                
                await websocket.send_json({
                    "type": "analysis",
                    "data": {
                        "summary": summary,
                        "recommendations": recommendations,
                        "health_score": profiler.calculate_health_score()
                    }
                })
            
            elif cmd == "hotspots":
                # Get CPU hotspots
                hotspots = profiler.identify_hotspots()
                
                await websocket.send_json({
                    "type": "hotspots",
                    "data": {
                        "hotspots": hotspots
                    }
                })
            
            elif cmd == "start_profiling":
                # Start profiling
                success = profiler.start_profiling()
                
                await websocket.send_json({
                    "type": "profiling_status",
                    "data": {
                        "status": "started" if success else "failed",
                        "is_profiling": profiler.is_profiling
                    }
                })
            
            elif cmd == "stop_profiling":
                # Stop profiling
                success = profiler.stop_profiling()
                hotspots = profiler.identify_hotspots() if success else []
                
                await websocket.send_json({
                    "type": "profiling_results",
                    "data": {
                        "status": "stopped" if success else "failed",
                        "is_profiling": profiler.is_profiling,
                        "hotspots": hotspots
                    }
                })
            
            elif cmd == "ping":
                # Simple ping response
                await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    
    except WebSocketDisconnect:
        logger.info("CPU WebSocket client disconnected")
        # Stop monitoring if we started it
        if profiler and not was_monitoring and profiler.monitoring_active:
            profiler.stop_monitoring()
    except Exception as e:
        logger.error(f"Error in CPU WebSocket: {str(e)}")
        if profiler and not was_monitoring and profiler.monitoring_active:
            profiler.stop_monitoring() 