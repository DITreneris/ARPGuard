from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, File, UploadFile, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import logging
from datetime import datetime
import json
import os
import tempfile
import pandas as pd
from sqlalchemy.orm import Session

from app.core.security import get_current_active_user
from app.core.dependencies import get_admin_user, get_db
from app.utils.feedback_analyzer import FeedbackAnalyzer
from app.models.feedback import Feedback
from app.schemas.feedback import FeedbackCreate, FeedbackResponse, FeedbackAnalysisResponse

router = APIRouter()
logger = logging.getLogger("arp_guard.api.feedback")

# Initialize a global feedback analyzer
analyzer = FeedbackAnalyzer()

@router.post("/submit", response_model=FeedbackResponse)
async def submit_feedback(
    feedback: FeedbackCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user)
):
    """
    Submit feedback from beta testers
    
    Args:
        feedback: Feedback data
        
    Returns:
        Created feedback entry
    """
    try:
        # Create DB model
        feedback_model = Feedback(
            user_id=user.id,
            text=feedback.text,
            rating=feedback.rating,
            category=feedback.category,
            version=feedback.version,
            metadata=feedback.metadata
        )
        
        # Add to DB
        db.add(feedback_model)
        db.commit()
        db.refresh(feedback_model)
        
        # Also add to analyzer
        analyzer.add_feedback({
            "id": feedback_model.id,
            "user_id": user.id,
            "text": feedback.text,
            "rating": feedback.rating,
            "category": feedback.category,
            "version": feedback.version,
            "timestamp": feedback_model.created_at.isoformat(),
            "metadata": feedback.metadata
        })
        
        return FeedbackResponse(
            id=feedback_model.id,
            user_id=user.id,
            text=feedback.text,
            rating=feedback.rating,
            category=feedback.category,
            version=feedback.version,
            created_at=feedback_model.created_at,
            metadata=feedback.metadata
        )
    except Exception as e:
        logger.error(f"Error submitting feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

@router.get("/list", response_model=List[FeedbackResponse])
async def list_feedback(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    version: Optional[str] = None,
    category: Optional[str] = None,
    min_rating: Optional[int] = None,
    max_rating: Optional[int] = None,
    db: Session = Depends(get_db),
    user=Depends(get_admin_user)
):
    """
    List feedback entries (admin only)
    
    Args:
        limit: Maximum number of entries to return
        offset: Number of entries to skip
        version: Filter by version
        category: Filter by category
        min_rating: Minimum rating
        max_rating: Maximum rating
        
    Returns:
        List of feedback entries
    """
    try:
        # Build query
        query = db.query(Feedback)
        
        # Apply filters
        if version:
            query = query.filter(Feedback.version == version)
        if category:
            query = query.filter(Feedback.category == category)
        if min_rating is not None:
            query = query.filter(Feedback.rating >= min_rating)
        if max_rating is not None:
            query = query.filter(Feedback.rating <= max_rating)
        
        # Order by creation time (newest first)
        query = query.order_by(Feedback.created_at.desc())
        
        # Apply pagination
        feedback_list = query.offset(offset).limit(limit).all()
        
        return [
            FeedbackResponse(
                id=feedback.id,
                user_id=feedback.user_id,
                text=feedback.text,
                rating=feedback.rating,
                category=feedback.category,
                version=feedback.version,
                created_at=feedback.created_at,
                metadata=feedback.metadata
            )
            for feedback in feedback_list
        ]
    except Exception as e:
        logger.error(f"Error listing feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list feedback: {str(e)}")

@router.get("/analysis", response_model=FeedbackAnalysisResponse)
async def analyze_feedback(
    version: Optional[str] = None,
    category: Optional[str] = None,
    user=Depends(get_admin_user)
):
    """
    Analyze feedback data (admin only)
    
    Args:
        version: Filter by version
        category: Filter by category
        
    Returns:
        Feedback analysis
    """
    try:
        # If we need to filter, we should load from DB rather than using
        # the analyzer's cached data
        if version or category:
            # Use a database session
            db = next(get_db())
            
            # Build query
            query = db.query(Feedback)
            
            # Apply filters
            if version:
                query = query.filter(Feedback.version == version)
            if category:
                query = query.filter(Feedback.category == category)
            
            # Get feedback items
            feedback_items = query.all()
            
            # Create a temporary analyzer
            temp_analyzer = FeedbackAnalyzer()
            
            # Add feedback items
            for feedback in feedback_items:
                temp_analyzer.add_feedback({
                    "id": feedback.id,
                    "user_id": feedback.user_id,
                    "text": feedback.text,
                    "rating": feedback.rating,
                    "category": feedback.category,
                    "version": feedback.version,
                    "timestamp": feedback.created_at.isoformat(),
                    "metadata": feedback.metadata
                })
            
            # Get analysis
            analysis = temp_analyzer.analyze_feedback()
        else:
            # Use global analyzer with all data
            analysis = analyzer.analyze_feedback()
        
        # Extract relevant info
        overall_sentiment = analysis.get('overall_sentiment', {})
        sentiment_distribution = analysis.get('sentiment_distribution', {})
        category_distribution = analysis.get('category_distribution', {})
        
        # Get common themes
        common_themes = analyzer.generate_common_themes()
        
        return FeedbackAnalysisResponse(
            total_feedback=len(analyzer.feedback_data),
            overall_sentiment=overall_sentiment,
            sentiment_distribution=sentiment_distribution,
            category_distribution=category_distribution,
            common_themes=dict(common_themes),
            timestamp=datetime.now()
        )
    except Exception as e:
        logger.error(f"Error analyzing feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to analyze feedback: {str(e)}")

@router.get("/report", response_class=HTMLResponse)
async def get_feedback_report(
    user=Depends(get_admin_user)
):
    """
    Generate a comprehensive HTML feedback report
    
    Returns:
        HTML report
    """
    try:
        # Generate HTML report
        html_report = analyzer.generate_report(output_format='html')
        
        if not html_report:
            raise HTTPException(status_code=500, detail="Failed to generate report")
        
        return HTMLResponse(content=html_report)
    except Exception as e:
        logger.error(f"Error generating feedback report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.post("/import", response_model=Dict[str, Any])
async def import_feedback(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    user=Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Import feedback data from CSV or JSON (admin only)
    
    Args:
        file: CSV or JSON file with feedback data
        
    Returns:
        Import status
    """
    try:
        # Check file extension
        if not (file.filename.endswith('.csv') or file.filename.endswith('.json')):
            raise HTTPException(status_code=400, detail="Only CSV and JSON files are supported")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        
        # Write uploaded file to temp file
        with open(temp_file.name, 'wb') as f:
            content = await file.read()
            f.write(content)
        
        # Schedule background import task
        background_tasks.add_task(
            import_feedback_background, 
            temp_file.name, 
            file.filename, 
            db
        )
        
        return {
            "status": "success",
            "message": f"Importing {file.filename} in the background"
        }
    except Exception as e:
        logger.error(f"Error importing feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to import feedback: {str(e)}")

@router.get("/export", response_model=Dict[str, str])
async def export_feedback(
    format_type: str = Query("csv", regex="^(csv|json)$"),
    user=Depends(get_admin_user)
):
    """
    Export analyzed feedback data
    
    Args:
        format_type: Export format ('csv' or 'json')
        
    Returns:
        Export status with file path
    """
    try:
        # Create export directory if it doesn't exist
        export_dir = os.path.join(os.getcwd(), "exports")
        os.makedirs(export_dir, exist_ok=True)
        
        # Create export file path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"feedback_export_{timestamp}.{format_type}"
        file_path = os.path.join(export_dir, filename)
        
        # Export data
        success = analyzer.export_data(file_path, format_type)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to export data")
        
        return {
            "status": "success",
            "file_path": file_path,
            "download_url": f"/api/feedback/download/{filename}"
        }
    except Exception as e:
        logger.error(f"Error exporting feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to export feedback: {str(e)}")

@router.get("/download/{filename}", response_class=FileResponse)
async def download_export(
    filename: str,
    user=Depends(get_admin_user)
):
    """
    Download exported feedback file
    
    Args:
        filename: Name of the exported file
        
    Returns:
        File for download
    """
    export_dir = os.path.join(os.getcwd(), "exports")
    file_path = os.path.join(export_dir, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Export file not found")
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type='application/octet-stream'
    )

@router.post("/reset", response_model=Dict[str, str])
async def reset_analyzer(
    user=Depends(get_admin_user)
):
    """
    Reset the feedback analyzer (admin only)
    
    Returns:
        Reset status
    """
    try:
        analyzer.clear_data()
        
        return {
            "status": "success",
            "message": "Feedback analyzer reset successfully"
        }
    except Exception as e:
        logger.error(f"Error resetting analyzer: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to reset analyzer: {str(e)}")

@router.get("/sentiment-trend", response_model=Dict[str, Any])
async def get_sentiment_trend(
    timeframe: str = Query("day", regex="^(day|week|month)$"),
    user=Depends(get_admin_user)
):
    """
    Get sentiment trend data for plotting
    
    Args:
        timeframe: Time aggregation ('day', 'week', 'month')
        
    Returns:
        Base64 encoded sentiment trend image
    """
    try:
        img_base64 = analyzer.plot_sentiment_trend(timeframe)
        
        if not img_base64:
            raise HTTPException(status_code=500, detail="Failed to generate sentiment trend plot")
        
        return {
            "status": "success",
            "image_data": img_base64,
            "content_type": "image/png"
        }
    except Exception as e:
        logger.error(f"Error generating sentiment trend: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate sentiment trend: {str(e)}")

@router.get("/category-distribution", response_model=Dict[str, Any])
async def get_category_distribution(
    user=Depends(get_admin_user)
):
    """
    Get category distribution data for plotting
    
    Returns:
        Base64 encoded category distribution image
    """
    try:
        img_base64 = analyzer.plot_category_distribution()
        
        if not img_base64:
            raise HTTPException(status_code=500, detail="Failed to generate category distribution plot")
        
        return {
            "status": "success",
            "image_data": img_base64,
            "content_type": "image/png"
        }
    except Exception as e:
        logger.error(f"Error generating category distribution: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate category distribution: {str(e)}")

@router.get("/version-comparison", response_model=Dict[str, Any])
async def compare_versions(
    version1: str,
    version2: str,
    user=Depends(get_admin_user)
):
    """
    Compare feedback between two versions
    
    Args:
        version1: First version to compare
        version2: Second version to compare
        
    Returns:
        Version comparison data
    """
    try:
        comparison = analyzer.version_comparison(version1, version2)
        
        if not comparison:
            raise HTTPException(status_code=404, detail="One or both versions not found")
        
        return comparison
    except Exception as e:
        logger.error(f"Error comparing versions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to compare versions: {str(e)}")

# Helper functions
async def import_feedback_background(
    file_path: str,
    original_filename: str,
    db: Session
):
    """
    Background task to import feedback data
    
    Args:
        file_path: Path to the temporary file
        original_filename: Original filename
        db: Database session
    """
    try:
        # Load data from file
        if original_filename.endswith('.csv'):
            df = pd.read_csv(file_path)
            feedback_data = df.to_dict('records')
        else:  # JSON
            with open(file_path, 'r') as f:
                feedback_data = json.load(f)
                
        if not isinstance(feedback_data, list):
            feedback_data = [feedback_data]
        
        # Add to database and analyzer
        for data in feedback_data:
            # Create DB model
            feedback_model = Feedback(
                user_id=data.get('user_id'),
                text=data.get('text', ''),
                rating=data.get('rating'),
                category=data.get('category'),
                version=data.get('version'),
                metadata=data.get('metadata', {})
            )
            
            # Set created_at if present
            if 'timestamp' in data:
                try:
                    feedback_model.created_at = datetime.fromisoformat(data['timestamp'])
                except (ValueError, TypeError):
                    pass
            
            # Add to DB
            db.add(feedback_model)
            
            # Also add to analyzer
            analyzer.add_feedback({
                "id": feedback_model.id,
                "user_id": data.get('user_id'),
                "text": data.get('text', ''),
                "rating": data.get('rating'),
                "category": data.get('category'),
                "version": data.get('version'),
                "timestamp": feedback_model.created_at.isoformat(),
                "metadata": data.get('metadata', {})
            })
        
        # Commit all changes
        db.commit()
        
        logger.info(f"Successfully imported {len(feedback_data)} feedback entries from {original_filename}")
    except Exception as e:
        logger.error(f"Error in background import: {str(e)}")
    finally:
        # Always clean up the temporary file
        try:
            os.unlink(file_path)
        except Exception:
            pass 