"""
Webhook Controller
Handles webhooks from external services like the anomaly detection microservice
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Annotated, Optional
from datetime import datetime
import logging

from app.models.org import ModelStatus, ModelStatusUpdateRequest
from app.services.org_service import OrgService
from app.utils.database import get_db

router = APIRouter()
logger = logging.getLogger(__name__)


class ModelStatusWebhook(BaseModel):
    """Webhook payload for model status updates"""
    project_id: str
    api_key: str
    model_status: str
    log_count: int
    warmup_progress: float
    student_trained_at: Optional[str] = None


@router.post("/model-status")
async def receive_model_status_update(
    payload: ModelStatusWebhook,
    db: Annotated[AsyncSession, Depends(get_db)] = None,
    org_service: Annotated[OrgService, Depends(lambda: OrgService())] = None,
):
    """
    Receive model status update webhook from anomaly detection service.
    
    This is called when:
    - Student model training completes
    - Model status changes (warmup -> training -> active)
    
    Args:
        payload: ModelStatusWebhook with project details
        
    Returns:
        dict: Confirmation message
    """
    try:
        logger.info("Received model status webhook")
        
        # Verify API key matches the organization
        org = await org_service.get_org_by_api_key(payload.api_key, db)
        if not org:
            logger.warning("Invalid API key in model status webhook")
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        # Map string status to enum
        try:
            model_status = ModelStatus(payload.model_status)
        except ValueError:
            logger.warning("Invalid model status supplied in webhook")
            raise HTTPException(status_code=400, detail=f"Invalid model status: {payload.model_status}")
        
        # Parse student trained timestamp if provided
        student_trained_at = None
        if payload.student_trained_at:
            try:
                student_trained_at = datetime.fromisoformat(payload.student_trained_at.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        # Update organization model status
        success = await org_service.update_model_status(
            org_id=org.id,
            model_status=model_status,
            log_count=payload.log_count,
            warmup_progress=payload.warmup_progress,
            student_trained_at=student_trained_at,
            db=db
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        logger.info("Successfully updated model status webhook")
        
        return {
            "message": "Model status updated successfully",
            "org_id": org.id,
            "model_status": model_status.value
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing model status webhook: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process webhook: {str(e)}")


@router.get("/health")
async def webhook_health():
    """Health check for webhook endpoint"""
    return {"status": "healthy", "endpoint": "webhook"}
