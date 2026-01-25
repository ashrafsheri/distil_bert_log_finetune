"""
Admin Controller
Handles admin-related API endpoints
"""

from venv import logger
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional, List

from app.models.org import OrgCreate, OrgResponse, OrgSummary, DeleteOrgRequest, RegenerateApiKeyRequest, RegenerateApiKeyResponse
from app.services.org_service import OrgService
from app.utils.database import get_db
from app.utils.permissions import check_permission
import logging
router = APIRouter()

logger = logging.getLogger(__name__)

@router.post("/create-org", response_model=OrgResponse)
async def create_org(
    request: OrgCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/admin/create-org", "POST")),
    org_service: OrgService = Depends(lambda: OrgService())
):
    """
    Create a new organization with API key and manager user.

    Only accessible to admin users.
    """
    try:
        org_data = OrgCreate(
            name=request.name,
            manager_email=request.manager_email
        )

        result = await org_service.create_org(org_data, current_user["uid"], db)

        return result

    except Exception as e:
        logger.error(f"Error creating organization: {e}")   
        raise HTTPException(status_code=500, detail=f"Failed to create organization")


@router.delete("/delete-org/{org_id}")
async def delete_org(org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/admin/delete-org", "DELETE")),
    org_service: OrgService = Depends(lambda: OrgService())
):
    """
    Delete an organization by ID.

    Only accessible to admin users.
    """
    try:
        success = await org_service.delete_org(org_id, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Organization not found")

        return {"message": f"Organization {org_id} deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete organization: {str(e)}")


@router.post("/regenerate-api-key", response_model=RegenerateApiKeyResponse)
async def regenerate_api_key(
    request: RegenerateApiKeyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/admin/regenerate-api-key", "POST")),
    org_service: OrgService = Depends(lambda: OrgService())
):
    """
    Regenerate API key for an organization.

    Only accessible to admin users.
    """
    try:
        new_api_key = await org_service.regenerate_api_key(request.org_id, db)
        
        if not new_api_key:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        return RegenerateApiKeyResponse(
            org_id=request.org_id,
            new_api_key=new_api_key
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to regenerate API key: {str(e)}")


@router.get("/orgs", response_model=List[OrgSummary])
async def get_all_orgs(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/admin/orgs", "GET")),
    org_service: OrgService = Depends(lambda: OrgService())
):
    """
    Get all organizations with their user counts.

    Only accessible to admin users.
    """
    try:
        orgs = await org_service.get_all_orgs_with_user_count(db)
        return [OrgSummary(**org) for org in orgs]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organizations: {str(e)}")
