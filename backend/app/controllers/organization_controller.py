"""
Organization Controller
Handles organization-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import logging

from app.models.organization import (
    OrganizationCreate, OrganizationResponse, OrganizationSummary, OrganizationUpdate
)
from app.services.organization_service import OrganizationService
from app.utils.database import get_db
from app.utils.permissions import check_permission


router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/create", response_model=OrganizationResponse)
async def create_organization(
    request: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/organizations/create", "POST")),
    org_service: OrganizationService = Depends(lambda: OrganizationService())
):
    """
    Create a new organization.
    
    Only accessible to admin users.
    """
    try:
        result = await org_service.create_organization(request, current_user["uid"], db)
        return result
    except Exception as e:
        logger.error(f"Error creating organization: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create organization: {str(e)}")


@router.get("/all", response_model=List[OrganizationSummary])
async def get_all_organizations(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/organizations/all", "GET")),
    org_service: OrganizationService = Depends(lambda: OrganizationService())
):
    """
    Get all organizations with their project and user counts.
    
    Only accessible to admin users.
    """
    try:
        orgs = await org_service.get_all_organizations(db)
        return orgs
    except Exception as e:
        logger.error(f"Error getting organizations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organizations: {str(e)}")


@router.get("/my-organizations", response_model=List[OrganizationSummary])
async def get_my_organizations(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/organizations/my-organizations", "GET")),
    org_service: OrganizationService = Depends(lambda: OrganizationService())
):
    """
    Get organizations the current user has access to.
    
    Accessible to all authenticated users.
    """
    try:
        orgs = await org_service.get_organizations_by_user(current_user["uid"], db)
        return orgs
    except Exception as e:
        logger.error(f"Error getting user organizations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organizations: {str(e)}")


@router.get("/{org_id}", response_model=OrganizationSummary)
async def get_organization(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/organizations/{org_id}", "GET")),
    org_service: OrganizationService = Depends(lambda: OrganizationService())
):
    """
    Get a specific organization by ID.
    
    Accessible to users who belong to the organization or admins.
    """
    try:
        # Check if user is admin or belongs to the org
        if current_user.get("role") != "admin" and current_user.get("org_id") != org_id:
            raise HTTPException(status_code=403, detail="You don't have permission to access this organization")
        
        org = await org_service.get_organization_by_id(org_id, db)
        
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        # Get summary with counts
        orgs = await org_service.get_all_organizations(db)
        org_summary = next((o for o in orgs if o.id == org_id), None)
        
        if not org_summary:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        return org_summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting organization: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve organization: {str(e)}")


@router.put("/{org_id}")
async def update_organization(
    org_id: str,
    request: OrganizationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/organizations/{org_id}", "PUT")),
    org_service: OrganizationService = Depends(lambda: OrganizationService())
):
    """
    Update an organization.
    
    Only accessible to admin users.
    """
    try:
        success = await org_service.update_organization(org_id, request, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        return {"message": f"Organization {org_id} updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating organization: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update organization: {str(e)}")


@router.delete("/{org_id}")
async def delete_organization(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/organizations/{org_id}", "DELETE")),
    org_service: OrganizationService = Depends(lambda: OrganizationService())
):
    """
    Delete an organization.
    
    Only accessible to admin users.
    """
    try:
        success = await org_service.delete_organization(org_id, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        return {"message": f"Organization {org_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting organization: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete organization: {str(e)}")
