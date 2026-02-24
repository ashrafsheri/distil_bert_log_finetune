"""
Project Controller
Handles project-related API endpoints
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import logging

from app.models.project import (
    ProjectCreate, ProjectResponse, ProjectSummary, ProjectUpdate,
    RegenerateApiKeyRequest, RegenerateApiKeyResponse,
    UpdateLogTypeRequest, UpdateLogTypeResponse
)
from app.models.project_member import (
    ProjectMemberCreate, ProjectMemberResponse, ProjectMemberDetail, ProjectMemberUpdate
)
from app.services.project_service import ProjectService
from app.services.project_member_service import ProjectMemberService
from app.utils.database import get_db
from app.utils.permissions import check_permission


router = APIRouter()
logger = logging.getLogger(__name__)


# ==================== Project Management ====================

@router.post("/create", response_model=ProjectResponse)
async def create_project(
    request: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/create", "POST")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Create a new project within an organization.
    
    Accessible to admin and manager users.
    """
    try:
        # Check if user is admin or manager of the org
        if current_user.get("role") not in ["admin", "manager"] or \
           (current_user.get("role") == "manager" and current_user.get("org_id") != request.org_id):
            raise HTTPException(status_code=403, detail="You don't have permission to create projects in this organization")
        
        result = await project_service.create_project(request, current_user["uid"], db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")


@router.get("/organization/{org_id}", response_model=List[ProjectSummary])
async def get_projects_by_organization(
    org_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/organization/{org_id}", "GET")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Get all projects for an organization.
    
    Accessible to users who belong to the organization.
    """
    try:
        # Check if user is admin or belongs to the org
        if current_user.get("role") != "admin" and current_user.get("org_id") != org_id:
            raise HTTPException(status_code=403, detail="You don't have permission to access this organization's projects")
        
        projects = await project_service.get_projects_by_organization(org_id, db)
        return projects
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve projects: {str(e)}")


@router.get("/my-projects", response_model=List[ProjectSummary])
async def get_my_projects(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/my-projects", "GET")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Get all projects the current user has access to.
    
    - Managers: Get all projects in their organization
    - Employees: Get only projects they are members of
    - Admins: Get all projects they are members of (can use org endpoint for full access)
    
    Accessible to all authenticated users.
    """
    try:
        # Managers have access to all projects in their organization
        if current_user.get("role") == "manager" and current_user.get("org_id"):
            projects = await project_service.get_projects_by_organization(current_user["org_id"], db)
        else:
            # Employees and admins see only their assigned projects
            projects = await project_service.get_projects_by_user(current_user["uid"], db)
        return projects
    except Exception as e:
        logger.error(f"Error getting user projects: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve projects: {str(e)}")


@router.put("/log-type", response_model=UpdateLogTypeResponse)
async def update_project_log_type(
    request: UpdateLogTypeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/log-type", "PUT")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Update the log type for a project.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        logger.info(f"Attempting to update log type for project: {request.project_id}")
        project = await project_service.get_project_by_id(request.project_id, db)
        
        logger.info(f"Project lookup result: {project}")
        if not project:
            logger.error(f"Project not found in database: {request.project_id}")
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], request.project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to update this project")
        
        update_data = ProjectUpdate(log_type=request.log_type)
        success = await project_service.update_project(request.project_id, update_data, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Project not found")
        
        return UpdateLogTypeResponse(
            project_id=request.project_id,
            log_type=request.log_type,
            message=f"Log type updated to {request.log_type} successfully"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating log type: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update log type: {str(e)}")


@router.get("/{project_id}", response_model=ProjectSummary)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/{project_id}", "GET")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Get a specific project by ID.
    
    Accessible to:
    - Admins: Any project
    - Managers: Any project in their organization
    - Employees: Projects they are members of
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail="You don't have permission to access this project")
        
        # Get summary with member count
        projects = await project_service.get_projects_by_organization(project.org_id, db)
        project_summary = next((p for p in projects if p.id == project_id), None)
        
        if not project_summary:
            raise HTTPException(status_code=404, detail="Project not found")
        
        return project_summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve project: {str(e)}")


@router.put("/{project_id}")
async def update_project(
    project_id: str,
    request: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/{project_id}", "PUT")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Update a project.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to update this project")
        
        success = await project_service.update_project(project_id, request, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Project not found")
        
        return {"message": f"Project {project_id} updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating project: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update project: {str(e)}")


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/{project_id}", "DELETE")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Delete a project.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        is_owner = role == "owner"
        
        if not (is_admin or is_manager_in_org or is_owner):
            raise HTTPException(status_code=403, detail="You don't have permission to delete this project")
        
        success = await project_service.delete_project(project_id, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Project not found")
        
        return {"message": f"Project {project_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting project: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete project: {str(e)}")


@router.post("/regenerate-api-key", response_model=RegenerateApiKeyResponse)
async def regenerate_api_key(
    request: RegenerateApiKeyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/regenerate-api-key", "POST")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Regenerate API key for a project.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(request.project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], request.project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to regenerate API key for this project")
        
        new_api_key = await project_service.regenerate_api_key(request.project_id, db)
        
        if not new_api_key:
            raise HTTPException(status_code=404, detail="Project not found")
        
        return RegenerateApiKeyResponse(
            project_id=request.project_id,
            new_api_key=new_api_key
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error regenerating API key: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to regenerate API key: {str(e)}")


@router.get("/{project_id}/log-type")
async def get_project_log_type(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/{project_id}/log-type", "GET")),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Get the log type for a specific project.
    
    Accessible to:
    - Admins: Any project
    - Managers: Any project in their organization
    - Employees: Projects they are members of
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail="You don't have permission to access this project")
        
        return {
            "project_id": project.id,
            "log_type": project.log_type
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting log type: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get log type: {str(e)}")


# ==================== Project Member Management ====================

@router.post("/members/add", response_model=ProjectMemberResponse)
async def add_project_member(
    request: ProjectMemberCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/members/add", "POST")),
    member_service: ProjectMemberService = Depends(lambda: ProjectMemberService()),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Add a user to a project with a specific role.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(request.project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], request.project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to add members to this project")
        
        result = await member_service.add_member_to_project(request, db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding project member: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add member: {str(e)}")


@router.delete("/members/{project_id}/{user_id}")
async def remove_project_member(
    project_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/members/{project_id}/{user_id}", "DELETE")),
    member_service: ProjectMemberService = Depends(lambda: ProjectMemberService()),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Remove a user from a project.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to remove members from this project")
        
        success = await member_service.remove_member_from_project(project_id, user_id, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Project member not found")
        
        return {"message": "User removed from project successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing project member: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove member: {str(e)}")


@router.put("/members/{project_id}/{user_id}/role")
async def update_project_member_role(
    project_id: str,
    user_id: str,
    request: ProjectMemberUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/members/{project_id}/{user_id}/role", "PUT")),
    member_service: ProjectMemberService = Depends(lambda: ProjectMemberService()),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Update a project member's role.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to update member roles in this project")
        
        success = await member_service.update_member_role(project_id, user_id, request, db)
        
        if not success:
            raise HTTPException(status_code=404, detail="Project member not found")
        
        return {"message": "Member role updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating member role: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update role: {str(e)}")


@router.get("/{project_id}/members", response_model=List[ProjectMemberDetail])
async def get_project_members(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(check_permission("/api/v1/projects/{project_id}/members", "GET")),
    member_service: ProjectMemberService = Depends(lambda: ProjectMemberService()),
    project_service: ProjectService = Depends(lambda: ProjectService())
):
    """
    Get all members of a project.
    
    Accessible to:
    - Admins: Any project
    - Managers: Any project in their organization
    - Employees: Projects they are members of
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail="You don't have permission to access this project")
        
        members = await member_service.get_project_members(project_id, db)
        return members
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project members: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve members: {str(e)}")
