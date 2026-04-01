"""
Project Controller
Handles project-related API endpoints
"""

from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.models.project import (
    ProjectCreate, ProjectResponse, ProjectSummary, ProjectHealthSummary, ProjectUpdate,
    RegenerateApiKeyRequest, RegenerateApiKeyResponse,
    UpdateLogTypeRequest, UpdateLogTypeResponse
)
from app.models.project_member import (
    ProjectMemberCreate, ProjectMemberResponse, ProjectMemberDetail, ProjectMemberUpdate
)
from app.services.project_service import ProjectService
from app.services.project_member_service import ProjectMemberService
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.utils.database import get_db
from app.utils.firebase_auth import get_current_user
from app.utils.permissions import check_permission


router = APIRouter()
logger = logging.getLogger(__name__)

PROJECT_NOT_FOUND = "Project not found"
PROJECT_ACCESS_DENIED = "You don't have permission to access this project"
PROJECT_UPDATE_DENIED = "You don't have permission to update this project"
PROJECT_LIST_FAILED = "Failed to retrieve projects"
PROJECT_ADD_MEMBER_FAILED = "Failed to add member"
PROJECT_MEMBER_NOT_FOUND = "Project member not found"
PROJECT_AVAILABLE_MEMBERS_FAILED = "Failed to retrieve available members"
PROJECT_CREATE_RESPONSES = {
    400: {"description": "Organization ID is required or request is invalid"},
    403: {"description": "You don't have permission to create projects in this organization"},
    500: {"description": "Failed to create project"},
}
PROJECT_LIST_RESPONSES = {
    403: {"description": "You don't have permission to access this organization's projects"},
    500: {"description": PROJECT_LIST_FAILED},
}
PROJECT_LOG_TYPE_UPDATE_RESPONSES = {
    403: {"description": PROJECT_UPDATE_DENIED},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to update log type"},
}
PROJECT_GET_RESPONSES = {
    403: {"description": PROJECT_ACCESS_DENIED},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to retrieve project"},
}
PROJECT_HEALTH_RESPONSES = {
    403: {"description": PROJECT_ACCESS_DENIED},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to retrieve project health"},
}
PROJECT_UPDATE_RESPONSES = {
    403: {"description": PROJECT_UPDATE_DENIED},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to update project"},
}
PROJECT_DELETE_RESPONSES = {
    403: {"description": "You don't have permission to delete this project"},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to delete project"},
}
PROJECT_API_KEY_RESPONSES = {
    403: {"description": "You don't have permission to regenerate API key for this project"},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to regenerate API key"},
}
PROJECT_GET_LOG_TYPE_RESPONSES = {
    403: {"description": PROJECT_ACCESS_DENIED},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to get log type"},
}
PROJECT_ADD_MEMBER_RESPONSES = {
    400: {"description": PROJECT_ADD_MEMBER_FAILED},
    403: {"description": "You don't have permission to add members to this project"},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": PROJECT_ADD_MEMBER_FAILED},
}
PROJECT_REMOVE_MEMBER_RESPONSES = {
    403: {"description": "You don't have permission to remove members from this project"},
    404: {"description": PROJECT_MEMBER_NOT_FOUND},
    500: {"description": "Failed to remove member"},
}
PROJECT_UPDATE_MEMBER_RESPONSES = {
    403: {"description": "You don't have permission to update member roles in this project"},
    404: {"description": PROJECT_MEMBER_NOT_FOUND},
    500: {"description": "Failed to update role"},
}
PROJECT_GET_MEMBERS_RESPONSES = {
    403: {"description": PROJECT_ACCESS_DENIED},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": "Failed to retrieve members"},
}
PROJECT_AVAILABLE_MEMBERS_RESPONSES = {
    400: {"description": PROJECT_AVAILABLE_MEMBERS_FAILED},
    403: {"description": "You don't have permission to view available members"},
    404: {"description": PROJECT_NOT_FOUND},
    500: {"description": PROJECT_AVAILABLE_MEMBERS_FAILED},
}


# ==================== Project Management ====================

@router.post("/create", response_model=ProjectResponse, responses=PROJECT_CREATE_RESPONSES)
async def create_project(
    request: ProjectCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/create", "POST"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
):
    """
    Create a new project within an organization.
    
    Accessible to admin and manager users.
    """
    try:
        # Auto-fill org_id for managers if not provided
        if not request.org_id or request.org_id.strip() == "":
            if current_user.get("role") == "manager":
                request.org_id = current_user.get("org_id")
            elif current_user.get("role") != "admin":
                raise HTTPException(status_code=400, detail="Organization ID is required")
        
        # Check if user is admin or manager of the org
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == request.org_id
        )

        if not (is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail="You don't have permission to create projects in this organization")
        
        result = await project_service.create_project(request, current_user["uid"], db)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating project: {e}")
        raise HTTPException(status_code=500, detail="Failed to create project")


@router.get("/organization/{org_id}", response_model=List[ProjectSummary], responses=PROJECT_LIST_RESPONSES)
async def get_projects_by_organization(
    org_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/organization/{org_id}", "GET"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
        raise HTTPException(status_code=500, detail=PROJECT_LIST_FAILED)

@router.get("/my-projects", response_model=List[ProjectSummary], responses={500: {"description": PROJECT_LIST_FAILED}})
async def get_my_projects(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/my-projects", "GET"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
        raise HTTPException(status_code=500, detail=PROJECT_LIST_FAILED)


@router.put("/log-type", response_model=UpdateLogTypeResponse, responses=PROJECT_LOG_TYPE_UPDATE_RESPONSES)
async def update_project_log_type(
    request: UpdateLogTypeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/log-type", "PUT"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], request.project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail=PROJECT_UPDATE_DENIED)
        
        update_data = ProjectUpdate(log_type=request.log_type)
        success = await project_service.update_project(request.project_id, update_data, db)
        
        if not success:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        return UpdateLogTypeResponse(
            project_id=request.project_id,
            log_type=request.log_type,
            message=f"Log type updated to {request.log_type} successfully"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating log type: {e}")
        raise HTTPException(status_code=500, detail="Failed to update log type")


@router.get("/{project_id}", response_model=ProjectSummary, responses=PROJECT_GET_RESPONSES)
async def get_project(
    project_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}", "GET"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail=PROJECT_ACCESS_DENIED)
        
        # Get summary with member count
        projects = await project_service.get_projects_by_organization(project.org_id, db)
        project_summary = next((p for p in projects if p.id == project_id), None)
        
        if not project_summary:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        return project_summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve project")


@router.get("/{project_id}/health", response_model=ProjectHealthSummary, responses=PROJECT_HEALTH_RESPONSES)
async def get_project_health(
    project_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}", "GET"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
    anomaly_detection_service: Annotated[AnomalyDetectionService, Depends(lambda: AnomalyDetectionService())],
):
    """Get detailed detector health for a project."""
    try:
        project = await project_service.get_project_by_id(project_id, db)
        if not project:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)

        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and
            current_user.get("org_id") == project.org_id
        )
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail=PROJECT_ACCESS_DENIED)

        health = await anomaly_detection_service.get_project_health(project_id)
        if not health:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)

        return ProjectHealthSummary(**health)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project health: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve project health")


@router.put("/{project_id}", responses=PROJECT_UPDATE_RESPONSES)
async def update_project(
    project_id: str,
    request: ProjectUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}", "PUT"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail=PROJECT_UPDATE_DENIED)
        
        success = await project_service.update_project(project_id, request, db)
        
        if not success:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        return {"message": f"Project {project_id} updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating project: {e}")
        raise HTTPException(status_code=500, detail="Failed to update project")


@router.delete("/{project_id}", responses=PROJECT_DELETE_RESPONSES)
async def delete_project(
    project_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}", "DELETE"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        return {"message": f"Project {project_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting project: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete project")


@router.post("/regenerate-api-key", response_model=RegenerateApiKeyResponse, responses=PROJECT_API_KEY_RESPONSES)
async def regenerate_api_key(
    request: RegenerateApiKeyRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/regenerate-api-key", "POST"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], request.project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to regenerate API key for this project")
        
        new_api_key = await project_service.regenerate_api_key(request.project_id, db)
        
        if not new_api_key:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        return RegenerateApiKeyResponse(
            project_id=request.project_id,
            new_api_key=new_api_key
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error regenerating API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to regenerate API key")


@router.get("/{project_id}/log-type", responses=PROJECT_GET_LOG_TYPE_RESPONSES)
async def get_project_log_type(
    project_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}/log-type", "GET"))],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail=PROJECT_ACCESS_DENIED)
        
        return {
            "project_id": project.id,
            "log_type": project.log_type
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting log type: {e}")
        raise HTTPException(status_code=500, detail="Failed to get log type")


# ==================== Project Member Management ====================

@router.post("/members/add", response_model=ProjectMemberResponse, responses=PROJECT_ADD_MEMBER_RESPONSES)
async def add_project_member(
    request: ProjectMemberCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(get_current_user)],
    member_service: Annotated[ProjectMemberService, Depends(lambda: ProjectMemberService())],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], request.project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
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
        raise HTTPException(status_code=500, detail=PROJECT_ADD_MEMBER_FAILED)


@router.delete("/members/{project_id}/{user_id}", responses=PROJECT_REMOVE_MEMBER_RESPONSES)
async def remove_project_member(
    project_id: str,
    user_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/members/{project_id}/{user_id}", "DELETE"))],
    member_service: Annotated[ProjectMemberService, Depends(lambda: ProjectMemberService())],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to remove members from this project")
        
        success = await member_service.remove_member_from_project(project_id, user_id, db)
        
        if not success:
            raise HTTPException(status_code=404, detail=PROJECT_MEMBER_NOT_FOUND)
        
        return {"message": "User removed from project successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing project member: {e}")
        raise HTTPException(status_code=500, detail="Failed to remove member")


@router.put("/members/{project_id}/{user_id}/role", responses=PROJECT_UPDATE_MEMBER_RESPONSES)
async def update_project_member_role(
    project_id: str,
    user_id: str,
    request: ProjectMemberUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/members/{project_id}/{user_id}/role", "PUT"))],
    member_service: Annotated[ProjectMemberService, Depends(lambda: ProjectMemberService())],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to update member roles in this project")
        
        success = await member_service.update_member_role(project_id, user_id, request, db)
        
        if not success:
            raise HTTPException(status_code=404, detail=PROJECT_MEMBER_NOT_FOUND)
        
        return {"message": "Member role updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating member role: {e}")
        raise HTTPException(status_code=500, detail="Failed to update role")


@router.get("/{project_id}/members", response_model=List[ProjectMemberDetail], responses=PROJECT_GET_MEMBERS_RESPONSES)
async def get_project_members(
    project_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}/members", "GET"))],
    member_service: Annotated[ProjectMemberService, Depends(lambda: ProjectMemberService())],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
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
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        
        if not (role or is_admin or is_manager_in_org):
            raise HTTPException(status_code=403, detail=PROJECT_ACCESS_DENIED)
        
        members = await member_service.get_project_members(project_id, db)
        return members
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting project members: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve members")


@router.get("/{project_id}/available-members", responses=PROJECT_AVAILABLE_MEMBERS_RESPONSES)
async def get_available_members(
    project_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[dict, Depends(check_permission("/api/v1/projects/{project_id}/available-members", "GET"))],
    member_service: Annotated[ProjectMemberService, Depends(lambda: ProjectMemberService())],
    project_service: Annotated[ProjectService, Depends(lambda: ProjectService())],
):
    """
    Get organization members who are not yet members of the project.
    
    Used by ProjectAdmins and Owners to see available users to add.
    Only returns users from the same organization as the project.
    
    Accessible to:
    - System admins: Any project
    - Managers: Any project in their organization
    - Project admins/owners: Their projects only
    """
    try:
        project = await project_service.get_project_by_id(project_id, db)
        
        if not project:
            raise HTTPException(status_code=404, detail=PROJECT_NOT_FOUND)
        
        # Check access permissions - only users who can manage members
        role = await project_service.check_user_project_access(current_user["uid"], project_id, db)
        is_admin = current_user.get("role") == "admin"
        is_manager_in_org = (
            current_user.get("role") == "manager" and 
            current_user.get("org_id") == project.org_id
        )
        has_project_permission = role in ["project_admin", "owner"]
        
        if not (is_admin or is_manager_in_org or has_project_permission):
            raise HTTPException(status_code=403, detail="You don't have permission to view available members")
        
        available = await member_service.get_available_org_members(project_id, db)
        return available
    except ValueError as e:
        logger.error(f"Error getting available members: {e}")
        raise HTTPException(status_code=400, detail=PROJECT_AVAILABLE_MEMBERS_FAILED)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting available members: {e}")
        raise HTTPException(status_code=500, detail=PROJECT_AVAILABLE_MEMBERS_FAILED)
