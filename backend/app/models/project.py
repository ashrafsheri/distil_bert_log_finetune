"""
Project Model
Defines the structure for project data in the system
Projects belong to organizations
"""

from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime
import secrets


class ProjectBase(BaseModel):
    """Base project model with common fields"""
    name: str
    org_id: str
    log_type: Literal["apache", "nginx"] = "apache"


class Project(ProjectBase):
    """Complete project model with all fields"""
    id: str
    api_key: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "proj-123",
                "org_id": "org-abc123",
                "name": "Web Application Logs",
                "api_key": "sk-abc123...",
                "created_by": "user-uid",
                "log_type": "apache",
                "created_at": "2025-01-15T10:30:00Z",
                "updated_at": "2025-01-15T10:30:00Z"
            }
        }


class ProjectCreate(BaseModel):
    """Model for creating a new project"""
    name: str
    org_id: str
    log_type: Literal["apache", "nginx"] = "apache"


class ProjectUpdate(BaseModel):
    """Model for updating a project"""
    name: Optional[str] = None
    log_type: Optional[Literal["apache", "nginx"]] = None


class ProjectResponse(BaseModel):
    """Response model for project creation"""
    project_id: str
    api_key: str
    name: str
    org_id: str
    log_type: Literal["apache", "nginx"]


class ProjectSummary(BaseModel):
    """Response model for project summary"""
    id: str
    name: str
    org_id: str
    log_type: Literal["apache", "nginx"]
    member_count: int
    model_status: Optional[str] = None


class RegenerateApiKeyRequest(BaseModel):
    """Request model for regenerating project API key"""
    project_id: str


class RegenerateApiKeyResponse(BaseModel):
    """Response model for API key regeneration"""
    project_id: str
    new_api_key: str


class UpdateLogTypeRequest(BaseModel):
    """Request model for updating project log type"""
    project_id: str
    log_type: Literal["apache", "nginx"]


class UpdateLogTypeResponse(BaseModel):
    """Response model for log type update"""
    project_id: str
    log_type: Literal["apache", "nginx"]
    message: str


def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"sk-{secrets.token_urlsafe(32)}"
