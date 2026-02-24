"""
Project Member Model
Defines the structure for project member data (user access to projects)
"""

from pydantic import BaseModel
from typing import Literal
from datetime import datetime


# Project role type definition
ProjectRoleType = Literal["viewer", "editor", "admin", "owner"]


class ProjectMemberBase(BaseModel):
    """Base project member model"""
    project_id: str
    user_id: str
    role: ProjectRoleType


class ProjectMember(ProjectMemberBase):
    """Complete project member model with all fields"""
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "pm-123",
                "project_id": "proj-123",
                "user_id": "user-uid-123",
                "role": "editor",
                "created_at": "2025-01-15T10:30:00Z",
                "updated_at": "2025-01-15T10:30:00Z"
            }
        }


class ProjectMemberCreate(BaseModel):
    """Model for adding a user to a project"""
    project_id: str
    user_email: str  # We'll resolve email to user_id
    role: ProjectRoleType = "viewer"


class ProjectMemberUpdate(BaseModel):
    """Model for updating project member role"""
    role: ProjectRoleType


class ProjectMemberResponse(BaseModel):
    """Response model for project member operations"""
    project_id: str
    user_email: str
    user_id: str
    role: ProjectRoleType
    message: str


class ProjectMemberDetail(BaseModel):
    """Detailed project member information"""
    id: str
    project_id: str
    user_id: str
    user_email: str
    role: ProjectRoleType
    created_at: datetime
