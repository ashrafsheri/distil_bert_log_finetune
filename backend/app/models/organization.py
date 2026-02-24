"""
Organization Model (Top Level)
Defines the structure for organization data in the system
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uuid


class OrganizationBase(BaseModel):
    """Base organization model with common fields"""
    name: str


class Organization(OrganizationBase):
    """Complete organization model with all fields"""
    id: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "org-abc123",
                "name": "Acme Corporation",
                "created_by": "admin-uid-123",
                "created_at": "2025-01-15T10:30:00Z",
                "updated_at": "2025-01-15T10:30:00Z"
            }
        }


class OrganizationCreate(BaseModel):
    """Model for creating a new organization"""
    name: str
    manager_email: str


class OrganizationUpdate(BaseModel):
    """Model for updating an organization"""
    name: Optional[str] = None


class OrganizationResponse(BaseModel):
    """Response model for organization creation"""
    org_id: str
    name: str
    message: str
    manager_email: str
    manager_password: str


class OrganizationSummary(BaseModel):
    """Response model for organization summary with project and user counts"""
    id: str
    name: str
    project_count: int
    user_count: int
