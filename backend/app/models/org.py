"""
Organization Model
Defines the structure for organization data in the system
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import secrets


class OrgBase(BaseModel):
    """Base organization model with common fields"""
    name: str
    api_key: str
    created_by: str  # uid of the admin who created it


class Org(OrgBase):
    """Complete organization model with all fields"""
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "id": "org-123",
                "name": "Example Corp",
                "api_key": "sk-abc123...",
                "created_by": "admin-uid",
                "created_at": "2025-01-15T10:30:00Z",
                "updated_at": "2025-01-15T10:30:00Z"
            }
        }


class OrgCreate(BaseModel):
    """Model for creating a new organization"""
    name: str
    manager_email: str


class OrgResponse(BaseModel):
    """Response model for organization creation"""
    org_id: str
    api_key: str
    manager_email: str
    manager_password: str


class OrgSummary(BaseModel):
    """Response model for organization summary"""
    id: str
    name: str
    user_count: int


class DeleteOrgRequest(BaseModel):
    """Request model for deleting organization"""
    org_id: str


class RegenerateApiKeyRequest(BaseModel):
    """Request model for regenerating API key"""
    org_id: str


class RegenerateApiKeyResponse(BaseModel):
    """Response model for API key regeneration"""
    org_id: str
    new_api_key: str


def generate_api_key() -> str:
    """Generate a secure API key"""
    return f"sk-{secrets.token_urlsafe(32)}"