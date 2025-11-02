"""
User Model
Defines the structure for user data in the system
"""

from pydantic import BaseModel, EmailStr
from typing import Literal, Optional
from datetime import datetime

# Role type definition
RoleType = Literal["admin", "manager", "employee"]


class UserBase(BaseModel):
    """Base user model with common fields"""
    email: EmailStr
    uid: str
    role: RoleType


class User(UserBase):
    """Complete user model with all fields"""
    enabled: bool = True
    created_at: datetime
    updated_at: datetime

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "uid": "firebase-user-id-123",
                "role": "employee",
                "enabled": True,
                "created_at": "2025-01-15T10:30:00Z",
                "updated_at": "2025-01-15T10:30:00Z"
            }
        }


class UserCreate(UserBase):
    """Model for creating a new user"""
    pass


class UserUpdate(BaseModel):
    """Model for updating user information"""
    email: Optional[EmailStr] = None
    role: Optional[RoleType] = None
    enabled: Optional[bool] = None


class RoleUpdate(BaseModel):
    """Model for updating user role"""
    role: RoleType


class PasswordUpdate(BaseModel):
    """Model for updating user password"""
    new_password: str
    current_password: Optional[str] = None  # Optional for admin password resets


class UserCreateWithPassword(BaseModel):
    """Model for creating a new user with password (complete creation)"""
    email: EmailStr
    password: str
    role: RoleType


class UserResponse(UserBase):
    """Response model for user data"""
    enabled: bool = True
    created_at: datetime
    updated_at: datetime

