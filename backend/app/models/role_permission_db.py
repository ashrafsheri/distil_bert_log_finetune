"""
Role Permission Database Model
SQLAlchemy model for role_permissions table in PostgreSQL
Supports both organization-level and project-level permissions
"""

from sqlalchemy import Column, String, Enum as SQLEnum, UniqueConstraint, Integer
from sqlalchemy.sql import func
import enum

from app.utils.database import Base
from app.models.user_db import RoleEnum


class HTTPMethodEnum(str, enum.Enum):
    """HTTP method enumeration"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class PermissionLevel(str, enum.Enum):
    """Permission level enumeration"""
    ORGANIZATION = "organization"  # Organization-level permission
    PROJECT = "project"            # Project-level permission


class RolePermissionDB(Base):
    """SQLAlchemy model for role_permissions table"""
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    role = Column(SQLEnum(RoleEnum), nullable=False, index=True)
    api_path = Column(String, nullable=False, index=True)  # e.g., "/api/v1/users/create"
    http_method = Column(SQLEnum(HTTPMethodEnum), nullable=False, index=True)
    org_id = Column(String, nullable=True)
    project_id = Column(String, nullable=True)  # For project-level permissions
    permission_level = Column(
        SQLEnum(PermissionLevel), 
        nullable=False, 
        default=PermissionLevel.ORGANIZATION
    )
    
    # Ensure unique combination of role, api_path, and http_method
    __table_args__ = (
        UniqueConstraint('role', 'api_path', 'http_method', name='uq_role_permission'),
    )

    def __repr__(self):
        return f"<RolePermissionDB(role={self.role.value}, api_path={self.api_path}, http_method={self.http_method.value}, level={self.permission_level.value})>"

