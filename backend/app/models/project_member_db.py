"""
Project Member Database Model
SQLAlchemy model for project_members table in PostgreSQL
Manages user access and roles at the project level
"""

from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
import enum

from app.utils.database import Base


class ProjectRoleEnum(str, enum.Enum):
    """Project-level role enumeration"""
    VIEWER = "viewer"      # Can only view project data
    EDITOR = "editor"      # Can view and add logs
    ADMIN = "admin"        # Can manage project settings
    OWNER = "owner"        # Full control over project


class ProjectMemberDB(Base):
    """SQLAlchemy model for project_members table"""
    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint('project_id', 'user_id', name='unique_project_user'),)

    id = Column(String, primary_key=True, index=True, nullable=False)
    project_id = Column(String, ForeignKey('projects.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(String, ForeignKey('users.uid', ondelete='CASCADE'), nullable=False, index=True)
    role = Column(SQLEnum(ProjectRoleEnum), nullable=False, default=ProjectRoleEnum.VIEWER)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Ensure unique combination of project and user
    __table_args__ = (
        UniqueConstraint('project_id', 'user_id', name='uq_project_member'),
    )

    def __repr__(self):
        return f"<ProjectMemberDB(project_id={self.project_id}, user_id={self.user_id}, role={self.role.value})>"
