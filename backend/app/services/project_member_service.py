"""
Project Member Service
Business logic for project member management
"""

import uuid
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.project_member import (
    ProjectMemberCreate, ProjectMemberResponse, ProjectMemberDetail, ProjectMemberUpdate
)
from app.models.project_member_db import ProjectMemberDB, ProjectRoleEnum
from app.models.user_db import UserDB
from app.models.project_db import ProjectDB
import logging


logger = logging.getLogger(__name__)


class ProjectMemberService:
    """
    Project Member Service
    Service class for project member management
    """

    def __init__(self):
        """Initialize ProjectMemberService"""
        pass

    async def add_member_to_project(
        self, 
        member_data: ProjectMemberCreate, 
        db: AsyncSession
    ) -> ProjectMemberResponse:
        """
        Add a user to a project with a specific role
        
        Args:
            member_data: Project member creation data
            db: Database session
            
        Returns:
            ProjectMemberResponse with member details
        """
        # Verify project exists
        project_result = await db.execute(
            select(ProjectDB).where(ProjectDB.id == member_data.project_id)
        )
        project = project_result.scalar_one_or_none()
        if not project:
            raise ValueError(f"Project {member_data.project_id} not found")

        # Get user by email
        user_result = await db.execute(
            select(UserDB).where(UserDB.email == member_data.user_email)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            raise ValueError(f"User with email {member_data.user_email} not found")

        # Verify user belongs to the same organization as the project
        if user.org_id != project.org_id:
            raise ValueError("User must be a member of the same organization as the project")

        # Check if user already has access to this project
        existing_result = await db.execute(
            select(ProjectMemberDB)
            .where(ProjectMemberDB.project_id == member_data.project_id)
            .where(ProjectMemberDB.user_id == user.uid)
        )
        existing_member = existing_result.scalar_one_or_none()
        
        if existing_member:
            raise ValueError(f"User already has access to this project")

        # Add member
        member_id = f"pm-{uuid.uuid4().hex[:8]}"
        project_member = ProjectMemberDB(
            id=member_id,
            project_id=member_data.project_id,
            user_id=user.uid,
            role=member_data.role
        )
        db.add(project_member)
        await db.commit()

        return ProjectMemberResponse(
            project_id=member_data.project_id,
            user_email=member_data.user_email,
            user_id=user.uid,
            role=member_data.role,
            message="User added to project successfully"
        )

    async def remove_member_from_project(
        self, 
        project_id: str, 
        user_id: str, 
        db: AsyncSession
    ) -> bool:
        """
        Remove a user from a project
        
        Args:
            project_id: Project ID
            user_id: User UID
            db: Database session
            
        Returns:
            True if successful, False if not found
        """
        result = await db.execute(
            select(ProjectMemberDB)
            .where(ProjectMemberDB.project_id == project_id)
            .where(ProjectMemberDB.user_id == user_id)
        )
        member = result.scalar_one_or_none()
        
        if not member:
            return False
        
        await db.delete(member)
        await db.commit()
        return True

    async def update_member_role(
        self, 
        project_id: str, 
        user_id: str, 
        role_data: ProjectMemberUpdate, 
        db: AsyncSession
    ) -> bool:
        """
        Update a project member's role
        
        Args:
            project_id: Project ID
            user_id: User UID
            role_data: Update data with new role
            db: Database session
            
        Returns:
            True if successful, False if not found
        """
        result = await db.execute(
            select(ProjectMemberDB)
            .where(ProjectMemberDB.project_id == project_id)
            .where(ProjectMemberDB.user_id == user_id)
        )
        member = result.scalar_one_or_none()
        
        if not member:
            return False
        
        member.role = role_data.role
        await db.commit()
        return True

    async def get_project_members(
        self, 
        project_id: str, 
        db: AsyncSession
    ) -> List[ProjectMemberDetail]:
        """
        Get all members of a project
        
        Args:
            project_id: Project ID
            db: Database session
            
        Returns:
            List of ProjectMemberDetail
        """
        result = await db.execute(
            select(ProjectMemberDB, UserDB.email)
            .join(UserDB, ProjectMemberDB.user_id == UserDB.uid)
            .where(ProjectMemberDB.project_id == project_id)
            .order_by(ProjectMemberDB.created_at)
        )
        
        members = result.all()
        return [
            ProjectMemberDetail(
                id=member.ProjectMemberDB.id,
                project_id=member.ProjectMemberDB.project_id,
                user_id=member.ProjectMemberDB.user_id,
                user_email=member.email,
                role=member.ProjectMemberDB.role,
                created_at=member.ProjectMemberDB.created_at
            )
            for member in members
        ]

    async def get_user_project_role(
        self, 
        user_id: str, 
        project_id: str, 
        db: AsyncSession
    ) -> Optional[str]:
        """
        Get a user's role in a specific project
        
        Args:
            user_id: User UID
            project_id: Project ID
            db: Database session
            
        Returns:
            Role string or None if not a member
        """
        result = await db.execute(
            select(ProjectMemberDB)
            .where(ProjectMemberDB.user_id == user_id)
            .where(ProjectMemberDB.project_id == project_id)
        )
        member = result.scalar_one_or_none()
        
        return member.role if member else None

    async def get_user_projects(
        self, 
        user_id: str, 
        db: AsyncSession
    ) -> List[dict]:
        """
        Get all projects a user has access to with their roles
        
        Args:
            user_id: User UID
            db: Database session
            
        Returns:
            List of project dictionaries with role information
        """
        result = await db.execute(
            select(ProjectMemberDB, ProjectDB)
            .join(ProjectDB, ProjectMemberDB.project_id == ProjectDB.id)
            .where(ProjectMemberDB.user_id == user_id)
            .order_by(ProjectDB.created_at)
        )
        
        projects = result.all()
        return [
            {
                "project_id": proj.ProjectDB.id,
                "project_name": proj.ProjectDB.name,
                "org_id": proj.ProjectDB.org_id,
                "role": proj.ProjectMemberDB.role,
                "log_type": proj.ProjectDB.log_type
            }
            for proj in projects
        ]

    async def get_available_org_members(
        self, 
        project_id: str, 
        db: AsyncSession
    ) -> List[dict]:
        """
        Get organization members who are not yet members of the project
        
        Args:
            project_id: Project ID
            db: Database session
            
        Returns:
            List of available member dictionaries with uid, email, and org_role
        """
        # Get project to find org_id
        project_result = await db.execute(
            select(ProjectDB).where(ProjectDB.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        if not project:
            raise ValueError("Project not found")

        # Get all users in the organization
        org_users_result = await db.execute(
            select(UserDB).where(UserDB.org_id == project.org_id)
        )
        org_users = org_users_result.scalars().all()

        # Get current project member user IDs
        members_result = await db.execute(
            select(ProjectMemberDB.user_id).where(ProjectMemberDB.project_id == project_id)
        )
        member_user_ids = {row[0] for row in members_result.all()}

        # Return org users who are not already project members
        return [
            {
                "uid": user.uid,
                "email": user.email,
                "org_role": user.role.value if hasattr(user.role, 'value') else str(user.role)
            }
            for user in org_users
            if user.uid not in member_user_ids
        ]
