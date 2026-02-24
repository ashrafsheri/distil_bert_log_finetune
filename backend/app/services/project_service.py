"""
Project Service
Business logic for project management
"""

import uuid
import secrets
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.project import (
    ProjectCreate, ProjectResponse, ProjectSummary, ProjectUpdate,
    generate_api_key
)
from app.models.project_db import ProjectDB
from app.models.project_member_db import ProjectMemberDB, ProjectRoleEnum
from app.models.user_db import UserDB
from app.models.organization_db import OrganizationDB
import logging


logger = logging.getLogger(__name__)


class ProjectService:
    """
    Project Service
    Service class for project-related business logic
    """

    def __init__(self):
        """Initialize ProjectService"""
        pass

    async def create_project(
        self, 
        project_data: ProjectCreate, 
        creator_uid: str, 
        db: AsyncSession
    ) -> ProjectResponse:
        """
        Create a new project within an organization
        
        Args:
            project_data: Project creation data
            creator_uid: UID of the user creating the project
            db: Database session
            
        Returns:
            ProjectResponse with project details and API key
        """
        # Verify organization exists
        org_result = await db.execute(
            select(OrganizationDB).where(OrganizationDB.id == project_data.org_id)
        )
        org = org_result.scalar_one_or_none()
        if not org:
            raise ValueError(f"Organization {project_data.org_id} not found")

        # Generate unique project ID
        project_id = f"proj-{uuid.uuid4().hex[:8]}"

        # Generate unique API key
        api_key = generate_api_key()
        while await self._api_key_exists(api_key, db):
            api_key = generate_api_key()

        # Create project in database
        project_db = ProjectDB(
            id=project_id,
            org_id=project_data.org_id,
            name=project_data.name,
            api_key=api_key,
            created_by=creator_uid,
            log_type=project_data.log_type
        )
        db.add(project_db)

        # Add creator as project owner
        member_id = f"pm-{uuid.uuid4().hex[:8]}"
        project_member = ProjectMemberDB(
            id=member_id,
            project_id=project_id,
            user_id=creator_uid,
            role=ProjectRoleEnum.OWNER
        )
        db.add(project_member)

        await db.commit()
        await db.refresh(project_db)

        return ProjectResponse(
            project_id=project_id,
            api_key=api_key,
            name=project_data.name,
            org_id=project_data.org_id,
            log_type=project_data.log_type
        )

    async def _api_key_exists(self, api_key: str, db: AsyncSession) -> bool:
        """Check if API key already exists"""
        result = await db.execute(select(ProjectDB).where(ProjectDB.api_key == api_key))
        return result.scalar_one_or_none() is not None

    async def get_project_by_id(self, project_id: str, db: AsyncSession) -> Optional[ProjectDB]:
        """
        Get project by ID
        
        Args:
            project_id: Project ID
            db: Database session
            
        Returns:
            ProjectDB or None
        """
        result = await db.execute(select(ProjectDB).where(ProjectDB.id == project_id))
        return result.scalar_one_or_none()

    async def get_project_by_api_key(self, api_key: str, db: AsyncSession) -> Optional[ProjectDB]:
        """
        Get project by API key
        
        Args:
            api_key: Project API key
            db: Database session
            
        Returns:
            ProjectDB or None
        """
        result = await db.execute(select(ProjectDB).where(ProjectDB.api_key == api_key))
        return result.scalar_one_or_none()

    async def get_projects_by_organization(
        self, 
        org_id: str, 
        db: AsyncSession
    ) -> List[ProjectSummary]:
        """
        Get all projects for an organization
        
        Args:
            org_id: Organization ID
            db: Database session
            
        Returns:
            List of ProjectSummary
        """
        result = await db.execute(
            select(
                ProjectDB.id,
                ProjectDB.name,
                ProjectDB.org_id,
                ProjectDB.log_type,
                ProjectDB.model_status,
                func.count(ProjectMemberDB.id).label('member_count')
            )
            .outerjoin(ProjectMemberDB, ProjectDB.id == ProjectMemberDB.project_id)
            .where(ProjectDB.org_id == org_id)
            .group_by(
                ProjectDB.id, 
                ProjectDB.name, 
                ProjectDB.org_id, 
                ProjectDB.log_type,
                ProjectDB.model_status
            )
            .order_by(ProjectDB.created_at)
        )
        
        projects = result.all()
        return [
            ProjectSummary(
                id=proj.id,
                name=proj.name,
                org_id=proj.org_id,
                log_type=proj.log_type,
                model_status=proj.model_status,
                member_count=proj.member_count
            )
            for proj in projects
        ]

    async def get_projects_by_user(
        self, 
        user_id: str, 
        db: AsyncSession
    ) -> List[ProjectSummary]:
        """
        Get all projects a user has access to
        
        Args:
            user_id: User UID
            db: Database session
            
        Returns:
            List of ProjectSummary
        """
        result = await db.execute(
            select(
                ProjectDB.id,
                ProjectDB.name,
                ProjectDB.org_id,
                ProjectDB.log_type,
                ProjectDB.model_status,
                func.count(ProjectMemberDB.id).label('member_count')
            )
            .join(ProjectMemberDB, ProjectDB.id == ProjectMemberDB.project_id)
            .where(ProjectMemberDB.user_id == user_id)
            .group_by(
                ProjectDB.id, 
                ProjectDB.name, 
                ProjectDB.org_id, 
                ProjectDB.log_type,
                ProjectDB.model_status
            )
            .order_by(ProjectDB.created_at)
        )
        
        projects = result.all()
        return [
            ProjectSummary(
                id=proj.id,
                name=proj.name,
                org_id=proj.org_id,
                log_type=proj.log_type,
                model_status=proj.model_status,
                member_count=proj.member_count
            )
            for proj in projects
        ]

    async def update_project(
        self, 
        project_id: str, 
        project_data: ProjectUpdate, 
        db: AsyncSession
    ) -> bool:
        """
        Update a project
        
        Args:
            project_id: Project ID
            project_data: Update data
            db: Database session
            
        Returns:
            True if successful, False if not found
        """
        result = await db.execute(select(ProjectDB).where(ProjectDB.id == project_id))
        project = result.scalar_one_or_none()
        
        if not project:
            return False
        
        if project_data.name:
            project.name = project_data.name
        if project_data.log_type:
            project.log_type = project_data.log_type
        
        await db.commit()
        return True

    async def delete_project(self, project_id: str, db: AsyncSession) -> bool:
        """
        Delete a project
        
        Args:
            project_id: Project ID
            db: Database session
            
        Returns:
            True if successful, False if not found
        """
        result = await db.execute(select(ProjectDB).where(ProjectDB.id == project_id))
        project = result.scalar_one_or_none()
        
        if not project:
            return False
        
        await db.delete(project)
        await db.commit()
        return True

    async def regenerate_api_key(self, project_id: str, db: AsyncSession) -> Optional[str]:
        """
        Generate a new API key for a project
        
        Args:
            project_id: Project ID
            db: Database session
            
        Returns:
            New API key or None if project not found
        """
        result = await db.execute(select(ProjectDB).where(ProjectDB.id == project_id))
        project = result.scalar_one_or_none()
        
        if not project:
            return None
        
        # Generate new unique API key
        new_api_key = generate_api_key()
        while await self._api_key_exists(new_api_key, db):
            new_api_key = generate_api_key()
        
        project.api_key = new_api_key
        await db.commit()
        
        return new_api_key

    async def check_user_project_access(
        self, 
        user_id: str, 
        project_id: str, 
        db: AsyncSession
    ) -> Optional[str]:
        """
        Check if a user has access to a project and return their role
        
        Args:
            user_id: User UID
            project_id: Project ID
            db: Database session
            
        Returns:
            Role string or None if no access
        """
        result = await db.execute(
            select(ProjectMemberDB)
            .where(ProjectMemberDB.user_id == user_id)
            .where(ProjectMemberDB.project_id == project_id)
        )
        member = result.scalar_one_or_none()
        
        return member.role.value if member else None
