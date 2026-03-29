"""
Organization Service (Top Level)
Business logic for organization management
"""

import uuid
import secrets
import string
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.organization import OrganizationCreate, OrganizationResponse, OrganizationSummary, OrganizationUpdate
from app.models.organization_db import OrganizationDB
from app.models.project_db import ProjectDB
from app.models.user_db import UserDB, RoleEnum
import logging


logger = logging.getLogger(__name__)


class OrganizationService:
    """
    Organization Service
    Service class for organization-related business logic
    """

    def __init__(self):
        """Initialize OrganizationService"""
        pass

    async def create_organization(
        self, 
        org_data: OrganizationCreate, 
        creator_uid: str, 
        db: AsyncSession
    ) -> OrganizationResponse:
        """
        Create a new organization and a manager user (both in Firebase and database)
        
        Args:
            org_data: Organization creation data
            creator_uid: UID of the user creating the organization
            db: Database session
            
        Returns:
            OrganizationResponse with org_id, manager details and password
        """
        from firebase_admin import auth
        from app.utils.firebase_auth import get_firebase_app
        
        # Generate unique org ID
        org_id = f"org-{uuid.uuid4().hex[:8]}"

        # Generate a random password for the manager
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
        manager_password = ''.join(secrets.choice(alphabet) for _ in range(16))
        
        firebase_uid = None
        try:
            # Initialize Firebase Admin SDK
            get_firebase_app()
            
            # Create Firebase user first
            firebase_user = auth.create_user(
                email=org_data.manager_email,
                password=manager_password,
                email_verified=True
            )
            firebase_uid = firebase_user.uid
            logger.info(f"Created Firebase user for manager: {org_data.manager_email}")
            
        except auth.EmailAlreadyExistsError:
            # User already exists in Firebase, try to get their UID
            try:
                existing_user = auth.get_user_by_email(org_data.manager_email)
                firebase_uid = existing_user.uid
                logger.info(f"Manager email already exists in Firebase, using existing UID: {firebase_uid}")
            except Exception as e:
                logger.error(f"Failed to get existing Firebase user: {e}")
                raise Exception(f"User with email '{org_data.manager_email}' already exists")
        except Exception as e:
            logger.error(f"Failed to create Firebase user: {e}")
            raise Exception(f"Failed to create manager user in Firebase: {str(e)}")

        # Create org in database
        org_db = OrganizationDB(
            id=org_id,
            name=org_data.name,
            created_by=creator_uid
        )
        db.add(org_db)
        await db.flush()  # Flush to get org_id available for user creation
        
        # Create manager user in database
        manager_user = UserDB(
            uid=firebase_uid,  # Use Firebase UID
            email=org_data.manager_email,
            role=RoleEnum.MANAGER,
            org_id=org_id,
            enabled=True
        )
        db.add(manager_user)
        await db.commit()
        await db.refresh(org_db)

        logger.info(f"Created organization {org_id} with manager {org_data.manager_email}")

        return OrganizationResponse(
            org_id=org_id,
            name=org_data.name,
            message="Organization created successfully",
            manager_email=org_data.manager_email,
            manager_password=manager_password
        )

    async def get_organization_by_id(self, org_id: str, db: AsyncSession) -> Optional[OrganizationDB]:
        """
        Get organization by ID
        
        Args:
            org_id: Organization ID
            db: Database session
            
        Returns:
            OrganizationDB or None
        """
        result = await db.execute(select(OrganizationDB).where(OrganizationDB.id == org_id))
        return result.scalar_one_or_none()

    async def get_all_organizations(self, db: AsyncSession) -> List[OrganizationSummary]:
        """
        Get all organizations with their project and user counts
        
        Args:
            db: Database session
            
        Returns:
            List of OrganizationSummary
        """
        # Query to get orgs with project count and user count
        result = await db.execute(
            select(
                OrganizationDB.id,
                OrganizationDB.name,
                func.count(func.distinct(ProjectDB.id)).label('project_count'),
                func.count(func.distinct(UserDB.uid)).label('user_count')
            )
            .outerjoin(ProjectDB, OrganizationDB.id == ProjectDB.org_id)
            .outerjoin(UserDB, OrganizationDB.id == UserDB.org_id)
            .group_by(OrganizationDB.id, OrganizationDB.name)
            .order_by(OrganizationDB.created_at)
        )
        
        orgs = result.all()
        return [
            OrganizationSummary(
                id=org.id,
                name=org.name,
                project_count=org.project_count,
                user_count=org.user_count
            )
            for org in orgs
        ]

    async def update_organization(
        self, 
        org_id: str, 
        org_data: OrganizationUpdate, 
        db: AsyncSession
    ) -> bool:
        """
        Update an organization
        
        Args:
            org_id: Organization ID
            org_data: Update data
            db: Database session
            
        Returns:
            True if successful, False if not found
        """
        result = await db.execute(select(OrganizationDB).where(OrganizationDB.id == org_id))
        org = result.scalar_one_or_none()
        
        if not org:
            return False
        
        if org_data.name:
            org.name = org_data.name
        
        await db.commit()
        return True

    async def delete_organization(self, org_id: str, db: AsyncSession) -> bool:
        """
        Delete an organization
        
        Args:
            org_id: Organization ID
            db: Database session
            
        Returns:
            True if successful, False if not found
        """
        result = await db.execute(select(OrganizationDB).where(OrganizationDB.id == org_id))
        org = result.scalar_one_or_none()
        
        if not org:
            return False
        
        await db.delete(org)
        await db.commit()
        return True

    async def get_organizations_by_user(self, user_id: str, db: AsyncSession) -> List[OrganizationSummary]:
        """
        Get all organizations a user has access to
        
        Args:
            user_id: User UID
            db: Database session
            
        Returns:
            List of OrganizationSummary
        """
        # Get user's org_id
        user_result = await db.execute(select(UserDB).where(UserDB.uid == user_id))
        user = user_result.scalar_one_or_none()
        
        if not user or not user.org_id:
            return []
        
        # Get the organization
        result = await db.execute(
            select(
                OrganizationDB.id,
                OrganizationDB.name,
                func.count(func.distinct(ProjectDB.id)).label('project_count'),
                func.count(func.distinct(UserDB.uid)).label('user_count')
            )
            .outerjoin(ProjectDB, OrganizationDB.id == ProjectDB.org_id)
            .outerjoin(UserDB, OrganizationDB.id == UserDB.org_id)
            .where(OrganizationDB.id == user.org_id)
            .group_by(OrganizationDB.id, OrganizationDB.name)
        )
        
        orgs = result.all()
        return [
            OrganizationSummary(
                id=org.id,
                name=org.name,
                project_count=org.project_count,
                user_count=org.user_count
            )
            for org in orgs
        ]
