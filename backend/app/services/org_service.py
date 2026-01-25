"""
Organization Service
Business logic for organization management
"""

import uuid
import secrets
import string
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext

from app.models.org import Org, OrgCreate, OrgResponse, generate_api_key
from app.models.org_db import OrgDB
from app.models.user import UserCreate
from app.models.user_db import UserDB, RoleEnum
import firebase_admin
from firebase_admin import auth
from app.utils.firebase_auth import get_firebase_app
import logging


logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class OrgService:
    """Service class for organization-related business logic"""

    def __init__(self):
        pass

    def generate_random_password(self, length: int = 12) -> str:
        """Generate a random password"""
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(characters) for _ in range(length))

    async def create_org(self, org_data: OrgCreate, creator_uid: str, db: AsyncSession) -> OrgResponse:
        """Create a new organization with API key and manager user"""

        # Generate unique org ID
        org_id = f"org-{uuid.uuid4().hex[:8]}"

        # Generate unique API key
        api_key = generate_api_key()
        while await self._api_key_exists(api_key, db):
            api_key = generate_api_key()

        # Generate manager credentials
        manager_password = self.generate_random_password()

        # Initialize Firebase Admin SDK
        get_firebase_app()

        firebase_uid = None
        try:
            # Create Firebase user for manager
            try:
                firebase_user = auth.create_user(
                    email=org_data.manager_email,
                    password=manager_password,
                    email_verified=True
                )
                firebase_uid = firebase_user.uid
            except auth.EmailAlreadyExistsError:
                raise ValueError(f"User with email '{org_data.manager_email}' already exists in Firebase")
            except Exception as e:
                raise ValueError(f"Failed to create Firebase user: {str(e)}")

            # Create org in database
            org_db = OrgDB(
                id=org_id,
                name=org_data.name,
                api_key=api_key,
                created_by=creator_uid
            )
            db.add(org_db)

            # Create manager user in database
            user_db = UserDB(
                uid=firebase_uid,
                email=org_data.manager_email,
                role=RoleEnum.MANAGER,
                org_id=org_id,
                enabled=True
            )

            db.add(user_db)
            await db.commit()

            return OrgResponse(
                org_id=org_id,
                api_key=api_key,
                manager_email=org_data.manager_email,
                manager_password=manager_password
            )

        except Exception as e:
            # If database operations fail, rollback Firebase user
            if firebase_uid:
                try:
                    auth.delete_user(firebase_uid)
                except Exception as rollback_error:
                    # Log but don't fail on rollback
                 
                    logger.error(f"Failed to rollback Firebase user {firebase_uid}: {rollback_error}")
            
            # Re-raise the original exception
            raise

    async def _api_key_exists(self, api_key: str, db: AsyncSession) -> bool:
        """Check if API key already exists"""
        result = await db.execute(select(OrgDB).where(OrgDB.api_key == api_key))
        return result.scalar_one_or_none() is not None

    async def delete_org(self, org_id: str, db: AsyncSession) -> bool:
        """Delete an organization by ID"""
        # Check if org exists
        result = await db.execute(select(OrgDB).where(OrgDB.id == org_id))
        org = result.scalar_one_or_none()
        
        if not org:
            return False
        
        # Delete the org
        await db.delete(org)
        await db.commit()
        return True

    async def regenerate_api_key(self, org_id: str, db: AsyncSession) -> Optional[str]:
        """Generate a new API key for an organization"""
        # Check if org exists
        result = await db.execute(select(OrgDB).where(OrgDB.id == org_id))
        org = result.scalar_one_or_none()
        
        if not org:
            return None
        
        # Generate new unique API key
        new_api_key = generate_api_key()
        while await self._api_key_exists(new_api_key, db):
            new_api_key = generate_api_key()
        
        # Update the org
        org.api_key = new_api_key
        await db.commit()
        
        return new_api_key

    async def get_all_orgs_with_user_count(self, db: AsyncSession) -> list:
        """Get all organizations with their user counts"""
        from sqlalchemy import func
        
        # Query to get orgs with user count
        result = await db.execute(
            select(
                OrgDB.id,
                OrgDB.name,
                func.count(UserDB.uid).label('user_count')
            )
            .outerjoin(UserDB, OrgDB.id == UserDB.org_id)
            .group_by(OrgDB.id, OrgDB.name)
            .order_by(OrgDB.created_at)
        )
        
        orgs = result.all()
        return [
            {
                "id": org.id,
                "name": org.name,
                "user_count": org.user_count
            }
            for org in orgs
        ]