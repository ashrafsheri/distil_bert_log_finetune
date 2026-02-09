"""
User Service
Business logic for user management with PostgreSQL
"""

from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
import logging

from app.models.user import User, UserCreate, UserUpdate, RoleType
from app.models.user_db import UserDB, RoleEnum

logger = logging.getLogger(__name__)


def _map_role_to_enum(role: RoleType) -> RoleEnum:
    """
    Map RoleType string to RoleEnum
    
    Args:
        role: RoleType string value
        
    Returns:
        Corresponding RoleEnum value
    """
    role_map = {
        "admin": RoleEnum.ADMIN,
        "manager": RoleEnum.MANAGER,
        "employee": RoleEnum.EMPLOYEE
    }
    return role_map[role]


def _map_enum_to_role(role_enum: RoleEnum) -> RoleType:
    """
    Map RoleEnum to RoleType string
    
    Args:
        role_enum: RoleEnum value
        
    Returns:
        Corresponding RoleType string
    """
    return role_enum.value


def _db_to_pydantic(db_user: UserDB) -> User:
    """
    Convert SQLAlchemy model to Pydantic model
    
    Args:
        db_user: SQLAlchemy UserDB model instance
        
    Returns:
        Pydantic User model instance
    """
    return User(
        email=db_user.email,
        uid=db_user.uid,
        role=_map_enum_to_role(db_user.role),
        org_id=db_user.org_id,
        enabled=db_user.enabled if db_user.enabled is not None else True,  # Handle None as True
        created_at=db_user.created_at,
        updated_at=db_user.updated_at
    )


class UserService:
    """Service class for user-related business logic with PostgreSQL"""
    
    def __init__(self, db: AsyncSession):
        """
        Initialize UserService with database session
        
        Args:
            db: Async database session
        """
        self.db = db
    
    async def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user
        
        Args:
            user_data: User creation data
            
        Returns:
            Created User object
            
        Raises:
            ValueError: If user with same uid or email already exists
        """
        try:
            # Create database model
            db_user = UserDB(
                uid=user_data.uid,
                email=user_data.email,
                role=_map_role_to_enum(user_data.role),
                org_id=user_data.org_id,
                enabled=True  # New users are enabled by default (database default will also apply)
            )
            
            # Add to session
            self.db.add(db_user)
            await self.db.flush()  # Flush to get generated values but don't commit yet
            await self.db.refresh(db_user)
            
            logger.info(f"Created user: {user_data.uid} ({user_data.email}) with role: {user_data.role}")
            
            # Convert to Pydantic model
            return _db_to_pydantic(db_user)
            
        except IntegrityError as e:
            await self.db.rollback()
            error_msg = str(e.orig) if hasattr(e, 'orig') else str(e)
            
            if 'uid' in error_msg.lower() or 'unique constraint' in error_msg.lower():
                raise ValueError(f"User with uid '{user_data.uid}' already exists")
            elif 'email' in error_msg.lower():
                raise ValueError(f"User with email '{user_data.email}' already exists")
            else:
                raise ValueError(f"Failed to create user: {error_msg}")
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error creating user: {e}")
            raise ValueError(f"Failed to create user: {str(e)}")
    
    async def get_user(self, uid: str) -> Optional[User]:
        """
        Get a user by uid
        
        Args:
            uid: User ID (Firebase UID)
            
        Returns:
            User object if found, None otherwise
        """
        try:
            result = await self.db.execute(
                select(UserDB).where(UserDB.uid == uid)
            )
            db_user = result.scalar_one_or_none()
            
            if db_user is None:
                return None
            
            return _db_to_pydantic(db_user)
        except Exception as e:
            logger.error(f"Error getting user by uid: {e}")
            raise
    
    async def get_all_users(self, org_id: Optional[str] = None) -> List[User]:
        """
        Get all users, optionally filtered by organization
        
        Args:
            org_id: Organization ID to filter by (None for all users)
            
        Returns:
            List of User objects
        """
        try:
            query = select(UserDB)
            if org_id is not None:
                query = query.where(UserDB.org_id == org_id)
            
            result = await self.db.execute(query)
            db_users = result.scalars().all()
            
            return [_db_to_pydantic(db_user) for db_user in db_users]
        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            raise
    
    async def update_user(self, uid: str, user_data: UserUpdate) -> User:
        """
        Update user enabled status
        
        Args:
            uid: User ID (Firebase UID)
            user_data: User update data (only enabled field)
            
        Returns:
            Updated User object
            
        Raises:
            ValueError: If user not found
        """
        try:
            # Get existing user
            result = await self.db.execute(
                select(UserDB).where(UserDB.uid == uid)
            )
            db_user = result.scalar_one_or_none()
            
            if db_user is None:
                raise ValueError(f"User with uid '{uid}' not found")
            
            # Update only enabled field
            await self.db.execute(
                update(UserDB)
                .where(UserDB.uid == uid)
                .values(enabled=user_data.enabled)
            )
            await self.db.flush()  # Flush to apply changes
            
            # Re-fetch user to get updated data including timestamps
            result = await self.db.execute(
                select(UserDB).where(UserDB.uid == uid)
            )
            updated_db_user = result.scalar_one()
            
            logger.info(f"Updated user enabled status: {uid} - enabled: {updated_db_user.enabled}")
            
            return _db_to_pydantic(updated_db_user)
            
        except ValueError:
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating user: {e}")
            raise ValueError(f"Failed to update user: {str(e)}")
    
    async def update_user_role(self, uid: str, role: RoleType) -> User:
        """
        Update user role
        
        Args:
            uid: User ID (Firebase UID)
            role: New role
            
        Returns:
            Updated User object
            
        Raises:
            ValueError: If user not found
        """
        try:
            # Get existing user
            result = await self.db.execute(
                select(UserDB).where(UserDB.uid == uid)
            )
            db_user = result.scalar_one_or_none()
            
            if db_user is None:
                raise ValueError(f"User with uid '{uid}' not found")
            
            # Update role
            await self.db.execute(
                update(UserDB)
                .where(UserDB.uid == uid)
                .values(role=_map_role_to_enum(role))
            )
            await self.db.flush()  # Flush to apply changes
            
            # Re-fetch user to get updated data including timestamps
            result = await self.db.execute(
                select(UserDB).where(UserDB.uid == uid)
            )
            updated_db_user = result.scalar_one()
            
            logger.info(f"Updated user role: {uid} - role: {updated_db_user.role.value}")
            
            return _db_to_pydantic(updated_db_user)
            
        except ValueError:
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error updating user role: {e}")
            raise ValueError(f"Failed to update user role: {str(e)}")
    
    async def remove_user(self, uid: str) -> bool:
        """
        Remove (delete) a user
        
        Args:
            uid: User ID (Firebase UID)
            
        Returns:
            True if user was deleted
            
        Raises:
            ValueError: If user not found
        """
        try:
            # Check if user exists
            result = await self.db.execute(
                select(UserDB).where(UserDB.uid == uid)
            )
            db_user = result.scalar_one_or_none()
            
            if db_user is None:
                raise ValueError(f"User with uid '{uid}' not found")
            
            # Delete user
            await self.db.execute(
                delete(UserDB).where(UserDB.uid == uid)
            )
            await self.db.flush()  # Flush to apply deletion
            
            logger.info(f"Removed user: {uid} ({db_user.email})")
            return True
            
        except ValueError:
            raise
        except Exception as e:
            await self.db.rollback()
            logger.error(f"Error removing user: {e}")
            raise ValueError(f"Failed to remove user: {str(e)}")


def get_user_service(db: AsyncSession) -> UserService:
    """
    Get UserService instance with database session
    
    Args:
        db: Async database session
        
    Returns:
        UserService instance
    """
    return UserService(db)
